//! Finding a strategy: the sites are checked without jink, then with each
//! strategy in turn; the one that gets the most checks through is kept,
//! unless it does no better than none.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use jink_core::config::Config;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinSet;

use crate::daemon::{Backend, BackendEvent};
use crate::probe::{HOSTS, Outcome, Probe, Tls};
use crate::protocol::{Checks, FailedCheck, FindResult, Found, Problem, Tried};

/// How long a strategy may take to come online.
const ONLINE_LIMIT: Duration = Duration::from_secs(10);

/// Ends finding when its sender says so, or is gone.
#[derive(Debug)]
pub(crate) struct Cancel(watch::Receiver<bool>);

impl Cancel {
    pub(crate) fn new(cancelled: watch::Receiver<bool>) -> Self {
        Self(cancelled)
    }

    /// `work`'s result, or `None` if cancelled first.
    async fn or<T>(&mut self, work: impl Future<Output = T>) -> Option<T> {
        tokio::select! {
            biased;
            _ = self.0.wait_for(|cancelled| *cancelled) => None,
            done = work => Some(done),
        }
    }
}

/// Tries `plan` (strategy ids and their configurations, in order), saying
/// at each `step` which strategy it tries; `None` if cancelled. Every
/// engine it starts has stopped when this returns.
pub(crate) async fn find<B: Backend, P: Probe>(
    backend: Arc<B>,
    probe: Arc<P>,
    plan: Vec<(String, Config)>,
    step: impl Fn(usize, Option<&str>) + Send,
    mut cancel: Cancel,
) -> Option<Found> {
    step(1, None);
    let without = cancel.or(round(&probe)).await?;
    let checks = HOSTS.len().saturating_mul(Tls::ALL.len());
    let found = |result, tried| Found {
        result,
        checks,
        without: without.clone(),
        tried,
    };
    if without.passed == checks {
        return Some(found(FindResult::NothingBlocked, Vec::new()));
    }
    let unreachable =
        |check: &FailedCheck| matches!(check.outcome, Outcome::NoAddress | Outcome::Unreachable);
    if without.passed == 0 && without.failed.iter().all(unreachable) {
        return Some(found(FindResult::NoNetwork, Vec::new()));
    }
    let mut tried = Vec::with_capacity(plan.len());
    for (index, (strategy, config)) in plan.into_iter().enumerate() {
        step(index.saturating_add(2), Some(&strategy));
        let (checks, problem) = attempt(&*backend, &probe, config, &mut cancel).await?;
        tried.push(Tried {
            strategy,
            checks,
            problem,
        });
    }
    // The most checks passed; of equals, the first tried (`max_by_key`
    // takes the last of equals, so it looks from the end).
    let best = tried.iter().rev().max_by_key(|t| t.checks.passed);
    let result = match best {
        Some(best) if best.checks.passed > without.passed => FindResult::Kept {
            strategy: best.strategy.clone(),
        },
        _ => FindResult::NoneHelped,
    };
    Some(found(result, tried))
}

/// How a strategy's start went.
enum Start {
    Online,
    NotOnline(Problem),
    /// The engine ended (failed, usually) before coming online.
    Ended(Problem),
}

/// The checks with `config` on, or why it never came online (unchecked);
/// `None` if cancelled. The engine has stopped when this returns.
async fn attempt<B: Backend, P: Probe>(
    backend: &B,
    probe: &Arc<P>,
    config: Config,
    cancel: &mut Cancel,
) -> Option<(Checks, Option<Problem>)> {
    let (events, mut reports) = mpsc::unbounded_channel();
    let (stop, stopped) = oneshot::channel();
    let mut engine = tokio::spawn(backend.run(config, events, stopped));
    // The engine's end is watched itself, not its report channel closing:
    // whoever holds a sender may keep it.
    let start = cancel
        .or(async {
            tokio::select! {
                online = online(&mut reports) => match online {
                    Ok(()) => Start::Online,
                    Err(problem) => Start::NotOnline(problem),
                },
                ended = &mut engine => Start::Ended(why_ended(ended)),
            }
        })
        .await;
    let checked = match start {
        Some(Start::Ended(problem)) => return Some((Checks::default(), Some(problem))),
        Some(Start::Online) => cancel.or(round(probe)).await.map(Ok),
        Some(Start::NotOnline(problem)) => Some(Err(problem)),
        None => None,
    };
    // It may have ended by itself already; how is no news now.
    let _ = stop.send(());
    let _ = engine.await;
    Some(match checked? {
        Ok(checks) => (checks, None),
        Err(problem) => (Checks::default(), Some(problem)),
    })
}

fn why_ended(ended: Result<Result<(), Problem>, tokio::task::JoinError>) -> Problem {
    match ended {
        Ok(Ok(())) => Problem::new("ended", &"the engine stopped by itself"),
        Ok(Err(problem)) => problem,
        Err(e) => Problem::new("engine_task", &e),
    }
}

/// Waits until the engine is online, or says why it is not.
async fn online(reports: &mut mpsc::UnboundedReceiver<BackendEvent>) -> Result<(), Problem> {
    let wait = async {
        while let Some(event) = reports.recv().await {
            match event {
                BackendEvent::Online { .. } => return Ok(()),
                BackendEvent::Offline => return Err(Problem::new("offline", &"no network")),
                BackendEvent::Bypassed(problem) => return Err(problem),
                BackendEvent::Started | BackendEvent::Notice(_) => {}
            }
        }
        // The engine ended: its end says why.
        std::future::pending().await
    };
    tokio::time::timeout(ONLINE_LIMIT, wait)
        .await
        .unwrap_or_else(|_| {
            Err(Problem::new(
                "not_online",
                &format!("not online within {} s", ONLINE_LIMIT.as_secs()),
            ))
        })
}

/// Every site over every TLS version, at once.
async fn round<P: Probe>(probe: &Arc<P>) -> Checks {
    let mut checks = JoinSet::new();
    for (index, host) in HOSTS.into_iter().enumerate() {
        for tls in Tls::ALL {
            let probe = Arc::clone(probe);
            checks.spawn(async move { (index, tls, host, probe.check(host, tls).await) });
        }
    }
    let mut done = Vec::with_capacity(checks.len());
    // A check whose task failed is missing, so it does not pass.
    while let Some(joined) = checks.join_next().await {
        if let Ok(check) = joined {
            done.push(check);
        }
    }
    done.sort_unstable_by_key(|&(index, tls, _, _)| (index, tls));
    Checks {
        passed: done
            .iter()
            .filter(|&&(_, _, _, outcome)| outcome == Outcome::Passed)
            .count(),
        failed: done
            .into_iter()
            .filter(|&(_, _, _, outcome)| outcome != Outcome::Passed)
            .map(|(_, tls, host, outcome)| FailedCheck {
                host: host.to_owned(),
                tls,
                outcome,
            })
            .collect(),
    }
}
