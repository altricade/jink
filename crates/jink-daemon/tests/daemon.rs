//! The daemon's behaviour, with a fake engine and fake sites.

use std::future::Future;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use jink_core::catalog;
use jink_core::config::Config;
use jink_core::config::platform::Platform;
use jink_core::settings::Settings;
use jink_daemon::daemon::{Backend, BackendEvent, Handle, Setup, spawn};
use jink_daemon::probe::{HOSTS, Outcome, Probe, Tls};
use jink_daemon::protocol::{
    Engine, Failure, FindResult, Found, Message, Network, Problem, Request, SettingsWire, Status,
    Support,
};
use jink_daemon::saved::Saved;
use tokio::sync::{mpsc, oneshot};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// One run of the fake engine: its configuration, its reports, and a way to
/// make it fail.
struct Run {
    config: Config,
    events: mpsc::UnboundedSender<BackendEvent>,
    fail: Option<oneshot::Sender<Problem>>,
}

/// What the fake engine does by itself once started.
#[derive(Clone, Default)]
enum Answer {
    /// Nothing: the test reports for it.
    #[default]
    Nothing,
    Online,
    Report(BackendEvent),
    Fail(Problem),
}

#[derive(Clone, Default)]
struct Fake {
    runs: Arc<Mutex<Vec<Run>>>,
    answer: Arc<Mutex<Answer>>,
    /// The configuration of the engine running now.
    current: Arc<Mutex<Option<Config>>>,
    /// Engines running now.
    live: Arc<AtomicUsize>,
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Counts an engine as running until dropped.
struct Live(Fake);

impl Drop for Live {
    fn drop(&mut self) {
        self.0.live.fetch_sub(1, Ordering::SeqCst);
        *lock(&self.0.current) = None;
    }
}

impl Fake {
    fn runs(&self) -> std::sync::MutexGuard<'_, Vec<Run>> {
        lock(&self.runs)
    }

    fn answer(&self, answer: Answer) {
        *lock(&self.answer) = answer;
    }

    fn live(&self) -> usize {
        self.live.load(Ordering::SeqCst)
    }

    fn report(&self, run: usize, event: BackendEvent) -> Result<()> {
        let runs = self.runs();
        runs.get(run).ok_or("no such run")?.events.send(event)?;
        Ok(())
    }
}

impl Backend for Fake {
    fn platform(&self) -> Platform {
        Platform::MacOs
    }

    fn run(
        &self,
        config: Config,
        events: mpsc::UnboundedSender<BackendEvent>,
        stop: oneshot::Receiver<()>,
    ) -> impl Future<Output = std::result::Result<(), Problem>> + Send + 'static {
        let (fail, failed) = oneshot::channel();
        let started = events.send(BackendEvent::Started);
        let answer = lock(&self.answer).clone();
        let answered = match &answer {
            Answer::Online => events.send(BackendEvent::Online {
                uplink: "en0".into(),
                ipv6: false,
            }),
            Answer::Report(event) => events.send(event.clone()),
            Answer::Nothing | Answer::Fail(_) => Ok(()),
        };
        let last_word = events.clone();
        self.live.fetch_add(1, Ordering::SeqCst);
        *lock(&self.current) = Some(config.clone());
        let live = Live(self.clone());
        self.runs().push(Run {
            config,
            events,
            fail: Some(fail),
        });
        async move {
            let _live = live;
            started.map_err(|e| Problem::new("test", &e))?;
            answered.map_err(|e| Problem::new("test", &e))?;
            if let Answer::Fail(problem) = answer {
                return Err(problem);
            }
            tokio::select! {
                _ = stop => {
                    // A last report while stopping, as a real engine may
                    // send: it arrives after the next run has started. The
                    // daemon may be gone already.
                    let _ = last_word.send(BackendEvent::Offline);
                    // Stopping takes a moment (routes to remove).
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    Ok(())
                }
                Ok(problem) = failed => Err(problem),
            }
        }
    }
}

/// Fake sites: with each strategy (or none), the first so many checks pass
/// and the rest fail as said.
#[derive(Clone)]
struct Sites {
    fake: Fake,
    /// For no strategy (`None`) or one, how many checks pass and how the
    /// others fail; anything not listed passes nothing and is cut.
    script: Arc<Mutex<Vec<Line>>>,
    stall: Arc<std::sync::atomic::AtomicBool>,
}

/// A strategy's configuration (`None` for none), the checks it passes, and
/// how the others fail (over TLS 1.2, and over TLS 1.3).
type Line = (Option<Config>, usize, [Outcome; 2]);

impl Sites {
    /// With `strategy` (an id; `None` for without jink) `passed` checks pass
    /// and the others end as `failed`.
    fn set(&self, strategy: Option<&str>, passed: usize, failed: Outcome) -> Result<()> {
        self.set_each(strategy, passed, [failed; 2])
    }

    /// As [`Sites::set`], failing over TLS 1.2 and TLS 1.3 differently.
    fn set_each(&self, strategy: Option<&str>, passed: usize, failed: [Outcome; 2]) -> Result<()> {
        let config = match strategy {
            Some(id) => {
                let strategy = catalog::find(id).ok_or("no such strategy")?;
                Some(catalog::build(strategy, &Settings::default())?)
            }
            None => None,
        };
        lock(&self.script).push((config, passed, failed));
        Ok(())
    }
}

impl Probe for Sites {
    fn check(&self, host: &'static str, tls: Tls) -> impl Future<Output = Outcome> + Send {
        let current = lock(&self.fake.current).clone();
        let (passed, failed) = lock(&self.script)
            .iter()
            .find(|(config, _, _)| *config == current)
            .map_or((0, [Outcome::Cut; 2]), |&(_, passed, failed)| {
                (passed, failed)
            });
        let failed = match tls {
            Tls::V12 => failed[0],
            Tls::V13 => failed[1],
        };
        // Stalled sites never answer while a strategy runs.
        let stalled = self.stall.load(Ordering::SeqCst) && current.is_some();
        let position = HOSTS
            .iter()
            .position(|h| *h == host)
            .and_then(|h| h.checked_mul(2))
            .and_then(|h| h.checked_add(usize::from(tls == Tls::V13)));
        let outcome = match position {
            Some(position) if position < passed => Outcome::Passed,
            _ => failed,
        };
        // Later checks answer first, as real sites answer in any order.
        let wait = position
            .and_then(|position| 16_u64.checked_sub(u64::try_from(position).ok()?))
            .unwrap_or_default();
        async move {
            if stalled {
                std::future::pending::<()>().await;
            }
            tokio::time::sleep(Duration::from_millis(wait)).await;
            outcome
        }
    }
}

struct Daemon {
    handle: Handle,
    fake: Fake,
    sites: Sites,
    saved_at: PathBuf,
    /// Every state change, as the daemon logs it.
    log: Arc<Mutex<Vec<String>>>,
}

impl Daemon {
    fn logged(&self) -> Vec<String> {
        self.log
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

fn scratch(name: &str) -> Result<PathBuf> {
    let dir = std::env::temp_dir().join(format!("jink-daemon-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    Ok(dir.join("state.json"))
}

fn start(saved_at: PathBuf) -> Daemon {
    let fake = Fake::default();
    let sites = Sites {
        fake: fake.clone(),
        script: Arc::default(),
        stall: Arc::default(),
    };
    let log = Arc::new(Mutex::new(Vec::new()));
    let lines = Arc::clone(&log);
    let (handle, _task) = spawn(Setup {
        backend: fake.clone(),
        probe: sites.clone(),
        saved_at: saved_at.clone(),
        log: Box::new(move |line| {
            lines
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(line.to_owned());
        }),
    });
    Daemon {
        handle,
        fake,
        sites,
        saved_at,
        log,
    }
}

/// Waits (briefly) until the status satisfies `wanted`.
async fn until(handle: &Handle, wanted: impl Fn(&Status) -> bool) -> Result<Status> {
    until_within(handle, Duration::from_secs(2), wanted).await
}

async fn until_within(
    handle: &Handle,
    limit: Duration,
    wanted: impl Fn(&Status) -> bool,
) -> Result<Status> {
    let (mut status, _) = handle.watch();
    let found = tokio::time::timeout(limit, status.wait_for(|s| wanted(s))).await??;
    Ok(found.clone())
}

/// Finds, and waits for what it finds.
async fn find(daemon: &Daemon) -> Result<(Found, Status)> {
    assert_eq!(daemon.handle.request(Request::Find).await, Message::Done);
    // Long enough for every strategy to time out (with paused time).
    let status = until_within(&daemon.handle, Duration::from_secs(3600), |s| {
        s.found.is_some()
    })
    .await?;
    Ok((status.found.clone().ok_or("nothing found")?, status))
}

fn kept(strategy: &str) -> FindResult {
    FindResult::Kept {
        strategy: strategy.into(),
    }
}

fn on(network: Network) -> Engine {
    Engine::On { network }
}

#[tokio::test]
async fn a_fresh_install_is_off_with_the_best_strategy() -> Result<()> {
    let daemon = start(scratch("fresh")?);
    let Message::Status { status } = daemon.handle.request(Request::Status).await else {
        return Err("no status".into());
    };
    assert_eq!(status.engine, Engine::Off);
    // General cannot fully run on macOS (seqovl); ALT can.
    assert_eq!(status.strategy, "alt");
    assert!(!status.start_at_boot);
    assert_eq!(status.version, env!("CARGO_PKG_VERSION"));
    let Message::Strategies { strategies } = daemon.handle.request(Request::Strategies).await
    else {
        return Err("no strategies".into());
    };
    let support = |id: &str| strategies.iter().find(|s| s.id == id).map(|s| s.support);
    assert_eq!(support("general"), Some(Support::Partial));
    assert_eq!(support("alt"), Some(Support::Full));
    assert!(daemon.fake.runs().is_empty());
    Ok(())
}

#[tokio::test]
async fn start_runs_and_follows_the_network() -> Result<()> {
    let daemon = start(scratch("start")?);
    let reply = daemon
        .handle
        .request(Request::Start {
            strategy: Some("alt13".into()),
        })
        .await;
    assert_eq!(reply, Message::Done);
    let status = until(&daemon.handle, |s| s.engine == on(Network::Checking)).await?;
    assert_eq!(status.strategy, "alt13");
    daemon.fake.report(
        0,
        BackendEvent::Online {
            uplink: "en0".into(),
            ipv6: true,
        },
    )?;
    until(&daemon.handle, |s| {
        s.engine
            == on(Network::Online {
                uplink: "en0".into(),
                ipv6: true,
            })
    })
    .await?;
    daemon.fake.report(0, BackendEvent::Offline)?;
    until(&daemon.handle, |s| s.engine == on(Network::Offline)).await?;
    daemon.fake.report(0, BackendEvent::Active)?;
    until(&daemon.handle, |s| s.engine == on(Network::Active)).await?;
    // The choice is saved.
    assert_eq!(
        Saved::load(&daemon.saved_at)?.map(|s| s.strategy),
        Some("alt13".to_owned())
    );
    assert_eq!(daemon.handle.request(Request::Stop).await, Message::Done);
    until(&daemon.handle, |s| s.engine == Engine::Off).await?;
    Ok(())
}

#[tokio::test]
async fn unknown_strategies_start_nothing() -> Result<()> {
    let daemon = start(scratch("unknown")?);
    let reply = daemon
        .handle
        .request(Request::Start {
            strategy: Some("alt99".into()),
        })
        .await;
    assert_eq!(
        reply,
        Message::Error {
            error: Failure::UnknownStrategy {
                strategy: "alt99".into()
            }
        }
    );
    assert!(daemon.fake.runs().is_empty());
    Ok(())
}

#[tokio::test]
async fn new_settings_restart_the_engine_and_bad_ones_change_nothing() -> Result<()> {
    let daemon = start(scratch("settings")?);
    daemon
        .handle
        .request(Request::Start { strategy: None })
        .await;
    until(&daemon.handle, |s| s.engine == on(Network::Checking)).await?;
    let rules = |run: usize| daemon.fake.runs().get(run).map(|r| r.config.rules.len());
    assert_eq!(rules(0), Some(5));

    let bad = SettingsWire {
        my_ips: vec!["300.1.1.1".into()],
        ..SettingsWire::default()
    };
    let reply = daemon
        .handle
        .request(Request::UpdateSettings { settings: bad })
        .await;
    assert!(matches!(
        reply,
        Message::Error {
            error: Failure::InvalidSettings { .. }
        }
    ));
    assert_eq!(daemon.fake.runs().len(), 1);

    let good = SettingsWire {
        my_ips: vec!["203.0.113.0/24".into()],
        my_sites: vec!["https://www.example.com/page".into()],
        ..SettingsWire::default()
    };
    let reply = daemon
        .handle
        .request(Request::UpdateSettings { settings: good })
        .await;
    assert_eq!(reply, Message::Done);
    // Restarted with the IP groups the new IPs need.
    assert_eq!(daemon.fake.runs().len(), 2);
    assert_eq!(rules(1), Some(7));
    // Saved and sent back normalized.
    let Message::Settings { settings } = daemon.handle.request(Request::Settings).await else {
        return Err("no settings".into());
    };
    assert_eq!(settings.my_sites, ["www.example.com"]);
    let saved = Saved::load(&daemon.saved_at)?.ok_or("not saved")?;
    assert_eq!(saved.settings, settings);
    Ok(())
}

#[tokio::test]
async fn reports_of_a_stopped_engine_are_ignored() -> Result<()> {
    let daemon = start(scratch("stale")?);
    daemon
        .handle
        .request(Request::Start { strategy: None })
        .await;
    until(&daemon.handle, |s| s.engine == on(Network::Checking)).await?;
    // Switching stops the first run, whose last reports ("offline", then
    // "ended") are still on their way when the second run starts.
    daemon
        .handle
        .request(Request::Start {
            strategy: Some("alt4".into()),
        })
        .await;
    daemon.fake.report(
        1,
        BackendEvent::Online {
            uplink: "en0".into(),
            ipv6: false,
        },
    )?;
    let online = on(Network::Online {
        uplink: "en0".into(),
        ipv6: false,
    });
    until(&daemon.handle, |s| s.engine == online).await?;
    let Message::Status { status } = daemon.handle.request(Request::Status).await else {
        return Err("no status".into());
    };
    assert_eq!(status.engine, online);
    // The second run is still the one running: stopping stops it.
    assert_eq!(daemon.handle.request(Request::Stop).await, Message::Done);
    until(&daemon.handle, |s| s.engine == Engine::Off).await?;
    assert!(daemon.fake.report(1, BackendEvent::Offline).is_err());
    // And it stays off: the stopped run's last report ("offline") does not
    // turn it back on, not even for a moment.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let Message::Status { status } = daemon.handle.request(Request::Status).await else {
        return Err("no status".into());
    };
    assert_eq!(status.engine, Engine::Off);
    let logged = daemon.logged();
    assert!(
        !logged.iter().any(|line| line == "on, no network"),
        "{logged:?}"
    );
    Ok(())
}

#[tokio::test]
async fn a_failing_engine_says_why() -> Result<()> {
    let daemon = start(scratch("failing")?);
    daemon
        .handle
        .request(Request::Start { strategy: None })
        .await;
    until(&daemon.handle, |s| s.engine == on(Network::Checking)).await?;
    let fail = daemon
        .fake
        .runs()
        .get_mut(0)
        .and_then(|r| r.fail.take())
        .ok_or("no run")?;
    let problem = Problem::new("not_root", &"jink needs root");
    fail.send(problem.clone()).map_err(|_| "engine gone")?;
    until(&daemon.handle, |s| {
        s.engine
            == Engine::Failed {
                problem: problem.clone(),
            }
    })
    .await?;
    Ok(())
}

#[tokio::test]
async fn notices_are_sent_once_per_kind() -> Result<()> {
    let daemon = start(scratch("notices")?);
    let (_, mut notices) = daemon.handle.watch();
    daemon
        .handle
        .request(Request::Start { strategy: None })
        .await;
    until(&daemon.handle, |s| s.engine == on(Network::Checking)).await?;
    for detail in ["first", "second"] {
        daemon.fake.report(
            0,
            BackendEvent::Notice(Problem::new("no_handshake", &detail)),
        )?;
    }
    daemon
        .fake
        .report(0, BackendEvent::Notice(Problem::new("capture_ended", &"x")))?;
    let codes = [notices.recv().await?.detail, notices.recv().await?.code];
    assert_eq!(codes, ["first", "capture_ended"]);
    Ok(())
}

#[tokio::test]
async fn start_at_boot_is_remembered() -> Result<()> {
    let saved_at = scratch("boot")?;
    let first = start(saved_at.clone());
    let reply = first
        .handle
        .request(Request::SetStartAtBoot { on: true })
        .await;
    assert_eq!(reply, Message::Done);
    first.handle.shut_down().await;
    // The next daemon (after a reboot) starts by itself.
    let next = start(saved_at);
    let status = until(&next.handle, |s| s.engine == on(Network::Checking)).await?;
    assert!(status.start_at_boot);
    assert_eq!(next.fake.runs().len(), 1);
    Ok(())
}

/// Talks to the daemon the way an app does: JSON lines over a connection.
#[tokio::test]
async fn apps_talk_in_json_lines() -> Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let daemon = start(scratch("lines")?);
    let (app, served) = tokio::io::duplex(1 << 20);
    let (daemon_read, daemon_write) = tokio::io::split(served);
    let handle = daemon.handle.clone();
    tokio::spawn(async move {
        jink_daemon::server::connection(daemon_read, daemon_write, &handle).await
    });
    let (app_read, mut app_write) = tokio::io::split(app);
    let mut replies = BufReader::new(app_read).lines();
    let mut ask = async |line: &str| -> Result<serde_json::Value> {
        app_write.write_all(format!("{line}\n").as_bytes()).await?;
        let reply = replies.next_line().await?.ok_or("connection closed")?;
        Ok(serde_json::from_str(&reply)?)
    };

    let status = ask(r#"{"cmd":"status"}"#).await?;
    assert_eq!(status["type"], "status");
    assert_eq!(status["status"]["engine"]["state"], "off");
    let refused = ask(r#"{"cmd":"reboot"}"#).await?;
    assert_eq!(refused["error"]["code"], "bad_request");
    let started = ask(r#"{"cmd":"start","strategy":"alt9"}"#).await?;
    assert_eq!(started["type"], "done");
    // After watch, the connection carries updates: the status now, then
    // each change.
    let watching = ask(r#"{"cmd":"watch"}"#).await?;
    assert_eq!(watching["type"], "status");
    assert_eq!(watching["status"]["strategy"], "alt9");
    daemon.fake.report(0, BackendEvent::Offline)?;
    let update: serde_json::Value = loop {
        let line = replies.next_line().await?.ok_or("connection closed")?;
        let update: serde_json::Value = serde_json::from_str(&line)?;
        if update["status"]["engine"]["network"]["state"] == "offline" {
            break update;
        }
    };
    assert_eq!(update["type"], "status");
    Ok(())
}

#[tokio::test]
async fn an_endless_line_ends_the_connection() -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let daemon = start(scratch("endless")?);
    let (mut app, daemon_side) = tokio::io::duplex(1 << 20);
    let (read, write) = tokio::io::split(daemon_side);
    let handle = daemon.handle.clone();
    let connection =
        tokio::spawn(async move { jink_daemon::server::connection(read, write, &handle).await });
    app.write_all(&vec![b'x'; 70 * 1024]).await?;
    let mut reply = String::new();
    app.read_to_string(&mut reply).await?;
    let reply: serde_json::Value = serde_json::from_str(reply.trim())?;
    assert_eq!(reply["error"]["code"], "bad_request");
    connection.await??;
    Ok(())
}

#[tokio::test]
async fn finding_keeps_the_strategy_that_gets_through_best() -> Result<()> {
    let daemon = start(scratch("find-best")?);
    daemon.fake.answer(Answer::Online);
    // Without jink, some sites answer and the others' names do not resolve
    // (blocked by DNS): that is not "no network".
    daemon.sites.set(None, 4, Outcome::NoAddress)?;
    daemon.sites.set(Some("alt"), 10, Outcome::Cut)?;
    // Two that get everything through: the first tried is kept.
    daemon.sites.set(Some("alt4"), 16, Outcome::Cut)?;
    daemon.sites.set(Some("alt9"), 16, Outcome::Cut)?;
    let (found, _) = find(&daemon).await?;

    let Message::Strategies { strategies } = daemon.handle.request(Request::Strategies).await
    else {
        return Err("no strategies".into());
    };
    let tried: Vec<&str> = found.tried.iter().map(|t| t.strategy.as_str()).collect();
    assert_eq!(tried.len(), strategies.len());
    // Full support first, main strategies before variants.
    let rank = |id: &&str| {
        strategies
            .iter()
            .find(|s| s.id == *id)
            .map(|s| (s.support != Support::Full, s.variant_of.is_some()))
    };
    let ranks: Vec<_> = tried.iter().map(rank).collect();
    assert!(ranks.is_sorted(), "{tried:?}");
    assert_eq!(ranks.first(), Some(&Some((false, false))));
    assert_eq!(ranks.last(), Some(&Some((true, true))));
    let first = tried
        .iter()
        .find(|id| ["alt4", "alt9"].contains(id))
        .ok_or("not tried")?;
    assert_eq!(found.result, kept(first));

    assert_eq!(found.checks, 16);
    assert_eq!(found.without.passed, 4);
    assert_eq!(found.without.failed.len(), 12);
    let first_failed = found.without.failed.first().ok_or("none failed")?;
    assert_eq!(
        (
            first_failed.host.as_str(),
            first_failed.tls,
            first_failed.outcome
        ),
        ("cdn.discordapp.com", Tls::V12, Outcome::NoAddress)
    );
    let passed = |id: &str| {
        found
            .tried
            .iter()
            .find(|t| t.strategy == id)
            .map(|t| (t.checks.passed, t.checks.failed.len(), t.problem.is_none()))
    };
    assert_eq!(passed("alt"), Some((10, 6, true)));
    assert_eq!(passed("alt13"), Some((0, 16, true)));

    // Kept: saved and on, and the only engine running.
    let status = until(&daemon.handle, |s| {
        s.engine
            == on(Network::Online {
                uplink: "en0".into(),
                ipv6: false,
            })
    })
    .await?;
    assert_eq!(status.strategy, *first);
    assert_eq!(
        Saved::load(&daemon.saved_at)?.map(|s| s.strategy),
        Some((*first).to_owned())
    );
    assert_eq!(daemon.fake.live(), 1);
    let logged = daemon.logged();
    assert!(
        logged
            .iter()
            .any(|line| line.starts_with(&format!("found: keeping {first} (4 of 16"))),
        "{logged:?}"
    );
    Ok(())
}

#[tokio::test]
async fn when_nothing_is_blocked_desync_stays_as_it_was() -> Result<()> {
    let daemon = start(scratch("find-clear")?);
    daemon.fake.answer(Answer::Online);
    daemon.sites.set(None, 16, Outcome::Cut)?;
    daemon
        .handle
        .request(Request::Start {
            strategy: Some("alt13".into()),
        })
        .await;
    let (found, _) = find(&daemon).await?;
    assert_eq!(found.result, FindResult::NothingBlocked);
    assert_eq!(found.tried, []);
    // Back on, with the same strategy: nothing else was started.
    let status = until(&daemon.handle, |s| matches!(s.engine, Engine::On { .. })).await?;
    assert_eq!(status.strategy, "alt13");
    assert_eq!(daemon.fake.runs().len(), 2);
    assert_eq!(daemon.fake.live(), 1);
    Ok(())
}

#[tokio::test]
async fn without_a_network_nothing_is_tried() -> Result<()> {
    let daemon = start(scratch("find-offline")?);
    daemon.sites.set(None, 0, Outcome::NoAddress)?;
    let (found, status) = find(&daemon).await?;
    assert_eq!(found.result, FindResult::NoNetwork);
    assert_eq!(status.engine, Engine::Off);
    assert!(daemon.fake.runs().is_empty());
    Ok(())
}

#[tokio::test]
async fn sites_that_are_reached_but_cut_mean_a_network() -> Result<()> {
    let daemon = start(scratch("find-cut")?);
    daemon.fake.answer(Answer::Online);
    // Nothing passes, but TLS 1.3 reaches the sites (and is cut).
    daemon
        .sites
        .set_each(None, 0, [Outcome::Unreachable, Outcome::Cut])?;
    let (found, _) = find(&daemon).await?;
    assert_eq!(found.result, FindResult::NoneHelped);
    assert_eq!(found.tried.len(), 13);
    Ok(())
}

#[tokio::test]
async fn finding_can_be_ended_while_it_checks_sites() -> Result<()> {
    let daemon = start(scratch("find-stall")?);
    daemon.fake.answer(Answer::Online);
    daemon.sites.set(None, 4, Outcome::Cut)?;
    daemon.sites.stall.store(true, Ordering::SeqCst);
    daemon.handle.request(Request::Find).await;
    until(&daemon.handle, |s| {
        matches!(s.engine, Engine::Finding { step: 2, .. })
    })
    .await?;
    let cancelled = tokio::time::timeout(
        Duration::from_secs(2),
        daemon.handle.request(Request::CancelFind),
    )
    .await?;
    assert_eq!(cancelled, Message::Done);
    assert_eq!(daemon.fake.live(), 0);
    Ok(())
}

#[tokio::test]
async fn a_strategy_no_better_than_none_is_not_kept() -> Result<()> {
    let daemon = start(scratch("find-none")?);
    daemon.fake.answer(Answer::Online);
    daemon.sites.set(None, 4, Outcome::Cut)?;
    daemon.sites.set(Some("alt"), 4, Outcome::Cut)?;
    let (found, status) = find(&daemon).await?;
    assert_eq!(found.result, FindResult::NoneHelped);
    assert_eq!(status.engine, Engine::Off);
    assert_eq!(status.strategy, "alt");
    assert_eq!(daemon.fake.live(), 0);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn strategies_that_never_come_online_are_not_checked() -> Result<()> {
    let daemon = start(scratch("find-offline-engines")?);
    daemon.sites.set(None, 4, Outcome::Cut)?;
    let problems = |found: &Found| -> Vec<Option<String>> {
        found
            .tried
            .iter()
            .map(|t| {
                assert_eq!(t.checks.passed, 0);
                assert_eq!(t.checks.failed, []);
                t.problem.as_ref().map(|p| p.code.clone())
            })
            .collect()
    };
    let every = |code: &str| vec![Some(code.to_owned()); 13];

    let taken = Problem::new("routes_taken", &"a VPN has the routes");
    daemon
        .fake
        .answer(Answer::Report(BackendEvent::Bypassed(taken)));
    let (found, _) = find(&daemon).await?;
    assert_eq!(found.result, FindResult::NoneHelped);
    assert_eq!(problems(&found), every("routes_taken"));

    daemon.fake.answer(Answer::Report(BackendEvent::Offline));
    assert_eq!(problems(&find(&daemon).await?.0), every("offline"));

    daemon
        .fake
        .answer(Answer::Fail(Problem::new("tun", &"no utun")));
    assert_eq!(problems(&find(&daemon).await?.0), every("tun"));

    // Silent engines are given up on in time.
    daemon.fake.answer(Answer::Nothing);
    assert_eq!(problems(&find(&daemon).await?.0), every("not_online"));
    assert_eq!(daemon.fake.live(), 0);
    Ok(())
}

#[tokio::test]
async fn finding_counts_working_on_every_network_as_online() -> Result<()> {
    let daemon = start(scratch("find-active")?);
    daemon.fake.answer(Answer::Report(BackendEvent::Active));
    daemon.sites.set(None, 4, Outcome::Cut)?;
    daemon.sites.set(Some("alt4"), 16, Outcome::Cut)?;
    let (found, _) = find(&daemon).await?;
    assert_eq!(found.result, kept("alt4"));
    assert!(found.tried.iter().all(|t| t.problem.is_none()));
    Ok(())
}

#[tokio::test]
async fn finding_shows_its_progress_and_can_be_ended() -> Result<()> {
    let daemon = start(scratch("find-cancel")?);
    daemon.sites.set(None, 4, Outcome::Cut)?;
    // Engines that never come online keep the finder at its second step.
    daemon.fake.answer(Answer::Nothing);
    let at_second_step = |s: &Status| matches!(s.engine, Engine::Finding { step: 2, .. });
    daemon
        .handle
        .request(Request::Start {
            strategy: Some("alt13".into()),
        })
        .await;
    until(&daemon.handle, |s| s.engine == on(Network::Checking)).await?;

    // Cancelled: desync is back on, as it was.
    assert_eq!(daemon.handle.request(Request::Find).await, Message::Done);
    let status = until(&daemon.handle, at_second_step).await?;
    let Engine::Finding { of, strategy, .. } = status.engine else {
        return Err("not finding".into());
    };
    assert_eq!(of, 14);
    assert!(strategy.is_some());
    // Asking again changes nothing.
    assert_eq!(daemon.handle.request(Request::Find).await, Message::Done);
    assert_eq!(
        daemon.handle.request(Request::CancelFind).await,
        Message::Done
    );
    let status = until(&daemon.handle, |s| s.engine == on(Network::Checking)).await?;
    assert_eq!(status.strategy, "alt13");
    assert_eq!(status.found, None);
    assert_eq!(daemon.fake.live(), 1);

    // Stopped: off.
    daemon.handle.request(Request::Find).await;
    until(&daemon.handle, at_second_step).await?;
    assert_eq!(daemon.handle.request(Request::Stop).await, Message::Done);
    until(&daemon.handle, |s| s.engine == Engine::Off).await?;
    assert_eq!(daemon.fake.live(), 0);

    // Started: on, with the strategy asked for.
    daemon.handle.request(Request::Find).await;
    until(&daemon.handle, at_second_step).await?;
    daemon
        .handle
        .request(Request::Start {
            strategy: Some("alt9".into()),
        })
        .await;
    let status = until(&daemon.handle, |s| s.engine == on(Network::Checking)).await?;
    assert_eq!(status.strategy, "alt9");
    assert_eq!(daemon.fake.live(), 1);
    // Nothing the finder did turns up later.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let Message::Status { status } = daemon.handle.request(Request::Status).await else {
        return Err("no status".into());
    };
    assert_eq!(status.engine, on(Network::Checking));
    assert_eq!(
        daemon.handle.request(Request::CancelFind).await,
        Message::Done
    );
    Ok(())
}

#[tokio::test]
async fn shutting_down_ends_finding() -> Result<()> {
    let daemon = start(scratch("find-shutdown")?);
    daemon.sites.set(None, 4, Outcome::Cut)?;
    daemon.fake.answer(Answer::Nothing);
    daemon.handle.request(Request::Find).await;
    until(&daemon.handle, |s| {
        matches!(s.engine, Engine::Finding { step: 2, .. })
    })
    .await?;
    assert_eq!(daemon.fake.live(), 1);
    daemon.handle.shut_down().await;
    assert_eq!(daemon.fake.live(), 0);
    Ok(())
}
