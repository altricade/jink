//! The daemon's state, kept by one task that takes requests in order: the
//! saved choices, whether desync runs, and what the running engine (or the
//! finder) reports. The engine itself is a [`Backend`] and the finder's
//! site checks a [`Probe`], so this works the same on every platform (and
//! in tests, with fakes).

use std::collections::HashSet;
use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;

use jink_core::catalog::{self, Strategy};
use jink_core::config::Config;
use jink_core::config::platform::Platform;
use jink_core::settings::Settings;
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tokio::task::JoinHandle;

use crate::finder::{self, Cancel};
use crate::probe::Probe;
use crate::protocol::{
    Engine, Failure, FindResult, Found, Message, Network, Problem, Request, SettingsWire, Status,
    StrategyInfo, Support,
};
use crate::saved::Saved;

/// What a running engine reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendEvent {
    /// Set up; looking at the network.
    Started,
    Online {
        uplink: String,
        ipv6: bool,
    },
    /// Working on every network (Windows).
    Active,
    Offline,
    /// Cannot work on this network; traffic bypasses it.
    Bypassed(Problem),
    /// Something went wrong without changing the state.
    Notice(Problem),
}

/// What runs desync on this platform.
pub trait Backend: Send + Sync + 'static {
    fn platform(&self) -> Platform;

    /// Runs desync with `config` until `stop` fires (then `Ok`), reporting
    /// to `events`; `Err` if it cannot start or stops by itself.
    fn run(
        &self,
        config: Config,
        events: mpsc::UnboundedSender<BackendEvent>,
        stop: oneshot::Receiver<()>,
    ) -> impl Future<Output = Result<(), Problem>> + Send + 'static;
}

/// Talks to the daemon's task.
#[derive(Debug, Clone)]
pub struct Handle {
    requests: mpsc::Sender<Input>,
    status: watch::Receiver<Status>,
    notices: broadcast::Sender<Problem>,
}

impl Handle {
    /// The answer to `request` ([`Request::Watch`] is for [`Handle::watch`]).
    pub async fn request(&self, request: Request) -> Message {
        let (reply, answer) = oneshot::channel();
        if self
            .requests
            .send(Input::Request(request, reply))
            .await
            .is_err()
        {
            return stopping();
        }
        answer.await.unwrap_or_else(|_| stopping())
    }

    /// The status now and at every change, and the notices from now on.
    #[must_use]
    pub fn watch(&self) -> (watch::Receiver<Status>, broadcast::Receiver<Problem>) {
        (self.status.clone(), self.notices.subscribe())
    }

    /// Stops desync and the task.
    pub async fn shut_down(&self) {
        let (done, finished) = oneshot::channel();
        if self.requests.send(Input::ShutDown(done)).await.is_ok() {
            // The task ends either way; there is nothing to report.
            let _ = finished.await;
        }
    }
}

fn stopping() -> Message {
    Message::Error {
        error: Failure::Failed {
            detail: "the daemon is stopping".to_owned(),
        },
    }
}

#[derive(Debug)]
enum Input {
    Request(Request, oneshot::Sender<Message>),
    ShutDown(oneshot::Sender<()>),
}

/// A report from the engine (or finder) of run number `.0`. Its channel is
/// unbounded: the task may be waiting for that engine to end, which must
/// never wait for room in the channel.
type Report = (u64, EngineInput);

#[derive(Debug)]
enum EngineInput {
    Event(BackendEvent),
    Ended(Result<(), Problem>),
    /// The finder is at `step`, trying `strategy`.
    Step {
        step: usize,
        strategy: Option<String>,
    },
    /// The finder is done.
    Found(Found),
}

/// A running engine.
#[derive(Debug)]
struct Running {
    stop: oneshot::Sender<()>,
    task: JoinHandle<()>,
}

/// A running finder.
#[derive(Debug)]
struct Finding {
    cancel: watch::Sender<bool>,
    task: JoinHandle<()>,
    /// Its steps.
    of: usize,
    /// Whether desync was on before, to turn it back on if nothing is kept.
    resume: bool,
}

/// What the daemon runs with, where it keeps its state, and where it
/// reports.
pub struct Setup<B, P> {
    pub backend: B,
    pub probe: P,
    pub saved_at: PathBuf,
    /// One line per state change or notice, for the daemon's log.
    pub log: Box<dyn Fn(&str) + Send + Sync>,
}

impl<B, P> std::fmt::Debug for Setup<B, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Setup")
            .field("saved_at", &self.saved_at)
            .finish_non_exhaustive()
    }
}

/// Starts the daemon's task: loads the saved state, and starts desync if it
/// is set to start by itself.
pub fn spawn<B: Backend, P: Probe>(setup: Setup<B, P>) -> (Handle, JoinHandle<()>) {
    let Setup {
        backend,
        probe,
        saved_at,
        log,
    } = setup;
    let platform = backend.platform();
    let strategies = strategies(platform);
    let fallback = default_strategy(&strategies);
    let saved = match Saved::load(&saved_at) {
        Ok(Some(saved)) => saved,
        Ok(None) => Saved::new(&fallback),
        Err(e) => {
            log(&format!("{e}; starting from the defaults"));
            Saved::new(&fallback)
        }
    };
    let (settings, dropped) = saved.settings.parse_valid();
    if !dropped.is_empty() {
        log(&format!("saved settings entries dropped: {dropped:?}"));
    }
    let strategy = if catalog::find(&saved.strategy).is_some() {
        saved.strategy.clone()
    } else {
        fallback
    };
    let status = Status {
        engine: Engine::Off,
        strategy: strategy.clone(),
        start_at_boot: saved.start_at_boot,
        version: env!("CARGO_PKG_VERSION").to_owned(),
        found: None,
    };
    let (requests, inputs) = mpsc::channel(32);
    let (reports, reported) = mpsc::unbounded_channel();
    let (status_tx, status_rx) = watch::channel(status);
    let (notices, _) = broadcast::channel(64);
    let state = State {
        backend: Arc::new(backend),
        probe: Arc::new(probe),
        saved_at,
        saved: Saved { strategy, ..saved },
        settings,
        strategies,
        status: status_tx,
        notices: notices.clone(),
        seen: HashSet::new(),
        log,
        reports,
        running: None,
        finding: None,
        run: 0,
    };
    let task = tokio::spawn(state.serve(inputs, reported));
    let handle = Handle {
        requests,
        status: status_rx,
        notices,
    };
    (handle, task)
}

/// The strategies, and how much of each this platform runs.
fn strategies(platform: Platform) -> Vec<StrategyInfo> {
    catalog::all()
        .iter()
        .map(|strategy| {
            let full = catalog::build(strategy, &Settings::default())
                .is_ok_and(|config| platform.unsupported(&config).is_empty());
            StrategyInfo {
                id: strategy.id.to_owned(),
                name: strategy.name.to_owned(),
                variant_of: strategy.variant_of.map(str::to_owned),
                support: if full {
                    Support::Full
                } else {
                    Support::Partial
                },
            }
        })
        .collect()
}

/// The first main strategy this platform runs fully.
fn default_strategy(strategies: &[StrategyInfo]) -> String {
    strategies
        .iter()
        .find(|s| s.variant_of.is_none() && s.support == Support::Full)
        .or_else(|| strategies.first())
        .map_or_else(String::new, |s| s.id.clone())
}

struct State<B, P> {
    backend: Arc<B>,
    probe: Arc<P>,
    saved_at: PathBuf,
    saved: Saved,
    settings: Settings,
    strategies: Vec<StrategyInfo>,
    status: watch::Sender<Status>,
    notices: broadcast::Sender<Problem>,
    /// Notice codes already sent for the current run.
    seen: HashSet<String>,
    log: Box<dyn Fn(&str) + Send + Sync>,
    /// For the engine's reports.
    reports: mpsc::UnboundedSender<Report>,
    running: Option<Running>,
    finding: Option<Finding>,
    /// The number of the latest run; reports from earlier ones are stale.
    run: u64,
}

impl<B: Backend, P: Probe> State<B, P> {
    async fn serve(
        mut self,
        mut inputs: mpsc::Receiver<Input>,
        mut reported: mpsc::UnboundedReceiver<Report>,
    ) {
        if self.saved.start_at_boot {
            self.start();
        }
        loop {
            tokio::select! {
                input = inputs.recv() => match input {
                    Some(Input::Request(request, reply)) => {
                        let answer = self.handle(request).await;
                        // The app may have gone; the change stands either way.
                        let _ = reply.send(answer);
                    }
                    Some(Input::ShutDown(done)) => {
                        self.end_finding().await;
                        self.stop().await;
                        let _ = done.send(());
                        return;
                    }
                    None => break,
                },
                Some((run, report)) = reported.recv() => {
                    if run == self.run {
                        self.engine(report);
                    }
                }
            }
        }
        self.end_finding().await;
        self.stop().await;
    }

    async fn handle(&mut self, request: Request) -> Message {
        match request {
            Request::Status => Message::Status {
                status: self.status.borrow().clone(),
            },
            Request::Strategies => Message::Strategies {
                strategies: self.strategies.clone(),
            },
            Request::Settings => Message::Settings {
                settings: SettingsWire::from(&self.settings),
            },
            Request::Start { strategy } => {
                let id = strategy.unwrap_or_else(|| self.saved.strategy.clone());
                if catalog::find(&id).is_none() {
                    return error(Failure::UnknownStrategy { strategy: id });
                }
                if let Err(detail) = self.save(Saved {
                    strategy: id,
                    ..self.saved.clone()
                }) {
                    return error(Failure::Failed { detail });
                }
                self.end_finding().await;
                self.stop().await;
                self.start();
                Message::Done
            }
            Request::Stop => {
                self.end_finding().await;
                self.stop().await;
                self.set_engine(Engine::Off);
                Message::Done
            }
            Request::UpdateSettings { settings } => {
                let parsed = match settings.parse() {
                    Ok(parsed) => parsed,
                    Err(problems) => return error(Failure::InvalidSettings { problems }),
                };
                if let Err(detail) = self.save(Saved {
                    settings: SettingsWire::from(&parsed),
                    ..self.saved.clone()
                }) {
                    return error(Failure::Failed { detail });
                }
                self.settings = parsed;
                if self.running.is_some() {
                    self.stop().await;
                    self.start();
                }
                Message::Done
            }
            Request::SetStartAtBoot { on } => {
                if let Err(detail) = self.save(Saved {
                    start_at_boot: on,
                    ..self.saved.clone()
                }) {
                    return error(Failure::Failed { detail });
                }
                Message::Done
            }
            Request::Find => {
                if self.finding.is_none() {
                    self.find().await;
                }
                Message::Done
            }
            Request::CancelFind => {
                if let Some(resume) = self.end_finding().await {
                    self.resume(resume);
                }
                Message::Done
            }
            Request::Watch => error(Failure::BadRequest {
                detail: "watch is answered by the connection".to_owned(),
            }),
        }
    }

    /// Saves `saved` and makes it the current state, or says why not.
    fn save(&mut self, saved: Saved) -> Result<(), String> {
        saved
            .save(&self.saved_at)
            .map_err(|e| format!("cannot save {}: {e}", self.saved_at.display()))?;
        self.saved = saved;
        let (strategy, start_at_boot) = (self.saved.strategy.clone(), self.saved.start_at_boot);
        self.update(|status| {
            status.strategy = strategy;
            status.start_at_boot = start_at_boot;
        });
        Ok(())
    }

    fn start(&mut self) {
        let Some(strategy) = catalog::find(&self.saved.strategy) else {
            return;
        };
        let config = match catalog::build(strategy, &self.settings) {
            Ok(config) => config,
            Err(e) => {
                return self.set_engine(Engine::Failed {
                    problem: Problem::new("strategy", &e),
                });
            }
        };
        self.launch(strategy, config);
    }

    fn launch(&mut self, strategy: &Strategy, config: Config) {
        self.run = self.run.wrapping_add(1);
        self.seen.clear();
        let run = self.run;
        let (events, mut backend_events) = mpsc::unbounded_channel();
        let (stop, stopped) = oneshot::channel();
        let engine = self.backend.run(config, events, stopped);
        let reports = self.reports.clone();
        let task = tokio::spawn(async move {
            // The daemon may be shutting down while this runs; then nobody
            // needs the reports, and sending them fails harmlessly.
            let forward = |event| {
                let _ = reports.send((run, EngineInput::Event(event)));
            };
            tokio::pin!(engine);
            // Until the engine ends (not until its report channel closes:
            // whoever holds a sender may keep it).
            let ended = loop {
                tokio::select! {
                    ended = &mut engine => break ended,
                    Some(event) = backend_events.recv() => forward(event),
                }
            };
            while let Ok(event) = backend_events.try_recv() {
                forward(event);
            }
            let _ = reports.send((run, EngineInput::Ended(ended)));
        });
        self.running = Some(Running { stop, task });
        (self.log)(&format!("starting {}", strategy.name));
        self.set_engine(Engine::Starting);
    }

    /// Stops the engine and waits until it has (its routes are gone, so
    /// the next run can start).
    async fn stop(&mut self) {
        if let Some(Running { stop, task }) = self.running.take() {
            // Already ended by itself if this fails.
            let _ = stop.send(());
            if let Err(e) = task.await {
                (self.log)(&format!("the engine task failed: {e}"));
            }
            // Its last reports are stale now.
            self.run = self.run.wrapping_add(1);
            self.set_engine(Engine::Off);
        }
    }

    /// Stops desync and starts finding.
    async fn find(&mut self) {
        let resume = self.running.is_some();
        self.stop().await;
        let plan = self.plan();
        let of = plan.len().saturating_add(1);
        self.run = self.run.wrapping_add(1);
        let run = self.run;
        let (cancel, cancelled) = watch::channel(false);
        let reports = self.reports.clone();
        let steps = reports.clone();
        // The daemon may be shutting down; then nobody needs the reports.
        let step = move |step, strategy: Option<&str>| {
            let strategy = strategy.map(str::to_owned);
            let _ = steps.send((run, EngineInput::Step { step, strategy }));
        };
        let finder = finder::find(
            Arc::clone(&self.backend),
            Arc::clone(&self.probe),
            plan,
            step,
            Cancel::new(cancelled),
        );
        let task = tokio::spawn(async move {
            if let Some(found) = finder.await {
                let _ = reports.send((run, EngineInput::Found(found)));
            }
        });
        self.finding = Some(Finding {
            cancel,
            task,
            of,
            resume,
        });
        self.update(|status| status.found = None);
        self.set_engine(Engine::Finding {
            step: 1,
            of,
            strategy: None,
        });
    }

    /// The strategies to try, with the current settings: the ones this
    /// platform runs fully first, main ones before variants.
    fn plan(&self) -> Vec<(String, Config)> {
        let mut order: Vec<&StrategyInfo> = self.strategies.iter().collect();
        order.sort_by_key(|s| (s.support != Support::Full, s.variant_of.is_some()));
        order
            .into_iter()
            .filter_map(|info| {
                let strategy = catalog::find(&info.id)?;
                catalog::build(strategy, &self.settings)
                    .map_err(|e| (self.log)(&format!("cannot try {}: {e}", info.id)))
                    .ok()
                    .map(|config| (info.id.clone(), config))
            })
            .collect()
    }

    /// Ends finding (and the engine it runs) if it runs; then whether
    /// desync was on before it.
    async fn end_finding(&mut self) -> Option<bool> {
        let Finding {
            cancel,
            task,
            resume,
            ..
        } = self.finding.take()?;
        // It may have finished already.
        let _ = cancel.send(true);
        if let Err(e) = task.await {
            (self.log)(&format!("the finder's task failed: {e}"));
        }
        // Its last reports are stale now: a result it sent just before
        // being ended must not land on the next finding.
        self.run = self.run.wrapping_add(1);
        Some(resume)
    }

    /// Keeps what finding found: its strategy, turned on; or else desync
    /// as it was.
    fn found(&mut self, found: Found, resume: bool) {
        (self.log)(&describe_found(&found));
        let kept = match &found.result {
            FindResult::Kept { strategy } => Some(strategy.clone()),
            FindResult::NothingBlocked | FindResult::NoneHelped | FindResult::NoNetwork => None,
        };
        self.update(|status| status.found = Some(found));
        let Some(strategy) = kept else {
            return self.resume(resume);
        };
        match self.save(Saved {
            strategy,
            ..self.saved.clone()
        }) {
            Ok(()) => self.start(),
            Err(detail) => self.set_engine(Engine::Failed {
                problem: Problem::new("save", &detail),
            }),
        }
    }

    /// Desync back on if it was, else off.
    fn resume(&mut self, on: bool) {
        if on {
            self.start();
        } else {
            self.set_engine(Engine::Off);
        }
    }

    fn engine(&mut self, input: EngineInput) {
        let network = |network| Engine::On { network };
        match input {
            EngineInput::Event(BackendEvent::Started) => {
                self.set_engine(network(Network::Checking));
            }
            EngineInput::Event(BackendEvent::Online { uplink, ipv6 }) => {
                self.set_engine(network(Network::Online { uplink, ipv6 }));
            }
            EngineInput::Event(BackendEvent::Active) => self.set_engine(network(Network::Active)),
            EngineInput::Event(BackendEvent::Offline) => self.set_engine(network(Network::Offline)),
            EngineInput::Event(BackendEvent::Bypassed(problem)) => {
                self.set_engine(network(Network::Bypassed { problem }));
            }
            EngineInput::Event(BackendEvent::Notice(problem)) => {
                if self.seen.insert(problem.code.clone()) {
                    (self.log)(&format!("{}: {}", problem.code, problem.detail));
                    // Nobody may be watching; that is fine.
                    let _ = self.notices.send(problem);
                }
            }
            EngineInput::Step { step, strategy } => {
                if let Some(Finding { of, .. }) = self.finding {
                    self.set_engine(Engine::Finding { step, of, strategy });
                }
            }
            EngineInput::Found(found) => {
                // Its task ends right after this report: no need to wait.
                if let Some(Finding { resume, .. }) = self.finding.take() {
                    self.found(found, resume);
                }
            }
            EngineInput::Ended(result) => {
                self.running = None;
                self.set_engine(match result {
                    Ok(()) => Engine::Off,
                    Err(problem) => Engine::Failed { problem },
                });
            }
        }
    }

    fn set_engine(&self, engine: Engine) {
        if self.status.borrow().engine != engine {
            (self.log)(&describe(&engine));
        }
        self.update(|status| status.engine = engine);
    }

    fn update(&self, change: impl FnOnce(&mut Status)) {
        self.status.send_if_modified(|status| {
            let before = status.clone();
            change(status);
            *status != before
        });
    }
}

fn error(error: Failure) -> Message {
    Message::Error { error }
}

/// A log line for an engine state.
fn describe(engine: &Engine) -> String {
    match engine {
        Engine::Off => "off".to_owned(),
        Engine::Starting => "starting".to_owned(),
        Engine::On { network } => match network {
            Network::Checking => "on, checking the network".to_owned(),
            Network::Online { uplink, ipv6 } => {
                format!(
                    "on, leaving through {uplink}{}",
                    if *ipv6 { " (IPv6 turned away)" } else { "" }
                )
            }
            Network::Active => "on, on every network".to_owned(),
            Network::Offline => "on, no network".to_owned(),
            Network::Bypassed { problem } => {
                format!("on but bypassed: {} ({})", problem.code, problem.detail)
            }
        },
        Engine::Failed { problem } => format!("failed: {} ({})", problem.code, problem.detail),
        Engine::Finding { step, of, strategy } => format!(
            "finding: step {step} of {of}, {}",
            strategy.as_deref().unwrap_or("without jink")
        ),
    }
}

/// A log line for what finding found.
fn describe_found(found: &Found) -> String {
    let result = match &found.result {
        FindResult::Kept { strategy } => format!("keeping {strategy}"),
        FindResult::NothingBlocked => "nothing is blocked".to_owned(),
        FindResult::NoneHelped => "no strategy helped".to_owned(),
        FindResult::NoNetwork => "no network".to_owned(),
    };
    let tried: Vec<String> = found
        .tried
        .iter()
        .map(|t| format!("{} {}", t.strategy, t.checks.passed))
        .collect();
    format!(
        "found: {result} ({} of {} checks passed without jink; {})",
        found.without.passed,
        found.checks,
        tried.join(", ")
    )
}
