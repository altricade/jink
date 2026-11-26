//! The daemon's behaviour, with a fake engine.

use std::future::Future;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use jink_core::config::Config;
use jink_core::config::platform::Platform;
use jink_daemon::daemon::{Backend, BackendEvent, Handle, Setup, spawn};
use jink_daemon::protocol::{
    Engine, Failure, Message, Network, Problem, Request, SettingsWire, Status, Support,
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

#[derive(Clone, Default)]
struct Fake {
    runs: Arc<Mutex<Vec<Run>>>,
}

impl Fake {
    fn runs(&self) -> std::sync::MutexGuard<'_, Vec<Run>> {
        self.runs.lock().unwrap_or_else(PoisonError::into_inner)
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
        let last_word = events.clone();
        self.runs().push(Run {
            config,
            events,
            fail: Some(fail),
        });
        async move {
            started.map_err(|e| Problem::new("test", &e))?;
            tokio::select! {
                _ = stop => {
                    // A last report while stopping, as a real engine may
                    // send: it arrives after the next run has started. The
                    // daemon may be gone already.
                    let _ = last_word.send(BackendEvent::Offline);
                    Ok(())
                }
                Ok(problem) = failed => Err(problem),
            }
        }
    }
}

struct Daemon {
    handle: Handle,
    fake: Fake,
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
    let log = Arc::new(Mutex::new(Vec::new()));
    let lines = Arc::clone(&log);
    let (handle, _task) = spawn(Setup {
        backend: fake.clone(),
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
        saved_at,
        log,
    }
}

/// Waits (briefly) until the status satisfies `wanted`.
async fn until(handle: &Handle, wanted: impl Fn(&Status) -> bool) -> Result<Status> {
    let (mut status, _) = handle.watch();
    let found =
        tokio::time::timeout(Duration::from_secs(2), status.wait_for(|s| wanted(s))).await??;
    Ok(found.clone())
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
