//! The Windows engine as a [`Backend`]: WinDivert's capture loop on a
//! thread of its own, its events turned into the daemon's under stable
//! codes, stopped through [`Stop`].

use std::future::Future;

use jink_core::config::Config;
use jink_core::config::platform::Platform;
use jink_core::desync::PlanError;
use jink_core::engine::PacketEngine;
use jink_windivert::filter::{FilterOptions, build};
use jink_windivert::{Event, RunError, Stop};
use tokio::sync::{mpsc, oneshot};

use crate::daemon::{Backend, BackendEvent};
use crate::entropy::OsSeeded;
use crate::protocol::Problem;

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Windows;

impl Backend for Windows {
    fn platform(&self) -> Platform {
        Platform::Windows
    }

    fn run(
        &self,
        config: Config,
        events: mpsc::UnboundedSender<BackendEvent>,
        stop: oneshot::Receiver<()>,
    ) -> impl Future<Output = Result<(), Problem>> + Send + 'static {
        serve(config, events, stop)
    }
}

async fn serve(
    config: Config,
    events: mpsc::UnboundedSender<BackendEvent>,
    stop: oneshot::Receiver<()>,
) -> Result<(), Problem> {
    let filter =
        build(&config.capture, FilterOptions::default()).map_err(|e| Problem::new("filter", &e))?;
    let asked = Stop::new();
    let mut capture = tokio::task::spawn_blocking({
        let asked = asked.clone();
        move || capture(config, &filter, &events, &asked)
    });
    tokio::select! {
        ended = &mut capture => ended.unwrap_or_else(|e| Err(Problem::new("crashed", &e))),
        // A dropped sender stops the engine too.
        _ = stop => {
            asked.stop();
            capture.await.unwrap_or_else(|e| Err(Problem::new("crashed", &e)))
        }
    }
}

/// The capture loop, until asked to stop or it fails (on its own thread:
/// WinDivert blocks while it waits for packets).
fn capture(
    config: Config,
    filter: &str,
    events: &mpsc::UnboundedSender<BackendEvent>,
    asked: &Stop,
) -> Result<(), Problem> {
    let entropy = OsSeeded::new().map_err(|e| Problem::new("entropy", &e))?;
    // As zapret does before every run. Without them, fakes that fool with
    // timestamps cannot be made; the rest of the strategy still works.
    if config.uses_tcp_timestamps()
        && let Err(e) = jink_windivert::enable_tcp_timestamps()
    {
        report(events, notice("tcp_timestamps", &e));
    }
    // Rules Windows cannot run yet pass traffic unchanged (the app shows
    // such strategies as partial).
    let mut engine = PacketEngine::new(config, Box::new(entropy));
    let mut on_event = |event| {
        if let Some(event) = translate(event) {
            report(events, event);
        }
    };
    jink_windivert::run(&mut engine, filter, &mut on_event, asked)
        .map_err(|e| Problem::new(run_code(&e), &e))
}

/// The daemon has stopped listening: nothing to tell.
fn report(events: &mpsc::UnboundedSender<BackendEvent>, event: BackendEvent) {
    let _ = events.send(event);
}

fn notice(code: &str, detail: &dyn std::fmt::Display) -> BackendEvent {
    BackendEvent::Notice(Problem::new(code, &detail.to_string()))
}

/// The daemon's event for an engine event; rules that use techniques jink
/// lacks are left out (the strategy is shown as partial already).
fn translate(event: Event) -> Option<BackendEvent> {
    match event {
        Event::Capturing => Some(BackendEvent::Active),
        Event::PlanFailed(PlanError::Unimplemented(_)) => None,
        Event::PlanFailed(e) => Some(notice("plan_failed", &e)),
        Event::SendFailed(e) => Some(notice("send_failed", &e)),
    }
}

fn run_code(error: &RunError) -> &'static str {
    match error {
        RunError::MissingDriver => "missing_driver",
        RunError::AccessDenied => "access_denied",
        RunError::Open(_) => "driver",
        RunError::Recv(_) => "capture",
    }
}
