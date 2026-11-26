//! The macOS engine as a [`Backend`]: `jink_macos::serve`, with its events
//! turned into the daemon's, under stable codes.

use std::future::Future;

use jink_core::config::Config;
use jink_core::config::platform::Platform;
use jink_core::engine::stream::StreamEngine;
use jink_macos::{DesyncError, Event, LinkError, RunError};
use tokio::sync::{mpsc, oneshot};

use crate::daemon::{Backend, BackendEvent};
use crate::entropy::OsSeeded;
use crate::protocol::Problem;

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct MacOs;

impl Backend for MacOs {
    fn platform(&self) -> Platform {
        Platform::MacOs
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
    let entropy = OsSeeded::new().map_err(|e| Problem::new("entropy", &e))?;
    // Rules this Mac cannot run pass traffic unchanged (the app shows such
    // strategies as partial).
    let (engine, _) = StreamEngine::partial(config, Box::new(entropy));
    let on_event = move |event| {
        if let Some(event) = translate(event) {
            // The daemon has stopped listening: nothing to tell.
            let _ = events.send(event);
        }
    };
    let stopped = async {
        // A dropped sender stops the engine too.
        let _ = stop.await;
    };
    jink_macos::serve(engine, on_event, stopped)
        .await
        .map(|_| ())
        .map_err(|e| Problem::new(run_code(&e), &e))
}

/// The daemon's event for an engine event; per-connection noise (servers
/// that refuse, connections from before jink started) is left out.
fn translate(event: Event) -> Option<BackendEvent> {
    let notice = |code: &str, detail: &dyn std::fmt::Display| {
        Some(BackendEvent::Notice(Problem::new(
            code,
            &detail.to_string(),
        )))
    };
    match event {
        Event::Started { .. } => Some(BackendEvent::Started),
        Event::Online { uplink, ipv6 } => Some(BackendEvent::Online { uplink, ipv6 }),
        Event::Offline => Some(BackendEvent::Offline),
        Event::Unavailable(e) => Some(BackendEvent::Bypassed(Problem::new(link_code(&e), &e))),
        Event::Desync { server, error } => {
            let code = match error {
                DesyncError::NoHandshake => "no_handshake",
                DesyncError::Plan(_) => "plan_failed",
                DesyncError::Fake(_) => "fake_not_sent",
            };
            notice(code, &format!("{error} (first seen with {server})"))
        }
        Event::CaptureEnded(e) => notice("capture_ended", &e),
        Event::RoutesLeft(errors) => notice("routes_left", &format!("{errors:?}")),
        Event::StateFile(e) => notice("state_file", &e),
        Event::Relay { .. } | Event::Foreign(_) => None,
    }
}

fn link_code(error: &LinkError) -> &'static str {
    match error {
        LinkError::RouteTable(_) => "route_table",
        LinkError::Capture(_) => "capture",
        LinkError::RawSocket(_) => "raw_socket",
        LinkError::RoutesTaken => "routes_taken",
        LinkError::Routes(_) => "routes",
    }
}

fn run_code(error: &RunError) -> &'static str {
    match error {
        RunError::NotRoot => "not_root",
        RunError::AlreadyRunning => "already_running",
        RunError::Lock(_) => "lock",
        RunError::Tun(_) => "tun",
        RunError::RouteListener(_) => "route_listener",
        RunError::Runtime(_) => "runtime",
        RunError::Stack(_) => "stack",
        RunError::Cleanup(_) => "cleanup",
    }
}
