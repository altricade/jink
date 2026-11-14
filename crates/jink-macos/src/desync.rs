//! Desync for jink's TCP connections: the [`FirstMessage`] hook that turns
//! the engine's plan into fake packets on the raw socket and split writes.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use jink_core::engine::stream::{StreamEngine, StreamError, TcpStep};

use crate::fake::RawSender;
use crate::handshake::{Expected, Handshakes};
use crate::relay::FirstMessage;

/// How long to wait for the capture thread to report a handshake. It has
/// normally seen the SYN-ACK before the connection even completes.
const HANDSHAKE_WAIT: Duration = Duration::from_millis(300);

/// Why one connection went out without desync.
#[derive(Debug, thiserror::Error)]
pub enum DesyncError {
    #[error("handshake not captured, sent without desync")]
    NoHandshake,
    #[error("rule not applied: {0}")]
    Plan(#[from] StreamError),
    #[error("fake packet not sent: {0}")]
    Fake(io::Error),
}

/// What happened to one connection's first message.
#[derive(Debug)]
pub(crate) enum Outcome {
    /// Fakes were sent, or the message split, or both.
    Desynced,
    /// No rule applied: written whole.
    Unchanged,
    Failed(DesyncError),
}

pub(crate) struct Desyncer {
    engine: Mutex<StreamEngine>,
    handshakes: Arc<Handshakes>,
    raw: RawSender,
    report: Box<dyn Fn(SocketAddr, Outcome) + Send + Sync>,
}

impl std::fmt::Debug for Desyncer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Desyncer")
            .field("raw", &self.raw)
            .finish_non_exhaustive()
    }
}

impl Desyncer {
    pub(crate) fn new(
        engine: StreamEngine,
        handshakes: Arc<Handshakes>,
        raw: RawSender,
        report: impl Fn(SocketAddr, Outcome) + Send + Sync + 'static,
    ) -> Self {
        Self {
            engine: Mutex::new(engine),
            handshakes,
            raw,
            report: Box::new(report),
        }
    }

    /// The engine's steps for `message`.
    async fn plan(
        &self,
        mut ticket: Expected,
        message: &[u8],
    ) -> Result<Vec<TcpStep>, DesyncError> {
        let conn = ticket
            .wait(HANDSHAKE_WAIT)
            .await
            .ok_or(DesyncError::NoHandshake)?;
        let plan = self
            .engine
            .lock()
            // A panic while planning leaves no half-done state behind: each
            // call updates the flow table in single steps.
            .unwrap_or_else(PoisonError::into_inner)
            .tcp_message(&conn, message, Instant::now())?;
        Ok(plan.steps)
    }
}

impl FirstMessage for Desyncer {
    type Ticket = Expected;

    fn expect(&self, local: SocketAddr, server: SocketAddr) -> Expected {
        self.handshakes.expect(local.port(), server)
    }

    async fn prepare(&self, ticket: Expected, server: SocketAddr, message: &[u8]) -> Vec<TcpStep> {
        match self.plan(ticket, message).await {
            Ok(steps) => {
                let writes = steps
                    .iter()
                    .filter(|s| matches!(s, TcpStep::Write(_)))
                    .count();
                let changed = writes > 1 || steps.iter().any(|s| matches!(s, TcpStep::Fake(_)));
                (self.report)(
                    server,
                    if changed {
                        Outcome::Desynced
                    } else {
                        Outcome::Unchanged
                    },
                );
                steps
            }
            Err(e) => {
                (self.report)(server, Outcome::Failed(e));
                std::iter::once(TcpStep::Write(0..message.len())).collect()
            }
        }
    }

    fn fake(&self, server: SocketAddr, packet: &[u8]) {
        if let Err(e) = self.raw.send(packet) {
            (self.report)(server, Outcome::Failed(DesyncError::Fake(e)));
        }
    }
}
