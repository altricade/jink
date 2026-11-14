//! Desync for jink's connections: the [`FirstMessage`] hook that turns the
//! engine's plan into fake packets on the raw socket and split writes, and
//! the [`Datagrams`] hook that plans UDP decoys.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use jink_core::engine::stream::{StreamEngine, StreamError, TcpStep, UdpPlan};

use crate::fake::RawSender;
use crate::handshake::{Expected, Handshakes};
use crate::relay::{Datagrams, FirstMessage};

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

/// What happened to one connection's first message, or a UDP datagram.
#[derive(Debug)]
pub(crate) enum Outcome {
    /// Fakes were sent, or the message split, or both.
    Desynced,
    /// Decoys were sent before a UDP datagram.
    Decoys,
    /// No rule applied: written whole.
    Unchanged,
    Failed(DesyncError),
}

/// The engine and what it needs, shared by every connection.
pub(crate) struct Desyncer {
    engine: Mutex<StreamEngine>,
    handshakes: Arc<Handshakes>,
    report: Box<dyn Fn(SocketAddr, Outcome) + Send + Sync>,
}

impl std::fmt::Debug for Desyncer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Desyncer").finish_non_exhaustive()
    }
}

impl Desyncer {
    pub(crate) fn new(
        engine: StreamEngine,
        handshakes: Arc<Handshakes>,
        report: impl Fn(SocketAddr, Outcome) + Send + Sync + 'static,
    ) -> Self {
        Self {
            engine: Mutex::new(engine),
            handshakes,
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

/// The hooks for one connection: the shared [`Desyncer`], and the raw socket
/// of the uplink the connection leaves through.
#[derive(Debug)]
pub(crate) struct Linked {
    pub(crate) desyncer: Arc<Desyncer>,
    pub(crate) raw: Arc<RawSender>,
}

impl FirstMessage for Linked {
    type Ticket = Expected;

    fn expect(&self, local: SocketAddr, server: SocketAddr) -> Expected {
        self.desyncer.handshakes.expect(local.port(), server)
    }

    async fn prepare(&self, ticket: Expected, server: SocketAddr, message: &[u8]) -> Vec<TcpStep> {
        let report = &self.desyncer.report;
        match self.desyncer.plan(ticket, message).await {
            Ok(steps) => {
                let writes = steps
                    .iter()
                    .filter(|s| matches!(s, TcpStep::Write(_)))
                    .count();
                let changed = writes > 1 || steps.iter().any(|s| matches!(s, TcpStep::Fake(_)));
                report(
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
                report(server, Outcome::Failed(e));
                std::iter::once(TcpStep::Write(0..message.len())).collect()
            }
        }
    }

    fn fake(&self, server: SocketAddr, packet: &[u8]) {
        if let Err(e) = self.raw.send(packet) {
            (self.desyncer.report)(server, Outcome::Failed(DesyncError::Fake(e)));
        }
    }
}

impl Datagrams for Linked {
    fn datagram(&self, local: SocketAddr, server: SocketAddr, payload: &[u8]) -> UdpPlan {
        let Desyncer { engine, report, .. } = &*self.desyncer;
        let plan = engine
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .udp_datagram(local, server, payload, Instant::now());
        match plan {
            Ok(plan) => {
                if !plan.decoys.is_empty() {
                    report(server, Outcome::Decoys);
                }
                plan
            }
            Err(e) => {
                report(server, Outcome::Failed(e.into()));
                UdpPlan::default()
            }
        }
    }
}
