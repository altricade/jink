//! Setting up (utun interface, userspace stack), following the network
//! (see [`crate::link`]), relaying with desync (TCP fakes and split writes,
//! UDP decoys) until a signal arrives, and tearing down.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use ipstack::{IpStack, IpStackConfig, IpStackError, IpStackStream, TcpConfig};
use jink_core::engine::stream::StreamEngine;
use route_manager::AsyncRouteListener;
use tokio::signal::unix::{SignalKind, signal};
use tokio::time::{Instant, MissedTickBehavior};

use crate::desync::{DesyncError, Desyncer, Linked, Outcome};
use crate::handshake::Handshakes;
use crate::instance::{self, ClaimError, Leftovers, Lock};
use crate::link::{LinkError, Network, Path};
use crate::relay::{self, RelayError};
use crate::route;
use crate::tun::{self, TunIo};

/// A TCP connection idle this long is closed. Long, so that quiet but live
/// connections (chat, push) survive.
const TCP_IDLE: Duration = Duration::from_hours(2);
/// A UDP flow idle this long is forgotten (zapret uses the same).
const UDP_IDLE: Duration = Duration::from_mins(1);
/// Routing table changes come in bursts (a default route deleted, another
/// added): jink looks once they settle.
const SETTLE: Duration = Duration::from_millis(500);
/// How often jink looks at the routing table anyway, in case a change was
/// missed.
const RECHECK: Duration = Duration::from_secs(10);

/// What happens while jink runs, for the caller to report.
#[derive(Debug)]
pub enum Event {
    /// jink's interface is up; traffic flows through it once online.
    Started { tun: String },
    /// Traffic now flows through jink and leaves through `uplink`. With
    /// `ipv6`, the network has IPv6, which jink turns away so that apps use
    /// IPv4.
    Online { uplink: String, ipv6: bool },
    /// There is no network; jink waits for one.
    Offline,
    /// jink cannot work on this network, so traffic bypasses it; it tries
    /// again when the network changes.
    Unavailable(LinkError),
    /// Routes that could not be deleted while following the network, or
    /// left by a jink that was killed.
    RoutesLeft(Vec<io::Error>),
    /// The file that records jink's routes, for cleaning up after a crash,
    /// cannot be written; a crash now may leave two harmless routes.
    StateFile(io::Error),
    /// One connection or flow failed; others carry on.
    Relay {
        server: SocketAddr,
        error: RelayError,
    },
    /// One connection went out without desync.
    Desync {
        server: SocketAddr,
        error: DesyncError,
    },
    /// A handshake capture ended with an error (its connections went out
    /// without desync).
    CaptureEnded(pcap::Error),
    /// A connection that did not come from jink's interface (one opened
    /// before jink started, or one bound to an address) was dropped.
    Foreign(IpAddr),
}

#[derive(Debug, thiserror::Error)]
pub enum RunError {
    #[error("jink needs root: run it with sudo")]
    NotRoot,
    #[error("jink is already running (as a service, or in another terminal)")]
    AlreadyRunning,
    #[error("cannot take jink's lock file: {0}")]
    Lock(io::Error),
    #[error("cannot create the utun interface: {0}")]
    Tun(io::Error),
    #[error("cannot watch the routing table: {0}")]
    RouteListener(io::Error),
    #[error("cannot start the async runtime or signal handlers: {0}")]
    Runtime(io::Error),
    #[error(transparent)]
    Stack(#[from] IpStackError),
    #[error("could not delete jink's routes ({0:?}); they go away with its interface")]
    Cleanup(Vec<io::Error>),
}

/// Counts of what jink relayed, for the caller to report when it stops.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Summary {
    /// TCP connections made to servers.
    pub tcp_connected: u64,
    /// TCP connections that could not be made.
    pub tcp_failed: u64,
    /// TCP connections whose first message was desynced.
    pub tcp_desynced: u64,
    /// UDP flows set up.
    pub udp_flows: u64,
    /// UDP flows whose socket could not be set up.
    pub udp_failed: u64,
    /// UDP datagrams sent after decoys.
    pub udp_decoyed: u64,
}

#[derive(Debug, Default)]
struct Counters {
    tcp_connected: AtomicU64,
    tcp_failed: AtomicU64,
    tcp_desynced: AtomicU64,
    udp_flows: AtomicU64,
    udp_failed: AtomicU64,
    udp_decoyed: AtomicU64,
}

impl Counters {
    fn summary(&self) -> Summary {
        Summary {
            tcp_connected: self.tcp_connected.load(Ordering::Relaxed),
            tcp_failed: self.tcp_failed.load(Ordering::Relaxed),
            tcp_desynced: self.tcp_desynced.load(Ordering::Relaxed),
            udp_flows: self.udp_flows.load(Ordering::Relaxed),
            udp_failed: self.udp_failed.load(Ordering::Relaxed),
            udp_decoyed: self.udp_decoyed.load(Ordering::Relaxed),
        }
    }
}

fn bump(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

pub(crate) type OnEvent = Arc<dyn Fn(Event) + Send + Sync>;

/// Routes all IPv4 traffic through jink, desyncing TCP connections and UDP
/// flows as `engine` plans, until SIGINT (Ctrl+C), SIGTERM or SIGHUP. Needs
/// root. Follows the network as it changes, and steps aside while there is
/// none.
///
/// # Errors
/// If setting up fails (nothing is left changed), or the stack stops.
pub fn run(
    engine: StreamEngine,
    on_event: impl Fn(Event) + Send + Sync + 'static,
) -> Result<Summary, RunError> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(RunError::Runtime)?
        .block_on(serve(engine, Arc::new(on_event)))
}

async fn serve(engine: StreamEngine, on_event: OnEvent) -> Result<Summary, RunError> {
    let lock = Lock::claim(instance::LOCK.as_ref()).map_err(|e| match e {
        ClaimError::Taken => RunError::AlreadyRunning,
        ClaimError::Io(e) if e.kind() == io::ErrorKind::PermissionDenied => RunError::NotRoot,
        ClaimError::Io(e) => RunError::Lock(e),
    })?;
    let leftovers = Leftovers::new(&lock, instance::LEFTOVERS);
    let swept = leftovers.sweep();
    if !swept.is_empty() {
        on_event(Event::RoutesLeft(swept));
    }
    let device = tun::create().map_err(|e| match e.kind() {
        io::ErrorKind::PermissionDenied => RunError::NotRoot,
        _ => RunError::Tun(e),
    })?;
    let counters = Arc::new(Counters::default());
    let handshakes = Arc::new(Handshakes::default());
    let desyncer = {
        let (on_event, counters) = (Arc::clone(&on_event), Arc::clone(&counters));
        Arc::new(Desyncer::new(
            engine,
            Arc::clone(&handshakes),
            move |server, outcome| match outcome {
                Outcome::Desynced => bump(&counters.tcp_desynced),
                Outcome::Decoys => bump(&counters.udp_decoyed),
                Outcome::Unchanged => {}
                Outcome::Failed(error) => on_event(Event::Desync { server, error }),
            },
        ))
    };
    let tun_name = device.name().map_err(RunError::Tun)?;
    let tun_index = device.if_index().map_err(RunError::Tun)?;
    let mut stack = IpStack::new(stack_config()?, TunIo(device));
    let mut interrupt = signal(SignalKind::interrupt()).map_err(RunError::Runtime)?;
    let mut terminate = signal(SignalKind::terminate()).map_err(RunError::Runtime)?;
    let mut hangup = signal(SignalKind::hangup()).map_err(RunError::Runtime)?;
    let mut changes = AsyncRouteListener::new().map_err(RunError::RouteListener)?;
    let first_recheck = Instant::now()
        .checked_add(RECHECK)
        .unwrap_or_else(Instant::now);
    let mut recheck = tokio::time::interval_at(first_recheck, RECHECK);
    recheck.set_missed_tick_behavior(MissedTickBehavior::Delay);
    on_event(Event::Started { tun: tun_name });
    let mut network = Network::new(tun_index, handshakes, leftovers, Arc::clone(&on_event));
    network.refresh();

    let mut settled_at: Option<Instant> = None;
    let stopped = loop {
        tokio::select! {
            _ = interrupt.recv() => break Ok(()),
            _ = terminate.recv() => break Ok(()),
            _ = hangup.recv() => break Ok(()),
            change = changes.listen() => {
                // A change that could not be read may have been one that
                // matters.
                if change.as_ref().map_or(true, route::concerns_jink) {
                    settled_at = settled_at.or_else(|| Instant::now().checked_add(SETTLE));
                }
            }
            () = tokio::time::sleep_until(settled_at.unwrap_or_else(Instant::now)),
                if settled_at.is_some() => {
                settled_at = None;
                network.refresh();
            }
            _ = recheck.tick() => network.refresh(),
            accepted = stack.accept() => match accepted {
                Ok(stream) => dispatch(stream, network.path(), &desyncer, &on_event, &counters),
                Err(e) => break Err(RunError::Stack(e)),
            },
        }
    };
    let leftover = network.shut_down();
    drop(lock);
    stopped?;
    if leftover.is_empty() {
        Ok(counters.summary())
    } else {
        Err(RunError::Cleanup(leftover))
    }
}

fn stack_config() -> Result<IpStackConfig, IpStackError> {
    let mut tcp = TcpConfig::default();
    tcp.timeout = TCP_IDLE;
    let mut config = IpStackConfig::default();
    config
        .mtu(tun::MTU)?
        .udp_timeout(UDP_IDLE)
        .with_tcp_config(tcp);
    Ok(config)
}

/// Starts relaying one new connection or flow on `path`. ICMP and other
/// protocols are dropped, and so is everything while jink has no path (it
/// has just stepped aside).
fn dispatch(
    stream: IpStackStream,
    path: Option<Path>,
    desyncer: &Arc<Desyncer>,
    on_event: &OnEvent,
    counters: &Arc<Counters>,
) {
    let source = stream.local_addr().ip();
    if !matches!(stream, IpStackStream::Tcp(_) | IpStackStream::Udp(_)) {
        return;
    }
    // Apps' connections come from the interface's address. Anything else
    // (a connection opened before jink started, or jink's own traffic if
    // pinning ever failed) is dropped rather than relayed in a loop.
    if source != IpAddr::V4(tun::ADDRESS) {
        on_event(Event::Foreign(source));
        return;
    }
    let Some(Path { uplink, raw }) = path else {
        return;
    };
    let server = stream.peer_addr();
    let on_event = Arc::clone(on_event);
    let counters = Arc::clone(counters);
    let hooks = Linked {
        desyncer: Arc::clone(desyncer),
        raw,
    };
    tokio::spawn(async move {
        let result = match stream {
            IpStackStream::Tcp(tcp) => {
                relay::tcp(tcp, server, uplink, &hooks, || {
                    bump(&counters.tcp_connected);
                })
                .await
            }
            IpStackStream::Udp(udp) => {
                relay::udp(udp, server, uplink, &hooks, || {
                    bump(&counters.udp_flows);
                })
                .await
            }
            IpStackStream::UnknownTransport(_) | IpStackStream::UnknownNetwork(_) => Ok(()),
        };
        match &result {
            Err(RelayError::TcpConnect(_)) => bump(&counters.tcp_failed),
            Err(RelayError::UdpSocket(_)) => bump(&counters.udp_failed),
            _ => {}
        }
        if let Err(error) = result {
            on_event(Event::Relay { server, error });
        }
    });
}
