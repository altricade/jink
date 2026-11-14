//! Setting up (handshake capture, raw socket, utun interface, routes,
//! userspace stack), relaying with desync until a signal arrives, and
//! tearing down.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use ipstack::{IpStack, IpStackConfig, IpStackError, IpStackStream, TcpConfig};
use jink_core::engine::stream::StreamEngine;
use tokio::signal::unix::{SignalKind, signal};

use crate::desync::{DesyncError, Desyncer, Outcome};
use crate::fake::RawSender;
use crate::handshake::{CaptureError, Handshakes, Watcher};
use crate::relay::{self, RelayError};
use crate::route::{self, Captured};
use crate::tun::{self, TunIo};

/// A TCP connection idle this long is closed. Long, so that quiet but live
/// connections (chat, push) survive.
const TCP_IDLE: Duration = Duration::from_hours(2);
/// A UDP flow idle this long is forgotten (zapret uses the same).
const UDP_IDLE: Duration = Duration::from_mins(1);

/// What happens while jink runs, for the caller to report.
#[derive(Debug)]
pub enum Event {
    /// Traffic now flows through jink.
    Ready { tun: String, uplink: String },
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
    /// The handshake capture stopped early; later connections go out
    /// without desync.
    CaptureEnded(pcap::Error),
    /// A connection that did not come from jink's interface (one opened
    /// before jink started, or one bound to an address) was dropped.
    Foreign(IpAddr),
}

#[derive(Debug, thiserror::Error)]
pub enum RunError {
    #[error("cannot find the network interface to send through: {0}")]
    Uplink(io::Error),
    #[error("creating the utun interface needs root: run jink with sudo")]
    NotRoot,
    #[error("cannot create the utun interface: {0}")]
    Tun(io::Error),
    #[error(transparent)]
    Capture(#[from] CaptureError),
    #[error("cannot open a raw socket for fake packets: {0}")]
    RawSocket(io::Error),
    #[error("another VPN already routes all traffic; stop it first")]
    RoutesTaken,
    #[error("cannot add routes: {0}")]
    Routes(io::Error),
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
}

#[derive(Debug, Default)]
struct Counters {
    tcp_connected: AtomicU64,
    tcp_failed: AtomicU64,
    tcp_desynced: AtomicU64,
    udp_flows: AtomicU64,
    udp_failed: AtomicU64,
}

impl Counters {
    fn summary(&self) -> Summary {
        Summary {
            tcp_connected: self.tcp_connected.load(Ordering::Relaxed),
            tcp_failed: self.tcp_failed.load(Ordering::Relaxed),
            tcp_desynced: self.tcp_desynced.load(Ordering::Relaxed),
            udp_flows: self.udp_flows.load(Ordering::Relaxed),
            udp_failed: self.udp_failed.load(Ordering::Relaxed),
        }
    }
}

fn bump(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

type OnEvent = Arc<dyn Fn(Event) + Send + Sync>;

/// Routes all IPv4 traffic through jink, desyncing TCP connections as
/// `engine` plans, until SIGINT (Ctrl+C), SIGTERM or SIGHUP. Needs root.
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
    let uplink = route::uplink().map_err(RunError::Uplink)?;
    let device = tun::create().map_err(|e| match e.kind() {
        io::ErrorKind::PermissionDenied => RunError::NotRoot,
        _ => RunError::Tun(e),
    })?;
    let counters = Arc::new(Counters::default());
    let handshakes = Arc::new(Handshakes::default());
    let watcher = Watcher::start(&uplink.name, Arc::clone(&handshakes))?;
    let raw = RawSender::open(uplink.index).map_err(RunError::RawSocket)?;
    let desyncer = {
        let (on_event, counters) = (Arc::clone(&on_event), Arc::clone(&counters));
        Arc::new(Desyncer::new(
            engine,
            handshakes,
            raw,
            move |server, outcome| match outcome {
                Outcome::Desynced => bump(&counters.tcp_desynced),
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
    // Routes last: if anything above failed, nothing was changed.
    let routes = Captured::add(tun_index, &uplink).map_err(|e| match e.kind() {
        io::ErrorKind::AlreadyExists => RunError::RoutesTaken,
        _ => RunError::Routes(e),
    })?;
    on_event(Event::Ready {
        tun: tun_name,
        uplink: uplink.name,
    });

    let stopped = loop {
        tokio::select! {
            _ = interrupt.recv() => break Ok(()),
            _ = terminate.recv() => break Ok(()),
            _ = hangup.recv() => break Ok(()),
            accepted = stack.accept() => match accepted {
                Ok(stream) => dispatch(stream, uplink.index, &desyncer, &on_event, &counters),
                Err(e) => break Err(RunError::Stack(e)),
            },
        }
    };
    let leftover = routes.remove();
    if let Err(e) = watcher.stop() {
        on_event(Event::CaptureEnded(e));
    }
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

/// Starts relaying one new connection or flow. ICMP and other protocols are
/// dropped.
fn dispatch(
    stream: IpStackStream,
    uplink: NonZeroU32,
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
    let server = stream.peer_addr();
    let on_event = Arc::clone(on_event);
    let counters = Arc::clone(counters);
    let desyncer = Arc::clone(desyncer);
    tokio::spawn(async move {
        let result = match stream {
            IpStackStream::Tcp(tcp) => {
                relay::tcp(tcp, server, uplink, &*desyncer, || {
                    bump(&counters.tcp_connected);
                })
                .await
            }
            IpStackStream::Udp(udp) => {
                relay::udp(udp, server, uplink, || bump(&counters.udp_flows)).await
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
