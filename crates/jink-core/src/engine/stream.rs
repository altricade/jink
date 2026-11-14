//! Stream-mode driver, for backends that own the connection to the server:
//! the macOS backend ends each app connection in a userspace TCP/IP stack and
//! opens its own socket to the server.
//!
//! Such a backend never rewrites the kernel's packets. For each TCP
//! connection it reads the app's first message (the whole ClientHello: see
//! [`wanted_len`]) and asks for a [`TcpPlan`]: fake packets to send through a
//! raw socket before writing, and where to split its writes. For each UDP
//! datagram it asks for a [`UdpPlan`]: decoy payloads to send first on the
//! same socket.
//!
//! Techniques that need to rewrite or reorder the kernel's own segments
//! (seqovl, multidisorder, ...) are refused when the engine is created, or,
//! with [`StreamEngine::partial`], their rules pass traffic unchanged.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::ops::Range;
use std::time::Instant;

use super::flow::{ClientPacket, FlowKey, FlowTable};
use super::inspect::{Inspection, QuicProgress, inspect_tcp, quic_progress};
use crate::config::platform::{Platform, Unsupported};
use crate::config::{Config, Desync, Split};
use crate::desync::{Entropy, Message, PlanError, Verdict, plan};
use crate::l7::quic::CryptoStream;
use crate::l7::{Protocol, classify_udp, tls};
use crate::packet::{
    Dissected, IpHeader, TcpFlags, TcpHeader, TcpOptions, TcpTimestamps, Transport as Wire,
    UdpHeader, dissect,
};
use crate::rules::{Transport, normalize_host};

/// Most of a first message waited for (zapret `TCP_MAX_REASM`).
pub const MAX_MESSAGE: usize = 16 * 1024;

/// The backend's own TCP connection to the server, as its packets show it
/// (the macOS backend reads these with BPF).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpConnection {
    pub local: SocketAddr,
    pub server: SocketAddr,
    /// Sequence number of the next byte the socket will send.
    pub seq: u32,
    /// What the socket acknowledges.
    pub ack: u32,
    pub window: u16,
    /// TTL (IPv4) or hop limit (IPv6) the socket sends with.
    pub ttl: u8,
    /// The timestamps option of the socket's latest segment, if it uses one.
    pub timestamps: Option<TcpTimestamps>,
    /// The most payload one of the socket's segments carries (the peer's MSS
    /// less TCP option space): the message is planned in pieces this long,
    /// as zapret plans each packet the kernel sends.
    pub mss: u16,
}

/// One step of sending a first message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpStep {
    /// A complete IP packet to send through a raw socket.
    Fake(Vec<u8>),
    /// Bytes of the message to write; each write should leave as its own
    /// segment (`TCP_NODELAY`, at most [`TcpConnection::mss`] long).
    Write(Range<usize>),
}

/// What to do with the first message of a TCP connection: steps in order.
/// The writes cover the message, in order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TcpPlan {
    pub steps: Vec<TcpStep>,
}

impl TcpPlan {
    /// The fakes, in order.
    #[must_use]
    pub fn fakes(&self) -> Vec<&[u8]> {
        self.steps
            .iter()
            .filter_map(|s| match s {
                TcpStep::Fake(p) => Some(p.as_slice()),
                TcpStep::Write(_) => None,
            })
            .collect()
    }

    /// The writes, in order.
    #[must_use]
    pub fn writes(&self) -> Vec<Range<usize>> {
        self.steps
            .iter()
            .filter_map(|s| match s {
                TcpStep::Write(r) => Some(r.clone()),
                TcpStep::Fake(_) => None,
            })
            .collect()
    }
}

/// What to send before one UDP datagram.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UdpPlan {
    /// Payloads to send first, on the same socket.
    pub decoys: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StreamError {
    #[error("the configuration needs techniques this backend cannot perform: {0:?}")]
    Unsupported(Vec<Unsupported>),
    #[error(transparent)]
    Plan(#[from] PlanError),
    /// A `ts`-fooled fake would be accepted by the server and corrupt the
    /// connection if the socket does not send TCP timestamps.
    #[error("ts fooling needs TCP timestamps, which this connection does not use")]
    NoTimestamps,
}

/// How many bytes of the first message to read before planning: a whole
/// TLS record for a ClientHello (if it fits [`MAX_MESSAGE`]), else `None`
/// (plan with what has arrived).
#[must_use]
pub fn wanted_len(first_bytes: &[u8]) -> Option<usize> {
    tls::client_hello_record_len(first_bytes).filter(|&n| n <= MAX_MESSAGE)
}

pub struct StreamEngine {
    config: Config,
    flows: FlowTable,
    /// QUIC CRYPTO data per UDP flow, for hellos spanning datagrams.
    quic: HashMap<FlowKey, CryptoStream>,
    entropy: Box<dyn Entropy + Send>,
    /// Rules that match as usual but pass traffic unchanged (partial mode).
    disabled: HashSet<usize>,
}

impl std::fmt::Debug for StreamEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamEngine")
            .field("rules", &self.config.rules.len())
            .field("flows", &self.flows.len())
            .finish_non_exhaustive()
    }
}

impl StreamEngine {
    /// # Errors
    /// [`StreamError::Unsupported`] if any rule needs a technique the macOS
    /// backend cannot perform.
    pub fn new(config: Config, entropy: Box<dyn Entropy + Send>) -> Result<Self, StreamError> {
        let unsupported = Platform::MacOs.unsupported(&config);
        if !unsupported.is_empty() {
            return Err(StreamError::Unsupported(unsupported));
        }
        Ok(Self::with_disabled(config, entropy, HashSet::new()))
    }

    /// Like [`new`](Self::new), but a rule that needs a technique the macOS
    /// backend cannot perform still matches (first match wins, as always)
    /// and passes its traffic unchanged. Returns those rules too.
    #[must_use]
    pub fn partial(config: Config, entropy: Box<dyn Entropy + Send>) -> (Self, Vec<Unsupported>) {
        let unsupported = Platform::MacOs.unsupported(&config);
        let disabled = unsupported.iter().map(|u| u.rule).collect();
        (Self::with_disabled(config, entropy, disabled), unsupported)
    }

    fn with_disabled(
        config: Config,
        entropy: Box<dyn Entropy + Send>,
        disabled: HashSet<usize>,
    ) -> Self {
        Self {
            config,
            flows: FlowTable::default(),
            quic: HashMap::new(),
            entropy,
            disabled,
        }
    }

    /// Plans the first message the app sends on a TCP connection, in
    /// [`TcpConnection::mss`]-sized pieces, each the way zapret plans one
    /// packet of it.
    ///
    /// # Errors
    /// [`StreamError::Plan`] if the rule cannot be applied,
    /// [`StreamError::NoTimestamps`] if it needs `ts` fooling but the
    /// connection does not use timestamps. Either way, write the message
    /// unchanged.
    pub fn tcp_message(
        &mut self,
        conn: &TcpConnection,
        message: &[u8],
        now: Instant,
    ) -> Result<TcpPlan, StreamError> {
        self.flows.purge(now);
        let key = FlowKey {
            transport: Transport::Tcp,
            client: conn.local,
            server: conn.server,
        };
        // The handshake already happened on the socket; count it as zapret
        // would have seen it, for cutoff.
        let syn = ClientPacket {
            flags: TcpFlags::SYN,
            seq: conn.seq.wrapping_sub(1),
            has_payload: false,
        };
        self.flows.client_tcp(key, syn, now);
        let inspection = inspect_tcp(message);
        let mut steps = Vec::new();
        let mut offset = 0_usize;
        for piece in message.chunks(usize::from(conn.mss.max(1))) {
            let seq = conn.seq.wrapping_add(to_u32(offset)?);
            let data = ClientPacket {
                flags: TcpFlags::ACK,
                seq,
                has_payload: true,
            };
            self.flows.client_tcp(key, data, now);
            let end = offset
                .checked_add(piece.len())
                .ok_or(PlanError::BadMessage)?;
            let disabled = &self.disabled;
            let desync = rule_for(&mut self.flows, &self.config, &key, &inspection)
                .filter(|i| !disabled.contains(i))
                .and_then(|i| self.config.rules.get(i))
                .map(|r| &r.desync);
            let Some(desync) = desync else {
                steps.push(TcpStep::Write(offset..end));
                offset = end;
                continue;
            };
            if sends_fakes(desync)
                && desync.fooling.ts
                && !desync.fooling.badseq
                && !desync.fooling.md5sig
                && conn.timestamps.is_none()
            {
                return Err(StreamError::NoTimestamps);
            }
            let packet = Dissected {
                ip: ip_header(
                    conn.local.ip(),
                    conn.server.ip(),
                    conn.ttl,
                    &mut *self.entropy,
                ),
                transport: Wire::Tcp {
                    header: TcpHeader {
                        src_port: conn.local.port(),
                        dst_port: conn.server.port(),
                        seq,
                        ack: conn.ack,
                        flags: TcpFlags::ACK | TcpFlags::PSH,
                        window: conn.window,
                        options: TcpOptions {
                            timestamps: conn.timestamps,
                            ..TcpOptions::default()
                        },
                    },
                    payload: piece,
                },
            };
            let msg = Message {
                protocol: inspection.protocol,
                data: message,
                offset,
                positions: &inspection.positions,
            };
            let planned = plan(desync, &packet, &msg, self.entropy.as_mut())?;
            let mut real = planned.real.iter().peekable();
            for (index, packet) in planned.send.into_iter().enumerate() {
                match real.next_if(|(i, _)| *i == index) {
                    Some((_, range)) => {
                        let start = offset.checked_add(range.start);
                        let stop = offset.checked_add(range.end);
                        let (Some(start), Some(stop)) = (start, stop) else {
                            return Err(PlanError::BadMessage.into());
                        };
                        steps.push(TcpStep::Write(start..stop));
                    }
                    None => steps.push(TcpStep::Fake(packet)),
                }
            }
            if planned.original == Verdict::Pass {
                steps.push(TcpStep::Write(offset..end));
            }
            offset = end;
        }
        Ok(TcpPlan { steps })
    }

    /// Plans one UDP datagram the app sends.
    ///
    /// # Errors
    /// [`StreamError::Plan`] if the rule cannot be applied; send the
    /// datagram without decoys.
    pub fn udp_datagram(
        &mut self,
        local: SocketAddr,
        server: SocketAddr,
        payload: &[u8],
        now: Instant,
    ) -> Result<UdpPlan, StreamError> {
        self.flows.purge(now);
        let key = FlowKey {
            transport: Transport::Udp,
            client: local,
            server,
        };
        self.flows.client_udp(key, !payload.is_empty(), now);
        let protocol = classify_udp(payload);
        let first = self
            .flows
            .get(&key)
            .is_some_and(|f| f.client_data_packets() == 1);
        let inspection = if protocol == Protocol::Quic {
            let crypto = self.quic.entry(key).or_default();
            match quic_progress(payload, crypto) {
                QuicProgress::Hello(i) => {
                    self.quic.remove(&key);
                    i
                }
                QuicProgress::NeedMore | QuicProgress::Opaque => Inspection::opaque(Protocol::Quic),
            }
        } else {
            Inspection::opaque(protocol)
        };
        let disabled = &self.disabled;
        let Some(desync) = rule_for(&mut self.flows, &self.config, &key, &inspection)
            .filter(|i| !disabled.contains(i))
            .and_then(|i| self.config.rules.get(i))
            .map(|r| &r.desync)
        else {
            return Ok(UdpPlan::default());
        };
        let ip = ip_header(local.ip(), server.ip(), 64, &mut *self.entropy);
        let packet = Dissected {
            ip,
            transport: Wire::Udp {
                header: UdpHeader {
                    src_port: local.port(),
                    dst_port: server.port(),
                },
                payload,
            },
        };
        let msg = Message {
            protocol: inspection.protocol,
            data: payload,
            // Decoys only before a flow's first datagram, as zapret.
            offset: usize::from(!first),
            positions: &inspection.positions,
        };
        let planned = plan(desync, &packet, &msg, self.entropy.as_mut())?;
        let decoys = planned
            .send
            .iter()
            .filter_map(|p| match dissect(p).ok()?.transport {
                Wire::Udp { payload, .. } => Some(payload.to_vec()),
                Wire::Tcp { .. } => None,
            })
            .collect();
        Ok(UdpPlan { decoys })
    }
}

/// Whether the rule sends fooled fakes on TCP (which `ts` fooling needs
/// timestamps for).
const fn sends_fakes(desync: &Desync) -> bool {
    desync.modes.fake
        || matches!(
            desync.modes.split,
            Some(Split::FakedSplit | Split::HostFakeSplit)
        )
}

fn to_u32(n: usize) -> Result<u32, PlanError> {
    u32::try_from(n).map_err(|_| PlanError::BadMessage)
}

/// The index of the flow's rule (re-searched after a discovery) if desync
/// applies, with cutoff taken into account.
fn rule_for(
    flows: &mut FlowTable,
    config: &Config,
    key: &FlowKey,
    inspection: &Inspection,
) -> Option<usize> {
    let hostname = inspection.hostname.as_deref().map(normalize_host);
    let flow = flows.get_mut(key)?;
    flow.discover(inspection.protocol, hostname.as_deref());
    let index = flow.rule(config, key)?;
    let desync = &config.rules.get(index)?.desync;
    if let Some(cutoff) = desync.cutoff
        && flow.cut_off(cutoff)
    {
        return None;
    }
    Some(index)
}

fn ip_header(src: IpAddr, dst: IpAddr, ttl: u8, entropy: &mut dyn Entropy) -> IpHeader {
    match (src, dst) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let mut id = [0_u8; 2];
            entropy.fill(&mut id);
            IpHeader::V4 {
                src,
                dst,
                ttl,
                id: u16::from_be_bytes(id),
                dont_fragment: true,
                tos: 0,
            }
        }
        (src, dst) => IpHeader::V6 {
            src: to_v6(src),
            dst: to_v6(dst),
            hop_limit: ttl,
            traffic_class: 0,
            flow_label: 0,
        },
    }
}

fn to_v6(ip: IpAddr) -> std::net::Ipv6Addr {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    }
}
