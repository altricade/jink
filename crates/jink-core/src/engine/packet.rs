//! Packet-mode driver, for backends that see and can drop every packet the
//! OS sends (WinDivert on Windows).
//!
//! For each captured packet [`PacketEngine::process`] returns packets to send
//! and a verdict on the original. The backend sends `send` in order, then
//! reinjects the original if the verdict is [`Verdict::Pass`].
//!
//! A ClientHello split over several TCP segments, or a QUIC ClientHello over
//! several Initial datagrams, cannot be classified from its first packet. As
//! in zapret, those packets are held (dropped) until enough has arrived, then
//! replayed through desync. Holds are bounded in size, count and time;
//! call [`PacketEngine::expire_holds`] periodically.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use super::flow::{ClientPacket, FlowKey, FlowTable, choose_rule};
use super::inspect::{Inspection, QuicProgress, inspect_tcp, quic_progress};
use crate::config::Config;
use crate::desync::{Entropy, Message, PlanError, Verdict, plan};
use crate::l7::quic::CryptoStream;
use crate::l7::{Protocol, classify_udp, tls};
use crate::packet::{Dissected, IpHeader, TcpFlags, TcpHeader, Transport as Wire, dissect};
use crate::rules::{Transport, normalize_host};

/// Most bytes held while reassembling one message (zapret `TCP_MAX_REASM`).
pub const MAX_REASSEMBLY: usize = 16 * 1024;
/// Most packets held for one message.
pub const MAX_HELD_PACKETS: usize = 32;
/// Held packets are released, desynced with what is known, after this long.
pub const HOLD_TIMEOUT: Duration = Duration::from_millis(500);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Sent by this machine.
    Outbound,
    /// Received from the network.
    Inbound,
}

/// What to do with one captured packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    /// Packets to send, in order, before the verdict on the original applies.
    pub send: Vec<Vec<u8>>,
    pub original: Verdict,
    /// Rules that could not be applied; affected packets went out unchanged.
    pub errors: Vec<PlanError>,
}

impl Output {
    const fn pass() -> Self {
        Self {
            send: Vec::new(),
            original: Verdict::Pass,
            errors: Vec::new(),
        }
    }

    const fn drop() -> Self {
        Self {
            send: Vec::new(),
            original: Verdict::Drop,
            errors: Vec::new(),
        }
    }
}

/// A packet released by [`PacketEngine::expire_holds`], with the tag of the
/// packet that started its hold (on Windows: the capture interface).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outgoing {
    pub tag: u64,
    pub bytes: Vec<u8>,
}

/// Packets released by [`PacketEngine::expire_holds`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Released {
    pub packets: Vec<Outgoing>,
    pub errors: Vec<PlanError>,
}

#[derive(Debug)]
enum HoldKind {
    Tcp { expected_seq: u32, total_len: usize },
    Quic { crypto: CryptoStream },
}

#[derive(Debug)]
struct Held {
    bytes: Vec<u8>,
    /// Where this packet's payload starts in the hold's `data`.
    offset: usize,
}

#[derive(Debug)]
struct Hold {
    kind: HoldKind,
    /// Payloads of the held packets, concatenated.
    data: Vec<u8>,
    packets: Vec<Held>,
    started: Instant,
    /// Tag of the packet that started the hold.
    tag: u64,
}

impl Hold {
    fn push(&mut self, bytes: &[u8], payload: &[u8]) {
        self.packets.push(Held {
            bytes: bytes.to_vec(),
            offset: self.data.len(),
        });
        self.data.extend_from_slice(payload);
    }

    fn has_room(&self, payload: &[u8]) -> bool {
        self.packets.len() < MAX_HELD_PACKETS
            && self
                .data
                .len()
                .checked_add(payload.len())
                .is_some_and(|n| n <= MAX_REASSEMBLY)
    }
}

pub struct PacketEngine {
    config: Config,
    flows: FlowTable,
    holds: HashMap<FlowKey, Hold>,
    entropy: Box<dyn Entropy + Send>,
}

impl std::fmt::Debug for PacketEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PacketEngine")
            .field("rules", &self.config.rules.len())
            .field("flows", &self.flows.len())
            .field("holds", &self.holds.len())
            .finish_non_exhaustive()
    }
}

impl PacketEngine {
    #[must_use]
    pub fn new(config: Config, entropy: Box<dyn Entropy + Send>) -> Self {
        Self {
            config,
            flows: FlowTable::default(),
            holds: HashMap::new(),
            entropy,
        }
    }

    #[must_use]
    pub const fn flows(&self) -> &FlowTable {
        &self.flows
    }

    /// Handles one captured packet. Packets that are not IPv4/IPv6 TCP/UDP,
    /// or are malformed, pass unchanged. `tag` is opaque to the engine and
    /// comes back with held packets that [`Self::expire_holds`] releases
    /// (the Windows backend passes the capture interface).
    pub fn process(
        &mut self,
        packet: &[u8],
        direction: Direction,
        tag: u64,
        now: Instant,
    ) -> Output {
        let Ok(dissected) = dissect(packet) else {
            return Output::pass();
        };
        self.flows.purge(now);
        let ip = ip_of(&dissected.ip);
        match (direction, dissected.transport) {
            (Direction::Inbound, Wire::Tcp { header, .. }) => {
                let key = server_key(Transport::Tcp, ip, header.src_port, header.dst_port);
                let closing =
                    header.flags.contains(TcpFlags::FIN) || header.flags.contains(TcpFlags::RST);
                self.flows.server_packet(&key, closing, now);
                Output::pass()
            }
            (Direction::Inbound, Wire::Udp { header, .. }) => {
                let key = server_key(Transport::Udp, ip, header.src_port, header.dst_port);
                self.flows.server_packet(&key, false, now);
                Output::pass()
            }
            (Direction::Outbound, Wire::Tcp { header, payload }) => {
                self.outbound_tcp(packet, &dissected, &header, payload, tag, now)
            }
            (Direction::Outbound, Wire::Udp { header, payload }) => {
                let key = client_key(Transport::Udp, ip, header.src_port, header.dst_port);
                self.outbound_udp(key, packet, &dissected, payload, tag, now)
            }
        }
    }

    /// Releases holds older than [`HOLD_TIMEOUT`], desynced with whatever is
    /// known so far.
    pub fn expire_holds(&mut self, now: Instant) -> Released {
        let expired: Vec<FlowKey> = self
            .holds
            .iter()
            .filter(|(_, h)| {
                now.checked_duration_since(h.started)
                    .is_some_and(|d| d >= HOLD_TIMEOUT)
            })
            .map(|(k, _)| *k)
            .collect();
        let holds: Vec<(FlowKey, Hold)> = expired
            .into_iter()
            .filter_map(|key| self.holds.remove(&key).map(|hold| (key, hold)))
            .collect();
        holds
            .into_iter()
            .fold(Released::default(), |mut acc, (key, hold)| {
                let inspection = match &hold.kind {
                    HoldKind::Tcp { .. } => inspect_tcp(&hold.data),
                    HoldKind::Quic { .. } => Inspection::opaque(Protocol::Quic),
                };
                let out = self.replay(key, &hold, &inspection);
                acc.packets
                    .extend(out.send.into_iter().map(|bytes| Outgoing {
                        tag: hold.tag,
                        bytes,
                    }));
                acc.errors.extend(out.errors);
                acc
            })
    }

    fn outbound_tcp(
        &mut self,
        packet: &[u8],
        dissected: &Dissected<'_>,
        tcp: &TcpHeader,
        payload: &[u8],
        tag: u64,
        now: Instant,
    ) -> Output {
        let key = client_key(
            Transport::Tcp,
            ip_of(&dissected.ip),
            tcp.src_port,
            tcp.dst_port,
        );
        let tracked = self.flows.client_tcp(
            key,
            ClientPacket {
                flags: tcp.flags,
                seq: tcp.seq,
                has_payload: !payload.is_empty(),
            },
            now,
        );
        if payload.is_empty() {
            return Output::pass();
        }
        if let Some(hold) = self.holds.remove(&key) {
            return self.continue_tcp_hold(key, hold, packet, dissected, tcp, payload);
        }
        // Only the first data packet of a tracked flow starts a reassembly.
        let first_data = tracked
            && self
                .flows
                .get(&key)
                .is_some_and(|f| f.client_data_packets() == 1);
        if first_data
            && let Some(total_len) = tls::client_hello_record_len(payload)
            && total_len > payload.len()
            && total_len <= MAX_REASSEMBLY
        {
            let mut hold = Hold {
                kind: HoldKind::Tcp {
                    expected_seq: next_seq(tcp.seq, payload),
                    total_len,
                },
                data: Vec::new(),
                packets: Vec::new(),
                started: now,
                tag,
            };
            hold.push(packet, payload);
            self.holds.insert(key, hold);
            return Output::drop();
        }
        let inspection = inspect_tcp(payload);
        self.apply(key, tracked, dissected, payload, 0, &inspection)
    }

    fn continue_tcp_hold(
        &mut self,
        key: FlowKey,
        mut hold: Hold,
        packet: &[u8],
        dissected: &Dissected<'_>,
        tcp: &TcpHeader,
        payload: &[u8],
    ) -> Output {
        let in_order = match hold.kind {
            HoldKind::Tcp {
                expected_seq,
                total_len,
            } if tcp.seq == expected_seq => Some(total_len),
            HoldKind::Tcp { .. } | HoldKind::Quic { .. } => None,
        };
        if let Some(total_len) = in_order
            && hold.has_room(payload)
        {
            hold.kind = HoldKind::Tcp {
                expected_seq: next_seq(tcp.seq, payload),
                total_len,
            };
            hold.push(packet, payload);
            if hold.data.len() >= total_len {
                let inspection = inspect_tcp(&hold.data);
                return self.replay(key, &hold, &inspection);
            }
            self.holds.insert(key, hold);
            return Output::drop();
        }
        // Out of order, retransmitted or too large: release what was held,
        // then handle this packet on its own (zapret `reasm_orig_cancel`).
        let inspection = inspect_tcp(&hold.data);
        let released = self.replay(key, &hold, &inspection);
        let tracked = self.flows.get(&key).is_some();
        let current = self.apply(key, tracked, dissected, payload, 0, &inspect_tcp(payload));
        combine(released, current)
    }

    fn outbound_udp(
        &mut self,
        key: FlowKey,
        packet: &[u8],
        dissected: &Dissected<'_>,
        payload: &[u8],
        tag: u64,
        now: Instant,
    ) -> Output {
        self.flows.client_udp(key, !payload.is_empty(), now);
        if payload.is_empty() {
            return Output::pass();
        }
        if let Some(hold) = self.holds.remove(&key) {
            return self.continue_quic_hold(key, hold, packet, dissected, payload);
        }
        let protocol = classify_udp(payload);
        if protocol != Protocol::Quic {
            return self.apply(
                key,
                true,
                dissected,
                payload,
                0,
                &Inspection::opaque(protocol),
            );
        }
        let mut crypto = CryptoStream::default();
        match quic_progress(payload, &mut crypto) {
            QuicProgress::Hello(inspection) => {
                self.apply(key, true, dissected, payload, 0, &inspection)
            }
            QuicProgress::Opaque => self.apply(
                key,
                true,
                dissected,
                payload,
                0,
                &Inspection::opaque(Protocol::Quic),
            ),
            QuicProgress::NeedMore => {
                let mut hold = Hold {
                    kind: HoldKind::Quic { crypto },
                    data: Vec::new(),
                    packets: Vec::new(),
                    started: now,
                    tag,
                };
                hold.push(packet, payload);
                self.holds.insert(key, hold);
                Output::drop()
            }
        }
    }

    fn continue_quic_hold(
        &mut self,
        key: FlowKey,
        mut hold: Hold,
        packet: &[u8],
        dissected: &Dissected<'_>,
        payload: &[u8],
    ) -> Output {
        let progress = match &mut hold.kind {
            HoldKind::Quic { crypto }
                if classify_udp(payload) == Protocol::Quic
                    && hold.packets.len() < MAX_HELD_PACKETS =>
            {
                Some(quic_progress(payload, crypto))
            }
            HoldKind::Quic { .. } | HoldKind::Tcp { .. } => None,
        };
        match progress {
            Some(QuicProgress::NeedMore) if hold.has_room(payload) => {
                hold.push(packet, payload);
                self.holds.insert(key, hold);
                Output::drop()
            }
            Some(QuicProgress::Hello(inspection)) if hold.has_room(payload) => {
                hold.push(packet, payload);
                self.replay(key, &hold, &inspection)
            }
            _ => {
                // Not part of the hello, or the hold is full: release it,
                // then handle this datagram on its own.
                let released = self.replay(key, &hold, &Inspection::opaque(Protocol::Quic));
                let current = self.apply(
                    key,
                    true,
                    dissected,
                    payload,
                    0,
                    &Inspection::opaque(classify_udp(payload)),
                );
                combine(released, current)
            }
        }
    }

    /// Runs every held packet through desync as part of one message, in
    /// order. All originals were dropped, so passes are re-sent here.
    fn replay(&mut self, key: FlowKey, hold: &Hold, inspection: &Inspection) -> Output {
        let tracked = self.flows.get(&key).is_some();
        let mut out = Output::drop();
        for held in &hold.packets {
            let Ok(dissected) = dissect(&held.bytes) else {
                out.send.push(held.bytes.clone());
                continue;
            };
            let one = self.apply(
                key,
                tracked,
                &dissected,
                &hold.data,
                held.offset,
                inspection,
            );
            out.send.extend(one.send);
            if one.original == Verdict::Pass {
                out.send.push(held.bytes.clone());
            }
            out.errors.extend(one.errors);
        }
        out
    }

    /// Chooses the rule (re-searching after a discovery on tracked flows),
    /// applies cutoff, and plans this packet.
    fn apply(
        &mut self,
        key: FlowKey,
        tracked: bool,
        packet: &Dissected<'_>,
        message: &[u8],
        offset: usize,
        inspection: &Inspection,
    ) -> Output {
        let hostname = inspection.hostname.as_deref().map(normalize_host);
        let flow = if tracked {
            self.flows.get_mut(&key)
        } else {
            None
        };
        let rule = match flow {
            Some(flow) => {
                flow.discover(inspection.protocol, hostname.as_deref());
                flow.rule(&self.config, &key)
            }
            None => choose_rule(&self.config, &key, inspection.protocol, hostname.as_deref()),
        };
        let Some(desync) = rule
            .and_then(|i| self.config.rules.get(i))
            .map(|r| &r.desync)
        else {
            return Output::pass();
        };
        if let Some(cutoff) = desync.cutoff {
            // zapret: cutoff needs a tracked flow; without one, no desync.
            let cut = self
                .flows
                .get_mut(&key)
                .filter(|_| tracked)
                .is_none_or(|f| f.cut_off(cutoff));
            if cut {
                return Output::pass();
            }
        }
        let msg = Message {
            protocol: inspection.protocol,
            data: message,
            offset,
            positions: &inspection.positions,
        };
        match plan(desync, packet, &msg, self.entropy.as_mut()) {
            Ok(p) => Output {
                send: p.send,
                original: p.original,
                errors: Vec::new(),
            },
            Err(e) => Output {
                errors: vec![e],
                ..Output::pass()
            },
        }
    }
}

fn combine(released: Output, current: Output) -> Output {
    Output {
        send: released.send.into_iter().chain(current.send).collect(),
        original: current.original,
        errors: released.errors.into_iter().chain(current.errors).collect(),
    }
}

fn next_seq(seq: u32, payload: &[u8]) -> u32 {
    seq.wrapping_add(u32::try_from(payload.len()).unwrap_or(u32::MAX))
}

fn ip_of(ip: &IpHeader) -> (IpAddr, IpAddr) {
    match *ip {
        IpHeader::V4 { src, dst, .. } => (IpAddr::V4(src), IpAddr::V4(dst)),
        IpHeader::V6 { src, dst, .. } => (IpAddr::V6(src), IpAddr::V6(dst)),
    }
}

/// Key for a packet sent by the client.
fn client_key(
    transport: Transport,
    (src, dst): (IpAddr, IpAddr),
    src_port: u16,
    dst_port: u16,
) -> FlowKey {
    FlowKey {
        transport,
        client: SocketAddr::new(src, src_port),
        server: SocketAddr::new(dst, dst_port),
    }
}

/// Key for a packet sent by the server.
fn server_key(
    transport: Transport,
    (src, dst): (IpAddr, IpAddr),
    src_port: u16,
    dst_port: u16,
) -> FlowKey {
    FlowKey {
        transport,
        client: SocketAddr::new(dst, dst_port),
        server: SocketAddr::new(src, src_port),
    }
}
