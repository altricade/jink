//! Turns one outgoing packet into a [`Plan`]: forged packets to send, and
//! whether the original goes out too. Mirrors zapret v72.9
//! `dpi_desync_tcp_packet_play` / `dpi_desync_udp_packet_play` for the
//! techniques implemented here: fakes (UDP, and TCP with `ts`/`badseq`/
//! `md5sig` fooling), `multisplit` with `seqovl`, `fakedsplit` and
//! `hostfakesplit`. Other techniques return [`PlanError::Unimplemented`]
//! rather than silently doing less.
//!
//! The plan is platform-neutral: the Windows backend sends every packet with
//! WinDivert and applies the verdict to the original.

use std::ops::Range;

use crate::config::{Desync, FakeData, IpIdMode, Marker, MarkerBase, Rule, Split, TlsFake};
use crate::l7::Protocol;
use crate::packet::{Dissected, IpHeader, TcpHeader, Transport, UdpHeader};

use super::craft::{CraftError, TcpFields, tcp_options, tcp_packet, udp_packet};
use super::positions::{Positions, resolve, split_points};

/// zapret's built-in HTTP fake (`fake_http_request_default`).
const BUILTIN_HTTP: &[u8] = b"GET / HTTP/1.1\r\nHost: www.iana.org\r\n\
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0\r\n\
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n\
Accept-Encoding: gzip, deflate, br\r\n\r\n";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Send the original packet unchanged (after the forged ones).
    Pass,
    /// The forged packets replace the original.
    Drop,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// Complete IP packets, in sending order.
    pub send: Vec<Vec<u8>>,
    pub original: Verdict,
    /// The packets of `send` that carry the original payload: their index
    /// in `send` and the payload range they carry. Every other packet is a
    /// fake. Lets a backend that owns the connection (macOS) send the fakes
    /// itself and turn the real segments into separate writes.
    pub real: Vec<(usize, Range<usize>)>,
}

impl Plan {
    const fn pass() -> Self {
        Self {
            send: Vec::new(),
            original: Verdict::Pass,
            real: Vec::new(),
        }
    }
}

/// A plan under construction: packets in order, real ones remembered.
#[derive(Default)]
struct Out {
    send: Vec<Vec<u8>>,
    real: Vec<(usize, Range<usize>)>,
}

impl Out {
    fn fake(&mut self, packet: Vec<u8>, copies: u16) {
        self.send
            .extend(std::iter::repeat_n(packet, usize::from(copies)));
    }

    fn real(&mut self, range: Range<usize>, packet: Vec<u8>) {
        self.real.push((self.send.len(), range));
        self.send.push(packet);
    }

    fn finish(self, original: Verdict) -> Plan {
        Plan {
            send: self.send,
            original,
            real: self.real,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PlanError {
    #[error(transparent)]
    Craft(#[from] CraftError),
    /// zapret's built-in TLS ClientHello fake is not shipped with jink; give
    /// one with `--dpi-desync-fake-tls`.
    #[error("the built-in TLS fake is not available")]
    BuiltinTlsFake,
    #[error("not implemented yet: {0}")]
    Unimplemented(&'static str),
    #[error("message offset or length out of range")]
    BadMessage,
}

/// Techniques `rule` uses that [`plan`] cannot perform yet, so callers can
/// refuse a configuration up front instead of failing packet by packet.
/// Everything listed is TCP-only, so a rule that never matches TCP has none.
#[must_use]
pub fn unimplemented(rule: &Rule) -> Vec<&'static str> {
    let tcp_possible = rule
        .matcher
        .tcp_ports
        .items()
        .is_none_or(|items| !items.iter().all(|r| r.denies_all()));
    if !tcp_possible {
        return Vec::new();
    }
    let desync = &rule.desync;
    let modes = desync.modes;
    let tls_fakes = |pred: fn(&TlsFake) -> bool| modes.fake && desync.fakes.tls.iter().any(pred);
    [
        modes.syndata.then_some("syndata"),
        match modes.split {
            Some(Split::MultiDisorder) => Some("multidisorder"),
            Some(Split::HostFakeSplit) if desync.hostfakesplit.host.is_none() => {
                Some("hostfakesplit without host=")
            }
            Some(Split::MultiSplit | Split::FakedSplit | Split::HostFakeSplit) | None => None,
        },
        tls_fakes(|f| f.mods != crate::config::TlsMods::default()).then_some("fake-tls-mod"),
        tls_fakes(|f| f.data == FakeData::Builtin).then_some("built-in TLS fake"),
        (modes.split.is_some()
            && desync
                .seqovl
                .is_some_and(|m| m.base != MarkerBase::Absolute))
        .then_some("seqovl relative to a marker"),
        (modes.split == Some(Split::FakedSplit) && desync.seqovl.is_some())
            .then_some("fakedsplit with seqovl"),
    ]
    .into_iter()
    .flatten()
    .collect()
}

/// Randomness for MD5 signatures and random IP ids. Injected so plans are
/// reproducible in tests.
pub trait Entropy {
    fn fill(&mut self, buf: &mut [u8]);
}

/// The application message a packet belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Message<'a> {
    pub protocol: Protocol,
    /// The message bytes received so far (a reassembled ClientHello may span
    /// several TCP segments). For UDP, the datagram payload.
    pub data: &'a [u8],
    /// Where this packet's payload starts within `data`.
    pub offset: usize,
    /// Host and SNI positions within `data`.
    pub positions: &'a Positions,
}

/// Plans what to send for `packet` under the rule's `desync` settings.
///
/// # Errors
/// [`PlanError::Unimplemented`] for techniques not implemented yet,
/// [`PlanError::BuiltinTlsFake`] if a fake phase needs zapret's built-in TLS
/// fake, [`PlanError::Craft`] if a forged packet cannot be built.
pub fn plan(
    desync: &Desync,
    packet: &Dissected<'_>,
    message: &Message<'_>,
    entropy: &mut dyn Entropy,
) -> Result<Plan, PlanError> {
    if message.protocol == Protocol::Unknown && !desync.any_protocol {
        return Ok(Plan::pass());
    }
    match packet.transport {
        Transport::Tcp { header, payload } => {
            plan_tcp(desync, &packet.ip, &header, payload, message, entropy)
        }
        Transport::Udp { header, payload } => {
            plan_udp(desync, &packet.ip, header, payload, message, entropy)
        }
    }
}

fn plan_udp(
    d: &Desync,
    ip: &IpHeader,
    udp: UdpHeader,
    payload: &[u8],
    message: &Message<'_>,
    entropy: &mut dyn Entropy,
) -> Result<Plan, PlanError> {
    // zapret's UDP second phase (ipfrag2, udplen, tamper) is not among the
    // configurable modes; TCP split modes do not apply to UDP. Fakes go only
    // before the first datagram of a message (zapret: `!reasm_offset`).
    if !d.modes.fake || payload.is_empty() || message.offset != 0 {
        return Ok(Plan::pass());
    }
    let protocol = message.protocol;
    let fakes = match protocol {
        Protocol::Quic => &d.fakes.quic,
        Protocol::Discord => &d.fakes.discord,
        Protocol::Stun => &d.fakes.stun,
        Protocol::Http | Protocol::Tls | Protocol::Unknown => &d.fakes.unknown_udp,
    };
    let mut ids = IpIds::new(d.ip_id, ip, entropy);
    let mut send = Vec::new();
    for fake in fakes {
        let data = udp_fake_bytes(fake, protocol);
        let pkt = udp_packet(ip, ids.current, udp.src_port, udp.dst_port, &data)?;
        send.extend(std::iter::repeat_n(pkt, usize::from(d.repeats)));
        ids.advance(entropy);
    }
    Ok(Plan {
        send,
        original: Verdict::Pass,
        real: Vec::new(),
    })
}

fn plan_tcp(
    d: &Desync,
    ip: &IpHeader,
    tcp: &TcpHeader,
    payload: &[u8],
    message: &Message<'_>,
    entropy: &mut dyn Entropy,
) -> Result<Plan, PlanError> {
    if payload.is_empty() {
        return if d.modes.syndata && tcp.flags.contains(crate::packet::TcpFlags::SYN) {
            Err(PlanError::Unimplemented("syndata"))
        } else {
            Ok(Plan::pass())
        };
    }
    // zapret `desync_skip_nosni` (on by default): no SNI, no desync.
    if message.protocol == Protocol::Tls && message.positions.host.is_none() {
        return Ok(Plan::pass());
    }
    if message
        .offset
        .checked_add(payload.len())
        .is_none_or(|end| end > message.data.len())
    {
        return Err(PlanError::BadMessage);
    }
    let first_packet = message.offset == 0;
    let mut ids = IpIds::new(d.ip_id, ip, entropy);
    let mut out = Out::default();

    if d.modes.fake && first_packet {
        for data in tcp_fakes(d, message.protocol)? {
            let fields = fooled(d, tcp, tcp.seq, entropy);
            out.fake(tcp_packet(ip, ids.current, &fields, &data)?, d.repeats);
            ids.advance(entropy);
        }
    }

    let split = Split2 {
        d,
        ip,
        tcp,
        payload,
        message,
    };
    let split_done = match d.modes.split {
        None => false,
        Some(Split::MultiSplit) => split.multisplit(&mut out, &mut ids, entropy)?,
        Some(Split::FakedSplit) => split.faked_split(&mut out, &mut ids, entropy)?,
        Some(Split::HostFakeSplit) => split.host_fake_split(&mut out, &mut ids, entropy)?,
        Some(Split::MultiDisorder) => return Err(PlanError::Unimplemented("multidisorder")),
    };
    Ok(out.finish(if split_done {
        Verdict::Drop
    } else {
        Verdict::Pass
    }))
}

/// One packet's phase-2 (split) desync.
struct Split2<'a> {
    d: &'a Desync,
    ip: &'a IpHeader,
    tcp: &'a TcpHeader,
    payload: &'a [u8],
    message: &'a Message<'a>,
}

impl Split2<'_> {
    /// The sequence number of payload byte `at`, moved back by `back`.
    fn seq(&self, at: usize, back: usize) -> Result<u32, PlanError> {
        let at = u32::try_from(at).map_err(|_| PlanError::BadMessage)?;
        let back = u32::try_from(back).map_err(|_| PlanError::BadMessage)?;
        Ok(self.tcp.seq.wrapping_add(at).wrapping_sub(back))
    }

    /// An unfooled segment at payload offset `at` (moved back by `back`).
    fn real_segment(
        &self,
        id: u16,
        at: usize,
        back: usize,
        data: &[u8],
    ) -> Result<Vec<u8>, PlanError> {
        let fields = TcpFields {
            src_port: self.tcp.src_port,
            dst_port: self.tcp.dst_port,
            seq: self.seq(at, back)?,
            ack: self.tcp.ack,
            flags: self.tcp.flags,
            window: self.tcp.window,
            options: tcp_options(&self.tcp.options, None, None),
        };
        Ok(tcp_packet(self.ip, id, &fields, data)?)
    }

    /// A fooled segment at payload offset `at`.
    fn fake_segment(
        &self,
        id: u16,
        at: usize,
        data: &[u8],
        entropy: &mut dyn Entropy,
    ) -> Result<Vec<u8>, PlanError> {
        let fields = fooled(self.d, self.tcp, self.seq(at, 0)?, entropy);
        Ok(tcp_packet(self.ip, id, &fields, data)?)
    }

    fn part(&self, range: Range<usize>) -> Result<&[u8], PlanError> {
        self.payload.get(range).ok_or(PlanError::BadMessage)
    }

    /// zapret `DESYNC_MULTISPLIT`: the payload cut at the split points, the
    /// first segment (of the first packet only) prefixed with `seqovl`
    /// pattern bytes and its sequence number moved back by as many. `false`
    /// if no split point falls inside this packet (the original then goes
    /// out unchanged).
    fn multisplit(
        &self,
        out: &mut Out,
        ids: &mut IpIds,
        entropy: &mut dyn Entropy,
    ) -> Result<bool, PlanError> {
        let (d, message) = (self.d, self.message);
        let points = split_points(
            &d.split_positions,
            message.positions,
            message.data.len(),
            message.offset,
            self.payload.len(),
        );
        if points.is_empty() {
            return Ok(false);
        }
        let seqovl = match d.seqovl {
            None => 0,
            Some(Marker {
                base: MarkerBase::Absolute,
                offset,
            }) if offset > 0 => usize::try_from(offset).map_err(|_| PlanError::BadMessage)?,
            Some(_) => return Err(PlanError::Unimplemented("seqovl relative to a marker")),
        };
        let bounds: Vec<usize> = std::iter::once(0)
            .chain(points)
            .chain(std::iter::once(self.payload.len()))
            .collect();
        for (i, w) in bounds.windows(2).enumerate() {
            let (&from, &to) = (w.first().unwrap_or(&0), w.last().unwrap_or(&0));
            // Only the first segment of the first packet overlaps: later
            // overlaps race with the server consuming its buffer.
            let overlap = if i == 0 && message.offset == 0 {
                seqovl
            } else {
                0
            };
            let data = [overlap_bytes(d, overlap), self.part(from..to)?.to_vec()].concat();
            out.real(
                from..to,
                self.real_segment(ids.current, from, overlap, &data)?,
            );
            ids.advance(entropy);
        }
        Ok(true)
    }

    /// zapret `DESYNC_FAKEDSPLIT`: the payload cut once; each part is sent
    /// between two groups of fooled fakes of the same length and sequence
    /// number, filled with the pattern (zeros by default). A packet the split
    /// position does not fall in is treated as one part. Always replaces the
    /// original.
    fn faked_split(
        &self,
        out: &mut Out,
        ids: &mut IpIds,
        entropy: &mut dyn Entropy,
    ) -> Result<bool, PlanError> {
        let (d, message, len) = (self.d, self.message, self.payload.len());
        if d.seqovl.is_some() {
            return Err(PlanError::Unimplemented("fakedsplit with seqovl"));
        }
        // The first marker that resolves, relative ones before absolute
        // ones; position 1 if none does.
        let (relative, absolute): (Vec<Marker>, Vec<Marker>) = d
            .split_positions
            .iter()
            .partition(|m| m.base != MarkerBase::Absolute);
        let position = relative
            .iter()
            .chain(&absolute)
            .find_map(|&m| resolve(m, message.positions, message.data.len()))
            .unwrap_or(1);
        let at = position
            .checked_sub(message.offset)
            .filter(|&p| p > 0 && p < len)
            .unwrap_or(len);
        let pattern: &[u8] = match &d.fakedsplit_pattern {
            Some(FakeData::Bytes(b)) if !b.is_empty() => b,
            _ => &[0],
        };
        for (from, to) in [(0, at), (at, len)] {
            if from == to {
                continue;
            }
            let span = to.saturating_sub(from);
            let filler: Vec<u8> = pattern.iter().copied().cycle().take(span).collect();
            let fake = self.fake_segment(ids.current, from, &filler, entropy)?;
            out.fake(fake, d.repeats);
            ids.advance(entropy);
            out.real(
                from..to,
                self.real_segment(ids.current, from, 0, self.part(from..to)?)?,
            );
            ids.advance(entropy);
            let fake = self.fake_segment(ids.current, from, &filler, entropy)?;
            out.fake(fake, d.repeats);
            ids.advance(entropy);
        }
        Ok(true)
    }

    /// zapret `DESYNC_HOSTFAKESPLIT`: the part before the host name, then
    /// fooled segments carrying a fake host name at the host's sequence
    /// number around the real host name, then the rest. With `altorder`,
    /// the fake host, the rest, then the real host. `false` (original
    /// unchanged) unless the whole host name lies strictly inside this
    /// packet.
    fn host_fake_split(
        &self,
        out: &mut Out,
        ids: &mut IpIds,
        entropy: &mut dyn Entropy,
    ) -> Result<bool, PlanError> {
        let (d, len) = (self.d, self.payload.len());
        let Some(host) = self.message.positions.host.as_ref().and_then(|h| {
            let start = h.start.checked_sub(self.message.offset)?;
            let end = h.end.checked_sub(self.message.offset)?;
            (start > 0 && start < end && end < len).then_some(start..end)
        }) else {
            return Ok(false);
        };
        let Some(template) = d.hostfakesplit.host.as_deref() else {
            return Err(PlanError::Unimplemented("hostfakesplit without host="));
        };
        let fake_name = fake_host(host.len(), template.as_bytes(), entropy);
        let before = 0..host.start;
        let after = host.end..len;
        out.real(
            before.clone(),
            self.real_segment(ids.current, 0, 0, self.part(before)?)?,
        );
        ids.advance(entropy);
        let fake = self.fake_segment(ids.current, host.start, &fake_name, entropy)?;
        out.fake(fake, d.repeats);
        ids.advance(entropy);
        let real_host = self.real_segment(ids.current, host.start, 0, self.part(host.clone())?)?;
        ids.advance(entropy);
        if d.hostfakesplit.alt_order {
            let rest = self.real_segment(ids.current, after.start, 0, self.part(after.clone())?)?;
            ids.advance(entropy);
            out.real(after, rest);
            out.real(host, real_host);
        } else {
            out.real(host.clone(), real_host);
            let fake = self.fake_segment(ids.current, host.start, &fake_name, entropy)?;
            out.fake(fake, d.repeats);
            ids.advance(entropy);
            let rest = self.real_segment(ids.current, after.start, 0, self.part(after.clone())?)?;
            ids.advance(entropy);
            out.real(after, rest);
        }
        Ok(true)
    }
}

/// zapret's fake host name for `hostfakesplit` with `host=<template>`, as
/// long as the real one (`len` bytes): the template's last `len` bytes if it
/// is at least that long, else random label characters, a dot, and the
/// template (`xk3j9.www.google.com`).
fn fake_host(len: usize, template: &[u8], entropy: &mut dyn Entropy) -> Vec<u8> {
    const FIRST: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
    const REST: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let Some(extra) = len.checked_sub(template.len()).filter(|&n| n > 0) else {
        let skip = template.len().saturating_sub(len);
        return template.get(skip..).unwrap_or_default().to_vec();
    };
    let mut random = vec![0_u8; extra.saturating_sub(1)];
    entropy.fill(&mut random);
    let label = random.iter().enumerate().map(|(i, &b)| {
        let set = if i == 0 { FIRST } else { REST };
        usize::from(b)
            .checked_rem(set.len())
            .and_then(|i| set.get(i))
            .copied()
            .unwrap_or(b'a')
    });
    label
        .chain(std::iter::once(b'.'))
        .chain(template.iter().copied())
        .collect()
}

/// The seqovl prefix: the pattern repeated to `len` bytes (zapret
/// `fill_pattern`), or zeros without a pattern.
fn overlap_bytes(d: &Desync, len: usize) -> Vec<u8> {
    match d.seqovl_pattern.as_deref() {
        Some(pattern) if !pattern.is_empty() => pattern.iter().copied().cycle().take(len).collect(),
        _ => vec![0; len],
    }
}

/// Header fields of a fake at sequence number `seq`, with the rule's
/// fooling applied.
fn fooled(d: &Desync, tcp: &TcpHeader, seq: u32, entropy: &mut dyn Entropy) -> TcpFields {
    let fooling = d.fooling;
    let (seq, ack) = if fooling.badseq {
        (
            seq.wrapping_add_signed(d.badseq_increment),
            tcp.ack.wrapping_add_signed(d.badseq_ack_increment),
        )
    } else {
        (seq, tcp.ack)
    };
    let md5 = fooling.md5sig.then(|| {
        let mut sig = [0_u8; 16];
        entropy.fill(&mut sig);
        sig
    });
    TcpFields {
        src_port: tcp.src_port,
        dst_port: tcp.dst_port,
        seq,
        ack,
        flags: tcp.flags,
        window: tcp.window,
        options: tcp_options(&tcp.options, md5, fooling.ts.then_some(d.ts_increment)),
    }
}

/// TCP fake payloads for a protocol, in order.
fn tcp_fakes(d: &Desync, protocol: Protocol) -> Result<Vec<Vec<u8>>, PlanError> {
    match protocol {
        Protocol::Tls => d.fakes.tls.iter().map(tls_fake_bytes).collect(),
        Protocol::Http => Ok(d
            .fakes
            .http
            .iter()
            .map(|f| fake_bytes(f, BUILTIN_HTTP))
            .collect()),
        Protocol::Quic | Protocol::Stun | Protocol::Discord | Protocol::Unknown => Ok(d
            .fakes
            .unknown_tcp
            .iter()
            .map(|f| fake_bytes(f, &[0; 256]))
            .collect()),
    }
}

fn tls_fake_bytes(fake: &TlsFake) -> Result<Vec<u8>, PlanError> {
    if fake.mods != crate::config::TlsMods::default() {
        return Err(PlanError::Unimplemented("fake-tls-mod"));
    }
    match &fake.data {
        FakeData::Bytes(b) => Ok(b.to_vec()),
        FakeData::Builtin => Err(PlanError::BuiltinTlsFake),
    }
}

/// zapret `dp_fake_defaults` for UDP: a 620-byte QUIC-looking blob for QUIC,
/// 64 zero bytes otherwise.
fn udp_fake_bytes(fake: &FakeData, protocol: Protocol) -> Vec<u8> {
    match (fake, protocol) {
        (FakeData::Bytes(b), _) => b.to_vec(),
        (FakeData::Builtin, Protocol::Quic) => std::iter::once(0x40)
            .chain(std::iter::repeat_n(0, 619))
            .collect(),
        (FakeData::Builtin, _) => vec![0; 64],
    }
}

fn fake_bytes(fake: &FakeData, builtin: &[u8]) -> Vec<u8> {
    match fake {
        FakeData::Bytes(b) => b.to_vec(),
        FakeData::Builtin => builtin.to_vec(),
    }
}

/// IPv4 ids of generated packets (zapret `IP4_IP_ID_FIX` / `IP4_IP_ID_NEXT`).
struct IpIds {
    mode: IpIdMode,
    current: u16,
}

impl IpIds {
    fn new(mode: IpIdMode, ip: &IpHeader, entropy: &mut dyn Entropy) -> Self {
        let original = match ip {
            IpHeader::V4 { id, .. } => *id,
            IpHeader::V6 { .. } => 0,
        };
        let current = match mode {
            IpIdMode::Seq | IpIdMode::SeqGroup if original != 0 => original,
            IpIdMode::Seq | IpIdMode::SeqGroup | IpIdMode::Random => random_nonzero(entropy),
            IpIdMode::Zero => 0,
        };
        Self { mode, current }
    }

    fn advance(&mut self, entropy: &mut dyn Entropy) {
        self.current = match self.mode {
            IpIdMode::Seq | IpIdMode::SeqGroup => match self.current.wrapping_add(1) {
                0 => 1,
                next => next,
            },
            IpIdMode::Random => random_nonzero(entropy),
            IpIdMode::Zero => 0,
        };
    }
}

fn random_nonzero(entropy: &mut dyn Entropy) -> u16 {
    let mut b = [0_u8; 2];
    entropy.fill(&mut b);
    match u16::from_be_bytes(b) {
        0 => 1,
        v => v,
    }
}

#[cfg(test)]
mod tests {
    use super::{Entropy, fake_host};

    struct Bytes(u8);

    impl Entropy for Bytes {
        fn fill(&mut self, buf: &mut [u8]) {
            for b in buf {
                *b = self.0;
                self.0 = self.0.wrapping_add(37);
            }
        }
    }

    const TEMPLATE: &[u8] = b"www.google.com";

    #[test]
    fn fake_host_matches_the_real_length() {
        let mut e = Bytes(0);
        assert_eq!(fake_host(14, TEMPLATE, &mut e), TEMPLATE);
        assert_eq!(fake_host(10, TEMPLATE, &mut e), b"google.com");
        assert_eq!(fake_host(15, TEMPLATE, &mut e), b".www.google.com");
        let long = fake_host(20, TEMPLATE, &mut e);
        assert_eq!(long.len(), 20);
        assert!(long.ends_with(b".www.google.com"), "{long:?}");
        assert!(long[0].is_ascii_lowercase(), "{long:?}");
        assert!(
            long[..5]
                .iter()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        );
    }
}
