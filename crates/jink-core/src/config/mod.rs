//! Typed configuration: what to capture, and per rule, which flows it applies
//! to ([`Match`]) and what to do with them ([`Desync`]).
//!
//! [`winws`] builds it from a zapret `winws`/`nfqws` command line, [`bat`]
//! extracts that command line from a zapret-discord-youtube strategy file,
//! and [`platform`] reports techniques a platform backend cannot perform.

pub mod bat;
pub mod platform;
pub mod winws;

use std::sync::Arc;

use crate::rules::{Match, PortFilter};

/// Immutable shared bytes (a fake payload or pattern loaded once).
pub type Blob = Arc<[u8]>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Ports the Windows backend diverts (`--wf-tcp` / `--wf-udp`); other
    /// backends may ignore this.
    pub capture: Capture,
    /// Tried in order; the first matching rule wins.
    pub rules: Vec<Rule>,
    /// List lines that were skipped as unparsable, per file.
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Capture {
    pub tcp: Option<PortFilter>,
    pub udp: Option<PortFilter>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub matcher: Match,
    pub desync: Desync,
}

/// The split technique that sends the original data in a modified form
/// (zapret's second desync phase).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Split {
    /// Segments at the split positions, in order.
    MultiSplit,
    /// Same segments, sent in reverse order.
    MultiDisorder,
    /// One split, each part surrounded by same-sized fake parts.
    FakedSplit,
    /// The host name part is sent alongside fake host names.
    HostFakeSplit,
}

/// Which techniques a rule applies, in zapret's phase order. A rule with all
/// three unset passes traffic through untouched.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Modes {
    /// Phase 0: put fake data into the SYN.
    pub syndata: bool,
    /// Phase 1: send fake packets before the original.
    pub fake: bool,
    /// Phase 2: send the original data split up.
    pub split: Option<Split>,
}

/// How TCP fakes are made unacceptable to the server while still being read
/// by the DPI.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Fooling {
    /// Shift the TCP timestamp value back (`ts_increment`).
    pub ts: bool,
    /// Shift sequence and acknowledgement numbers (`badseq_*_increment`).
    pub badseq: bool,
    /// Add a TCP MD5 signature option.
    pub md5sig: bool,
}

/// A split position: an offset from a protocol-defined point (zapret
/// "marker"). `Absolute` counts from the payload start, or from its end when
/// negative.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkerBase {
    Absolute,
    Method,
    Host,
    EndHost,
    Sld,
    MidSld,
    EndSld,
    SniExt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Marker {
    pub base: MarkerBase,
    pub offset: i16,
}

/// Bytes of a fake: loaded from a file or hex, or zapret's built-in default
/// for that protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FakeData {
    Builtin,
    Bytes(Blob),
}

/// Run-time edits to a TLS fake (`--dpi-desync-fake-tls-mod`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TlsMods {
    /// Randomize the `random` and session id fields.
    pub rnd: bool,
    /// Replace the SNI with a random one.
    pub rnd_sni: bool,
    /// Copy the session id from the real ClientHello.
    pub dup_sid: bool,
    /// Replace the SNI with this name.
    pub sni: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsFake {
    pub data: FakeData,
    pub mods: TlsMods,
}

/// Fake payloads per detected protocol, sent in list order. After
/// [`winws::parse`] no list is empty: a protocol without fakes gets
/// [`FakeData::Builtin`], as in zapret.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Fakes {
    pub tls: Vec<TlsFake>,
    pub http: Vec<FakeData>,
    pub quic: Vec<FakeData>,
    pub discord: Vec<FakeData>,
    pub stun: Vec<FakeData>,
    /// TCP payloads of unknown protocol (needs `any_protocol`).
    pub unknown_tcp: Vec<FakeData>,
    pub unknown_udp: Vec<FakeData>,
}

/// zapret `--dpi-desync-hostfakesplit-mod`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostFakeSplitMods {
    /// Template for fake host names (expanded to the real name's length).
    pub host: Option<String>,
    /// Send the whole request with the fake host first, then the real host.
    pub alt_order: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CutoffMode {
    /// Packets sent by the client (`nN`).
    Packets,
    /// Packets with payload sent by the client (`dN`).
    DataPackets,
    /// Client bytes, by relative sequence number (`sN`).
    SeqBytes,
}

/// Stop applying desync to a flow after this point (`--dpi-desync-cutoff`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cutoff {
    pub mode: CutoffMode,
    pub limit: u32,
}

/// IPv4 identification of generated packets (`--ip-id`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum IpIdMode {
    /// Continue from the original packet's id, +1 per generated packet.
    #[default]
    Seq,
    /// Like `Seq`, but fake replacements reuse the original's id.
    SeqGroup,
    Random,
    Zero,
}

/// zapret's documented defaults (`nfq/params.h`).
pub const TS_INCREMENT_DEFAULT: i32 = -600_000;
pub const BADSEQ_INCREMENT_DEFAULT: i32 = -10_000;
pub const BADSEQ_ACK_INCREMENT_DEFAULT: i32 = -66_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Desync {
    pub modes: Modes,
    /// How many times each fake is sent.
    pub repeats: u16,
    pub fooling: Fooling,
    pub ts_increment: i32,
    pub badseq_increment: i32,
    pub badseq_ack_increment: i32,
    /// Where `multisplit`/`multidisorder`/`fakedsplit` cut the payload.
    pub split_positions: Vec<Marker>,
    /// `--dpi-desync-split-seqovl`: bytes prepended to the first segment with
    /// its sequence number moved back by the same amount.
    pub seqovl: Option<Marker>,
    /// Bytes of the overlap, repeated to fill it (zeros if unset).
    pub seqovl_pattern: Option<Blob>,
    pub fakedsplit_pattern: Option<FakeData>,
    pub hostfakesplit: HostFakeSplitMods,
    pub fakes: Fakes,
    pub cutoff: Option<Cutoff>,
    /// Also desync payloads whose protocol was not recognised.
    pub any_protocol: bool,
    pub ip_id: IpIdMode,
}

impl Default for Desync {
    fn default() -> Self {
        Self {
            modes: Modes::default(),
            repeats: 1,
            fooling: Fooling::default(),
            ts_increment: TS_INCREMENT_DEFAULT,
            badseq_increment: BADSEQ_INCREMENT_DEFAULT,
            badseq_ack_increment: BADSEQ_ACK_INCREMENT_DEFAULT,
            // zapret `split_compat`: position 2 when none is given.
            split_positions: vec![Marker {
                base: MarkerBase::Absolute,
                offset: 2,
            }],
            seqovl: None,
            seqovl_pattern: None,
            fakedsplit_pattern: None,
            hostfakesplit: HostFakeSplitMods::default(),
            fakes: Fakes::default(),
            cutoff: None,
            any_protocol: false,
            ip_id: IpIdMode::default(),
        }
    }
}
