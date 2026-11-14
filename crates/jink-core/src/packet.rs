//! Read-only dissection of a raw IP packet (no link layer), as delivered by
//! WinDivert and by a utun device.
//!
//! The result is a typed view: only IPv4/IPv6 carrying TCP or UDP is
//! representable, everything else is a distinct [`DissectError`].

use std::net::{Ipv4Addr, Ipv6Addr};

use etherparse::{NetSlice, SlicedPacket, TcpOptionElement, TcpSlice, TransportSlice};

#[derive(Debug, thiserror::Error)]
pub enum DissectError {
    #[error("malformed packet: {0}")]
    Malformed(#[from] etherparse::err::packet::SliceError),
    #[error("not an IP packet")]
    NotIp,
    /// IP fragments carry only part of the transport payload; the engine
    /// passes them through untouched.
    #[error("fragmented IP packet")]
    Fragmented,
    #[error("transport protocol is neither TCP nor UDP")]
    UnsupportedTransport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpHeader {
    V4 {
        src: Ipv4Addr,
        dst: Ipv4Addr,
        ttl: u8,
        /// IP ID, which some DPIs track (zapret `--ip-id`).
        id: u16,
        dont_fragment: bool,
        /// DSCP and ECN, as the second header byte.
        tos: u8,
    },
    V6 {
        src: Ipv6Addr,
        dst: Ipv6Addr,
        hop_limit: u8,
        traffic_class: u8,
        flow_label: u32,
    },
}

/// TCP flag bits as on the wire (byte 13 of the TCP header).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpFlags(u8);

impl std::ops::BitOr for TcpFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl TcpFlags {
    pub const FIN: Self = Self(0x01);
    pub const SYN: Self = Self(0x02);
    pub const RST: Self = Self(0x04);
    pub const PSH: Self = Self(0x08);
    pub const ACK: Self = Self(0x10);
    pub const URG: Self = Self(0x20);
    pub const ECE: Self = Self(0x40);
    pub const CWR: Self = Self(0x80);

    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    fn from_slice(tcp: &TcpSlice<'_>) -> Self {
        let bit = |set: bool, flag: Self| if set { flag.0 } else { 0 };
        Self(
            bit(tcp.fin(), Self::FIN)
                | bit(tcp.syn(), Self::SYN)
                | bit(tcp.rst(), Self::RST)
                | bit(tcp.psh(), Self::PSH)
                | bit(tcp.ack(), Self::ACK)
                | bit(tcp.urg(), Self::URG)
                | bit(tcp.ece(), Self::ECE)
                | bit(tcp.cwr(), Self::CWR),
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpTimestamps {
    pub value: u32,
    pub echo_reply: u32,
}

/// TCP options that desync needs to copy into forged segments or to fool.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TcpOptions {
    pub mss: Option<u16>,
    pub window_scale: Option<u8>,
    pub sack_permitted: bool,
    pub timestamps: Option<TcpTimestamps>,
}

impl TcpOptions {
    /// Collects known options. Unknown or malformed options are skipped, not
    /// fatal: the packet is still forwarded, desync just knows less about it.
    fn from_slice(tcp: &TcpSlice<'_>) -> Self {
        tcp.options_iterator()
            .filter_map(Result::ok)
            .fold(Self::default(), |acc, opt| match opt {
                TcpOptionElement::MaximumSegmentSize(v) => Self {
                    mss: Some(v),
                    ..acc
                },
                TcpOptionElement::WindowScale(v) => Self {
                    window_scale: Some(v),
                    ..acc
                },
                TcpOptionElement::SelectiveAcknowledgementPermitted => Self {
                    sack_permitted: true,
                    ..acc
                },
                TcpOptionElement::Timestamp(value, echo_reply) => Self {
                    timestamps: Some(TcpTimestamps { value, echo_reply }),
                    ..acc
                },
                TcpOptionElement::Noop | TcpOptionElement::SelectiveAcknowledgement(..) => acc,
            })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: TcpFlags,
    pub window: u16,
    pub options: TcpOptions,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport<'a> {
    Tcp {
        header: TcpHeader,
        payload: &'a [u8],
    },
    Udp {
        header: UdpHeader,
        payload: &'a [u8],
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dissected<'a> {
    pub ip: IpHeader,
    pub transport: Transport<'a>,
}

/// Dissects a raw IPv4/IPv6 packet.
///
/// # Errors
/// See [`DissectError`]: malformed headers, non-IP, fragments, or a transport
/// other than TCP/UDP.
pub fn dissect(packet: &[u8]) -> Result<Dissected<'_>, DissectError> {
    let sliced = SlicedPacket::from_ip(packet)?;
    let ip = match sliced.net {
        Some(NetSlice::Ipv4(v4)) => {
            if v4.is_payload_fragmented() {
                return Err(DissectError::Fragmented);
            }
            let h = v4.header();
            IpHeader::V4 {
                src: h.source_addr(),
                dst: h.destination_addr(),
                ttl: h.ttl(),
                id: h.identification(),
                dont_fragment: h.dont_fragment(),
                tos: (h.dcp().value() << 2) | h.ecn().value(),
            }
        }
        Some(NetSlice::Ipv6(v6)) => {
            if v6.is_payload_fragmented() {
                return Err(DissectError::Fragmented);
            }
            let h = v6.header();
            IpHeader::V6 {
                src: h.source_addr(),
                dst: h.destination_addr(),
                hop_limit: h.hop_limit(),
                traffic_class: h.traffic_class(),
                flow_label: h.flow_label().value(),
            }
        }
        Some(NetSlice::Arp(_)) | None => return Err(DissectError::NotIp),
    };
    let transport = match sliced.transport {
        Some(TransportSlice::Tcp(tcp)) => Transport::Tcp {
            header: TcpHeader {
                src_port: tcp.source_port(),
                dst_port: tcp.destination_port(),
                seq: tcp.sequence_number(),
                ack: tcp.acknowledgment_number(),
                flags: TcpFlags::from_slice(&tcp),
                window: tcp.window_size(),
                options: TcpOptions::from_slice(&tcp),
            },
            payload: tcp.payload(),
        },
        Some(TransportSlice::Udp(udp)) => Transport::Udp {
            header: UdpHeader {
                src_port: udp.source_port(),
                dst_port: udp.destination_port(),
            },
            payload: udp.payload(),
        },
        Some(_) | None => return Err(DissectError::UnsupportedTransport),
    };
    Ok(Dissected { ip, transport })
}
