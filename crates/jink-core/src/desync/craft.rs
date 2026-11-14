//! Builds forged IPv4/IPv6 TCP/UDP packets with valid checksums, copying the
//! original packet's addressing and IP fields (zapret `prepare_tcp_segment`,
//! `prepare_udp_segment`).

use etherparse::{
    IpDscp, IpEcn, IpNumber, Ipv4Header, Ipv6FlowLabel, Ipv6Header, TcpHeader, UdpHeader,
};

use crate::packet::{IpHeader, TcpFlags, TcpOptions};

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CraftError {
    #[error("forged packet would exceed the maximum IP packet size")]
    TooLarge,
    #[error("TCP options do not fit the TCP header")]
    OptionsTooLong,
    #[error("invalid IP header field in the original packet")]
    BadIpField,
}

/// TCP header fields of a forged segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TcpFields {
    pub(crate) src_port: u16,
    pub(crate) dst_port: u16,
    pub(crate) seq: u32,
    pub(crate) ack: u32,
    pub(crate) flags: TcpFlags,
    pub(crate) window: u16,
    /// Raw option bytes, already padded to a multiple of 4.
    pub(crate) options: Vec<u8>,
}

/// TCP options of a forged segment, in zapret's order (MSS, SACK-permitted,
/// MD5 signature, timestamps, window scale), NOP-padded to 4 bytes.
/// Copies what the original carried; `md5` adds a signature option and
/// `ts_increment` shifts the timestamp value.
pub(crate) fn tcp_options(
    orig: &TcpOptions,
    md5: Option<[u8; 16]>,
    ts_increment: Option<i32>,
) -> Vec<u8> {
    let mss = orig
        .mss
        .map(|v| [&[2_u8, 4][..], &v.to_be_bytes()].concat());
    let sack = orig.sack_permitted.then(|| vec![4_u8, 2]);
    let md5 = md5.map(|sig| [&[19_u8, 18][..], &sig].concat());
    let ts = orig.timestamps.map(|t| {
        let value = match ts_increment {
            Some(inc) => t.value.wrapping_add_signed(inc),
            None => t.value,
        };
        [
            &[8_u8, 10][..],
            &value.to_be_bytes(),
            &t.echo_reply.to_be_bytes(),
        ]
        .concat()
    });
    let wscale = orig.window_scale.map(|s| vec![3_u8, 3, s]);
    let mut out: Vec<u8> = [mss, sack, md5, ts, wscale]
        .into_iter()
        .flatten()
        .flatten()
        .collect();
    while !out.len().is_multiple_of(4) {
        out.push(1);
    }
    out
}

pub(crate) fn tcp_packet(
    ip: &IpHeader,
    ip_id: u16,
    tcp: &TcpFields,
    payload: &[u8],
) -> Result<Vec<u8>, CraftError> {
    let mut header = TcpHeader::new(tcp.src_port, tcp.dst_port, tcp.seq, tcp.window);
    header.acknowledgment_number = tcp.ack;
    let has = |f| tcp.flags.contains(f);
    header.fin = has(TcpFlags::FIN);
    header.syn = has(TcpFlags::SYN);
    header.rst = has(TcpFlags::RST);
    header.psh = has(TcpFlags::PSH);
    header.ack = has(TcpFlags::ACK);
    header.urg = has(TcpFlags::URG);
    header.ece = has(TcpFlags::ECE);
    header.cwr = has(TcpFlags::CWR);
    header
        .set_options_raw(&tcp.options)
        .map_err(|_| CraftError::OptionsTooLong)?;
    let transport_len = header
        .header_len()
        .checked_add(payload.len())
        .and_then(|l| u16::try_from(l).ok())
        .ok_or(CraftError::TooLarge)?;
    let mut out = ip_header(ip, ip_id, IpNumber::TCP, transport_len)?;
    header.checksum = match ip {
        IpHeader::V4 { src, dst, .. } => {
            header.calc_checksum_ipv4_raw(src.octets(), dst.octets(), payload)
        }
        IpHeader::V6 { src, dst, .. } => {
            header.calc_checksum_ipv6_raw(src.octets(), dst.octets(), payload)
        }
    }
    .map_err(|_| CraftError::TooLarge)?;
    out.extend_from_slice(&header.to_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

pub(crate) fn udp_packet(
    ip: &IpHeader,
    ip_id: u16,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Result<Vec<u8>, CraftError> {
    let transport_len = UdpHeader::LEN
        .checked_add(payload.len())
        .and_then(|l| u16::try_from(l).ok())
        .ok_or(CraftError::TooLarge)?;
    let mut header = UdpHeader {
        source_port: src_port,
        destination_port: dst_port,
        length: transport_len,
        checksum: 0,
    };
    let mut out = ip_header(ip, ip_id, IpNumber::UDP, transport_len)?;
    header.checksum = match ip {
        IpHeader::V4 { src, dst, .. } => {
            header.calc_checksum_ipv4_raw(src.octets(), dst.octets(), payload)
        }
        IpHeader::V6 { src, dst, .. } => {
            header.calc_checksum_ipv6_raw(src.octets(), dst.octets(), payload)
        }
    }
    .map_err(|_| CraftError::TooLarge)?;
    out.extend_from_slice(&header.to_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// The serialized IP header for a packet whose transport part (header plus
/// payload) is `transport_len` bytes. `ip_id` only applies to IPv4.
fn ip_header(
    ip: &IpHeader,
    ip_id: u16,
    protocol: IpNumber,
    transport_len: u16,
) -> Result<Vec<u8>, CraftError> {
    let mut out = Vec::new();
    match *ip {
        IpHeader::V4 {
            src,
            dst,
            ttl,
            dont_fragment,
            tos,
            ..
        } => {
            let mut h = Ipv4Header::new(transport_len, ttl, protocol, src.octets(), dst.octets())
                .map_err(|_| CraftError::TooLarge)?;
            h.identification = ip_id;
            h.dont_fragment = dont_fragment;
            h.dscp = IpDscp::try_new(tos >> 2).map_err(|_| CraftError::BadIpField)?;
            h.ecn = IpEcn::try_new(tos & 0x03).map_err(|_| CraftError::BadIpField)?;
            h.write(&mut out).map_err(|_| CraftError::TooLarge)?;
        }
        IpHeader::V6 {
            src,
            dst,
            hop_limit,
            traffic_class,
            flow_label,
        } => {
            let h = Ipv6Header {
                traffic_class,
                flow_label: Ipv6FlowLabel::try_new(flow_label)
                    .map_err(|_| CraftError::BadIpField)?,
                payload_length: transport_len,
                next_header: protocol,
                hop_limit,
                source: src.octets(),
                destination: dst.octets(),
            };
            h.write(&mut out).map_err(|_| CraftError::TooLarge)?;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::tcp_options;
    use crate::packet::{TcpOptions, TcpTimestamps};

    #[test]
    fn option_layout_follows_zapret() {
        let ts = TcpOptions {
            timestamps: Some(TcpTimestamps {
                value: 1000,
                echo_reply: 7,
            }),
            ..TcpOptions::default()
        };
        // TS (10 bytes) + 2 NOPs.
        assert_eq!(
            tcp_options(&ts, None, None),
            vec![8, 10, 0, 0, 0x03, 0xe8, 0, 0, 0, 7, 1, 1]
        );
        // ts fooling: value - 600000 wrapping, echo untouched.
        let fooled = tcp_options(&ts, None, Some(-600_000));
        assert_eq!(&fooled[2..6], &1000_u32.wrapping_sub(600_000).to_be_bytes());
        // MD5 comes before timestamps; 18 + 10 = 28 bytes, no padding needed.
        let md5 = tcp_options(&ts, Some([0xaa; 16]), None);
        assert_eq!(md5.len(), 28);
        assert_eq!((md5[0], md5[1], md5[18]), (19, 18, 8));
        assert_eq!(
            tcp_options(&TcpOptions::default(), None, None),
            Vec::<u8>::new()
        );
    }
}
