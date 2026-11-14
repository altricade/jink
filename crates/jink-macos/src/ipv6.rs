//! Turning IPv6 away. jink desyncs IPv4 only, so on a network with IPv6 it
//! takes IPv6 traffic too (else it would leave without desync) and refuses
//! it at once: a TCP reset for a connection attempt, an ICMPv6 "prohibited"
//! for anything else. Apps then use the server's IPv4 address straight away
//! (Happy Eyeballs moves on at a reset; a connected UDP socket, such as
//! QUIC's, gets an error on its next call), and that goes through jink.

use etherparse::{
    Icmpv6Type, IpNumber, Ipv6HeaderSlice, PacketBuilder, TcpHeaderSlice,
    icmpv6::DestUnreachableCode,
};

/// Hop limit of the replies; they never leave the Mac.
const HOP_LIMIT: u8 = 64;
/// An ICMPv6 error carries as much of the packet that caused it as fits in
/// the minimum IPv6 MTU (RFC 4443 2.4 c): 1280 - 40 (IPv6) - 8 (ICMPv6).
const QUOTED_MAX: usize = 1232;
/// ICMPv6 Echo Request: the only ICMPv6 message answered. Errors are never
/// answered, and neighbour discovery and multicast listener messages are the
/// system's own.
const ECHO_REQUEST: u8 = 128;

/// The reply that turns `packet` (an IPv6 packet from the utun interface)
/// away, or `None` if it needs none.
pub(crate) fn refusal(packet: &[u8]) -> Option<Vec<u8>> {
    let ip = Ipv6HeaderSlice::from_slice(packet).ok()?;
    let (source, destination) = (ip.source_addr(), ip.destination_addr());
    if destination.is_multicast() || source.is_multicast() || source.is_unspecified() {
        return None;
    }
    let payload = packet.get(ip.slice().len()..)?;
    let reply = PacketBuilder::ipv6(destination.octets(), source.octets(), HOP_LIMIT);
    let mut out = Vec::new();
    match ip.next_header() {
        IpNumber::TCP => {
            let tcp = TcpHeaderSlice::from_slice(payload).ok()?;
            if tcp.rst() {
                return None;
            }
            // RFC 9293 3.10.7.1: a segment with an ACK is answered with its
            // acknowledgment number as the sequence number; one without
            // (a SYN) with an ACK of everything it carried.
            let (seq, ack) = if tcp.ack() {
                (tcp.acknowledgment_number(), None)
            } else {
                let data = payload.len().checked_sub(tcp.slice().len())?;
                let length = u32::try_from(data)
                    .ok()?
                    .wrapping_add(u32::from(tcp.syn()))
                    .wrapping_add(u32::from(tcp.fin()));
                (0, Some(tcp.sequence_number().wrapping_add(length)))
            };
            let builder = reply
                .tcp(tcp.destination_port(), tcp.source_port(), seq, 0)
                .rst();
            match ack {
                Some(ack) => builder.ack(ack).write(&mut out, &[]),
                None => builder.write(&mut out, &[]),
            }
            .ok()?;
        }
        IpNumber::IPV6_ICMP if payload.first() != Some(&ECHO_REQUEST) => return None,
        _ => {
            let quoted = packet.get(..QUOTED_MAX).unwrap_or(packet);
            reply
                .icmpv6(Icmpv6Type::DestinationUnreachable(
                    DestUnreachableCode::Prohibited,
                ))
                .write(&mut out, quoted)
                .ok()?;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;

    use etherparse::{
        Icmpv6Type, NetSlice, PacketBuilder, SlicedPacket, TransportSlice,
        icmpv6::DestUnreachableCode,
    };

    use super::refusal;

    const APP: Ipv6Addr = Ipv6Addr::new(0xfd6a, 0x696e, 0x6b00, 0, 0, 0, 0, 1);
    const SERVER: Ipv6Addr = Ipv6Addr::new(0x2a00, 0x1450, 0x4010, 0xc03, 0, 0, 0, 0x5b);

    fn from_app() -> etherparse::PacketBuilderStep<etherparse::IpHeaders> {
        PacketBuilder::ipv6(APP.octets(), SERVER.octets(), 64)
    }

    fn build(
        step: impl FnOnce(&mut Vec<u8>) -> Result<(), etherparse::err::packet::BuildWriteError>,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        step(&mut out).unwrap();
        out
    }

    /// The reply's addresses (it must go back to the app) and transport.
    fn parse(reply: &[u8]) -> (Ipv6Addr, Ipv6Addr, TransportSlice<'_>) {
        let sliced = SlicedPacket::from_ip(reply).unwrap();
        let Some(NetSlice::Ipv6(ip)) = sliced.net else {
            panic!("not IPv6")
        };
        let header = ip.header();
        (
            header.source_addr(),
            header.destination_addr(),
            sliced.transport.unwrap(),
        )
    }

    #[test]
    fn a_connection_attempt_is_reset() {
        let syn = build(|out| {
            from_app()
                .tcp(50_000, 443, 1000, 65_535)
                .syn()
                .write(out, &[])
        });
        let reply = refusal(&syn).unwrap();
        let (source, destination, transport) = parse(&reply);
        assert_eq!((source, destination), (SERVER, APP));
        let TransportSlice::Tcp(tcp) = transport else {
            panic!("not TCP")
        };
        assert!(tcp.rst() && tcp.ack() && !tcp.syn());
        assert_eq!((tcp.source_port(), tcp.destination_port()), (443, 50_000));
        assert_eq!(tcp.sequence_number(), 0);
        assert_eq!(tcp.acknowledgment_number(), 1001);
        // The checksum is right, or the app's kernel would ignore it.
        let checksum = tcp
            .to_header()
            .calc_checksum_ipv6_raw(SERVER.octets(), APP.octets(), &[])
            .unwrap();
        assert_eq!(tcp.checksum(), checksum);
    }

    #[test]
    fn data_on_a_connection_is_reset_at_its_ack() {
        let data = build(|out| {
            from_app()
                .tcp(50_000, 443, 1001, 65_535)
                .ack(7777)
                .write(out, b"hello")
        });
        let reply = refusal(&data).unwrap();
        let (_, _, TransportSlice::Tcp(tcp)) = parse(&reply) else {
            panic!("not TCP")
        };
        assert!(tcp.rst() && !tcp.ack());
        assert_eq!(tcp.sequence_number(), 7777);

        // Data without an ACK is acknowledged in full; a FIN counts one.
        let fin = build(|out| {
            from_app()
                .tcp(50_000, 443, 1001, 65_535)
                .fin()
                .write(out, b"hello")
        });
        let reply = refusal(&fin).unwrap();
        let (_, _, TransportSlice::Tcp(tcp)) = parse(&reply) else {
            panic!("not TCP")
        };
        assert_eq!(tcp.acknowledgment_number(), 1001 + 5 + 1);
    }

    #[test]
    fn a_reset_is_not_answered() {
        let rst = build(|out| from_app().tcp(50_000, 443, 1001, 0).rst().write(out, &[]));
        assert_eq!(refusal(&rst), None);
    }

    #[test]
    fn udp_and_ping_are_prohibited_quoting_the_packet() {
        let quic = build(|out| from_app().udp(50_000, 443).write(out, &[0xc3; 1350]));
        let reply = refusal(&quic).unwrap();
        let (source, destination, transport) = parse(&reply);
        assert_eq!((source, destination), (SERVER, APP));
        let TransportSlice::Icmpv6(icmp) = transport else {
            panic!("not ICMPv6")
        };
        assert_eq!(
            icmp.icmp_type(),
            Icmpv6Type::DestinationUnreachable(DestUnreachableCode::Prohibited)
        );
        // The quote fits the minimum MTU and starts with the packet.
        assert_eq!(reply.len(), 1280);
        assert_eq!(icmp.payload(), &quic[..1232]);

        let ping = build(|out| from_app().icmpv6_echo_request(1, 1).write(out, b"ping"));
        let reply = refusal(&ping).unwrap();
        let (_, _, transport) = parse(&reply);
        assert!(matches!(transport, TransportSlice::Icmpv6(_)));
    }

    #[test]
    fn system_and_error_messages_are_not_answered() {
        let unreachable = build(|out| {
            from_app()
                .icmpv6(Icmpv6Type::DestinationUnreachable(
                    DestUnreachableCode::Port,
                ))
                .write(out, &[0; 48])
        });
        assert_eq!(refusal(&unreachable), None);
        // Multicast (neighbour discovery, MLD), and the unspecified source.
        let multicast = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x16);
        let to_group = build(|out| {
            PacketBuilder::ipv6(APP.octets(), multicast.octets(), 1)
                .udp(5353, 5353)
                .write(out, &[0; 12])
        });
        assert_eq!(refusal(&to_group), None);
        let anonymous = build(|out| {
            PacketBuilder::ipv6(Ipv6Addr::UNSPECIFIED.octets(), SERVER.octets(), 64)
                .udp(1, 2)
                .write(out, &[])
        });
        assert_eq!(refusal(&anonymous), None);
        // Not IPv6 at all, or cut short.
        assert_eq!(refusal(&[0x45; 40]), None);
        assert_eq!(refusal(&to_group[..30]), None);
    }
}
