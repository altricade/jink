//! Dissection of raw IP packets built with etherparse's builder.

use std::error::Error;
use std::net::{Ipv4Addr, Ipv6Addr};

use etherparse::{PacketBuilder, TcpOptionElement};
use jink_core::l7::tls::parse_record;
use jink_core::packet::{
    DissectError, IpHeader, TcpFlags, TcpOptions, TcpTimestamps, Transport, dissect,
};

const GOOGLE_HELLO: &[u8] = include_bytes!("fixtures/tls_clienthello_www_google_com.bin");
const QUIC_GOOGLE: &[u8] = include_bytes!("fixtures/quic_initial_www_google_com.bin");

fn tcp_hello_v4() -> Result<Vec<u8>, Box<dyn Error>> {
    let builder = PacketBuilder::ipv4([192, 168, 1, 10], [142, 250, 74, 4], 128)
        .tcp(50123, 443, 0x1000_0000, 512)
        .ack(0x2000_0000)
        .psh()
        .options(&[
            TcpOptionElement::Noop,
            TcpOptionElement::Noop,
            TcpOptionElement::Timestamp(111, 222),
        ])?;
    let mut out = Vec::with_capacity(builder.size(GOOGLE_HELLO.len()));
    builder.write(&mut out, GOOGLE_HELLO)?;
    Ok(out)
}

#[test]
fn ipv4_tcp_hello_end_to_end() -> Result<(), Box<dyn Error>> {
    let pkt = tcp_hello_v4()?;
    let d = dissect(&pkt).unwrap();
    assert!(matches!(
        d.ip,
        IpHeader::V4 { src, dst, ttl: 128, .. }
            if src == Ipv4Addr::new(192, 168, 1, 10) && dst == Ipv4Addr::new(142, 250, 74, 4)
    ));
    let Transport::Tcp { header, payload } = d.transport else {
        panic!("expected TCP");
    };
    assert_eq!((header.src_port, header.dst_port), (50123, 443));
    assert_eq!((header.seq, header.ack), (0x1000_0000, 0x2000_0000));
    assert!(header.flags.contains(TcpFlags::ACK) && header.flags.contains(TcpFlags::PSH));
    assert!(!header.flags.contains(TcpFlags::SYN));
    assert_eq!(header.flags.bits(), 0x18);
    assert_eq!(
        header.options,
        TcpOptions {
            timestamps: Some(TcpTimestamps {
                value: 111,
                echo_reply: 222
            }),
            ..TcpOptions::default()
        }
    );
    assert_eq!(payload, GOOGLE_HELLO);
    // The payload goes straight into the TLS parser.
    assert_eq!(
        parse_record(payload)?.server_name.map(|s| s.host.name),
        Some("www.google.com")
    );
    Ok(())
}

#[test]
fn syn_options_are_collected() {
    let builder = PacketBuilder::ipv4([10, 0, 0, 1], [1, 1, 1, 1], 64)
        .tcp(40000, 443, 7, 65535)
        .syn()
        .options(&[
            TcpOptionElement::MaximumSegmentSize(1460),
            TcpOptionElement::Noop,
            TcpOptionElement::WindowScale(8),
            TcpOptionElement::SelectiveAcknowledgementPermitted,
            TcpOptionElement::Timestamp(5, 0),
        ])
        .unwrap();
    let mut pkt = Vec::new();
    builder.write(&mut pkt, &[]).unwrap();
    let Transport::Tcp { header, payload } = dissect(&pkt).unwrap().transport else {
        panic!("expected TCP");
    };
    assert!(header.flags.contains(TcpFlags::SYN));
    assert_eq!(payload, b"");
    assert_eq!(
        header.options,
        TcpOptions {
            mss: Some(1460),
            window_scale: Some(8),
            sack_permitted: true,
            timestamps: Some(TcpTimestamps {
                value: 5,
                echo_reply: 0
            }),
        }
    );
}

#[test]
fn ipv6_udp_quic() {
    let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst: Ipv6Addr = "2a00:1450:4001::64".parse().unwrap();
    let builder = PacketBuilder::ipv6(src.octets(), dst.octets(), 57).udp(55555, 443);
    let mut pkt = Vec::new();
    builder.write(&mut pkt, QUIC_GOOGLE).unwrap();
    let d = dissect(&pkt).unwrap();
    assert_eq!(
        d.ip,
        IpHeader::V6 {
            src,
            dst,
            hop_limit: 57,
            traffic_class: 0,
            flow_label: 0,
        }
    );
    let Transport::Udp { header, payload } = d.transport else {
        panic!("expected UDP");
    };
    assert_eq!((header.src_port, header.dst_port), (55555, 443));
    assert_eq!(payload, QUIC_GOOGLE);
}

#[test]
fn ipv4_fragments_are_refused() -> Result<(), Box<dyn Error>> {
    let mut pkt = tcp_hello_v4()?;
    pkt[6] |= 0x20; // set More Fragments
    assert!(matches!(dissect(&pkt), Err(DissectError::Fragmented)));
    Ok(())
}

#[test]
fn icmp_is_unsupported_transport() {
    let builder = PacketBuilder::ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64).icmpv4_echo_request(1, 1);
    let mut pkt = Vec::new();
    builder.write(&mut pkt, b"ping").unwrap();
    assert!(matches!(
        dissect(&pkt),
        Err(DissectError::UnsupportedTransport)
    ));
}

#[test]
fn garbage_and_truncation_never_panic() -> Result<(), Box<dyn Error>> {
    assert!(matches!(dissect(&[]), Err(DissectError::Malformed(_))));
    assert!(matches!(
        dissect(&[0x00; 40]),
        Err(DissectError::Malformed(_))
    ));
    let pkt = tcp_hello_v4()?;
    for n in 0..pkt.len() {
        // Truncated packets may fail or succeed with a shorter payload; they must not panic.
        let _ = dissect(&pkt[..n]);
    }
    Ok(())
}
