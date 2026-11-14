//! Protocol classification as zapret's `--filter-l7` sees it.

use jink_core::l7::{Protocol, classify_tcp, classify_udp};

const STUN: &[u8] = include_bytes!("fixtures/stun.bin");
const STUN2: &[u8] = include_bytes!("fixtures/stun2.bin");
const DISCORD_DECOY: &[u8] = include_bytes!("fixtures/ACTIVE_DISCORD_UDP.bin");
const QUIC_GOOGLE: &[u8] = include_bytes!("fixtures/quic_initial_www_google_com.bin");
const TENCENT: &[u8] = include_bytes!("fixtures/quic_initial_tencent_com.bin");
const TLS_GOOGLE: &[u8] = include_bytes!("fixtures/tls_clienthello_www_google_com.bin");

fn discord_ip_discovery() -> Vec<u8> {
    let mut p = vec![0x00, 0x01, 0x00, 0x46, 0x12, 0x34, 0x56, 0x78]; // header + SSRC
    p.resize(74, 0);
    p
}

#[test]
fn udp_classification() {
    assert_eq!(classify_udp(QUIC_GOOGLE), Protocol::Quic);
    // The bundle's "Discord" decoy is itself a QUIC Initial.
    assert_eq!(classify_udp(DISCORD_DECOY), Protocol::Quic);
    assert_eq!(classify_udp(STUN), Protocol::Stun);
    assert_eq!(classify_udp(STUN2), Protocol::Stun);
    assert_eq!(classify_udp(&discord_ip_discovery()), Protocol::Discord);
    assert_eq!(classify_udp(TENCENT), Protocol::Unknown);
    assert_eq!(classify_udp(&[]), Protocol::Unknown);
}

#[test]
fn discord_check_is_exact() {
    let mut wrong_len = discord_ip_discovery();
    wrong_len.push(0);
    assert_eq!(classify_udp(&wrong_len), Protocol::Unknown);
    let mut has_address = discord_ip_discovery();
    has_address[20] = b'1';
    assert_eq!(classify_udp(&has_address), Protocol::Unknown);
}

#[test]
fn stun_length_must_match() {
    let mut longer = STUN.to_vec();
    longer.extend([0, 0, 0, 0]);
    assert_eq!(classify_udp(&longer), Protocol::Unknown);
}

#[test]
fn tcp_classification() {
    assert_eq!(classify_tcp(TLS_GOOGLE), Protocol::Tls);
    // First segment of a split hello, ending before the extensions.
    assert_eq!(classify_tcp(&TLS_GOOGLE[..50]), Protocol::Tls);
    assert_eq!(
        classify_tcp(b"GET / HTTP/1.1\r\nHost: a.b\r\n\r\n"),
        Protocol::Http
    );
    assert_eq!(classify_tcp(b"SSH-2.0-OpenSSH_9.9\r\n"), Protocol::Unknown);
    assert_eq!(classify_tcp(&TLS_GOOGLE[..3]), Protocol::Unknown);
}
