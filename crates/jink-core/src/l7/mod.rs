//! Application-layer protocol recognition.

pub mod discord;
pub mod host;
pub mod http;
pub mod quic;
pub mod stun;
pub mod tls;

/// The protocols zapret's `--filter-l7` and per-protocol fakes distinguish.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Http,
    Tls,
    Quic,
    Stun,
    Discord,
    Unknown,
}

/// Classifies the first data of a TCP flow (zapret order: HTTP, then TLS).
/// A ClientHello whose first segment ends before the extensions still counts
/// as TLS, so it can be reassembled.
#[must_use]
pub fn classify_tcp(payload: &[u8]) -> Protocol {
    if http::is_request(payload) {
        Protocol::Http
    } else if matches!(
        tls::parse_record(payload),
        Ok(_) | Err(tls::TlsError::TruncatedBeforeExtensions)
    ) {
        Protocol::Tls
    } else {
        Protocol::Unknown
    }
}

/// Classifies a UDP payload (zapret order: QUIC, Discord, STUN).
#[must_use]
pub fn classify_udp(payload: &[u8]) -> Protocol {
    if quic::is_client_initial(payload) {
        Protocol::Quic
    } else if discord::is_ip_discovery_request(payload) {
        Protocol::Discord
    } else if stun::is_message(payload) {
        Protocol::Stun
    } else {
        Protocol::Unknown
    }
}
