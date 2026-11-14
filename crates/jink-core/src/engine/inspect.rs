//! What a message reveals for rule choice and planning: protocol, host
//! name and split positions. Shared by the packet and stream drivers.

use crate::desync::Positions;
use crate::l7::quic::{self, CryptoStream};
use crate::l7::{Protocol, http, tls};

/// What is known about a message for rule choice and planning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Inspection {
    pub(crate) protocol: Protocol,
    pub(crate) hostname: Option<String>,
    pub(crate) positions: Positions,
}

impl Inspection {
    pub(crate) fn opaque(protocol: Protocol) -> Self {
        Self {
            protocol,
            hostname: None,
            positions: Positions::default(),
        }
    }
}

pub(crate) enum QuicProgress {
    Hello(Inspection),
    NeedMore,
    Opaque,
}

/// Protocol, host name and split positions of a TCP message.
pub(crate) fn inspect_tcp(message: &[u8]) -> Inspection {
    if let Some(request) = http::parse_request(message) {
        return Inspection {
            protocol: Protocol::Http,
            hostname: request.host.as_ref().map(|h| h.name.to_owned()),
            positions: Positions::from_http(&request),
        };
    }
    match tls::parse_record(message) {
        Ok(hello) => Inspection {
            protocol: Protocol::Tls,
            hostname: hello.server_name.as_ref().map(|s| s.host.name.to_owned()),
            positions: Positions::from_tls(&hello),
        },
        Err(tls::TlsError::TruncatedBeforeExtensions) => Inspection::opaque(Protocol::Tls),
        Err(tls::TlsError::NotClientHello) => Inspection::opaque(Protocol::Unknown),
    }
}

/// Adds one Initial datagram to the CRYPTO stream. The SNI is enough to
/// decide; unlike zapret this does not wait for the rest of the hello.
pub(crate) fn quic_progress(datagram: &[u8], crypto: &mut CryptoStream) -> QuicProgress {
    let Ok(initial) = quic::decrypt_initial(datagram) else {
        return QuicProgress::Opaque;
    };
    if crypto.add_frames(&initial.plaintext).is_err() {
        return QuicProgress::Opaque;
    }
    match tls::parse_handshake(crypto.contiguous()) {
        Ok(hello) if hello.complete || hello.server_name.is_some() => {
            QuicProgress::Hello(Inspection {
                protocol: Protocol::Quic,
                hostname: hello.server_name.as_ref().map(|s| s.host.name.to_owned()),
                positions: Positions::default(),
            })
        }
        Ok(_) | Err(tls::TlsError::TruncatedBeforeExtensions) => QuicProgress::NeedMore,
        // The first CRYPTO piece has not arrived yet.
        Err(tls::TlsError::NotClientHello) if crypto.contiguous().is_empty() => {
            QuicProgress::NeedMore
        }
        Err(tls::TlsError::NotClientHello) => QuicProgress::Opaque,
    }
}
