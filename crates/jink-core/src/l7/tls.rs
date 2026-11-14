//! TLS ClientHello parsing (RFC 8446 §4.1.2, SNI per RFC 6066 §3).
//!
//! Mirrors zapret's partial-hello rules (`nfq/protocol.c`, `TLS_PARTIALS_ENABLE`):
//! a hello split across TCP segments (or QUIC CRYPTO frames) is still parsed as
//! far as its bytes go, so the engine can learn the total length and decide
//! whether to reassemble.
//!
//! Offsets are absolute: relative to the first byte passed to [`parse_record`]
//! (the TCP payload start) or to [`parse_handshake`] (the CRYPTO stream start).

use super::host::HostName;
use crate::cursor::Cursor;

const RECORD_HEADER_LEN: usize = 5;
const HANDSHAKE_HEADER_LEN: usize = 4;
const CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const EXT_SERVER_NAME: u16 = 0x0000;
const SNI_TYPE_HOST_NAME: u8 = 0;
/// Legacy version (2) + random (32), after the handshake header.
const HELLO_FIXED_FIELDS: usize = 2 + 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TlsError {
    /// The bytes do not start with a TLS ClientHello.
    #[error("not a TLS ClientHello")]
    NotClientHello,
    /// The input ends before the extensions length field, so nothing about the
    /// extensions can be known yet.
    #[error("ClientHello truncated before its extensions")]
    TruncatedBeforeExtensions,
}

/// The SNI extension's server name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerName<'a> {
    /// `sniext`: start of the SNI extension's data field.
    pub ext_data_offset: usize,
    pub host: HostName<'a>,
}

/// A ClientHello, possibly still incomplete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello<'a> {
    /// Bytes the whole message occupies: the TLS record (header included) for
    /// [`parse_record`], the handshake message for [`parse_handshake`]. If this
    /// exceeds the input, the rest arrives in later segments or frames.
    pub total_len: usize,
    /// Whether all `total_len` bytes were present in the input.
    pub complete: bool,
    /// `None` if the hello has no SNI, or if the SNI extension lies beyond the
    /// bytes received so far (check `complete`).
    pub server_name: Option<ServerName<'a>>,
}

/// The total length (header included) of the TLS record starting at
/// `payload[0]`, if its header announces a ClientHello. Needs only the first
/// 6 bytes, so it works on a first segment too short to parse further.
#[must_use]
pub fn client_hello_record_len(payload: &[u8]) -> Option<usize> {
    let mut c = Cursor::new(payload);
    match (c.u8(), c.u8(), c.u8(), c.u16(), c.u8()) {
        (
            Some(CONTENT_TYPE_HANDSHAKE),
            Some(3),
            Some(minor),
            Some(body_len),
            Some(HANDSHAKE_CLIENT_HELLO),
        ) if minor <= 3 => usize::from(body_len).checked_add(RECORD_HEADER_LEN),
        _ => None,
    }
}

/// Parses a TLS record that starts at `payload[0]` and carries a ClientHello.
///
/// # Errors
/// [`TlsError::NotClientHello`] if the record header does not match;
/// [`TlsError::TruncatedBeforeExtensions`] if too few bytes arrived to reach the
/// extensions.
pub fn parse_record(payload: &[u8]) -> Result<ClientHello<'_>, TlsError> {
    let mut c = Cursor::new(payload);
    let header = (c.u8(), c.u8(), c.u8(), c.u16(), c.u8());
    let (
        Some(CONTENT_TYPE_HANDSHAKE),
        Some(3),
        Some(minor),
        Some(body_len),
        Some(HANDSHAKE_CLIENT_HELLO),
    ) = header
    else {
        return Err(TlsError::NotClientHello);
    };
    if minor > 3 {
        return Err(TlsError::NotClientHello);
    }
    let total_len = usize::from(body_len)
        .checked_add(RECORD_HEADER_LEN)
        .ok_or(TlsError::NotClientHello)?;
    // Data beyond this record (e.g. a second record) is not part of the hello.
    let in_record = payload.get(..total_len).unwrap_or(payload);
    let mut hello = Cursor::new(in_record);
    hello
        .skip(RECORD_HEADER_LEN)
        .ok_or(TlsError::NotClientHello)?;
    Ok(ClientHello {
        total_len,
        complete: payload.len() >= total_len,
        server_name: find_server_name(hello)?,
    })
}

/// Parses a bare ClientHello handshake message (no record header), as carried
/// in QUIC CRYPTO frames.
///
/// # Errors
/// [`TlsError::NotClientHello`] if `data` is not a non-empty ClientHello
/// handshake; [`TlsError::TruncatedBeforeExtensions`] if it ends before the
/// extensions.
pub fn parse_handshake(data: &[u8]) -> Result<ClientHello<'_>, TlsError> {
    let mut c = Cursor::new(data);
    let (Some(HANDSHAKE_CLIENT_HELLO), Some(body_len)) = (c.u8(), c.u24()) else {
        return Err(TlsError::NotClientHello);
    };
    if body_len == 0 {
        return Err(TlsError::NotClientHello);
    }
    let total_len = usize::try_from(body_len)
        .ok()
        .and_then(|len| len.checked_add(HANDSHAKE_HEADER_LEN))
        .ok_or(TlsError::NotClientHello)?;
    let in_message = data.get(..total_len).unwrap_or(data);
    Ok(ClientHello {
        total_len,
        complete: data.len() >= total_len,
        server_name: find_server_name(Cursor::new(in_message))?,
    })
}

/// `c` is positioned at the handshake type byte.
fn find_server_name(mut c: Cursor<'_>) -> Result<Option<ServerName<'_>>, TlsError> {
    let truncated = TlsError::TruncatedBeforeExtensions;
    c.skip(HANDSHAKE_HEADER_LEN).ok_or(truncated)?;
    c.skip(HELLO_FIXED_FIELDS).ok_or(truncated)?;
    let session_id_len = c.u8().ok_or(truncated)?;
    c.skip(usize::from(session_id_len)).ok_or(truncated)?;
    let cipher_suites_len = c.u16().ok_or(truncated)?;
    c.skip(usize::from(cipher_suites_len)).ok_or(truncated)?;
    let compression_len = c.u8().ok_or(truncated)?;
    c.skip(usize::from(compression_len)).ok_or(truncated)?;
    let extensions_len = c.u16().ok_or(truncated)?;

    // Partial hellos: walk only the extensions that fully arrived.
    let mut exts = c.sub_truncated(usize::from(extensions_len));
    while let (Some(ext_type), Some(ext_len)) = (exts.u16(), exts.u16()) {
        let data_offset = exts.pos();
        let Some(ext_data) = exts.take(usize::from(ext_len)) else {
            return Ok(None);
        };
        if ext_type == EXT_SERVER_NAME {
            return Ok(parse_sni(ext_data, data_offset));
        }
    }
    Ok(None)
}

/// SNI extension data: list length (2), name type (1), name length (2), name.
/// Like zapret, only the first entry is read and must be a host name.
fn parse_sni(ext_data: &[u8], ext_data_offset: usize) -> Option<ServerName<'_>> {
    let mut c = Cursor::new(ext_data);
    c.skip(2)?;
    if c.u8()? != SNI_TYPE_HOST_NAME {
        return None;
    }
    let name_len = c.u16()?;
    let start = ext_data_offset.checked_add(c.pos())?;
    let host = HostName::at(c.take(usize::from(name_len))?, start)?;
    Some(ServerName {
        ext_data_offset,
        host,
    })
}
