//! QUIC client Initial packets: detection, decryption and CRYPTO reassembly.
//!
//! Initial packets are encrypted with keys anyone can derive from the
//! Destination Connection ID (RFC 9001 §5.2), so a DPI box reads the TLS
//! ClientHello inside them, and so do we. Supports QUIC v1 (RFC 9000) and
//! v2 (RFC 9369); pre-standard drafts that zapret still accepts are not
//! supported, since current browsers do not send them.

use std::ops::Range;

use aes::Aes128;
use aes::cipher::BlockCipherEncrypt;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, KeyInit};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::cursor::Cursor;

const MAX_CID_LEN: u8 = 20;
const SAMPLE_LEN: usize = 16;
/// The header-protection sample starts 4 bytes after the packet number start.
const SAMPLE_OFFSET: usize = 4;
/// Upper bound on a reassembled CRYPTO stream. A post-quantum ClientHello is
/// under 2 KiB; this leaves ample room while bounding memory per flow.
pub const MAX_CRYPTO_STREAM: usize = 16 * 1024;

const FRAME_PADDING: u8 = 0x00;
const FRAME_PING: u8 = 0x01;
const FRAME_CRYPTO: u8 = 0x06;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    V1,
    V2,
}

impl Version {
    const fn from_wire(v: u32) -> Option<Self> {
        match v {
            0x0000_0001 => Some(Self::V1),
            0x6b33_43cf => Some(Self::V2),
            _ => None,
        }
    }

    /// Long-header packet type bits (`first & 0x30`) that mean "Initial".
    const fn initial_type_bits(self) -> u8 {
        match self {
            Self::V1 => 0x00,
            Self::V2 => 0x10,
        }
    }

    const fn initial_salt(self) -> [u8; 20] {
        match self {
            // RFC 9001 §5.2
            Self::V1 => [
                0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8,
                0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
            ],
            // RFC 9369 §3.3.1
            Self::V2 => [
                0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26,
                0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
            ],
        }
    }

    /// HKDF labels for packet key, IV and header-protection key.
    const fn labels(self) -> [&'static str; 3] {
        match self {
            Self::V1 => ["quic key", "quic iv", "quic hp"],
            Self::V2 => ["quicv2 key", "quicv2 iv", "quicv2 hp"],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum QuicError {
    #[error("not a QUIC long-header packet")]
    NotLongHeader,
    #[error("unsupported QUIC version {0:#010x}")]
    UnsupportedVersion(u32),
    #[error("long-header packet is not an Initial")]
    NotInitial,
    #[error("malformed or truncated Initial packet")]
    Malformed,
    /// Wrong keys or corrupted data: the AEAD tag did not verify.
    #[error("Initial packet failed to decrypt")]
    DecryptFailed,
    /// zapret also gives up on anything but PADDING, PING and CRYPTO frames.
    #[error("unsupported frame type {0:#04x} in Initial")]
    UnsupportedFrame(u8),
    #[error("CRYPTO data beyond {MAX_CRYPTO_STREAM} bytes")]
    CryptoTooLarge,
}

struct InitialHeader<'a> {
    version: Version,
    dcid: &'a [u8],
    /// Where the (protected) packet number starts.
    pn_offset: usize,
    /// End of this packet within the datagram (coalesced packets may follow).
    end: usize,
}

fn parse_header(datagram: &[u8]) -> Result<InitialHeader<'_>, QuicError> {
    let mut c = Cursor::new(datagram);
    let first = c.u8().ok_or(QuicError::Malformed)?;
    if first & 0xc0 != 0xc0 {
        return Err(QuicError::NotLongHeader);
    }
    let raw_version = c.u32().ok_or(QuicError::Malformed)?;
    let version =
        Version::from_wire(raw_version).ok_or(QuicError::UnsupportedVersion(raw_version))?;
    if first & 0x30 != version.initial_type_bits() {
        return Err(QuicError::NotInitial);
    }
    let dcid_len = c.u8().ok_or(QuicError::Malformed)?;
    if dcid_len == 0 || dcid_len > MAX_CID_LEN {
        return Err(QuicError::Malformed);
    }
    let dcid = c.take(usize::from(dcid_len)).ok_or(QuicError::Malformed)?;
    let scid_len = c.u8().ok_or(QuicError::Malformed)?;
    if scid_len > MAX_CID_LEN {
        return Err(QuicError::Malformed);
    }
    c.skip(usize::from(scid_len)).ok_or(QuicError::Malformed)?;
    let token_len = c.varint_usize().ok_or(QuicError::Malformed)?;
    c.skip(token_len).ok_or(QuicError::Malformed)?;
    let length = c.varint_usize().ok_or(QuicError::Malformed)?;
    let pn_offset = c.pos();
    let end = pn_offset.checked_add(length).ok_or(QuicError::Malformed)?;
    if end > datagram.len() {
        return Err(QuicError::Malformed);
    }
    Ok(InitialHeader {
        version,
        dcid,
        pn_offset,
        end,
    })
}

/// zapret `IsQUICInitial` for v1/v2: an Initial large enough to carry a
/// ClientHello (datagram >= 256 bytes, packet length >= 96; smaller Initials
/// are typically ACKs).
#[must_use]
pub fn is_client_initial(datagram: &[u8]) -> bool {
    datagram.len() >= 256
        && parse_header(datagram).is_ok_and(|h| h.end.saturating_sub(h.pn_offset) >= 96)
}

/// A decrypted Initial packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Initial {
    pub version: Version,
    pub packet_number: u32,
    /// Decrypted frames.
    pub plaintext: Vec<u8>,
    /// Bytes of the datagram this packet occupies; anything after it is a
    /// coalesced packet or padding.
    pub packet_len: usize,
}

/// Decrypts the first (Initial) packet of a client datagram.
///
/// # Errors
/// See [`QuicError`].
pub fn decrypt_initial(datagram: &[u8]) -> Result<Initial, QuicError> {
    let h = parse_header(datagram)?;
    let keys = InitialKeys::derive(h.version, h.dcid)?;

    let sample_start = h
        .pn_offset
        .checked_add(SAMPLE_OFFSET)
        .ok_or(QuicError::Malformed)?;
    let sample_end = sample_start
        .checked_add(SAMPLE_LEN)
        .ok_or(QuicError::Malformed)?;
    let sample: [u8; SAMPLE_LEN] = datagram
        .get(sample_start..sample_end)
        .and_then(|s| s.try_into().ok())
        .ok_or(QuicError::Malformed)?;
    let mask = keys.header_protection_mask(sample);

    // Remove header protection (RFC 9001 §5.4.1): long headers mask 4 bits.
    let (&protected_first, after_first) = datagram.split_first().ok_or(QuicError::Malformed)?;
    let first = protected_first ^ (mask.first().copied().unwrap_or(0) & 0x0f);
    let pn_len = usize::from(first & 0x03).saturating_add(1);
    let pn_end = h
        .pn_offset
        .checked_add(pn_len)
        .ok_or(QuicError::Malformed)?;
    let pn_bytes: Vec<u8> = datagram
        .get(h.pn_offset..pn_end)
        .ok_or(QuicError::Malformed)?
        .iter()
        .zip(mask.iter().skip(1))
        .map(|(b, m)| b ^ m)
        .collect();
    let packet_number = pn_bytes
        .iter()
        .fold(0_u32, |acc, &b| acc.wrapping_shl(8) | u32::from(b));

    // The AEAD's associated data is the unprotected header.
    let header_rest = after_first
        .get(..h.pn_offset.saturating_sub(1))
        .ok_or(QuicError::Malformed)?;
    let aad: Vec<u8> = std::iter::once(first)
        .chain(header_rest.iter().copied())
        .chain(pn_bytes.iter().copied())
        .collect();
    let ciphertext = datagram.get(pn_end..h.end).ok_or(QuicError::Malformed)?;
    let plaintext = keys.open(packet_number, &aad, ciphertext)?;
    Ok(Initial {
        version: h.version,
        packet_number,
        plaintext,
        packet_len: h.end,
    })
}

struct InitialKeys {
    key: [u8; 16],
    iv: [u8; 12],
    hp: [u8; 16],
}

impl InitialKeys {
    /// RFC 9001 §5.2: client Initial secrets from the DCID.
    fn derive(version: Version, dcid: &[u8]) -> Result<Self, QuicError> {
        let initial = Hkdf::<Sha256>::new(Some(&version.initial_salt()), dcid);
        let mut client = [0_u8; 32];
        initial
            .expand(&hkdf_label("client in", client.len())?, &mut client)
            .map_err(|_| QuicError::DecryptFailed)?;
        let client = Hkdf::<Sha256>::from_prk(&client).map_err(|_| QuicError::DecryptFailed)?;
        let [key_label, iv_label, hp_label] = version.labels();
        let mut keys = Self {
            key: [0; 16],
            iv: [0; 12],
            hp: [0; 16],
        };
        for (label, out) in [
            (key_label, keys.key.as_mut_slice()),
            (iv_label, keys.iv.as_mut_slice()),
            (hp_label, keys.hp.as_mut_slice()),
        ] {
            client
                .expand(&hkdf_label(label, out.len())?, out)
                .map_err(|_| QuicError::DecryptFailed)?;
        }
        Ok(keys)
    }

    /// AES-ECB of the sample under the header-protection key.
    fn header_protection_mask(&self, sample: [u8; SAMPLE_LEN]) -> [u8; SAMPLE_LEN] {
        let cipher = Aes128::new(&self.hp.into());
        let mut block = aes::Block::from(sample);
        cipher.encrypt_block(&mut block);
        block.into()
    }

    fn open(
        &self,
        packet_number: u32,
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, QuicError> {
        // Nonce = IV XOR packet number, right-aligned (RFC 9001 §5.3):
        // the 8-byte packet number covers the last 8 of the 12 IV bytes.
        let pn = u64::from(packet_number).to_be_bytes();
        let mut nonce = self.iv;
        nonce.iter_mut().skip(4).zip(pn).for_each(|(n, p)| *n ^= p);
        Aes128Gcm::new(&self.key.into())
            .decrypt(
                &nonce.into(),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| QuicError::DecryptFailed)
    }
}

/// TLS 1.3 `HkdfLabel` (RFC 8446 §7.1) with an empty context.
fn hkdf_label(label: &str, len: usize) -> Result<Vec<u8>, QuicError> {
    const PREFIX: &[u8] = b"tls13 ";
    let out_len = u16::try_from(len).map_err(|_| QuicError::DecryptFailed)?;
    let label_len = PREFIX
        .len()
        .checked_add(label.len())
        .and_then(|l| u8::try_from(l).ok())
        .ok_or(QuicError::DecryptFailed)?;
    Ok(out_len
        .to_be_bytes()
        .into_iter()
        .chain([label_len])
        .chain(PREFIX.iter().copied())
        .chain(label.bytes())
        .chain([0])
        .collect())
}

/// Reassembles the CRYPTO stream from frames that may arrive shuffled,
/// overlapping, repeated, or spread over several Initial packets (Chrome
/// scrambles them on purpose; post-quantum hellos span two packets).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CryptoStream {
    data: Vec<u8>,
    /// Received byte ranges: sorted, non-overlapping, non-adjacent.
    covered: Vec<Range<usize>>,
}

impl CryptoStream {
    /// Adds every CRYPTO frame in a decrypted Initial payload and returns how
    /// many there were.
    ///
    /// # Errors
    /// [`QuicError::UnsupportedFrame`] for frames other than PADDING, PING and
    /// CRYPTO; [`QuicError::Malformed`] for truncated frames;
    /// [`QuicError::CryptoTooLarge`] past [`MAX_CRYPTO_STREAM`]. On error,
    /// frames before the bad one have already been added.
    pub fn add_frames(&mut self, plaintext: &[u8]) -> Result<usize, QuicError> {
        let mut c = Cursor::new(plaintext);
        let mut crypto_frames = 0_usize;
        while let Some(frame_type) = c.u8() {
            match frame_type {
                FRAME_PADDING | FRAME_PING => {}
                FRAME_CRYPTO => {
                    let offset = c.varint_usize().ok_or(QuicError::Malformed)?;
                    let len = c.varint_usize().ok_or(QuicError::Malformed)?;
                    let bytes = c.take(len).ok_or(QuicError::Malformed)?;
                    self.insert(offset, bytes)?;
                    crypto_frames = crypto_frames.saturating_add(1);
                }
                other => return Err(QuicError::UnsupportedFrame(other)),
            }
        }
        Ok(crypto_frames)
    }

    fn insert(&mut self, offset: usize, bytes: &[u8]) -> Result<(), QuicError> {
        let end = offset
            .checked_add(bytes.len())
            .filter(|&e| e <= MAX_CRYPTO_STREAM)
            .ok_or(QuicError::CryptoTooLarge)?;
        if bytes.is_empty() {
            return Ok(());
        }
        if self.data.len() < end {
            self.data.resize(end, 0);
        }
        self.data
            .get_mut(offset..end)
            .ok_or(QuicError::CryptoTooLarge)?
            .copy_from_slice(bytes);
        let mut ranges = std::mem::take(&mut self.covered);
        ranges.push(offset..end);
        ranges.sort_by_key(|r| r.start);
        self.covered = ranges.into_iter().fold(Vec::new(), |mut merged, r| {
            match merged.last_mut() {
                Some(last) if r.start <= last.end => last.end = last.end.max(r.end),
                _ => merged.push(r),
            }
            merged
        });
        Ok(())
    }

    /// The gap-free prefix of the stream received so far: what a TLS parser
    /// can read. Empty until offset 0 has arrived.
    #[must_use]
    pub fn contiguous(&self) -> &[u8] {
        let len = self
            .covered
            .first()
            .filter(|r| r.start == 0)
            .map_or(0, |r| r.end);
        self.data.get(..len).unwrap_or_default()
    }
}
