//! QUIC test helpers: sealing client Initials (the sending side of RFC
//! 9001), so tests can build hellos that span several datagrams.

use std::error::Error;

use aes::Aes128;
use aes::cipher::BlockCipherEncrypt;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, KeyInit};
use hkdf::Hkdf;
use sha2::Sha256;

fn hkdf_label(label: &str, len: usize) -> Result<Vec<u8>, Box<dyn Error>> {
    let full = format!("tls13 {label}");
    Ok([
        &u16::try_from(len)?.to_be_bytes()[..],
        &[u8::try_from(full.len())?],
        full.as_bytes(),
        &[0],
    ]
    .concat())
}

fn expand(hk: &Hkdf<Sha256>, label: &str, out: &mut [u8]) -> Result<(), Box<dyn Error>> {
    hk.expand(&hkdf_label(label, out.len())?, out)
        .map_err(|_| "hkdf expand")?;
    Ok(())
}

/// Builds a QUIC v1 client Initial (packet number length 1) carrying
/// `frames`, padded to a 1200-byte datagram: the sending side of RFC 9001.
pub(crate) fn seal_initial(dcid: &[u8], pn: u8, frames: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    const SALT: [u8; 20] = [
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c,
        0xad, 0xcc, 0xbb, 0x7f, 0x0a,
    ];
    let initial = Hkdf::<Sha256>::new(Some(&SALT), dcid);
    let mut client = [0_u8; 32];
    expand(&initial, "client in", &mut client)?;
    let hk = Hkdf::<Sha256>::from_prk(&client).map_err(|_| "prk")?;
    let (mut key, mut iv, mut hp) = ([0_u8; 16], [0_u8; 12], [0_u8; 16]);
    expand(&hk, "quic key", &mut key)?;
    expand(&hk, "quic iv", &mut iv)?;
    expand(&hk, "quic hp", &mut hp)?;

    let mut plaintext = frames.to_vec();
    plaintext.resize(1150, 0); // PADDING frames
    let length = plaintext.len().checked_add(1 + 16).ok_or("len")?;
    let length = u16::try_from(length)? | 0x4000; // 2-byte varint
    let mut header = vec![0xc0, 0, 0, 0, 1, u8::try_from(dcid.len())?];
    header.extend_from_slice(dcid);
    header.extend_from_slice(&[0, 0]); // no SCID, no token
    header.extend_from_slice(&length.to_be_bytes());
    header.push(pn);

    if let Some(last) = iv.last_mut() {
        *last ^= pn;
    }
    let ciphertext = Aes128Gcm::new(&key.into())
        .encrypt(
            &iv.into(),
            Payload {
                msg: &plaintext,
                aad: &header,
            },
        )
        .map_err(|_| "seal")?;
    // Sample starts 4 bytes after the packet number start, i.e. 3 into the
    // ciphertext for a 1-byte packet number.
    let sample: [u8; 16] = ciphertext.get(3..19).ok_or("short")?.try_into()?;
    let mut block = aes::Block::from(sample);
    Aes128::new(&hp.into()).encrypt_block(&mut block);
    let mask: [u8; 16] = block.into();
    let (m0, m1) = (
        mask.first().copied().ok_or("mask")?,
        mask.get(1).copied().ok_or("mask")?,
    );
    if let Some(first) = header.first_mut() {
        *first ^= m0 & 0x0f;
    }
    if let Some(pn_byte) = header.last_mut() {
        *pn_byte ^= m1;
    }
    Ok([header, ciphertext].concat())
}

pub(crate) fn crypto_frame(offset: usize, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let varint = |v: usize| -> Result<[u8; 2], Box<dyn Error>> {
        Ok((u16::try_from(v)? | 0x4000).to_be_bytes())
    };
    Ok([&[0x06][..], &varint(offset)?, &varint(data.len())?, data].concat())
}
