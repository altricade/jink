//! QUIC Initial decryption and CRYPTO reassembly against the real QUIC
//! payloads shipped by zapret-discord-youtube. Expected values come from an
//! independent Python decoder (Part 2 of the investigation).

use std::error::Error;

use jink_core::l7::quic::{CryptoStream, QuicError, Version, decrypt_initial, is_client_initial};
use jink_core::l7::tls::parse_handshake;

struct Case {
    name: &'static str,
    data: &'static [u8],
    version: Version,
    packet_number: u32,
    host: &'static str,
    crypto_len: usize,
    crypto_frames: usize,
    packet_len: usize,
}

macro_rules! case {
    ($file:literal, $v:ident, $pn:literal, $host:literal, $clen:literal, $frames:literal, $plen:literal) => {
        Case {
            name: $file,
            data: include_bytes!(concat!("fixtures/", $file)),
            version: Version::$v,
            packet_number: $pn,
            host: $host,
            crypto_len: $clen,
            crypto_frames: $frames,
            packet_len: $plen,
        }
    };
}

const CASES: [Case; 10] = [
    // Named as Discord/game payloads, but they are QUIC Initials (Part 2).
    case!(
        "ACTIVE_DISCORD_UDP.bin",
        V1,
        0,
        "steamcommunity.com",
        260,
        1,
        1200
    ),
    case!("ACTIVE_GAME_UDP.bin", V1, 1, "4pda.to", 293, 7, 1250),
    // Chrome-style scrambling: CRYPTO split into shuffled pieces with PINGs.
    case!("quic_initial_4pda_to.bin", V1, 1, "4pda.to", 293, 7, 1250),
    case!("quic_initial_5ka_ru.bin", V1, 1, "5ka.ru", 289, 5, 1250),
    // Firefox-style: one CRYPTO frame, short packet followed by zero padding.
    case!(
        "quic_initial_lemana_pro.bin",
        V2,
        0,
        "dmp.dmpkit.lemanapro.ru",
        318,
        1,
        360
    ),
    case!(
        "quic_initial_rutube_ru.bin",
        V1,
        0,
        "rutube.ru",
        512,
        1,
        561
    ),
    case!(
        "quic_initial_steam_chat_com.bin",
        V2,
        0,
        "steam-chat.com",
        309,
        1,
        351
    ),
    case!(
        "quic_initial_steamcommunity_com.bin",
        V1,
        0,
        "steamcommunity.com",
        260,
        1,
        1200
    ),
    case!(
        "quic_initial_steamstatic_com.bin",
        V2,
        0,
        "cdn.fastly.steamstatic.com",
        321,
        1,
        370
    ),
    case!(
        "quic_initial_www_google_com.bin",
        V1,
        0,
        "www.google.com",
        273,
        1,
        1200
    ),
];

const TENCENT: &[u8] = include_bytes!("fixtures/quic_initial_tencent_com.bin");

#[test]
fn every_fixture_decrypts_to_the_expected_hello() -> Result<(), Box<dyn Error>> {
    for c in &CASES {
        assert!(is_client_initial(c.data), "{}", c.name);
        let initial = decrypt_initial(c.data).map_err(|e| format!("{}: {e}", c.name))?;
        assert_eq!(initial.version, c.version, "{}", c.name);
        assert_eq!(initial.packet_number, c.packet_number, "{}", c.name);
        assert_eq!(initial.packet_len, c.packet_len, "{}", c.name);

        let mut stream = CryptoStream::default();
        assert_eq!(
            stream.add_frames(&initial.plaintext)?,
            c.crypto_frames,
            "{}",
            c.name
        );
        assert_eq!(stream.contiguous().len(), c.crypto_len, "{}", c.name);

        let hello = parse_handshake(stream.contiguous())?;
        assert!(hello.complete, "{}", c.name);
        assert_eq!(hello.total_len, c.crypto_len, "{}", c.name);
        let host = hello.server_name.map(|s| s.host.name);
        assert_eq!(host, Some(c.host), "{}", c.name);
    }
    Ok(())
}

/// Random bytes shaped like a QUIC header: no DPI (and no parser) can read it.
#[test]
fn tencent_decoy_has_an_unknown_version() {
    assert!(!is_client_initial(TENCENT));
    assert_eq!(
        decrypt_initial(TENCENT),
        Err(QuicError::UnsupportedVersion(0xdfd2_21e2))
    );
}

#[test]
fn tampering_fails_authentication() {
    let google = CASES[9].data;
    // Flip one ciphertext byte well past the header.
    let mut tampered = google.to_vec();
    tampered[600] ^= 0x01;
    assert_eq!(decrypt_initial(&tampered), Err(QuicError::DecryptFailed));
    // A different DCID derives different keys.
    let mut other_dcid = google.to_vec();
    other_dcid[6] ^= 0x01;
    assert_eq!(decrypt_initial(&other_dcid), Err(QuicError::DecryptFailed));
}

#[test]
fn every_prefix_fails_cleanly() {
    for c in &CASES {
        for n in 0..c.packet_len {
            assert!(
                decrypt_initial(&c.data[..n]).is_err(),
                "{} prefix {n}",
                c.name
            );
        }
    }
}

#[test]
fn non_initials_are_rejected() {
    let stun: &[u8] = include_bytes!("fixtures/stun.bin");
    assert_eq!(decrypt_initial(stun), Err(QuicError::NotLongHeader));
    // Same packet relabelled as a v1 Handshake packet (type bits 10).
    let mut handshake = CASES[9].data.to_vec();
    handshake[0] = (handshake[0] & 0xcf) | 0x20;
    assert_eq!(decrypt_initial(&handshake), Err(QuicError::NotInitial));
}

/// Two-byte QUIC varint; test values stay below 2^14.
fn varint2(v: usize) -> Result<[u8; 2], String> {
    u16::try_from(v)
        .ok()
        .filter(|&v| v < 0x4000)
        .map(|v| (v | 0x4000).to_be_bytes())
        .ok_or_else(|| format!("{v} does not fit a 2-byte varint"))
}

fn crypto_frame(offset: usize, data: &[u8]) -> Result<Vec<u8>, String> {
    let mut f = vec![0x06];
    f.extend(varint2(offset)?);
    f.extend(varint2(data.len())?);
    f.extend_from_slice(data);
    Ok(f)
}

/// A post-quantum ClientHello spans two Initial packets. The stream must
/// report "incomplete" after the first and yield the SNI after the second.
#[test]
fn hello_across_two_packets() -> Result<(), Box<dyn Error>> {
    let google = decrypt_initial(CASES[9].data)?;
    let mut full = CryptoStream::default();
    full.add_frames(&google.plaintext)?;
    let hello = full.contiguous();

    let mut stream = CryptoStream::default();
    stream.add_frames(&crypto_frame(0, &hello[..100])?)?;
    let partial = parse_handshake(stream.contiguous())?;
    assert!(!partial.complete);
    assert_eq!(
        partial.total_len,
        hello.len(),
        "length known from the first packet"
    );
    assert_eq!(
        partial.server_name, None,
        "SNI lies beyond the first 100 bytes"
    );

    stream.add_frames(&crypto_frame(100, &hello[100..])?)?;
    let done = parse_handshake(stream.contiguous())?;
    assert!(done.complete);
    assert_eq!(
        done.server_name.map(|s| s.host.name),
        Some("www.google.com")
    );
    Ok(())
}

#[test]
fn overlaps_repeats_and_gaps() -> Result<(), Box<dyn Error>> {
    let mut s = CryptoStream::default();
    // Out of order with a gap: nothing readable yet.
    s.add_frames(&crypto_frame(6, b"GH")?)?;
    assert_eq!(s.contiguous(), b"");
    // Overlapping and repeated pieces (what zapret v72.12 learned to handle).
    s.add_frames(
        &[
            crypto_frame(0, b"ABCD")?,
            crypto_frame(2, b"CDEF")?,
            crypto_frame(2, b"CD")?,
        ]
        .concat(),
    )?;
    assert_eq!(s.contiguous(), b"ABCDEFGH");
    // Padding and PING around frames are fine; other frames are refused.
    assert_eq!(s.add_frames(&[0x00, 0x01, 0x00])?, 0);
    assert_eq!(
        s.add_frames(&[0x02, 0x00]),
        Err(QuicError::UnsupportedFrame(0x02))
    );
    Ok(())
}

#[test]
fn crypto_stream_is_bounded() -> Result<(), Box<dyn Error>> {
    let mut s = CryptoStream::default();
    let far = crypto_frame(0x3fff, b"x")?;
    assert_eq!(s.add_frames(&far), Ok(1), "16383 is within the 16 KiB cap");
    let mut beyond = vec![0x06, 0x80, 0x00, 0x40, 0x00, 0x01]; // offset 0x4000, len 1
    beyond.push(b'y');
    assert_eq!(s.add_frames(&beyond), Err(QuicError::CryptoTooLarge));
    Ok(())
}
