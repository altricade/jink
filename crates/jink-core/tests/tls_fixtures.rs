//! TLS ClientHello parsing against the real decoy payloads shipped by
//! zapret-discord-youtube. Expected offsets come from an independent Python
//! parse of the same files, not from this implementation.

use std::error::Error;

use jink_core::l7::tls::{ClientHello, ServerName, TlsError, parse_handshake, parse_record};

struct Case {
    name: &'static str,
    data: &'static [u8],
    host: &'static str,
    record_len: usize,
    sniext: usize,
    host_range: (usize, usize),
    sld_range: (usize, usize),
}

macro_rules! case {
    ($file:literal, $host:literal, $rec:literal, $ext:literal, $h0:literal, $h1:literal, $s0:literal, $s1:literal) => {
        Case {
            name: $file,
            data: include_bytes!(concat!("fixtures/", $file)),
            host: $host,
            record_len: $rec,
            sniext: $ext,
            host_range: ($h0, $h1),
            sld_range: ($s0, $s1),
        }
    };
}

const CASES: [Case; 10] = [
    case!(
        "tls_clienthello_4pda_to.bin",
        "4pda.to",
        284,
        126,
        131,
        138,
        131,
        135
    ),
    case!(
        "tls_clienthello_5ka_ru.bin",
        "5ka.ru",
        654,
        120,
        125,
        131,
        125,
        128
    ),
    case!(
        "tls_clienthello_awswaf_com.bin",
        "0692f8bdd7b5.edge.sdk.awswaf.com",
        1100,
        120,
        125,
        157,
        147,
        153
    ),
    // File name says max.ru but the hello carries onetrust (found in Part 2).
    case!(
        "tls_clienthello_max_ru.bin",
        "www.onetrust.com",
        664,
        120,
        125,
        141,
        129,
        137
    ),
    case!(
        "tls_clienthello_sochi_park.bin",
        "staging-sochi-park.predict.mail.ru",
        244,
        122,
        127,
        161,
        154,
        158
    ),
    case!(
        "tls_clienthello_steam_chat_com.bin",
        "steam-chat.com",
        1100,
        120,
        125,
        139,
        125,
        135
    ),
    case!(
        "tls_clienthello_steamstatic_com.bin",
        "cdn.fastly.steamstatic.com",
        1100,
        120,
        125,
        151,
        136,
        147
    ),
    case!(
        "tls_clienthello_teamspeak_com.bin",
        "www.teamspeak.com",
        1100,
        120,
        125,
        142,
        129,
        138
    ),
    case!(
        "tls_clienthello_www_google_com.bin",
        "www.google.com",
        681,
        120,
        125,
        139,
        129,
        135
    ),
    case!(
        "tls_clienthello_www_sferum_ru.bin",
        "www.sferum.ru",
        661,
        120,
        125,
        138,
        129,
        135
    ),
];

fn parse_full(c: &Case) -> Result<ClientHello<'static>, String> {
    parse_record(c.data).map_err(|e| format!("{}: {e}", c.name))
}

fn full_sni(c: &Case) -> Result<ServerName<'static>, String> {
    parse_full(c)?
        .server_name
        .ok_or_else(|| format!("{}: no SNI", c.name))
}

#[test]
fn every_fixture_matches_the_independent_oracle() -> Result<(), Box<dyn Error>> {
    for c in &CASES {
        let rec = parse_full(c)?;
        assert_eq!(rec.total_len, c.record_len, "{}", c.name);
        assert_eq!(
            rec.total_len,
            c.data.len(),
            "{}: fixture is exactly one record",
            c.name
        );
        assert!(rec.complete, "{}", c.name);
        let sni = rec
            .server_name
            .ok_or_else(|| format!("{}: no SNI", c.name))?;
        assert_eq!(sni.host.name, c.host, "{}", c.name);
        assert_eq!(sni.ext_data_offset, c.sniext, "{}", c.name);
        assert_eq!(
            (sni.host.range.start, sni.host.range.end),
            c.host_range,
            "{}",
            c.name
        );
        let sld = sni
            .host
            .sld_range
            .ok_or_else(|| format!("{}: no sld", c.name))?;
        assert_eq!((sld.start, sld.end), c.sld_range, "{}", c.name);
        // The host bytes really are at host_range in the raw payload.
        assert_eq!(
            &c.data[sni.host.range.clone()],
            c.host.as_bytes(),
            "{}",
            c.name
        );
    }
    Ok(())
}

#[test]
fn mid_sld_follows_zapret() -> Result<(), Box<dyn Error>> {
    // www.google.com: sld "google" at 129..135, midsld = 129 + 6/2.
    assert_eq!(full_sni(&CASES[8])?.host.mid_sld(), Some(132));
    // 4pda.to: sld "4pda" at 131..135, midsld = 131 + 4/2.
    assert_eq!(full_sni(&CASES[0])?.host.mid_sld(), Some(133));
    Ok(())
}

/// A hello split across TCP segments: every prefix must parse without panic,
/// report the same record length, and expose the SNI as soon as its bytes
/// have arrived, identical to the full parse.
#[test]
fn every_prefix_is_safe_and_consistent() -> Result<(), Box<dyn Error>> {
    for c in &CASES {
        let full = full_sni(c)?;
        for n in 0..=c.data.len() {
            let prefix = &c.data[..n];
            match parse_record(prefix) {
                Ok(rec) => {
                    assert_eq!(rec.total_len, c.record_len, "{} prefix {n}", c.name);
                    assert_eq!(rec.complete, n >= c.record_len, "{} prefix {n}", c.name);
                    match &rec.server_name {
                        Some(sni) => assert_eq!(sni, &full, "{} prefix {n}", c.name),
                        None => assert!(
                            n < full.host.range.end,
                            "{} prefix {n}: SNI should be visible",
                            c.name
                        ),
                    }
                }
                Err(TlsError::NotClientHello) => assert!(n < 6, "{} prefix {n}", c.name),
                Err(TlsError::TruncatedBeforeExtensions) => {
                    assert!(n < full.ext_data_offset, "{} prefix {n}", c.name);
                }
            }
        }
    }
    Ok(())
}

#[test]
fn bytes_after_the_record_are_ignored() -> Result<(), Box<dyn Error>> {
    let c = &CASES[8];
    let mut data = c.data.to_vec();
    data.extend_from_slice(&[0x17, 0x03, 0x03, 0x00, 0x10, 0xff]);
    let rec = parse_record(&data)?;
    assert!(rec.complete);
    assert_eq!(rec.total_len, c.record_len);
    assert_eq!(rec.server_name.map(|s| s.host.name), Some(c.host));
    Ok(())
}

#[test]
fn non_hellos_are_rejected() {
    let quic: &[u8] = include_bytes!("fixtures/quic_initial_www_google_com.bin");
    let stun: &[u8] = include_bytes!("fixtures/stun.bin");
    let http = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    // ServerHello (handshake type 2) is a TLS record but not a ClientHello.
    let server_hello = [0x16, 0x03, 0x03, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00];
    for input in [quic, stun, http.as_slice(), server_hello.as_slice(), &[]] {
        assert_eq!(parse_record(input), Err(TlsError::NotClientHello));
    }
}

#[test]
fn non_ascii_sni_is_not_reported() -> Result<(), Box<dyn Error>> {
    let c = &CASES[8];
    let mut data = c.data.to_vec();
    data[c.host_range.0] = 0xC3; // first host byte becomes non-ASCII
    assert_eq!(parse_record(&data)?.server_name, None);
    Ok(())
}

/// The same hello without its 5-byte record header is a bare handshake (as in
/// QUIC CRYPTO): identical SNI, offsets shifted by 5.
#[test]
fn bare_handshake_matches_record() -> Result<(), Box<dyn Error>> {
    for c in &CASES {
        let rec = full_sni(c)?;
        let hs = parse_handshake(&c.data[5..])?;
        assert!(hs.complete, "{}", c.name);
        assert_eq!(hs.total_len, c.record_len - 5, "{}", c.name);
        let sni = hs
            .server_name
            .ok_or_else(|| format!("{}: no SNI", c.name))?;
        assert_eq!(sni.host.name, rec.host.name, "{}", c.name);
        assert_eq!(sni.ext_data_offset + 5, rec.ext_data_offset, "{}", c.name);
        assert_eq!(sni.host.range.start + 5, rec.host.range.start, "{}", c.name);
    }
    assert_eq!(
        parse_handshake(&[0x01, 0, 0, 0]),
        Err(TlsError::NotClientHello),
        "empty body"
    );
    assert_eq!(
        parse_handshake(&[0x02, 0, 0, 4]),
        Err(TlsError::NotClientHello),
        "ServerHello"
    );
    Ok(())
}
