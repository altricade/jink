//! Golden wire tests: real strategy rules applied to a realistic original
//! packet, checking every forged packet field by field. Expected values are
//! derived from zapret v72.9's code paths (Part 4 tables), and checksums are
//! verified with an independent RFC 1071 implementation.

mod common;

use std::error::Error;

use common::{fixtures, load_with};
use jink_core::config::{Config, Desync, Marker, MarkerBase};
use jink_core::desync::{
    Entropy, Message, Plan, PlanError, Positions, Verdict, plan, unimplemented,
};
use jink_core::l7::Protocol;
use jink_core::l7::tls::parse_record;
use jink_core::packet::{Dissected, IpHeader, TcpHeader, Transport, dissect};

type TestResult = Result<(), Box<dyn Error>>;

const SEQ: u32 = 0x1000_0000;
const ACK: u32 = 0x2000_0000;
const IP_ID: u16 = 0x1234;
const TS_VAL: u32 = 111;
const TS_ECR: u32 = 222;

/// Deterministic "randomness": 0, 1, 2, ...
struct Counter(u8);

impl Entropy for Counter {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf {
            *b = self.0;
            self.0 = self.0.wrapping_add(1);
        }
    }
}

fn fixture(name: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(std::fs::read(fixtures().join(name))?)
}

// ---- independent checksum verification (RFC 1071) ----

/// RFC 1071 sum, carries folded as it goes (stays within 16 bits).
fn ones_complement_sum(bytes: &[u8]) -> u16 {
    let sum = bytes.chunks(2).fold(0_u32, |acc, chunk| {
        let word = match *chunk {
            [hi, lo] => u16::from_be_bytes([hi, lo]),
            [hi] => u16::from_be_bytes([hi, 0]),
            _ => 0,
        };
        let s = acc.wrapping_add(u32::from(word));
        (s & 0xffff).wrapping_add(s >> 16)
    });
    u16::try_from(sum).unwrap_or(0)
}

/// Every checksum in an IPv4/IPv6 TCP/UDP packet verifies.
fn checksums_valid(pkt: &[u8]) -> Result<bool, Box<dyn Error>> {
    let first = *pkt.first().ok_or("empty packet")?;
    let short = || "packet too short";
    let (pseudo, l4) = if first >> 4 == 4 {
        let ihl = usize::from(first & 0x0f).checked_mul(4).ok_or("bad IHL")?;
        if ones_complement_sum(pkt.get(..ihl).ok_or_else(short)?) != 0xffff {
            return Ok(false);
        }
        let l4 = pkt.get(ihl..).ok_or_else(short)?;
        let addrs = pkt.get(12..20).ok_or_else(short)?;
        let proto = *pkt.get(9).ok_or_else(short)?;
        let len = u16::try_from(l4.len())?.to_be_bytes();
        ([addrs, &[0, proto], &len].concat(), l4)
    } else {
        let l4 = pkt.get(40..).ok_or_else(short)?;
        let addrs = pkt.get(8..40).ok_or_else(short)?;
        let next = *pkt.get(6).ok_or_else(short)?;
        let len = u32::try_from(l4.len())?.to_be_bytes();
        ([addrs, &len, &[0, 0, 0, next]].concat(), l4)
    };
    Ok(ones_complement_sum(&[pseudo.as_slice(), l4].concat()) == 0xffff)
}

// ---- original packets ----

/// TCP ACK|PSH from 192.168.1.10:50123 to 162.159.128.233:443, TTL 128,
/// IP id 0x1234, DF, NOP NOP TS(111,222), carrying `payload`.
fn tcp_original(payload: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut tcp = etherparse::TcpHeader::new(50123, 443, SEQ, 512);
    tcp.acknowledgment_number = ACK;
    tcp.ack = true;
    tcp.psh = true;
    tcp.set_options(&[
        etherparse::TcpOptionElement::Noop,
        etherparse::TcpOptionElement::Noop,
        etherparse::TcpOptionElement::Timestamp(TS_VAL, TS_ECR),
    ])?;
    let len = u16::try_from(
        tcp.header_len()
            .checked_add(payload.len())
            .ok_or("too long")?,
    )?;
    let mut ip = etherparse::Ipv4Header::new(
        len,
        128,
        etherparse::IpNumber::TCP,
        [192, 168, 1, 10],
        [162, 159, 128, 233],
    )?;
    ip.identification = IP_ID;
    ip.dont_fragment = true;
    tcp.checksum = tcp.calc_checksum_ipv4(&ip, payload)?;
    let mut out = Vec::new();
    ip.write(&mut out)?;
    tcp.write(&mut out)?;
    out.extend_from_slice(payload);
    Ok(out)
}

/// UDP from 192.168.1.10:55555 to 142.250.74.4:443, TTL 128, IP id 0x1234.
fn udp_original_v4(payload: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let len = u16::try_from(
        etherparse::UdpHeader::LEN
            .checked_add(payload.len())
            .ok_or("too long")?,
    )?;
    let mut ip = etherparse::Ipv4Header::new(
        len,
        128,
        etherparse::IpNumber::UDP,
        [192, 168, 1, 10],
        [142, 250, 74, 4],
    )?;
    ip.identification = IP_ID;
    let udp = etherparse::UdpHeader::with_ipv4_checksum(55555, 443, &ip, payload)?;
    let mut out = Vec::new();
    ip.write(&mut out)?;
    udp.write(&mut out)?;
    out.extend_from_slice(payload);
    Ok(out)
}

// ---- running the planner ----

fn tls_positions(payload: &[u8]) -> Result<Positions, Box<dyn Error>> {
    Ok(Positions::from_tls(&parse_record(payload)?))
}

fn run(
    desync: &Desync,
    original: &[u8],
    protocol: Protocol,
    message: &[u8],
    offset: usize,
    positions: &Positions,
) -> Result<Plan, PlanError> {
    let packet = dissect(original).map_err(|_| PlanError::BadMessage)?;
    let msg = Message {
        protocol,
        data: message,
        offset,
        positions,
    };
    plan(desync, &packet, &msg, &mut Counter(0))
}

struct TcpOut {
    ttl: u8,
    id: u16,
    header: TcpHeader,
    payload: Vec<u8>,
}

fn tcp_out(pkt: &[u8]) -> Result<TcpOut, Box<dyn Error>> {
    assert!(checksums_valid(pkt)?, "bad checksum");
    let Dissected { ip, transport } = dissect(pkt)?;
    let IpHeader::V4 {
        ttl,
        id,
        dont_fragment,
        ..
    } = ip
    else {
        return Err("expected IPv4".into());
    };
    assert!(dont_fragment, "DF copied from the original");
    let Transport::Tcp { header, payload } = transport else {
        return Err("expected TCP".into());
    };
    Ok(TcpOut {
        ttl,
        id,
        header,
        payload: payload.to_vec(),
    })
}

/// Rule by its 1-based number in the strategy file.
fn rule(config: &Config, number: usize) -> Result<&Desync, Box<dyn Error>> {
    let index = number.checked_sub(1).ok_or("rules are numbered from 1")?;
    Ok(&config.rules.get(index).ok_or("no such rule")?.desync)
}

// ---- golden cases ----

/// general.bat rule 5: multisplit at 1 with a 568-byte overlap of the 4pda
/// hello (284 bytes, repeated twice). Part 4: `seq=S-568: [4pda x2][byte 0]`
/// then `seq=S+1: [bytes 1..]`, original dropped.
#[test]
fn general_rule5_seqovl_multisplit() -> TestResult {
    let config = load_with("general.bat", "12", false)?;
    let real = fixture("tls_clienthello_www_sferum_ru.bin")?;
    let pattern = fixture("tls_clienthello_4pda_to.bin")?;
    let original = tcp_original(&real)?;
    let plan = run(
        rule(&config, 5)?,
        &original,
        Protocol::Tls,
        &real,
        0,
        &tls_positions(&real)?,
    )?;

    assert_eq!(plan.original, Verdict::Drop);
    assert_eq!(plan.send.len(), 2);
    let first = tcp_out(&plan.send[0])?;
    assert_eq!(first.header.seq, SEQ.wrapping_sub(568));
    assert_eq!(
        first.payload,
        [&pattern[..], &pattern[..], &real[..1]].concat()
    );
    assert_eq!((first.ttl, first.id), (128, IP_ID));
    let second = tcp_out(&plan.send[1])?;
    assert_eq!(second.header.seq, SEQ + 1);
    assert_eq!(second.payload, &real[1..]);
    assert_eq!(second.id, IP_ID + 1);
    for seg in [&first, &second] {
        assert_eq!(seg.header.ack, ACK);
        assert_eq!(seg.header.flags.bits(), 0x18, "ACK|PSH copied");
        assert_eq!(seg.header.window, 512);
        let ts = seg.header.options.timestamps.ok_or("timestamps copied")?;
        assert_eq!((ts.value, ts.echo_reply), (TS_VAL, TS_ECR), "not fooled");
    }
    Ok(())
}

/// general.bat rule 4: same technique, 681-byte overlap = the whole Google
/// hello, and `--ip-id=zero`.
#[test]
fn general_rule4_google_overlap_and_ip_id_zero() -> TestResult {
    let config = load_with("general.bat", "12", false)?;
    let real = fixture("tls_clienthello_www_sferum_ru.bin")?;
    let google = fixture("tls_clienthello_www_google_com.bin")?;
    let original = tcp_original(&real)?;
    let plan = run(
        rule(&config, 4)?,
        &original,
        Protocol::Tls,
        &real,
        0,
        &tls_positions(&real)?,
    )?;
    let first = tcp_out(&plan.send[0])?;
    assert_eq!(first.header.seq, SEQ.wrapping_sub(681));
    assert_eq!(first.payload, [&google[..], &real[..1]].concat());
    // What a DPI reading this segment from its start sees: a complete,
    // valid ClientHello for www.google.com.
    let seen = parse_record(&first.payload)?;
    assert_eq!(
        seen.server_name.map(|s| s.host.name),
        Some("www.google.com")
    );
    assert_eq!(first.id, 0);
    assert_eq!(tcp_out(&plan.send[1])?.id, 0);
    Ok(())
}

/// SIMPLE FAKE ALT2 rule 5: fakes stun2.bin then the sferum hello, 6 times
/// each, same sequence as the original, timestamp moved back by 600000.
/// The original then goes out unchanged.
#[test]
fn simple_fake_alt2_ts_fooling() -> TestResult {
    let config = load_with("general (SIMPLE FAKE ALT2).bat", "12", false)?;
    let real = fixture("tls_clienthello_www_google_com.bin")?;
    let original = tcp_original(&real)?;
    let plan = run(
        rule(&config, 5)?,
        &original,
        Protocol::Tls,
        &real,
        0,
        &tls_positions(&real)?,
    )?;
    assert_eq!(plan.original, Verdict::Pass);
    assert_eq!(plan.send.len(), 12);
    let stun2 = fixture("stun2.bin")?;
    let sferum = fixture("tls_clienthello_www_sferum_ru.bin")?;
    for (i, pkt) in plan.send.iter().enumerate() {
        let out = tcp_out(pkt)?;
        let (payload, id) = if i < 6 {
            (&stun2, IP_ID)
        } else {
            (&sferum, IP_ID + 1)
        };
        assert_eq!(&out.payload, payload, "fake {i}");
        assert_eq!(out.id, id, "ip id advances per fake, not per repeat");
        assert_eq!((out.header.seq, out.header.ack), (SEQ, ACK));
        let ts = out.header.options.timestamps.ok_or("timestamps")?;
        assert_eq!(ts.value, TS_VAL.wrapping_sub(600_000));
        assert_eq!(ts.echo_reply, TS_ECR);
    }
    // All repeats of one fake are identical packets.
    assert!(plan.send[..6].windows(2).all(|w| w[0] == w[1]));
    Ok(())
}

/// SIMPLE FAKE ALT rule 5: badseq with increment 2; ack moves by the
/// default -66000.
#[test]
fn simple_fake_alt_badseq() -> TestResult {
    let config = load_with("general (SIMPLE FAKE ALT).bat", "12", false)?;
    let real = fixture("tls_clienthello_www_sferum_ru.bin")?;
    let original = tcp_original(&real)?;
    let plan = run(
        rule(&config, 5)?,
        &original,
        Protocol::Tls,
        &real,
        0,
        &tls_positions(&real)?,
    )?;
    assert_eq!(plan.original, Verdict::Pass);
    for pkt in &plan.send {
        let out = tcp_out(pkt)?;
        assert_eq!(out.header.seq, SEQ + 2);
        assert_eq!(out.header.ack, ACK.wrapping_sub(66_000));
        let ts = out.header.options.timestamps.ok_or("timestamps")?;
        assert_eq!(ts.value, TS_VAL, "no ts fooling");
    }
    Ok(())
}

/// ALT4 rule 5: badseq fakes (+1000), then multisplit at the default
/// position 2 without overlap; IP ids continue across both phases.
#[test]
fn alt4_fake_then_multisplit() -> TestResult {
    let config = load_with("general (ALT4).bat", "12", false)?;
    let real = fixture("tls_clienthello_www_google_com.bin")?;
    let original = tcp_original(&real)?;
    let plan = run(
        rule(&config, 5)?,
        &original,
        Protocol::Tls,
        &real,
        0,
        &tls_positions(&real)?,
    )?;
    assert_eq!(plan.original, Verdict::Drop);
    assert_eq!(plan.send.len(), 6 + 6 + 2);
    let fake = tcp_out(&plan.send[0])?;
    assert_eq!(fake.header.seq, SEQ + 1000);
    let seg1 = tcp_out(&plan.send[12])?;
    let seg2 = tcp_out(&plan.send[13])?;
    assert_eq!(
        (seg1.header.seq, seg1.payload.as_slice()),
        (SEQ, &real[..2])
    );
    assert_eq!(
        (seg2.header.seq, seg2.payload.as_slice()),
        (SEQ + 2, &real[2..])
    );
    assert_eq!((seg1.id, seg2.id), (IP_ID + 2, IP_ID + 3));
    assert_eq!(seg1.header.ack, ACK, "real segments are not fooled");
    Ok(())
}

/// ALT7 rule 5 (`split-pos=2,sniext+1`, seqovl 679) on a hello that arrives
/// in two TCP segments: positions resolve on the whole message, the overlap
/// applies only to the first segment.
#[test]
fn alt7_split_hello_across_two_segments() -> TestResult {
    let config = load_with("general (ALT7).bat", "12", false)?;
    let desync = rule(&config, 5)?;
    let real = fixture("tls_clienthello_www_sferum_ru.bin")?;
    let positions = tls_positions(&real)?;
    assert_eq!(positions.sni_ext, Some(120));
    let google = fixture("tls_clienthello_www_google_com.bin")?;

    // Segment 1: bytes 0..100 at SEQ.
    let first = run(
        desync,
        &tcp_original(&real[..100])?,
        Protocol::Tls,
        &real,
        0,
        &positions,
    )?;
    assert_eq!(first.send.len(), 2);
    let first_head = tcp_out(&first.send[0])?;
    assert_eq!(first_head.header.seq, SEQ.wrapping_sub(679));
    assert_eq!(first_head.payload, [&google[..679], &real[..2]].concat());
    let first_tail = tcp_out(&first.send[1])?;
    assert_eq!(
        (first_tail.header.seq, first_tail.payload.as_slice()),
        (SEQ + 2, &real[2..100])
    );

    // Segment 2: bytes 100.. (its original sequence number is SEQ for this
    // test packet, as built). sniext+1 = 121 lands at 21 inside it.
    let second = run(
        desync,
        &tcp_original(&real[100..])?,
        Protocol::Tls,
        &real,
        100,
        &positions,
    )?;
    assert_eq!(second.send.len(), 2);
    let second_head = tcp_out(&second.send[0])?;
    assert_eq!(
        (second_head.header.seq, second_head.payload.as_slice()),
        (SEQ, &real[100..121])
    );
    let second_tail = tcp_out(&second.send[1])?;
    assert_eq!(
        (second_tail.header.seq, second_tail.payload.as_slice()),
        (SEQ + 21, &real[121..])
    );
    Ok(())
}

/// general.bat rule 5 on the second segment: split position 1 is not in it,
/// so it goes out unchanged and nothing is forged.
#[test]
fn second_segment_without_split_point_passes() -> TestResult {
    let config = load_with("general.bat", "12", false)?;
    let real = fixture("tls_clienthello_www_sferum_ru.bin")?;
    let positions = tls_positions(&real)?;
    let plan = run(
        rule(&config, 5)?,
        &tcp_original(&real[600..])?,
        Protocol::Tls,
        &real,
        600,
        &positions,
    )?;
    assert_eq!(
        plan,
        Plan {
            send: vec![],
            original: Verdict::Pass,
            real: vec![]
        }
    );
    Ok(())
}

/// general.bat rule 1: QUIC fake 6 times, then the original.
#[test]
fn general_rule1_quic_fake() -> TestResult {
    let config = load_with("general.bat", "12", false)?;
    let real = fixture("quic_initial_www_google_com.bin")?;
    let original = udp_original_v4(&real)?;
    let plan = run(
        rule(&config, 1)?,
        &original,
        Protocol::Quic,
        &real,
        0,
        &Positions::default(),
    )?;
    assert_eq!(plan.original, Verdict::Pass);
    assert_eq!(plan.send.len(), 6);
    for pkt in &plan.send {
        assert!(checksums_valid(pkt)?);
        let Dissected { ip, transport } = dissect(pkt)?;
        assert!(matches!(
            ip,
            IpHeader::V4 {
                ttl: 128,
                id: IP_ID,
                ..
            }
        ));
        let Transport::Udp { header, payload } = transport else {
            return Err("expected UDP".into());
        };
        assert_eq!((header.src_port, header.dst_port), (55555, 443));
        assert_eq!(
            payload,
            real.as_slice(),
            "the fake happens to be this same file"
        );
    }
    Ok(())
}

/// general.bat rule 2: a Discord voice packet gets the "Discord" fake,
/// which is really a QUIC Initial for steamcommunity.com (Part 2).
#[test]
fn general_rule2_discord_fake() -> TestResult {
    let config = load_with("general.bat", "12", false)?;
    let mut voice = vec![0x00, 0x01, 0x00, 0x46, 0x12, 0x34, 0x56, 0x78];
    voice.resize(74, 0);
    let plan = run(
        rule(&config, 2)?,
        &udp_original_v4(&voice)?,
        Protocol::Discord,
        &voice,
        0,
        &Positions::default(),
    )?;
    let fake = fixture("ACTIVE_DISCORD_UDP.bin")?;
    assert_eq!(plan.send.len(), 6);
    let Transport::Udp { payload, .. } = dissect(&plan.send[0])?.transport else {
        return Err("expected UDP".into());
    };
    assert_eq!(payload, fake.as_slice());
    Ok(())
}

#[test]
fn ipv6_udp_fake_keeps_flow_label_and_checksums() -> TestResult {
    let config = load_with("general.bat", "12", false)?;
    let real = fixture("quic_initial_www_google_com.bin")?;
    let src: std::net::Ipv6Addr = "2001:db8::10".parse()?;
    let dst: std::net::Ipv6Addr = "2a00:1450:4001::64".parse()?;
    let builder = etherparse::PacketBuilder::ipv6(src.octets(), dst.octets(), 61).udp(55555, 443);
    let mut original = Vec::new();
    builder.write(&mut original, &real)?;
    original[1] |= 0x0a; // flow label 0xa0000 (top nibble of byte 1 is traffic class)
    let plan = run(
        rule(&config, 1)?,
        &original,
        Protocol::Quic,
        &real,
        0,
        &Positions::default(),
    )?;
    for pkt in &plan.send {
        assert!(checksums_valid(pkt)?);
        let IpHeader::V6 {
            hop_limit,
            flow_label,
            ..
        } = dissect(pkt)?.ip
        else {
            return Err("expected IPv6".into());
        };
        assert_eq!((hop_limit, flow_label), (61, 0xa_0000));
    }
    Ok(())
}

#[test]
fn passes_without_desync() -> TestResult {
    let config = load_with("general.bat", "12", false)?;
    let real = fixture("tls_clienthello_www_sferum_ru.bin")?;
    let original = tcp_original(&real)?;
    // Unknown protocol on a rule without any-protocol.
    let plan = run(
        rule(&config, 5)?,
        &original,
        Protocol::Unknown,
        &real,
        0,
        &Positions::default(),
    )?;
    assert_eq!(plan.original, Verdict::Pass);
    assert_eq!(plan.send, Vec::<Vec<u8>>::new());
    // TLS without SNI is skipped (zapret desync_skip_nosni).
    let plan = run(
        rule(&config, 5)?,
        &original,
        Protocol::Tls,
        &real,
        0,
        &Positions::default(),
    )?;
    assert_eq!(plan.send, Vec::<Vec<u8>>::new());
    Ok(())
}

/// ALT rule 4 (`fake,fakedsplit`, ts fooling, 6 repeats, `--ip-id=zero`):
/// six TLS fakes, then for each part of the split at 2 (zapret's default
/// position): six zero-filled fooled fakes of the part's length and
/// sequence number, the real part, six more. The original is dropped.
#[test]
fn alt_rule4_fake_then_fakedsplit() -> TestResult {
    let config = load_with("general (ALT).bat", "12", false)?;
    let real = fixture("tls_clienthello_www_google_com.bin")?;
    let len = real.len();
    let original = tcp_original(&real)?;
    let positions = tls_positions(&real)?;
    let plan = run(
        rule(&config, 4)?,
        &original,
        Protocol::Tls,
        &real,
        0,
        &positions,
    )?;
    assert_eq!(plan.original, Verdict::Drop);
    assert_eq!(plan.send.len(), 6 + 6 + 1 + 6 + 6 + 1 + 6);
    assert_eq!(plan.real, vec![(12, 0..2), (25, 2..len)]);
    let fooled_ts = TS_VAL.wrapping_sub(600_000);
    // (first index, count, seq, payload, fooled)
    let expected: [(usize, usize, u32, Vec<u8>, bool); 7] = [
        (0, 6, SEQ, real.clone(), true),
        (6, 6, SEQ, vec![0; 2], true),
        (12, 1, SEQ, real[..2].to_vec(), false),
        (13, 6, SEQ, vec![0; 2], true),
        (19, 6, SEQ + 2, vec![0; len - 2], true),
        (25, 1, SEQ + 2, real[2..].to_vec(), false),
        (26, 6, SEQ + 2, vec![0; len - 2], true),
    ];
    for (first, count, seq, payload, fooled) in expected {
        for pkt in &plan.send[first..first + count] {
            let out = tcp_out(pkt)?;
            assert_eq!((out.ttl, out.id), (128, 0), "packet {first}");
            assert_eq!(
                (out.header.seq, out.header.ack),
                (seq, ACK),
                "packet {first}"
            );
            assert_eq!(out.payload, payload, "packet {first}");
            let ts = out.header.options.timestamps.ok_or("timestamps kept")?;
            let want = if fooled { fooled_ts } else { TS_VAL };
            assert_eq!((ts.value, ts.echo_reply), (want, TS_ECR), "packet {first}");
        }
    }
    Ok(())
}

/// ALT13 rule 4 (`hostfakesplit`, `host=www.google.com`, ts fooling, no
/// repeats): the part before the SNI host, a fooled segment with a fake host
/// of the same length at the host's sequence number, the real host, another
/// fake, the rest. `www.sferum.ru` (13 bytes) gets the template's last 13
/// bytes. IP ids continue from the original's, one per packet.
#[test]
fn alt13_rule4_hostfakesplit() -> TestResult {
    let config = load_with("general (ALT13).bat", "12", false)?;
    let real = fixture("tls_clienthello_www_sferum_ru.bin")?;
    let len = real.len();
    let original = tcp_original(&real)?;
    let positions = tls_positions(&real)?;
    let host = positions.host.clone().ok_or("SNI host")?;
    assert_eq!(&real[host.clone()], b"www.sferum.ru");
    let (start, end) = (host.start, host.end);
    let plan = run(
        rule(&config, 4)?,
        &original,
        Protocol::Tls,
        &real,
        0,
        &positions,
    )?;
    assert_eq!(plan.original, Verdict::Drop);
    assert_eq!(plan.send.len(), 5);
    assert_eq!(
        plan.real,
        vec![(0, 0..start), (2, start..end), (4, end..len)]
    );
    let at = |n: usize| SEQ + u32::try_from(n).unwrap_or(0);
    let expected: [(usize, usize, u32, Vec<u8>, bool, u16); 5] = [
        (0, 1, SEQ, real[..start].to_vec(), false, IP_ID),
        (1, 1, at(start), b"ww.google.com".to_vec(), true, IP_ID + 1),
        (2, 1, at(start), real[host].to_vec(), false, IP_ID + 2),
        (3, 1, at(start), b"ww.google.com".to_vec(), true, IP_ID + 3),
        (4, 1, at(end), real[end..].to_vec(), false, IP_ID + 4),
    ];
    for (first, count, seq, payload, fooled, id) in expected {
        for pkt in &plan.send[first..first + count] {
            let out = tcp_out(pkt)?;
            assert_eq!(
                (out.id, out.header.seq, out.header.ack),
                (id, seq, ACK),
                "packet {first}"
            );
            assert_eq!(out.payload, payload, "packet {first}");
            let ts = out.header.options.timestamps.ok_or("timestamps kept")?;
            let want = if fooled {
                TS_VAL.wrapping_sub(600_000)
            } else {
                TS_VAL
            };
            assert_eq!(ts.value, want, "packet {first}");
        }
    }
    Ok(())
}

/// A later packet of a split hello (the split position falls outside it):
/// `fakedsplit` sends it whole between fakes; `hostfakesplit` passes it.
#[test]
fn later_packets_of_fakedsplit_and_hostfakesplit() -> TestResult {
    let real = fixture("tls_clienthello_www_google_com.bin")?;
    let positions = tls_positions(&real)?;
    let tail = &real[300..];
    let original = tcp_original(tail)?;
    let alt = load_with("general (ALT).bat", "12", false)?;
    let plan = run(
        rule(&alt, 4)?,
        &original,
        Protocol::Tls,
        &real,
        300,
        &positions,
    )?;
    assert_eq!(plan.send.len(), 6 + 1 + 6);
    assert_eq!(plan.real, vec![(6, 0..tail.len())]);
    assert_eq!(tcp_out(&plan.send[0])?.payload, vec![0; tail.len()]);
    assert_eq!(tcp_out(&plan.send[6])?.payload, tail);
    let alt13 = load_with("general (ALT13).bat", "12", false)?;
    let plan = run(
        rule(&alt13, 4)?,
        &original,
        Protocol::Tls,
        &real,
        300,
        &positions,
    )?;
    assert_eq!((plan.send.len(), plan.original), (0, Verdict::Pass));
    Ok(())
}

/// zapret's fakedsplit position: the first relative marker that resolves
/// (before any absolute one), else position 1.
#[test]
fn fakedsplit_position_choice() -> TestResult {
    let config = load_with("general (ALT).bat", "12", false)?;
    let mut d = rule(&config, 4)?.clone();
    let request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let original = tcp_original(request)?;
    let reals = |plan: &Plan| -> Vec<std::ops::Range<usize>> {
        plan.real.iter().map(|(_, r)| r.clone()).collect()
    };
    let host = Marker {
        base: MarkerBase::Host,
        offset: 0,
    };
    d.split_positions = vec![
        Marker {
            base: MarkerBase::Absolute,
            offset: 5,
        },
        host,
    ];
    let with_host = Positions {
        host: Some(22..33),
        ..Positions::default()
    };
    let plan = run(&d, &original, Protocol::Http, request, 0, &with_host)?;
    assert_eq!(reals(&plan), vec![0..22, 22..request.len()]);
    d.split_positions = vec![host];
    let plan = run(
        &d,
        &original,
        Protocol::Http,
        request,
        0,
        &Positions::default(),
    )?;
    assert_eq!(reals(&plan), vec![0..1, 1..request.len()]);
    Ok(())
}

#[test]
fn unimplemented_techniques_are_explicit() -> TestResult {
    let real = fixture("tls_clienthello_www_sferum_ru.bin")?;
    let original = tcp_original(&real)?;
    let positions = tls_positions(&real)?;
    let try_rule = |file: &str| -> Result<PlanError, Box<dyn Error>> {
        let config = load_with(file, "12", false)?;
        run(
            rule(&config, 5)?,
            &original,
            Protocol::Tls,
            &real,
            0,
            &positions,
        )
        .err()
        .ok_or_else(|| format!("{file} should not be plannable yet").into())
    };
    // ALT8's TLS fake is the built-in one with fake-tls-mod=none.
    assert_eq!(try_rule("general (ALT8).bat")?, PlanError::BuiltinTlsFake);
    assert_eq!(
        try_rule("general (FAKE TLS AUTO ALT3).bat")?,
        PlanError::Unimplemented("fake-tls-mod")
    );
    Ok(())
}

#[test]
fn md5sig_option_is_inserted_before_timestamps() -> TestResult {
    let args: Vec<String> = [
        "--dpi-desync=fake",
        "--dpi-desync-fooling=md5sig",
        "--dpi-desync-fake-tls=0x160301",
    ]
    .map(String::from)
    .to_vec();
    let config = jink_core::config::winws::parse(&args, &common::Bundle)?;
    let real = fixture("tls_clienthello_www_sferum_ru.bin")?;
    let plan = run(
        rule(&config, 1)?,
        &tcp_original(&real)?,
        Protocol::Tls,
        &real,
        0,
        &tls_positions(&real)?,
    )?;
    let pkt = &plan.send[0];
    assert!(checksums_valid(pkt)?);
    // IPv4 header 20 bytes, TCP fixed header 20: options start at 40.
    let opts = &pkt[40..40 + 28];
    assert_eq!(&opts[..2], &[19, 18]);
    assert_eq!(
        &opts[2..18],
        &(0..16).collect::<Vec<u8>>()[..],
        "signature from entropy"
    );
    assert_eq!(&opts[18..20], &[8, 10], "timestamps follow");
    assert_eq!(&pkt[40 + 28..], &[0x16, 0x03, 0x01]);
    Ok(())
}

/// The static check agrees with what planning does, for every strategy:
/// a rule plans a TLS hello (a data packet) without error exactly when
/// nothing it uses is listed as unimplemented, `syndata` aside, since that
/// only acts on SYN packets.
#[test]
fn unimplemented_matches_planning_for_all_strategies() -> TestResult {
    let real = fixture("tls_clienthello_www_sferum_ru.bin")?;
    let original = tcp_original(&real)?;
    let positions = tls_positions(&real)?;
    let mut runnable = Vec::new();
    for entry in std::fs::read_dir(fixtures().join("strategies"))? {
        let name = entry?.file_name().to_string_lossy().into_owned();
        let config = load_with(&name, "12", false)?;
        let mut all_ok = true;
        for (i, r) in config.rules.iter().enumerate() {
            let missing = unimplemented(r);
            if r.matcher.tcp_ports == jink_core::rules::PortFilter::deny_all() {
                assert_eq!(
                    missing,
                    Vec::<&str>::new(),
                    "{name} rule {}: UDP-only",
                    i + 1
                );
                continue;
            }
            let missing_on_data: Vec<_> = missing.iter().filter(|m| **m != "syndata").collect();
            let planned = run(&r.desync, &original, Protocol::Tls, &real, 0, &positions);
            assert_eq!(
                missing_on_data.is_empty(),
                planned.is_ok(),
                "{name} rule {}: {missing:?} vs {planned:?}",
                i + 1
            );
            all_ok &= missing.is_empty();
        }
        if all_ok {
            runnable.push(name);
        }
    }
    runnable.sort();
    assert_eq!(
        runnable,
        [
            "general (ALT).bat",
            "general (ALT10).bat",
            "general (ALT11).bat",
            "general (ALT12).bat",
            "general (ALT13).bat",
            "general (ALT2).bat",
            "general (ALT4).bat",
            "general (ALT6).bat",
            "general (ALT9).bat",
            "general (SIMPLE FAKE ALT).bat",
            "general (SIMPLE FAKE ALT2).bat",
            "general (SIMPLE FAKE).bat",
            "general.bat",
        ]
    );
    Ok(())
}
