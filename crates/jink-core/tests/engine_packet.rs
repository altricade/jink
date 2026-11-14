//! The packet-mode engine driven as the Windows backend will drive it:
//! one captured packet at a time, with real strategy rules.

mod common;
#[path = "common/quic.rs"]
mod quic;

use std::error::Error;
use std::time::{Duration, Instant};

use common::{fixtures, load_with};
use jink_core::desync::{Entropy, Verdict};
use jink_core::engine::{Direction, Outgoing, Output, PacketEngine};
use jink_core::l7::quic::{CryptoStream, decrypt_initial};
use jink_core::packet::{Transport, dissect};
use quic::{crypto_frame, seal_initial};

type TestResult = Result<(), Box<dyn Error>>;

const CLIENT: [u8; 4] = [192, 168, 1, 10];
const GOOGLE: [u8; 4] = [142, 250, 74, 4];
const SEQ: u32 = 0x1000_0000;

struct Counter(u8);

impl Entropy for Counter {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf {
            *b = self.0;
            self.0 = self.0.wrapping_add(1);
        }
    }
}

fn engine(file: &str, game: &str, full_ipset: bool) -> Result<PacketEngine, Box<dyn Error>> {
    Ok(PacketEngine::new(
        load_with(file, game, full_ipset)?,
        Box::new(Counter(0)),
    ))
}

fn fixture(name: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(std::fs::read(fixtures().join(name))?)
}

/// The Google ClientHello with its SNI changed to `music.youtu.be`: same
/// length, so every offset stays, and listed (via `youtu.be`) in
/// list-google.txt. `www.google.com` itself is in none of the lists.
fn youtube_hello() -> Result<Vec<u8>, Box<dyn Error>> {
    let mut hello = fixture("tls_clienthello_www_google_com.bin")?;
    let host = hello.get_mut(125..139).ok_or("short hello")?;
    assert_eq!(host, b"www.google.com");
    host.copy_from_slice(b"music.youtu.be");
    Ok(hello)
}

#[derive(Clone, Copy)]
enum Kind {
    Syn,
    Data,
    Rst,
}

/// A TCP packet between 192.168.1.10:50123 and `server`:443.
fn tcp(
    kind: Kind,
    server: [u8; 4],
    seq: u32,
    payload: &[u8],
    inbound: bool,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let (src, dst, sport, dport) = if inbound {
        (server, CLIENT, 443, 50123)
    } else {
        (CLIENT, server, 50123, 443)
    };
    let mut h = etherparse::TcpHeader::new(sport, dport, seq, 512);
    match kind {
        Kind::Syn => h.syn = true,
        Kind::Data => {
            h.ack = true;
            h.psh = true;
            h.acknowledgment_number = 1;
        }
        Kind::Rst => h.rst = true,
    }
    let len = u16::try_from(h.header_len().checked_add(payload.len()).ok_or("long")?)?;
    let mut ip = etherparse::Ipv4Header::new(len, 128, etherparse::IpNumber::TCP, src, dst)?;
    ip.identification = 0x1234;
    h.checksum = h.calc_checksum_ipv4(&ip, payload)?;
    let mut out = Vec::new();
    ip.write(&mut out)?;
    h.write(&mut out)?;
    out.extend_from_slice(payload);
    Ok(out)
}

fn udp(server: [u8; 4], dport: u16, payload: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let builder = etherparse::PacketBuilder::ipv4(CLIENT, server, 128).udp(55555, dport);
    let mut out = Vec::new();
    builder.write(&mut out, payload)?;
    Ok(out)
}

/// Sequence number (0 for UDP) and payload of each packet to send.
type Sent = Vec<(u32, Vec<u8>)>;

fn out_payloads(out: &Output) -> Result<Sent, Box<dyn Error>> {
    out.send
        .iter()
        .map(|p| match dissect(p)?.transport {
            Transport::Tcp { header, payload } => Ok((header.seq, payload.to_vec())),
            Transport::Udp { payload, .. } => Ok((0, payload.to_vec())),
        })
        .collect()
}

/// The flow's rule is found once the ClientHello names the site; later
/// packets of the flow (application data) are not desynced.
#[test]
fn tls_flow_gets_its_rule_from_the_sni() -> TestResult {
    let mut e = engine("general.bat", "12", false)?;
    let now = Instant::now();
    let hello = youtube_hello()?;
    let syn = e.process(
        &tcp(Kind::Syn, GOOGLE, SEQ.wrapping_sub(1), &[], false)?,
        Direction::Outbound,
        0,
        now,
    );
    assert_eq!((syn.send.len(), syn.original), (0, Verdict::Pass));

    let first = e.process(
        &tcp(Kind::Data, GOOGLE, SEQ, &hello, false)?,
        Direction::Outbound,
        0,
        now,
    );
    assert_eq!(
        first.original,
        Verdict::Drop,
        "rule 4 (Google): seqovl multisplit"
    );
    let segs = out_payloads(&first)?;
    assert_eq!(segs.len(), 2);
    assert_eq!(segs.first().map(|s| s.0), Some(SEQ.wrapping_sub(681)));

    let app_data = [0x17, 0x03, 0x03, 0x00, 0x01, 0x00];
    let later = e.process(
        &tcp(Kind::Data, GOOGLE, SEQ.wrapping_add(681), &app_data, false)?,
        Direction::Outbound,
        0,
        now,
    );
    assert_eq!((later.send.len(), later.original), (0, Verdict::Pass));
    Ok(())
}

/// A hello in two segments is held, then both are replayed: the first
/// desynced on the whole hello, the second re-sent unchanged.
#[test]
fn split_hello_is_reassembled_then_replayed() -> TestResult {
    let mut e = engine("general.bat", "12", false)?;
    let now = Instant::now();
    let hello = youtube_hello()?;
    let (head, tail) = hello.split_at(100);
    e.process(
        &tcp(Kind::Syn, GOOGLE, SEQ.wrapping_sub(1), &[], false)?,
        Direction::Outbound,
        0,
        now,
    );

    let first = e.process(
        &tcp(Kind::Data, GOOGLE, SEQ, head, false)?,
        Direction::Outbound,
        0,
        now,
    );
    assert_eq!(
        (first.send.len(), first.original),
        (0, Verdict::Drop),
        "held"
    );

    let second_pkt = tcp(Kind::Data, GOOGLE, SEQ.wrapping_add(100), tail, false)?;
    let second = e.process(&second_pkt, Direction::Outbound, 0, now);
    assert_eq!(second.original, Verdict::Drop);
    let google = fixture("tls_clienthello_www_google_com.bin")?;
    let segs = out_payloads(&second)?;
    assert_eq!(segs.len(), 3);
    assert_eq!(
        segs.first(),
        Some(&(SEQ.wrapping_sub(681), [&google[..], &hello[..1]].concat()))
    );
    assert_eq!(
        segs.get(1),
        Some(&(SEQ.wrapping_add(1), hello[1..100].to_vec()))
    );
    assert_eq!(
        second.send.get(2),
        Some(&second_pkt),
        "second segment re-sent as is"
    );
    assert!(e.flows().get(&flow_key(GOOGLE)).is_some());
    Ok(())
}

fn flow_key(server: [u8; 4]) -> jink_core::engine::FlowKey {
    jink_core::engine::FlowKey {
        transport: jink_core::rules::Transport::Tcp,
        client: (CLIENT, 50123).into(),
        server: (server, 443).into(),
    }
}

/// An unexpected sequence number ends the hold: held packets go out (the
/// partial hello has no SNI yet, so unchanged), then the new packet is
/// handled on its own.
#[test]
fn out_of_order_segment_releases_the_hold() -> TestResult {
    let mut e = engine("general.bat", "12", false)?;
    let now = Instant::now();
    let hello = youtube_hello()?;
    e.process(
        &tcp(Kind::Syn, GOOGLE, SEQ.wrapping_sub(1), &[], false)?,
        Direction::Outbound,
        0,
        now,
    );
    let head_pkt = tcp(Kind::Data, GOOGLE, SEQ, &hello[..100], false)?;
    e.process(&head_pkt, Direction::Outbound, 0, now);
    let gap = e.process(
        &tcp(
            Kind::Data,
            GOOGLE,
            SEQ.wrapping_add(500),
            &hello[500..],
            false,
        )?,
        Direction::Outbound,
        0,
        now,
    );
    assert_eq!(gap.send, vec![head_pkt]);
    assert_eq!(gap.original, Verdict::Pass);
    Ok(())
}

#[test]
fn holds_expire() -> TestResult {
    let mut e = engine("general.bat", "12", false)?;
    let now = Instant::now();
    let hello = youtube_hello()?;
    e.process(
        &tcp(Kind::Syn, GOOGLE, SEQ.wrapping_sub(1), &[], false)?,
        Direction::Outbound,
        0,
        now,
    );
    let head_pkt = tcp(Kind::Data, GOOGLE, SEQ, &hello[..100], false)?;
    let tag = 7;
    e.process(&head_pkt, Direction::Outbound, tag, now);
    assert_eq!(
        e.expire_holds(now + Duration::from_millis(100)).packets,
        vec![]
    );
    assert_eq!(
        e.expire_holds(now + Duration::from_millis(600)).packets,
        vec![Outgoing {
            tag,
            bytes: head_pkt
        }],
        "released with the tag it was captured with"
    );
    assert_eq!(e.expire_holds(now + Duration::from_secs(5)).packets, vec![]);
    Ok(())
}

/// A flow first searched without a host name (an expired, partial hold)
/// is searched again once a retransmitted hello names the site.
#[test]
fn rule_is_searched_again_when_the_host_appears_later() -> TestResult {
    let mut e = engine("general.bat", "12", false)?;
    let now = Instant::now();
    let hello = youtube_hello()?;
    e.process(
        &tcp(Kind::Syn, GOOGLE, SEQ.wrapping_sub(1), &[], false)?,
        Direction::Outbound,
        0,
        now,
    );
    e.process(
        &tcp(Kind::Data, GOOGLE, SEQ, &hello[..100], false)?,
        Direction::Outbound,
        0,
        now,
    );
    let later = now + Duration::from_secs(1);
    // Released without an SNI: no rule matches, sent unchanged.
    assert_eq!(e.expire_holds(later).packets.len(), 1);
    // The client retransmits the whole hello.
    let retransmit = e.process(
        &tcp(Kind::Data, GOOGLE, SEQ, &hello, false)?,
        Direction::Outbound,
        0,
        later,
    );
    assert_eq!(
        retransmit.original,
        Verdict::Drop,
        "rule 4 found on the second search"
    );
    assert_eq!(retransmit.send.len(), 2);
    Ok(())
}

/// Connections opened before the engine started are not tracked: complete
/// hellos are still desynced, split ones are not held (as in zapret).
#[test]
fn untracked_connections_are_handled_per_packet() -> TestResult {
    let mut e = engine("general.bat", "12", false)?;
    let now = Instant::now();
    let hello = youtube_hello()?;
    let whole = e.process(
        &tcp(Kind::Data, GOOGLE, SEQ, &hello, false)?,
        Direction::Outbound,
        0,
        now,
    );
    assert_eq!((whole.send.len(), whole.original), (2, Verdict::Drop));
    let part = e.process(
        &tcp(Kind::Data, GOOGLE, SEQ, &hello[..100], false)?,
        Direction::Outbound,
        0,
        now,
    );
    assert_eq!((part.send.len(), part.original), (0, Verdict::Pass));
    assert!(e.flows().is_empty());
    Ok(())
}

/// Game UDP rule (`cutoff=n2`, 12 repeats): only the first datagram of a
/// flow gets fakes.
#[test]
fn cutoff_limits_desync_to_the_first_packets() -> TestResult {
    let mut e = engine("general.bat", "1024-65535", true)?;
    let now = Instant::now();
    let game = udp([8, 8, 8, 8], 27015, &[0x42; 50])?;
    let first = e.process(&game, Direction::Outbound, 0, now);
    assert_eq!((first.send.len(), first.original), (12, Verdict::Pass));
    let fake = fixture("ACTIVE_GAME_UDP.bin")?;
    assert_eq!(
        out_payloads(&first)?.first().map(|p| p.1.clone()),
        Some(fake)
    );
    let second = e.process(&game, Direction::Outbound, 0, now);
    assert_eq!((second.send.len(), second.original), (0, Verdict::Pass));
    Ok(())
}

/// As shipped, the IP-list rules never apply: the only address in
/// `ipset-all.txt` is also in `ipset-exclude-user.txt`.
#[test]
fn shipped_ip_list_placeholder_is_excluded_too() -> TestResult {
    let mut e = engine("general.bat", "1024-65535", false)?;
    let out = e.process(
        &udp([203, 0, 113, 113], 27015, &[0x42; 50])?,
        Direction::Outbound,
        0,
        Instant::now(),
    );
    assert_eq!((out.send.len(), out.original), (0, Verdict::Pass));
    Ok(())
}

#[test]
fn closed_flows_are_purged() -> TestResult {
    let mut e = engine("general.bat", "12", false)?;
    let now = Instant::now();
    e.process(
        &tcp(Kind::Syn, GOOGLE, SEQ, &[], false)?,
        Direction::Outbound,
        0,
        now,
    );
    e.process(
        &tcp(Kind::Rst, GOOGLE, 1, &[], true)?,
        Direction::Inbound,
        0,
        now,
    );
    assert_eq!(e.flows().len(), 1);
    // Any later packet triggers the sweep; closing flows last 60 s.
    e.process(
        &udp([1, 1, 1, 1], 9999, b"x")?,
        Direction::Outbound,
        0,
        now + Duration::from_secs(70),
    );
    assert!(e.flows().get(&flow_key(GOOGLE)).is_none());
    Ok(())
}

// ---- QUIC: a ClientHello spread over two Initial datagrams ----

#[test]
fn sealed_initial_round_trips() -> TestResult {
    let sealed = seal_initial(&[1, 2, 3, 4, 5, 6, 7, 8], 0, &crypto_frame(0, b"hello")?)?;
    let opened = decrypt_initial(&sealed)?;
    let frame = crypto_frame(0, b"hello")?;
    assert_eq!(opened.plaintext.get(..frame.len()), Some(&frame[..]));
    Ok(())
}

/// Chrome's post-quantum hello needs two Initial datagrams. The first is
/// held; when the second makes the SNI readable, the first gets the QUIC
/// fakes (general.bat rule 6 with the full IP list) and both go out.
#[test]
fn quic_hello_across_two_datagrams() -> TestResult {
    let google_quic = fixture("quic_initial_www_google_com.bin")?;
    let mut stream = CryptoStream::default();
    stream.add_frames(&decrypt_initial(&google_quic)?.plaintext)?;
    let hello = stream.contiguous().to_vec();
    let dcid = [9, 8, 7, 6, 5, 4, 3, 2];
    let d1 = udp(
        GOOGLE,
        443,
        &seal_initial(&dcid, 0, &crypto_frame(0, &hello[..100])?)?,
    )?;
    let d2 = udp(
        GOOGLE,
        443,
        &seal_initial(&dcid, 1, &crypto_frame(100, &hello[100..])?)?,
    )?;

    let mut e = engine("general.bat", "12", true)?;
    let now = Instant::now();
    let first = e.process(&d1, Direction::Outbound, 0, now);
    assert_eq!(
        (first.send.len(), first.original),
        (0, Verdict::Drop),
        "held"
    );
    let second = e.process(&d2, Direction::Outbound, 0, now);
    assert_eq!(second.original, Verdict::Drop);
    assert_eq!(second.send.len(), 6 + 2);
    let fakes = out_payloads(&second)?;
    assert!(fakes.iter().take(6).all(|(_, p)| *p == google_quic));
    assert_eq!(second.send.get(6), Some(&d1));
    assert_eq!(
        second.send.get(7),
        Some(&d2),
        "no fakes before later datagrams"
    );
    Ok(())
}

/// Once a flow's QUIC hello has gone out, a later Initial with no CRYPTO
/// data (here a PING probe; a retransmitted later piece of the hello is
/// alike) goes out at once instead of being held as the start of another
/// hello. (Whether fakes precede it follows the rule, as for any
/// datagram.)
#[test]
fn quic_initials_after_the_hello_are_not_held() -> TestResult {
    let google_quic = fixture("quic_initial_www_google_com.bin")?;
    let mut e = engine("general.bat", "12", true)?;
    let now = Instant::now();
    let hello = e.process(
        &udp(GOOGLE, 443, &google_quic)?,
        Direction::Outbound,
        0,
        now,
    );
    assert_eq!(hello.original, Verdict::Pass, "fakes, then the hello");
    let ping = seal_initial(&[1, 2, 3, 4, 5, 6, 7, 8], 1, &[0x01])?;
    let later = e.process(&udp(GOOGLE, 443, &ping)?, Direction::Outbound, 0, now);
    assert_eq!(later.original, Verdict::Pass, "sent now, not held");
    Ok(())
}

#[test]
fn non_ip_and_untouched_traffic_pass() -> TestResult {
    let mut e = engine("general.bat", "12", false)?;
    let now = Instant::now();
    assert_eq!(
        e.process(&[0x00; 20], Direction::Outbound, 0, now).original,
        Verdict::Pass
    );
    let ssh = udp([1, 1, 1, 1], 22, b"not quic")?;
    assert_eq!(
        e.process(&ssh, Direction::Outbound, 0, now).send,
        Vec::<Vec<u8>>::new()
    );
    Ok(())
}
