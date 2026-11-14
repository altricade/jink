//! The stream-mode engine as the macOS backend will drive it: jink owns the
//! connection, so it gets fake packets for a raw socket plus write ranges
//! (TCP), or decoy payloads (UDP).

mod common;

use std::error::Error;
use std::time::Instant;

use common::{fixtures, load_with};
use jink_core::config::platform::{Technique, Unsupported};
use jink_core::desync::Entropy;
use jink_core::engine::stream::{
    StreamEngine, StreamError, TcpConnection, TcpPlan, TcpStep, wanted_len,
};
use jink_core::packet::{IpHeader, TcpTimestamps, Transport, dissect};

type TestResult = Result<(), Box<dyn Error>>;

const SEQ: u32 = 0x5000_0000;
const ACK: u32 = 0x7000_0000;

struct Counter(u8);

impl Entropy for Counter {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf {
            *b = self.0;
            self.0 = self.0.wrapping_add(1);
        }
    }
}

fn engine(file: &str, game: &str, full_ipset: bool) -> Result<StreamEngine, Box<dyn Error>> {
    Ok(StreamEngine::new(
        load_with(file, game, full_ipset)?,
        Box::new(Counter(0)),
    )?)
}

fn fixture(name: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(std::fs::read(fixtures().join(name))?)
}

/// The Google hello renamed to `music.youtu.be` (listed in list-google.txt).
fn youtube_hello() -> Result<Vec<u8>, Box<dyn Error>> {
    let mut hello = fixture("tls_clienthello_www_google_com.bin")?;
    hello
        .get_mut(125..139)
        .ok_or("short hello")?
        .copy_from_slice(b"music.youtu.be");
    Ok(hello)
}

/// jink's own socket to a video server, as BPF would report it.
fn connection(timestamps: bool) -> Result<TcpConnection, Box<dyn Error>> {
    Ok(TcpConnection {
        local: "192.168.1.10:50123".parse()?,
        server: "142.250.74.4:443".parse()?,
        seq: SEQ,
        ack: ACK,
        window: 2048,
        ttl: 64,
        timestamps: timestamps.then_some(TcpTimestamps {
            value: 1000,
            echo_reply: 2000,
        }),
        mss: 1400,
    })
}

#[test]
fn seqovl_strategies_are_refused_up_front() -> TestResult {
    let err = StreamEngine::new(load_with("general.bat", "12", false)?, Box::new(Counter(0)))
        .err()
        .ok_or("general.bat should be refused on macOS")?;
    let StreamError::Unsupported(list) = err else {
        return Err("expected Unsupported".into());
    };
    let rules: Vec<usize> = list
        .iter()
        .map(|&Unsupported { rule, technique }| {
            assert_eq!(technique, Technique::SeqOvl);
            rule
        })
        .collect();
    assert_eq!(rules, vec![2, 3, 4, 6, 7]);
    Ok(())
}

/// ALT4 rule 4: six badseq fakes (+1000, ack -66000, IP id 0) through the
/// raw socket, then the hello written as bytes 0..2 and 2.. (default split).
#[test]
fn alt4_fakes_and_split_writes() -> TestResult {
    let mut e = engine("general (ALT4).bat", "12", false)?;
    let hello = youtube_hello()?;
    let plan = e.tcp_message(&connection(true)?, &hello, Instant::now())?;
    assert_eq!(plan.writes(), vec![0..2, 2..hello.len()]);
    assert_eq!(plan.fakes().len(), 6);
    let google = fixture("tls_clienthello_www_google_com.bin")?;
    for fake in plan.fakes() {
        let packet = dissect(fake)?;
        assert!(matches!(packet.ip, IpHeader::V4 { ttl: 64, id: 0, .. }));
        let Transport::Tcp { header, payload } = packet.transport else {
            return Err("expected TCP".into());
        };
        assert_eq!((header.src_port, header.dst_port), (50123, 443));
        assert_eq!(header.seq, SEQ + 1000);
        assert_eq!(header.ack, ACK.wrapping_sub(66_000));
        assert_eq!(payload, google.as_slice());
    }
    Ok(())
}

/// SIMPLE FAKE ALT2 rule 4: ts-fooled fakes, then the hello in one write.
/// Without timestamps on the socket, the fakes would be accepted by the
/// server, so the plan is refused.
#[test]
fn ts_fooling_needs_timestamps() -> TestResult {
    let mut e = engine("general (SIMPLE FAKE ALT2).bat", "12", false)?;
    let hello = youtube_hello()?;
    let plan = e.tcp_message(&connection(true)?, &hello, Instant::now())?;
    assert_eq!(plan.writes(), vec![0..hello.len()]);
    assert_eq!(plan.fakes().len(), 6);
    let Transport::Tcp { header, .. } = dissect(plan.fakes()[0])?.transport else {
        return Err("expected TCP".into());
    };
    let ts = header.options.timestamps.ok_or("timestamps")?;
    assert_eq!(
        (ts.value, ts.echo_reply),
        (1000_u32.wrapping_sub(600_000), 2000)
    );
    assert_eq!((header.seq, header.ack), (SEQ, ACK));

    let mut fresh = engine("general (SIMPLE FAKE ALT2).bat", "12", false)?;
    assert_eq!(
        fresh.tcp_message(&connection(false)?, &hello, Instant::now()),
        Err(StreamError::NoTimestamps)
    );
    Ok(())
}

#[test]
fn unlisted_sites_are_written_unchanged() -> TestResult {
    let mut e = engine("general (ALT4).bat", "12", false)?;
    let hello = fixture("tls_clienthello_www_sferum_ru.bin")?;
    let plan = e.tcp_message(&connection(true)?, &hello, Instant::now())?;
    assert_eq!(plan.fakes(), Vec::<&[u8]>::new());
    assert_eq!(plan.writes(), vec![0..hello.len()]);
    Ok(())
}

/// ALT4's game UDP rule (cutoff n2): decoys before the first datagram only.
#[test]
fn udp_decoys_with_cutoff() -> TestResult {
    let config = load_with("general (ALT4).bat", "1024-65535", true)?;
    let repeats = usize::from(config.rules[8].desync.repeats);
    let mut e = StreamEngine::new(config, Box::new(Counter(0)))?;
    let (local, server) = ("192.168.1.10:55555".parse()?, "8.8.8.8:27015".parse()?);
    let now = Instant::now();
    let first = e.udp_datagram(local, server, &[0x42; 50], now)?;
    let game = fixture("ACTIVE_GAME_UDP.bin")?;
    assert_eq!(first.decoys, vec![game; repeats]);
    assert_eq!(
        e.udp_datagram(local, server, &[0x42; 50], now)?.decoys,
        Vec::<Vec<u8>>::new()
    );
    Ok(())
}

/// A single-datagram QUIC hello to a listed IP (full IP list): QUIC decoys.
#[test]
fn quic_decoys() -> TestResult {
    let config = load_with("general (ALT4).bat", "12", true)?;
    let repeats = usize::from(config.rules[5].desync.repeats);
    let mut e = StreamEngine::new(config, Box::new(Counter(0)))?;
    let quic = fixture("quic_initial_www_google_com.bin")?;
    let plan = e.udp_datagram(
        "192.168.1.10:55555".parse()?,
        "142.250.74.4:443".parse()?,
        &quic,
        Instant::now(),
    )?;
    assert_eq!(plan.decoys, vec![quic.clone(); repeats]);
    // This rule has no cutoff: still, only a flow's first datagram gets
    // decoys (zapret sends fakes only before the start of a message).
    let again = e.udp_datagram(
        "192.168.1.10:55555".parse()?,
        "142.250.74.4:443".parse()?,
        &quic,
        Instant::now(),
    )?;
    assert_eq!(again.decoys, Vec::<Vec<u8>>::new());
    Ok(())
}

#[test]
fn wanted_len_reads_the_whole_hello() -> TestResult {
    let hello = youtube_hello()?;
    assert_eq!(wanted_len(&hello[..10]), Some(hello.len()));
    assert_eq!(wanted_len(b"GET / HTTP/1.1\r\n"), None);
    Ok(())
}

/// `general.bat` with `--allow-partial`: the `music.youtu.be` hello still matches its
/// seqovl rule first (not a later rule) and goes out unchanged.
#[test]
fn partial_mode_passes_unsupported_rules_unchanged() -> TestResult {
    let (mut e, unsupported) =
        StreamEngine::partial(load_with("general.bat", "12", false)?, Box::new(Counter(0)));
    let rules: Vec<usize> = unsupported.iter().map(|u| u.rule).collect();
    assert_eq!(rules, vec![2, 3, 4, 6, 7]);
    let hello = youtube_hello()?;
    let plan = e.tcp_message(&connection(true)?, &hello, Instant::now())?;
    assert_eq!(plan.fakes(), Vec::<&[u8]>::new());
    assert_eq!(plan.writes(), vec![0..hello.len()]);
    Ok(())
}

/// A configuration macOS fully supports is unchanged by partial mode.
#[test]
fn partial_mode_keeps_supported_rules() -> TestResult {
    let (mut e, unsupported) = StreamEngine::partial(
        load_with("general (ALT4).bat", "12", false)?,
        Box::new(Counter(0)),
    );
    assert_eq!(unsupported, Vec::new());
    let hello = youtube_hello()?;
    let plan = e.tcp_message(&connection(true)?, &hello, Instant::now())?;
    assert_eq!(plan.fakes().len(), 6);
    Ok(())
}

/// The plan's shape: `f` per fake, `W` per write.
fn shape(plan: &TcpPlan) -> String {
    plan.steps
        .iter()
        .map(|s| match s {
            TcpStep::Fake(_) => 'f',
            TcpStep::Write(_) => 'W',
        })
        .collect()
}

/// ALT (fake + fakedsplit, ts) on a hello sent in 400-byte pieces, as the
/// kernel would with that MSS: the first piece gets the TLS fakes and the
/// split at 2, each part between zero-filled fakes; the next piece goes
/// whole between fakes at its own sequence number.
#[test]
fn alt_fakedsplit_steps_follow_the_pieces() -> TestResult {
    let mut e = engine("general (ALT).bat", "12", false)?;
    let hello = youtube_hello()?;
    let len = hello.len();
    assert!(len > 400 && len <= 800, "one later piece");
    let conn = TcpConnection {
        mss: 400,
        ..connection(true)?
    };
    let plan = e.tcp_message(&conn, &hello, Instant::now())?;
    assert_eq!(plan.writes(), vec![0..2, 2..400, 400..len]);
    let six = "f".repeat(6);
    assert_eq!(
        shape(&plan),
        format!("{six}{six}W{six}{six}W{six}{six}W{six}")
    );
    // The fakes just before the last write shadow it: same sequence number
    // and length, zeros, ts fooled.
    let TcpStep::Fake(fake) = &plan.steps[plan.steps.len() - 8] else {
        return Err("expected a fake".into());
    };
    let Transport::Tcp { header, payload } = dissect(fake)?.transport else {
        return Err("expected TCP".into());
    };
    assert_eq!(header.seq, SEQ + 400);
    assert_eq!(payload, vec![0; len - 400].as_slice());
    let ts = header.options.timestamps.ok_or("timestamps")?;
    assert_eq!(ts.value, 1000_u32.wrapping_sub(600_000));
    Ok(())
}

/// ALT13 (hostfakesplit with host=www.google.com; partial, for its altorder
/// rules): before the host, fake host, real host, fake host, the rest.
#[test]
fn alt13_hostfakesplit_steps() -> TestResult {
    let (mut e, unsupported) = StreamEngine::partial(
        load_with("general (ALT13).bat", "12", false)?,
        Box::new(Counter(0)),
    );
    assert!(!unsupported.is_empty(), "altorder rules");
    let hello = youtube_hello()?;
    let plan = e.tcp_message(&connection(true)?, &hello, Instant::now())?;
    // music.youtu.be is at 125..139 in this hello.
    assert_eq!(plan.writes(), vec![0..125, 125..139, 139..hello.len()]);
    assert_eq!(shape(&plan), "WfWfW");
    let TcpStep::Fake(fake) = &plan.steps[1] else {
        return Err("expected a fake".into());
    };
    let Transport::Tcp { header, payload } = dissect(fake)?.transport else {
        return Err("expected TCP".into());
    };
    assert_eq!((header.seq, payload), (SEQ + 125, &b"www.google.com"[..]));
    Ok(())
}
