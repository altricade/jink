//! Importing all 22 zapret-discord-youtube strategy files: `.bat` ->
//! arguments -> typed configuration -> rule selection and platform checks.

mod common;

use std::collections::BTreeSet;
use std::error::Error;
use std::net::SocketAddr;

use common::{Bundle, fixtures, load_with};
use jink_core::config::platform::{Platform, Technique, Unsupported};
use jink_core::config::winws::{ConfigError, ErrorKind, parse};
use jink_core::config::{Config, FakeData, IpIdMode, Marker, MarkerBase, Split, TlsFake, TlsMods};
use jink_core::l7::Protocol;
use jink_core::rules::{Flow, PortFilter, Transport};

type TestResult = Result<(), Box<dyn Error>>;

fn strategy_files() -> Result<Vec<String>, Box<dyn Error>> {
    let mut names = std::fs::read_dir(fixtures().join("strategies"))?
        .map(|e| Ok(e?.file_name().to_string_lossy().into_owned()))
        .collect::<Result<Vec<_>, std::io::Error>>()?;
    names.sort();
    Ok(names)
}

fn abs(offset: i16) -> Marker {
    Marker {
        base: MarkerBase::Absolute,
        offset,
    }
}

#[test]
fn all_22_strategies_load() -> TestResult {
    let files = strategy_files()?;
    assert_eq!(files.len(), 22);
    for file in &files {
        for game in ["12", "1024-65535"] {
            let config = load_with(file, game, false).map_err(|e| format!("{file}: {e}"))?;
            let expected_rules = if file == "general (ALT5).bat" { 6 } else { 9 };
            assert_eq!(config.rules.len(), expected_rules, "{file}");
            assert_eq!(config.warnings, Vec::<String>::new(), "{file}");
            assert!(
                config.capture.tcp.is_some() && config.capture.udp.is_some(),
                "{file}"
            );
        }
    }
    Ok(())
}

#[test]
fn general_bat_rule_5_is_seqovl_multisplit() -> TestResult {
    let config = load_with("general.bat", "12", false)?;
    let d = &config.rules[4].desync;
    assert_eq!(d.modes.split, Some(Split::MultiSplit));
    assert!(!d.modes.fake && !d.modes.syndata);
    assert_eq!(d.seqovl, Some(abs(568)));
    assert_eq!(d.split_positions, vec![abs(1)]);
    let pattern = std::fs::read(fixtures().join("tls_clienthello_4pda_to.bin"))?;
    assert_eq!(d.seqovl_pattern.as_deref(), Some(pattern.as_slice()));
    assert_eq!(d.repeats, 1);
    assert_eq!(d.ip_id, IpIdMode::Seq);
    // Rule 4 (Google) is the same technique with ip-id=zero and a 681-byte overlap.
    let google = &config.rules[3].desync;
    assert_eq!(
        (google.seqovl, google.ip_id),
        (Some(abs(681)), IpIdMode::Zero)
    );
    Ok(())
}

#[test]
fn general_bat_filters_and_capture() -> TestResult {
    let config = load_with("general.bat", "12", false)?;
    let tcp = config.capture.tcp.as_ref().ok_or("no --wf-tcp")?;
    for port in [80, 443, 2053, 8443, 12] {
        assert!(tcp.contains(port), "--wf-tcp should include {port}");
    }
    assert!(!tcp.contains(22));
    // Rule 2 is UDP only (--filter-udp given, --filter-tcp not).
    let voice = &config.rules[1].matcher;
    assert_eq!(voice.tcp_ports, PortFilter::deny_all());
    assert!(voice.udp_ports.contains(50_000));
    Ok(())
}

#[test]
fn parsed_rules_pick_like_the_hand_built_ones() -> TestResult {
    let config = load_with("general.bat", "12", false)?;
    let pick = |transport, dst: &str, l7, host| -> Result<Option<usize>, Box<dyn Error>> {
        let flow = Flow {
            transport,
            dst: dst.parse::<SocketAddr>()?,
            l7,
            hostname: host,
        };
        Ok(config
            .rules
            .iter()
            .position(|r| r.matcher.matches(&flow))
            .and_then(|i| i.checked_add(1)))
    };
    let tcp443 = "142.250.74.4:443";
    assert_eq!(
        pick(
            Transport::Tcp,
            tcp443,
            Protocol::Tls,
            Some("www.youtube.com")
        )?,
        Some(4)
    );
    assert_eq!(
        pick(Transport::Tcp, tcp443, Protocol::Tls, Some("discord.com"))?,
        Some(5)
    );
    assert_eq!(pick(Transport::Tcp, tcp443, Protocol::Tls, None)?, None);
    // The user-list placeholder is in both list-general-user.txt and
    // list-exclude-user.txt, so exclusion wins and it never matches.
    assert_eq!(
        pick(
            Transport::Tcp,
            tcp443,
            Protocol::Tls,
            Some("domain.example.abc")
        )?,
        None
    );
    assert_eq!(
        pick(Transport::Udp, "66.22.200.1:50005", Protocol::Discord, None)?,
        Some(2)
    );
    assert_eq!(
        pick(Transport::Udp, tcp443, Protocol::Quic, Some("discord.com"))?,
        Some(1)
    );
    Ok(())
}

/// `--dpi-desync-fake-tls-mod` applies to the fake just before it: the
/// `0x00000000` fake keeps no mods, the built-in one (`!`) gets them.
#[test]
fn fake_tls_mods_attach_like_zapret() -> TestResult {
    let config = load_with("general (FAKE TLS AUTO).bat", "12", false)?;
    let d = &config.rules[4].desync;
    assert!(d.modes.fake && d.modes.split == Some(Split::MultiDisorder));
    let google_mods = TlsMods {
        rnd: true,
        rnd_sni: false,
        dup_sid: true,
        sni: Some("www.google.com".into()),
    };
    assert_eq!(
        d.fakes.tls,
        vec![
            TlsFake {
                data: FakeData::Bytes(vec![0, 0, 0, 0].into()),
                mods: TlsMods::default(),
            },
            TlsFake {
                data: FakeData::Builtin,
                mods: google_mods,
            },
        ]
    );
    let midsld = Marker {
        base: MarkerBase::MidSld,
        offset: 0,
    };
    assert_eq!(d.split_positions, vec![abs(1), midsld]);
    Ok(())
}

#[test]
fn rules_without_fakes_get_builtin_defaults() -> TestResult {
    let config = load_with("general.bat", "12", false)?;
    let d = &config.rules[4].desync;
    assert_eq!(d.fakes.http, vec![FakeData::Builtin]);
    assert_eq!(d.fakes.tls.len(), 1);
    let builtin = &d.fakes.tls[0];
    assert_eq!(builtin.data, FakeData::Builtin);
    assert!(builtin.mods.rnd && builtin.mods.rnd_sni && builtin.mods.dup_sid);
    Ok(())
}

/// Strategies macOS design B runs fully. Part 5 predicted five; fakedsplit
/// and hostfakesplit turned out to fit too (fakes between jink's own writes,
/// at the sequence numbers those writes will use), which adds ALT, ALT9,
/// FAKE TLS AUTO ALT and SIMPLE FAKE. ALT3 and ALT13 still need
/// `hostfakesplit` with `altorder=1` (real segments out of order) in some
/// rules.
#[test]
fn platform_support() -> TestResult {
    let mut macos_ok = BTreeSet::new();
    for file in strategy_files()? {
        let config = load_with(&file, "12", false)?;
        assert_eq!(Platform::Windows.unsupported(&config), vec![], "{file}");
        if Platform::MacOs.unsupported(&config).is_empty() {
            macos_ok.insert(file);
        }
    }
    let expected: BTreeSet<String> = [
        "general (ALT).bat",
        "general (ALT4).bat",
        "general (ALT8).bat",
        "general (ALT9).bat",
        "general (ALT10).bat",
        "general (FAKE TLS AUTO ALT).bat",
        "general (SIMPLE FAKE).bat",
        "general (SIMPLE FAKE ALT).bat",
        "general (SIMPLE FAKE ALT2).bat",
    ]
    .map(String::from)
    .into();
    assert_eq!(macos_ok, expected);

    let general = load_with("general.bat", "12", false)?;
    let seqovl_rules: Vec<usize> = Platform::MacOs
        .unsupported(&general)
        .into_iter()
        .map(|Unsupported { rule, technique }| {
            assert_eq!(technique, Technique::SeqOvl);
            rule
        })
        .collect();
    assert_eq!(seqovl_rules, vec![2, 3, 4, 6, 7]);
    Ok(())
}

fn parse_args(args: &[&str]) -> Result<Config, ConfigError> {
    let args: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
    parse(&args, &Bundle)
}

#[test]
fn rejections_name_the_argument() {
    let err = |args: &[&str]| parse_args(args).err().map(|e| (e.index, e.kind));
    assert_eq!(
        err(&["--filter-tcp=443", "--dpi-desync-ttl=5"]),
        Some((1, ErrorKind::UnknownOption))
    );
    assert_eq!(err(&["filter-tcp=443"]), Some((0, ErrorKind::NotAnOption)));
    assert!(matches!(
        err(&["--dpi-desync=rst"]),
        Some((0, ErrorKind::Unsupported(_)))
    ));
    assert!(matches!(
        err(&[
            "--dpi-desync=multisplit",
            "--dpi-desync-split-seqovl=midsld"
        ]),
        Some((1, ErrorKind::BadValue(_)))
    ));
    assert!(matches!(
        err(&["--hostlist=lists/missing.txt"]),
        Some((0, ErrorKind::File { .. }))
    ));
    assert!(matches!(
        err(&["--dpi-desync-fooling=badsum"]),
        Some((0, ErrorKind::Unsupported(_)))
    ));
    assert!(matches!(
        err(&["--filter-l7=dht"]),
        Some((0, ErrorKind::Unsupported(_)))
    ));
}

#[test]
fn filter_defaults() -> TestResult {
    let both = parse_args(&["--dpi-desync=fake"])?;
    assert_eq!(both.rules[0].matcher.tcp_ports, PortFilter::Any);
    assert_eq!(both.rules[0].matcher.udp_ports, PortFilter::Any);
    let tcp_only = parse_args(&["--filter-tcp=443", "--new", "--filter-udp=443"])?;
    assert_eq!(tcp_only.rules[0].matcher.udp_ports, PortFilter::deny_all());
    assert_eq!(tcp_only.rules[1].matcher.tcp_ports, PortFilter::deny_all());
    let v4 = parse_args(&["--filter-l3=ipv4"])?;
    assert!(v4.rules[0].matcher.ipv4 && !v4.rules[0].matcher.ipv6);
    Ok(())
}
