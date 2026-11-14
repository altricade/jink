//! Rule selection with `general.bat`'s nine rules, built from the bundle's real
//! list files. Expected IP-list membership was computed independently with
//! Python's `ipaddress` module.

use std::collections::HashSet;
use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;

use jink_core::l7::Protocol;
use jink_core::lists::{DomainList, IpList};
use jink_core::rules::{
    Flow, ListSet, Match, PortFilter, PortFilterError, Transport, first_match, normalize_host,
};

type TestResult = Result<(), Box<dyn Error>>;

const LIST_GENERAL: &str = include_str!("fixtures/lists/list-general.txt");
const LIST_GOOGLE: &str = include_str!("fixtures/lists/list-google.txt");
const LIST_EXCLUDE: &str = include_str!("fixtures/lists/list-exclude.txt");
const IPSET_EXCLUDE: &str = include_str!("fixtures/lists/ipset-exclude.txt");
/// What ships as `ipset-all.txt`: one documentation address.
const IPSET_PLACEHOLDER: &str = include_str!("fixtures/lists/ipset-all.txt");
/// What `service.bat` swaps in when the IP list is enabled.
const IPSET_FULL: &str = include_str!("fixtures/lists/ipset-all-full.txt");

/// `%GameFilterTCP%` / `%GameFilterUDP%` when the game filter is off.
const GAME_OFF: &str = "12";
const GAME_ON: &str = "1024-65535";

fn ip_list(text: &str) -> Arc<IpList> {
    let (list, invalid) = IpList::parse(text);
    assert_eq!(invalid, vec![], "fixture lists parse cleanly");
    Arc::new(list)
}

/// `--filter-tcp` alone denies UDP, and vice versa (zapret).
fn tcp(spec: &str) -> Result<(PortFilter, PortFilter), PortFilterError> {
    Ok((PortFilter::parse(spec)?, PortFilter::deny_all()))
}
fn udp(spec: &str) -> Result<(PortFilter, PortFilter), PortFilterError> {
    Ok((PortFilter::deny_all(), PortFilter::parse(spec)?))
}

fn rule((tcp_ports, udp_ports): (PortFilter, PortFilter)) -> Match {
    Match {
        tcp_ports,
        udp_ports,
        ..Match::default()
    }
}

/// The nine `--new` sections of `general.bat`, in order.
fn general_bat(ipset_all: &str, game: &str) -> Result<Vec<Match>, PortFilterError> {
    let general = Arc::new(DomainList::parse(LIST_GENERAL));
    let google = Arc::new(DomainList::parse(LIST_GOOGLE));
    let exclude = Arc::new(DomainList::parse(LIST_EXCLUDE));
    let ip_exclude = ip_list(IPSET_EXCLUDE);
    let ip_all = ip_list(ipset_all);
    let hosts = |include: &[&Arc<DomainList>], exclude: &[&Arc<DomainList>]| ListSet {
        include: include.iter().map(|l| Arc::clone(l)).collect(),
        exclude: exclude.iter().map(|l| Arc::clone(l)).collect(),
    };
    let ips = |include: Option<&Arc<IpList>>| ListSet {
        include: include.into_iter().map(Arc::clone).collect(),
        exclude: vec![Arc::clone(&ip_exclude)],
    };
    Ok(vec![
        // 1. QUIC to general-list domains
        Match {
            hostlists: hosts(&[&general], &[&exclude]),
            ipsets: ips(None),
            ..rule(udp("443")?)
        },
        // 2. Discord voice / STUN
        Match {
            l7: Some(HashSet::from([Protocol::Discord, Protocol::Stun])),
            ..rule(udp("19294-19344,50000-50100")?)
        },
        // 3. discord.media on Cloudflare alt ports
        Match {
            hostlists: ListSet {
                include: vec![Arc::new(DomainList::from_entries(["discord.media"]))],
                exclude: vec![],
            },
            ..rule(tcp("2053,2083,2087,2096,8443")?)
        },
        // 4. Google/YouTube
        Match {
            hostlists: hosts(&[&google], &[]),
            ..rule(tcp("443")?)
        },
        // 5. general-list domains over TCP
        Match {
            hostlists: hosts(&[&general], &[&exclude]),
            ipsets: ips(None),
            ..rule(tcp("80,443")?)
        },
        // 6. QUIC by IP list
        Match {
            hostlists: hosts(&[], &[&exclude]),
            ipsets: ips(Some(&ip_all)),
            ..rule(udp("443")?)
        },
        // 7. TCP by IP list
        Match {
            hostlists: hosts(&[], &[&exclude]),
            ipsets: ips(Some(&ip_all)),
            ..rule(tcp("80,443,8443")?)
        },
        // 8. game TCP by IP list
        Match {
            ipsets: ips(Some(&ip_all)),
            ..rule(tcp(game)?)
        },
        // 9. game UDP by IP list
        Match {
            ipsets: ips(Some(&ip_all)),
            ..rule(udp(game)?)
        },
    ])
}

fn flow<'a>(
    transport: Transport,
    dst: &str,
    l7: Protocol,
    hostname: Option<&'a str>,
) -> Result<Flow<'a>, std::net::AddrParseError> {
    Ok(Flow {
        transport,
        dst: dst.parse::<SocketAddr>()?,
        l7,
        hostname,
    })
}

/// Rule number as written in general.bat (1-based), or `None`.
fn pick(rules: &[Match], f: &Flow<'_>) -> Option<usize> {
    first_match(rules, f).and_then(|i| i.checked_add(1))
}

#[test]
fn list_files_load() {
    assert_eq!(DomainList::parse(LIST_GENERAL).len(), 59);
    assert_eq!(DomainList::parse(LIST_GOOGLE).len(), 22);
    assert_eq!(ip_list(IPSET_FULL).len(), 33_336);
    assert_eq!(ip_list(IPSET_PLACEHOLDER).len(), 1);
    assert_eq!(ip_list(IPSET_EXCLUDE).len(), 11);
}

#[test]
fn full_ip_list_membership_matches_python() -> TestResult {
    let list = ip_list(IPSET_FULL);
    for (addr, expected) in [
        ("1.1.1.1", true),
        ("8.8.8.8", true),
        ("142.250.74.4", true),
        ("104.16.1.1", true),
        ("162.159.128.233", true),
        ("2606:4700::1111", true),
        ("10.0.0.5", false),
        ("203.0.113.113", false),
        ("2001:db8::1", false),
    ] {
        assert_eq!(list.contains(addr.parse()?), expected, "{addr}");
    }
    Ok(())
}

#[test]
fn tls_flows_pick_rules_once_the_name_is_known() -> TestResult {
    let rules = general_bat(IPSET_PLACEHOLDER, GAME_OFF)?;
    let dst = "142.250.74.4:443";
    // Before the ClientHello is read, every TCP/443 rule needs a host name.
    assert_eq!(
        pick(&rules, &flow(Transport::Tcp, dst, Protocol::Unknown, None)?),
        None
    );

    let tls = |host: &'static str| flow(Transport::Tcp, dst, Protocol::Tls, Some(host));
    assert_eq!(pick(&rules, &tls("rr3---sn-abc.googlevideo.com")?), Some(4));
    assert_eq!(pick(&rules, &tls("www.youtube.com")?), Some(4));
    assert_eq!(pick(&rules, &tls("discord.com")?), Some(5));
    assert_eq!(pick(&rules, &tls("cdn.discordapp.com")?), Some(5));
    // Listed in list-google.txt, and rule 4 comes first.
    assert_eq!(pick(&rules, &tls("stable.dl2.discordapp.net")?), Some(4));
    // `^dns.google` is exact-only.
    assert_eq!(pick(&rules, &tls("dns.google")?), Some(5));
    assert_eq!(pick(&rules, &tls("x.dns.google")?), None);
    assert_eq!(pick(&rules, &tls("example.org")?), None);
    Ok(())
}

#[test]
fn http_host_is_normalized_first() -> TestResult {
    let rules = general_bat(IPSET_PLACEHOLDER, GAME_OFF)?;
    let host = normalize_host("Discord.COM:80");
    let f = flow(
        Transport::Tcp,
        "162.159.128.233:80",
        Protocol::Http,
        Some(&host),
    )?;
    assert_eq!(pick(&rules, &f), Some(5));
    Ok(())
}

#[test]
fn discord_media_on_alt_ports() -> TestResult {
    let rules = general_bat(IPSET_PLACEHOLDER, GAME_OFF)?;
    let at = |host: &'static str| {
        flow(
            Transport::Tcp,
            "162.159.1.1:2053",
            Protocol::Tls,
            Some(host),
        )
    };
    assert_eq!(pick(&rules, &at("x.discord.media")?), Some(3));
    assert_eq!(
        pick(&rules, &at("discord.com")?),
        None,
        "port 2053 is only for discord.media"
    );
    Ok(())
}

#[test]
fn udp_rules() -> TestResult {
    let rules = general_bat(IPSET_PLACEHOLDER, GAME_OFF)?;
    let voice = |l7| flow(Transport::Udp, "66.22.200.1:50005", l7, None);
    assert_eq!(pick(&rules, &voice(Protocol::Discord)?), Some(2));
    assert_eq!(pick(&rules, &voice(Protocol::Stun)?), Some(2));
    assert_eq!(pick(&rules, &voice(Protocol::Unknown)?), None);

    let quic = |host: &'static str| {
        flow(
            Transport::Udp,
            "142.250.74.4:443",
            Protocol::Quic,
            Some(host),
        )
    };
    assert_eq!(pick(&rules, &quic("discord.com")?), Some(1));
    // YouTube is only in list-google.txt, and no QUIC rule uses that list.
    assert_eq!(pick(&rules, &quic("www.youtube.com")?), None);
    Ok(())
}

/// Shipped as-is, the IP-list rules only ever match the placeholder address.
#[test]
fn ip_rules_with_the_shipped_placeholder() -> TestResult {
    let rules = general_bat(IPSET_PLACEHOLDER, GAME_OFF)?;
    let tls = |dst, host| flow(Transport::Tcp, dst, Protocol::Tls, host);
    assert_eq!(
        pick(&rules, &tls("203.0.113.113:443", Some("example.org"))?),
        Some(7)
    );
    assert_eq!(
        pick(&rules, &tls("1.1.1.1:443", Some("example.org"))?),
        None
    );
    // Rule 7 has a hostlist-exclude, so it also waits for the host name.
    assert_eq!(pick(&rules, &tls("203.0.113.113:443", None)?), None);
    Ok(())
}

#[test]
fn ip_rules_with_the_full_list_and_game_filter() -> TestResult {
    let rules = general_bat(IPSET_FULL, GAME_ON)?;
    let tls = |dst, host| flow(Transport::Tcp, dst, Protocol::Tls, Some(host));
    assert_eq!(pick(&rules, &tls("1.1.1.1:443", "example.org")?), Some(7));
    // list-exclude.txt wins over the IP list.
    assert_eq!(pick(&rules, &tls("1.1.1.1:443", "www.twitch.tv")?), None);
    // Game rules have no domain lists: they match on the first packet.
    let game_udp = flow(Transport::Udp, "8.8.8.8:27015", Protocol::Unknown, None)?;
    assert_eq!(pick(&rules, &game_udp), Some(9));
    let game_tcp = flow(Transport::Tcp, "8.8.8.8:27015", Protocol::Unknown, None)?;
    assert_eq!(pick(&rules, &game_tcp), Some(8));
    // Private addresses are in ipset-exclude.txt.
    let lan = flow(Transport::Udp, "10.0.0.5:27015", Protocol::Unknown, None)?;
    assert_eq!(pick(&rules, &lan), None);
    Ok(())
}

#[test]
fn address_family_filter() -> TestResult {
    let v4_only = Match {
        ipv6: false,
        ..Match::default()
    };
    let v6 = flow(Transport::Tcp, "[2606:4700::1111]:443", Protocol::Tls, None)?;
    let v4 = flow(Transport::Tcp, "1.1.1.1:443", Protocol::Tls, None)?;
    assert!(!v4_only.matches(&v6));
    assert!(v4_only.matches(&v4));
    Ok(())
}
