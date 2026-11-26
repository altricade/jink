//! jink's built-in catalog against zapret's originals, and what the settings
//! do to it.

use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::net::SocketAddr;
use std::path::PathBuf;

use jink_core::catalog::{self, Group, Strategy};
use jink_core::config::Config;
use jink_core::config::bat::winws_args;
use jink_core::config::winws::{FileSource, parse};
use jink_core::l7::Protocol;
use jink_core::rules::{Flow, Transport, first_match};
use jink_core::settings::{Gaming, GamingMode, IpListMode, IpNet, Ports, Settings, Site};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const MY_SITES: &[&str] = &["mysite.example.com", "mirror.example.org"];
const EXCLUDED_SITES: &[&str] = &["bank.example.ru"];
const EXCLUDED_IPS: &[&str] = &["198.51.100.0/24"];

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// The zapret-discord-youtube bundle (the fixtures) as `service.bat` sets it
/// up with the full IP list loaded, the game filter on for TCP and UDP, and
/// the user lists filled in.
struct Zapret;

impl FileSource for Zapret {
    fn read(&self, path: &str) -> std::io::Result<Vec<u8>> {
        let user = |items: &[&str]| Ok(items.join("\n").into_bytes());
        match path {
            "lists/list-general-user.txt" => user(MY_SITES),
            "lists/list-exclude-user.txt" => user(EXCLUDED_SITES),
            "lists/ipset-exclude-user.txt" => user(EXCLUDED_IPS),
            "lists/ipset-all.txt" => std::fs::read(fixtures().join("lists/ipset-all-full.txt")),
            other => match other.strip_prefix("bin/") {
                Some(payload) => std::fs::read(fixtures().join(payload)),
                None => std::fs::read(fixtures().join(other)),
            },
        }
    }
}

fn original(strategy: &Strategy) -> Result<Config> {
    let file = if strategy.id == "general" {
        "general.bat".to_owned()
    } else {
        format!("general ({}).bat", strategy.name)
    };
    let text = std::fs::read_to_string(fixtures().join("strategies").join(file))?;
    let games = "1024-65535";
    let vars = HashMap::from([
        ("BIN", "bin/"),
        ("LISTS", "lists/"),
        ("GameFilterTCP", games),
        ("GameFilterUDP", games),
    ]);
    Ok(parse(&winws_args(&text, &vars)?, &Zapret)?)
}

fn sites(items: &[&str]) -> Result<Vec<Site>> {
    Ok(items
        .iter()
        .map(|s| Site::parse(s))
        .collect::<std::result::Result<_, _>>()?)
}

fn ips(items: &[&str]) -> Result<Vec<IpNet>> {
    Ok(items
        .iter()
        .map(|s| IpNet::parse(s))
        .collect::<std::result::Result<_, _>>()?)
}

/// The settings that match [`Zapret`].
fn like_zapret() -> Result<Settings> {
    Ok(Settings {
        my_sites: sites(MY_SITES)?,
        my_ips: Vec::new(),
        excluded_sites: sites(EXCLUDED_SITES)?,
        excluded_ips: ips(EXCLUDED_IPS)?,
        gaming: Gaming {
            mode: GamingMode::Both,
            ..Gaming::default()
        },
        ip_list: IpListMode::BuiltIn,
    })
}

#[test]
fn every_strategy_builds_what_its_original_does() -> Result<()> {
    assert_eq!(catalog::all().len(), 13);
    let settings = like_zapret()?;
    for strategy in catalog::all() {
        let built = catalog::build(strategy, &settings)?;
        let original = original(strategy)?;
        assert_eq!(built.capture, original.capture, "{}", strategy.name);
        assert_eq!(built.rules, original.rules, "{}", strategy.name);
        assert!(
            built.warnings.is_empty(),
            "{}: {:?}",
            strategy.name,
            built.warnings
        );
    }
    Ok(())
}

#[test]
fn strategies_that_fool_with_timestamps_say_so() -> Result<()> {
    let defaults = Settings::default();
    let uses = |id: &str| -> Result<bool> {
        let strategy = catalog::find(id).ok_or("unknown strategy")?;
        Ok(catalog::build(strategy, &defaults)?.uses_tcp_timestamps())
    };
    assert!(uses("alt")? && uses("alt13")? && uses("alt10")?);
    assert!(!uses("alt4")? && !uses("general")? && !uses("simple-fake-alt")?);
    Ok(())
}

#[test]
fn ids_are_unique_and_variants_name_a_main_strategy() {
    let ids: HashSet<&str> = catalog::all().iter().map(|s| s.id).collect();
    assert_eq!(ids.len(), catalog::all().len());
    for strategy in catalog::all() {
        assert_eq!(catalog::find(strategy.id), Some(strategy));
        if let Some(main) = strategy.variant_of {
            assert_eq!(
                catalog::find(main).map(|m| m.variant_of),
                Some(None),
                "{}",
                strategy.name
            );
        }
    }
    let variants: Vec<&str> = catalog::all()
        .iter()
        .filter(|s| s.variant_of.is_some())
        .map(|s| s.id)
        .collect();
    assert_eq!(variants, ["alt6", "simple-fake-alt2"]);
    assert_eq!(catalog::find("ALT"), None);
}

/// The group a flow lands in, if any.
fn group(config: &Config, settings: &Settings, flow: Flow<'_>) -> Option<Group> {
    let matchers: Vec<_> = config.rules.iter().map(|r| r.matcher.clone()).collect();
    let index = first_match(&matchers, &flow)?;
    catalog::groups(settings).get(index).copied()
}

/// A server, and the host name the flow shows (if any).
struct Target(SocketAddr, Option<&'static str>);

fn to(server: &str, host: Option<&'static str>) -> Result<Target> {
    Ok(Target(server.parse()?, host))
}

impl Target {
    fn flow(&self, transport: Transport) -> Flow<'_> {
        Flow {
            transport,
            dst: self.0,
            l7: Protocol::Unknown,
            hostname: self.1,
        }
    }
}

fn alt() -> Result<&'static Strategy> {
    catalog::find("alt").ok_or_else(|| "no ALT".into())
}

#[test]
fn by_default_only_the_lists_and_fixed_groups_apply() -> Result<()> {
    let defaults = Settings::default();
    let config = catalog::build(alt()?, &defaults)?;
    // No IP list and no own IPs: the IP and game groups are left out.
    assert_eq!(
        catalog::groups(&defaults),
        [
            Group::QuicSites,
            Group::DiscordVoice,
            Group::DiscordMedia,
            Group::Google,
            Group::Sites
        ]
    );
    assert_eq!(config.rules.len(), 5);
    let youtube = to("142.250.74.4:443", Some("www.youtube.com"))?;
    let at = |t: &Target, transport| group(&config, &defaults, t.flow(transport));
    assert_eq!(at(&youtube, Transport::Tcp), Some(Group::Google));
    let unlisted = to("93.184.215.14:443", Some("mysite.example.com"))?;
    assert_eq!(at(&unlisted, Transport::Tcp), None);
    let game = to("203.0.113.9:27015", None)?;
    assert_eq!(at(&game, Transport::Udp), None);
    Ok(())
}

#[test]
fn own_and_excluded_sites() -> Result<()> {
    let settings = Settings {
        my_sites: sites(&["mysite.example.com"])?,
        excluded_sites: sites(&["discord.com"])?,
        ..Settings::default()
    };
    let config = catalog::build(alt()?, &settings)?;
    let at = |t: &Target, transport| group(&config, &settings, t.flow(transport));
    let mine = to("93.184.215.14:443", Some("cdn.mysite.example.com"))?;
    assert_eq!(at(&mine, Transport::Tcp), Some(Group::Sites));
    assert_eq!(at(&mine, Transport::Udp), Some(Group::QuicSites));
    // discord.com is in the built-in list; excluding it wins.
    let defaults = Settings::default();
    let before = catalog::build(alt()?, &defaults)?;
    let listed = to("162.159.137.232:443", Some("discord.com"))?;
    assert_eq!(
        group(&before, &defaults, listed.flow(Transport::Tcp)),
        Some(Group::Sites)
    );
    assert_eq!(at(&listed, Transport::Tcp), None);
    Ok(())
}

#[test]
fn own_ips_work_without_the_ip_list_and_exclusions_win() -> Result<()> {
    let settings = Settings {
        my_ips: ips(&["203.0.113.0/24"])?,
        excluded_ips: ips(&["203.0.113.7"])?,
        ..Settings::default()
    };
    let config = catalog::build(alt()?, &settings)?;
    assert_eq!(config.rules.len(), 7);
    let at = |t: &Target, transport| group(&config, &settings, t.flow(transport));
    // The IP groups leave excluded sites alone too, so (as in zapret) they
    // apply once the server name is known.
    let mine = to("203.0.113.9:443", Some("game.example.net"))?;
    assert_eq!(at(&mine, Transport::Tcp), Some(Group::Ips));
    assert_eq!(at(&mine, Transport::Udp), Some(Group::QuicIps));
    let excluded = to("203.0.113.7:443", Some("game.example.net"))?;
    assert_eq!(at(&excluded, Transport::Tcp), None);
    Ok(())
}

#[test]
fn gaming_mode_covers_its_ports_and_protocols() -> Result<()> {
    let game = to("203.0.113.9:27015", None)?;
    let gaming = |mode, ip_list| -> Result<Settings> {
        Ok(Settings {
            gaming: Gaming {
                mode,
                tcp_ports: Ports::parse("27000-27100")?,
                udp_ports: Ports::GAMES,
            },
            ip_list,
            ..Settings::default()
        })
    };
    let captured = |config: &Config, transport| {
        let ports = match transport {
            Transport::Tcp => config.capture.tcp.as_ref(),
            Transport::Udp => config.capture.udp.as_ref(),
        };
        ports.is_some_and(|p| p.contains(27015))
    };
    // All IPs, UDP only: game UDP is covered and captured, game TCP not.
    let udp_only = gaming(GamingMode::Udp, IpListMode::All)?;
    let udp = catalog::build(alt()?, &udp_only)?;
    assert_eq!(udp.rules.len(), 8);
    assert_eq!(
        group(&udp, &udp_only, game.flow(Transport::Udp)),
        Some(Group::GameUdp)
    );
    assert_eq!(group(&udp, &udp_only, game.flow(Transport::Tcp)), None);
    assert!(captured(&udp, Transport::Udp) && !captured(&udp, Transport::Tcp));
    // Both, with a TCP range: a port outside it is not a game port.
    let all_both = gaming(GamingMode::Both, IpListMode::All)?;
    let both = catalog::build(alt()?, &all_both)?;
    assert_eq!(
        group(&both, &all_both, game.flow(Transport::Tcp)),
        Some(Group::GameTcp)
    );
    let outside = to("203.0.113.9:30000", None)?;
    assert_eq!(group(&both, &all_both, outside.flow(Transport::Tcp)), None);
    // Gaming without any IPs to cover does nothing (the app turns the
    // built-in list on with it).
    let no_ips = gaming(GamingMode::Both, IpListMode::Off)?;
    let nowhere = catalog::build(alt()?, &no_ips)?;
    assert_eq!(nowhere.rules.len(), 5);
    assert_eq!(catalog::groups(&no_ips).len(), 5);
    assert!(!captured(&nowhere, Transport::Udp) && !captured(&nowhere, Transport::Tcp));
    Ok(())
}
