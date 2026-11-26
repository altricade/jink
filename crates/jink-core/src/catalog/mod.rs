//! jink's built-in strategies, lists and payloads, compiled in, and
//! building a configuration from a strategy and the user's [`Settings`].
//!
//! Every strategy shares one skeleton of nine traffic [`Group`]s, which says
//! *which* traffic each group is (ports, lists); a strategy only says *how*
//! each group is desynced (its recipe). The settings fill in the skeleton:
//! the user's own sites and IPs, exclusions, gaming mode and the IP list
//! mode, the same for every strategy.

mod strategies;

use crate::config::Config;
use crate::config::winws::{ConfigError, FileSource, parse};
use crate::settings::{IpListMode, Settings};

/// The traffic groups of the skeleton, in rule order (the first matching
/// rule wins).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Group {
    /// QUIC (UDP 443) to the listed sites.
    QuicSites,
    /// Discord voice (STUN and Discord's own protocol on its UDP ports).
    DiscordVoice,
    /// Discord media on its extra TCP ports.
    DiscordMedia,
    /// YouTube and Google (TCP 443 to the Google list).
    Google,
    /// The listed sites, over TCP 80 and 443.
    Sites,
    /// QUIC to the IP list.
    QuicIps,
    /// TCP 80, 443 and 8443 to the IP list.
    Ips,
    /// Gaming mode, TCP, to the IP list.
    GameTcp,
    /// Gaming mode, UDP, to the IP list.
    GameUdp,
}

/// The number of [`Group`]s.
pub const GROUPS: usize = 9;

/// A built-in strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Strategy {
    /// Stable identifier (`alt13`), for settings and the control channel.
    pub id: &'static str,
    /// The name users know from zapret (`ALT13`).
    pub name: &'static str,
    /// For a variant (the same technique as another strategy, with other
    /// fake payloads), the `id` of that strategy.
    pub variant_of: Option<&'static str>,
    /// Per [`Group`], in order: zapret desync options.
    recipe: [&'static str; GROUPS],
}

/// Every built-in strategy, main ones and variants, in zapret's order.
#[must_use]
pub fn all() -> &'static [Strategy] {
    strategies::STRATEGIES
}

/// The strategy with this `id`.
#[must_use]
pub fn find(id: &str) -> Option<&'static Strategy> {
    all().iter().find(|s| s.id == id)
}

/// The built-in lists, the user's lists (rendered from the settings) and
/// the payloads, by the paths the arguments use.
const GENERAL: &str = "lists/list-general.txt";
const GOOGLE: &str = "lists/list-google.txt";
const EXCLUDE: &str = "lists/list-exclude.txt";
const IP_ALL: &str = "lists/ipset-all.txt";
const IP_EXCLUDE: &str = "lists/ipset-exclude.txt";
const MY_SITES: &str = "user/sites.txt";
const MY_IPS: &str = "user/ips.txt";
const MY_EXCLUDED_SITES: &str = "user/excluded-sites.txt";
const MY_EXCLUDED_IPS: &str = "user/excluded-ips.txt";

/// Ports of the fixed groups, captured whatever the settings.
const CAPTURE_TCP: &str = "80,443,2053,2083,2087,2096,8443";
const CAPTURE_UDP: &str = "443,19294-19344,50000-50100";

/// The configuration `strategy` gives with `settings`.
///
/// # Errors
/// Only if the built-in data is broken (a test builds every strategy).
pub fn build(strategy: &Strategy, settings: &Settings) -> Result<Config, ConfigError> {
    parse(&arguments(strategy, settings), &Files(settings))
}

/// The groups a configuration built with `settings` has, in rule order:
/// rule `i` of [`build`]'s configuration is group `i` here. The IP groups
/// need IPs to cover, and the game groups gaming mode too.
#[must_use]
pub fn groups(settings: &Settings) -> Vec<Group> {
    skeleton(settings)
        .0
        .into_iter()
        .map(|(group, _)| group)
        .collect()
}

/// The zapret command line for `strategy` with `settings`: the skeleton's
/// groups, each followed by its recipe.
fn arguments(strategy: &Strategy, settings: &Settings) -> Vec<String> {
    let (groups, capture) = skeleton(settings);
    let mut args = capture;
    for (index, (group, targets)) in groups.into_iter().enumerate() {
        if index > 0 {
            args.push("--new".to_owned());
        }
        args.extend(targets);
        args.extend(strategy.recipe(group).split_whitespace().map(str::to_owned));
    }
    args
}

/// The skeleton filled in from `settings`: each group with the options that
/// select its traffic, and the capture options.
type Skeleton = (Vec<(Group, Vec<String>)>, Vec<String>);

fn skeleton(settings: &Settings) -> Skeleton {
    let arg = |option: &str, value: &str| format!("--{option}={value}");
    let mine = |option: &str, path: &str, present: bool| present.then(|| arg(option, path));

    let sites_in: Vec<String> = std::iter::once(arg("hostlist", GENERAL))
        .chain(mine("hostlist", MY_SITES, !settings.my_sites.is_empty()))
        .collect();
    let sites_out: Vec<String> = std::iter::once(arg("hostlist-exclude", EXCLUDE))
        .chain(mine(
            "hostlist-exclude",
            MY_EXCLUDED_SITES,
            !settings.excluded_sites.is_empty(),
        ))
        .collect();
    let ips_out: Vec<String> = std::iter::once(arg("ipset-exclude", IP_EXCLUDE))
        .chain(mine(
            "ipset-exclude",
            MY_EXCLUDED_IPS,
            !settings.excluded_ips.is_empty(),
        ))
        .collect();
    let my_ips = mine("ipset", MY_IPS, !settings.my_ips.is_empty());
    // The IPs the IP groups cover; none at all leaves the groups out.
    let ips_in: Option<Vec<String>> = match settings.ip_list {
        IpListMode::All => Some(Vec::new()),
        IpListMode::BuiltIn => Some(
            std::iter::once(arg("ipset", IP_ALL))
                .chain(my_ips)
                .collect(),
        ),
        IpListMode::Off => my_ips.map(|m| vec![m]),
    };
    let game_tcp = ips_in.as_ref().and(settings.gaming.tcp());
    let game_udp = ips_in.as_ref().and(settings.gaming.udp());

    let filter = |transport: &str, ports: &str| vec![arg(&format!("filter-{transport}"), ports)];
    let join = |parts: &[&[String]]| parts.concat();
    let mut groups: Vec<(Group, Vec<String>)> = vec![
        (
            Group::QuicSites,
            join(&[&filter("udp", "443"), &sites_in, &sites_out, &ips_out]),
        ),
        (
            Group::DiscordVoice,
            join(&[
                &filter("udp", "19294-19344,50000-50100"),
                &[arg("filter-l7", "discord,stun")],
            ]),
        ),
        (
            Group::DiscordMedia,
            join(&[
                &filter("tcp", "2053,2083,2087,2096,8443"),
                &[arg("hostlist-domains", "discord.media")],
            ]),
        ),
        (
            Group::Google,
            join(&[&filter("tcp", "443"), &[arg("hostlist", GOOGLE)]]),
        ),
        (
            Group::Sites,
            join(&[&filter("tcp", "80,443"), &sites_in, &sites_out, &ips_out]),
        ),
    ];
    if let Some(ips_in) = &ips_in {
        groups.push((
            Group::QuicIps,
            join(&[&filter("udp", "443"), ips_in, &sites_out, &ips_out]),
        ));
        groups.push((
            Group::Ips,
            join(&[&filter("tcp", "80,443,8443"), ips_in, &sites_out, &ips_out]),
        ));
        if let Some(ports) = game_tcp {
            groups.push((
                Group::GameTcp,
                join(&[&filter("tcp", &ports.to_string()), ips_in, &ips_out]),
            ));
        }
        if let Some(ports) = game_udp {
            groups.push((
                Group::GameUdp,
                join(&[&filter("udp", &ports.to_string()), ips_in, &ips_out]),
            ));
        }
    }

    let capture = |fixed: &str, game: Option<crate::settings::Ports>| match game {
        Some(ports) => format!("{fixed},{ports}"),
        None => fixed.to_owned(),
    };
    let capture = vec![
        arg("wf-tcp", &capture(CAPTURE_TCP, game_tcp)),
        arg("wf-udp", &capture(CAPTURE_UDP, game_udp)),
    ];
    (groups, capture)
}

impl Strategy {
    fn recipe(&self, group: Group) -> &'static str {
        let index = match group {
            Group::QuicSites => 0,
            Group::DiscordVoice => 1,
            Group::DiscordMedia => 2,
            Group::Google => 3,
            Group::Sites => 4,
            Group::QuicIps => 5,
            Group::Ips => 6,
            Group::GameTcp => 7,
            Group::GameUdp => 8,
        };
        self.recipe.get(index).copied().unwrap_or_default()
    }
}

/// The files the arguments name: built-in data, and the user's lists.
struct Files<'a>(&'a Settings);

impl FileSource for Files<'_> {
    fn read(&self, path: &str) -> std::io::Result<Vec<u8>> {
        let settings = self.0;
        let user = match path {
            MY_SITES => Some(lines(&settings.my_sites)),
            MY_IPS => Some(lines(&settings.my_ips)),
            MY_EXCLUDED_SITES => Some(lines(&settings.excluded_sites)),
            MY_EXCLUDED_IPS => Some(lines(&settings.excluded_ips)),
            _ => None,
        };
        match user {
            Some(text) => Ok(text.into_bytes()),
            None => built_in(path).map(<[u8]>::to_vec).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, format!("no built-in {path}"))
            }),
        }
    }
}

/// A list file: one item per line.
fn lines<T: std::fmt::Display>(items: &[T]) -> String {
    items
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n")
}

/// A built-in list or payload.
fn built_in(path: &str) -> Option<&'static [u8]> {
    macro_rules! data {
        ($($path:literal),* $(,)?) => {
            match path {
                $($path => Some(include_bytes!(concat!("../../data/", $path)).as_slice()),)*
                _ => None,
            }
        };
    }
    data!(
        "lists/list-general.txt",
        "lists/list-google.txt",
        "lists/list-exclude.txt",
        "lists/ipset-all.txt",
        "lists/ipset-exclude.txt",
        "payloads/quic_initial_4pda_to.bin",
        "payloads/quic_initial_steamcommunity_com.bin",
        "payloads/quic_initial_www_google_com.bin",
        "payloads/stun.bin",
        "payloads/stun2.bin",
        "payloads/tls_clienthello_4pda_to.bin",
        "payloads/tls_clienthello_sochi_park.bin",
        "payloads/tls_clienthello_www_google_com.bin",
        "payloads/tls_clienthello_www_sferum_ru.bin",
    )
}
