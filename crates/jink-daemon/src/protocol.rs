//! The control channel's messages: what the apps send ([`Request`]) and
//! what the daemon sends back ([`Message`]), one JSON object per line. See
//! `docs/control-protocol.md`.
//!
//! Problems travel as codes, not sentences, so each app shows them in its
//! own language; a `detail` (the system's own text, in English) is for
//! diagnosis only.

use serde::{Deserialize, Serialize};

use crate::probe::{Outcome, Tls};
use jink_core::settings::{
    Gaming, GamingMode, IpListMode, IpNet, Ports, Settings, Site, SiteError,
};

/// A request from an app.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    /// Answered with [`Message::Status`].
    Status,
    /// Answered with [`Message::Strategies`].
    Strategies,
    /// Starts desync, with `strategy` (an id) if given, else the one used
    /// last; restarts with `strategy` if already on. The choice is saved.
    /// Answered with [`Message::Done`].
    Start {
        #[serde(default)]
        strategy: Option<String>,
    },
    /// Stops desync. Answered with [`Message::Done`].
    Stop,
    /// Answered with [`Message::Settings`].
    Settings,
    /// Replaces the settings (all or nothing: any invalid entry rejects
    /// them), applying them at once if desync is on. Answered with
    /// [`Message::Done`].
    UpdateSettings { settings: SettingsWire },
    /// Whether desync starts by itself when the computer starts. Answered
    /// with [`Message::Done`].
    SetStartAtBoot { on: bool },
    /// Tries every strategy and keeps the one that gets through best (see
    /// [`Found`]); nothing new if already finding. `start` and `stop` end
    /// it. Answered with [`Message::Done`] at once.
    Find,
    /// Ends finding, leaving desync as it was before. Answered with
    /// [`Message::Done`].
    CancelFind,
    /// Turns the connection into a stream of [`Message::Status`] (now, and
    /// at every change) and [`Message::Notice`].
    Watch,
}

/// A message from the daemon: the answer to one request, or an update on a
/// watching connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Message {
    Status {
        status: Status,
    },
    Strategies {
        strategies: Vec<StrategyInfo>,
    },
    Settings {
        settings: SettingsWire,
    },
    Done,
    Error {
        error: Failure,
    },
    /// Something that went wrong without changing the state (one
    /// connection without desync, for example), each kind once per start.
    Notice {
        notice: Problem,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Status {
    pub engine: Engine,
    /// The strategy desync runs (or last ran) with.
    pub strategy: String,
    pub start_at_boot: bool,
    /// The daemon's version (an app bundling another one offers to
    /// reinstall the service).
    pub version: String,
    /// What the last finding found (since the daemon started).
    pub found: Option<Found>,
}

/// Whether desync runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Engine {
    Off,
    Starting,
    On {
        network: Network,
    },
    /// It stopped by itself or could not start.
    Failed {
        problem: Problem,
    },
    /// Finding a strategy: at `step` of `of`, trying `strategy` (none at
    /// the first step, which checks the sites without jink).
    Finding {
        step: usize,
        of: usize,
        strategy: Option<String>,
    },
}

/// What finding found: what it did (`result`), how the sites answer without
/// jink, and with each strategy tried, out of `checks` checks each.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Found {
    #[serde(flatten)]
    pub result: FindResult,
    pub checks: usize,
    pub without: Checks,
    pub tried: Vec<Tried>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum FindResult {
    /// `strategy` got through best; it is saved and on.
    Kept { strategy: String },
    /// Every site answers without jink; desync is as it was.
    NothingBlocked,
    /// No strategy got through better than none; desync is as it was.
    NoneHelped,
    /// No site could even be looked up or reached; desync is as it was.
    NoNetwork,
}

/// One round of checks: each site over each TLS version.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct Checks {
    pub passed: usize,
    pub failed: Vec<FailedCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FailedCheck {
    pub host: String,
    pub tls: Tls,
    pub outcome: Outcome,
}

/// A strategy tried; with a `problem` when it never came online, so its
/// sites were not checked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Tried {
    pub strategy: String,
    #[serde(flatten)]
    pub checks: Checks,
    pub problem: Option<Problem>,
}

/// The network while desync is on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Network {
    /// Looking at the network (just started).
    Checking,
    /// Traffic goes through jink and leaves through `uplink`; with `ipv6`,
    /// the network has IPv6, turned away so that apps use IPv4.
    Online { uplink: String, ipv6: bool },
    /// Traffic on every network goes through jink (Windows, which does not
    /// tell jink which network is in use, or whether there is one).
    Active,
    /// No network; jink waits for one.
    Offline,
    /// jink cannot work on this network, so traffic bypasses it.
    Bypassed { problem: Problem },
}

/// A problem: a stable `code` for apps to explain, and the system's own
/// text as `detail`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Problem {
    pub code: String,
    pub detail: String,
}

impl Problem {
    #[must_use]
    pub fn new(code: &str, detail: &impl ToString) -> Self {
        Self {
            code: code.to_owned(),
            detail: detail.to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StrategyInfo {
    pub id: String,
    pub name: String,
    pub variant_of: Option<String>,
    pub support: Support,
}

/// How much of a strategy this computer can run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Support {
    Full,
    /// Some of its rules pass traffic unchanged here.
    Partial,
}

/// Why a request failed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum Failure {
    /// Not a request this daemon knows (`detail` says why).
    BadRequest {
        detail: String,
    },
    UnknownStrategy {
        strategy: String,
    },
    InvalidSettings {
        problems: Vec<SettingsProblem>,
    },
    /// The daemon could not do it (`detail` says why).
    Failed {
        detail: String,
    },
}

/// One invalid settings entry: the list (`field`), the entry's position in
/// it, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SettingsProblem {
    pub field: &'static str,
    /// Position in a list field; `None` for the port ranges.
    pub index: Option<usize>,
    pub code: &'static str,
}

/// [`Settings`] as text, as the apps edit them and the daemon saves them.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettingsWire {
    #[serde(default)]
    pub my_sites: Vec<String>,
    #[serde(default)]
    pub my_ips: Vec<String>,
    #[serde(default)]
    pub excluded_sites: Vec<String>,
    #[serde(default)]
    pub excluded_ips: Vec<String>,
    #[serde(default)]
    pub gaming: GamingWire,
    #[serde(default)]
    pub ip_list: IpListWire,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GamingWire {
    pub mode: GamingModeWire,
    pub tcp_ports: String,
    pub udp_ports: String,
}

impl Default for GamingWire {
    fn default() -> Self {
        Self::from(&Gaming::default())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GamingModeWire {
    #[default]
    Off,
    Tcp,
    Udp,
    Both,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpListWire {
    #[default]
    Off,
    BuiltIn,
    All,
}

impl SettingsWire {
    /// The settings, if every entry is valid.
    ///
    /// # Errors
    /// Every invalid entry.
    pub fn parse(&self) -> Result<Settings, Vec<SettingsProblem>> {
        let (settings, problems) = self.parse_valid();
        if problems.is_empty() {
            Ok(settings)
        } else {
            Err(problems)
        }
    }

    /// The settings made of the valid entries, and the invalid ones (left
    /// out; a port range falls back to the default).
    #[must_use]
    pub fn parse_valid(&self) -> (Settings, Vec<SettingsProblem>) {
        let mut problems = Vec::new();
        let my_sites = entries(&mut problems, "my_sites", &self.my_sites, site);
        let excluded_sites = entries(&mut problems, "excluded_sites", &self.excluded_sites, site);
        let my_ips = entries(&mut problems, "my_ips", &self.my_ips, ip);
        let excluded_ips = entries(&mut problems, "excluded_ips", &self.excluded_ips, ip);
        let mut ports = |field: &'static str, text: &str| {
            Ports::parse(text).unwrap_or_else(|_| {
                problems.push(SettingsProblem {
                    field,
                    index: None,
                    code: "invalid_ports",
                });
                Ports::GAMES
            })
        };
        let gaming = Gaming {
            mode: self.gaming.mode.into(),
            tcp_ports: ports("gaming.tcp_ports", &self.gaming.tcp_ports),
            udp_ports: ports("gaming.udp_ports", &self.gaming.udp_ports),
        };
        let settings = Settings {
            my_sites,
            my_ips,
            excluded_sites,
            excluded_ips,
            gaming,
            ip_list: self.ip_list.into(),
        };
        (settings, problems)
    }
}

/// The valid entries of the list `field`; the others go to `problems`.
fn entries<T>(
    problems: &mut Vec<SettingsProblem>,
    field: &'static str,
    items: &[String],
    parse: fn(&str) -> Result<T, &'static str>,
) -> Vec<T> {
    items
        .iter()
        .enumerate()
        .filter_map(|(index, item)| match parse(item) {
            Ok(value) => Some(value),
            Err(code) => {
                problems.push(SettingsProblem {
                    field,
                    index: Some(index),
                    code,
                });
                None
            }
        })
        .collect()
}

fn texts<T: ToString>(items: &[T]) -> Vec<String> {
    items.iter().map(ToString::to_string).collect()
}

fn site(text: &str) -> Result<Site, &'static str> {
    Site::parse(text).map_err(|e| match e {
        SiteError::Empty => "empty",
        SiteError::IpAddress => "ip_address",
        SiteError::NotAscii => "not_ascii",
        SiteError::NoDot => "no_dot",
        SiteError::Invalid => "invalid_site",
    })
}

fn ip(text: &str) -> Result<IpNet, &'static str> {
    IpNet::parse(text).map_err(|_| "invalid_ip")
}

impl From<&Settings> for SettingsWire {
    fn from(settings: &Settings) -> Self {
        Self {
            my_sites: texts(&settings.my_sites),
            my_ips: texts(&settings.my_ips),
            excluded_sites: texts(&settings.excluded_sites),
            excluded_ips: texts(&settings.excluded_ips),
            gaming: GamingWire::from(&settings.gaming),
            ip_list: settings.ip_list.into(),
        }
    }
}

impl From<&Gaming> for GamingWire {
    fn from(gaming: &Gaming) -> Self {
        Self {
            mode: gaming.mode.into(),
            tcp_ports: gaming.tcp_ports.to_string(),
            udp_ports: gaming.udp_ports.to_string(),
        }
    }
}

impl From<GamingModeWire> for GamingMode {
    fn from(mode: GamingModeWire) -> Self {
        match mode {
            GamingModeWire::Off => Self::Off,
            GamingModeWire::Tcp => Self::Tcp,
            GamingModeWire::Udp => Self::Udp,
            GamingModeWire::Both => Self::Both,
        }
    }
}

impl From<GamingMode> for GamingModeWire {
    fn from(mode: GamingMode) -> Self {
        match mode {
            GamingMode::Off => Self::Off,
            GamingMode::Tcp => Self::Tcp,
            GamingMode::Udp => Self::Udp,
            GamingMode::Both => Self::Both,
        }
    }
}

impl From<IpListWire> for IpListMode {
    fn from(mode: IpListWire) -> Self {
        match mode {
            IpListWire::Off => Self::Off,
            IpListWire::BuiltIn => Self::BuiltIn,
            IpListWire::All => Self::All,
        }
    }
}

impl From<IpListMode> for IpListWire {
    fn from(mode: IpListMode) -> Self {
        match mode {
            IpListMode::Off => Self::Off,
            IpListMode::BuiltIn => Self::BuiltIn,
            IpListMode::All => Self::All,
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{
        Checks, Engine, FailedCheck, Failure, FindResult, Found, GamingModeWire, IpListWire,
        Message, Network, Outcome, Problem, Request, SettingsProblem, SettingsWire, Status,
        StrategyInfo, Support, Tls, Tried,
    };

    fn request(text: &str) -> Result<Request, serde_json::Error> {
        serde_json::from_str(text)
    }

    fn wire(message: &Message) -> Value {
        serde_json::to_value(message).unwrap()
    }

    #[test]
    fn requests() {
        assert_eq!(request(r#"{"cmd":"status"}"#).unwrap(), Request::Status);
        assert_eq!(request(r#"{"cmd":"find"}"#).unwrap(), Request::Find);
        assert_eq!(
            request(r#"{"cmd":"cancel_find"}"#).unwrap(),
            Request::CancelFind
        );
        assert_eq!(
            request(r#"{"cmd":"start"}"#).unwrap(),
            Request::Start { strategy: None }
        );
        assert_eq!(
            request(r#"{"cmd":"start","strategy":"alt13"}"#).unwrap(),
            Request::Start {
                strategy: Some("alt13".into())
            }
        );
        assert_eq!(
            request(r#"{"cmd":"set_start_at_boot","on":false}"#).unwrap(),
            Request::SetStartAtBoot { on: false }
        );
        let update = request(
            r#"{"cmd":"update_settings","settings":{"my_sites":["youtube.com"],
                "gaming":{"mode":"both","tcp_ports":"1024-65535","udp_ports":"27015"},
                "ip_list":"built_in"}}"#,
        )
        .unwrap();
        let Request::UpdateSettings { settings } = update else {
            panic!("not an update")
        };
        assert_eq!(settings.my_sites, ["youtube.com"]);
        assert_eq!(settings.gaming.mode, GamingModeWire::Both);
        assert_eq!(settings.ip_list, IpListWire::BuiltIn);
        assert_eq!(settings.my_ips, Vec::<String>::new());
        // Unknown commands and misspelled fields are refused, not ignored
        // (so `start` with a typo cannot start the wrong strategy).
        assert!(request(r#"{"cmd":"reboot"}"#).is_err());
        assert!(request(r#"{"cmd":"start","stratgy":"alt"}"#).is_err());
        assert!(request(r#"{"cmd":"update_settings","settings":{"my_site":[]}}"#).is_err());
    }

    #[test]
    fn messages() {
        let status = Status {
            engine: Engine::On {
                network: Network::Online {
                    uplink: "en0".into(),
                    ipv6: false,
                },
            },
            strategy: "alt".into(),
            start_at_boot: true,
            version: "0.1.0".into(),
            found: None,
        };
        assert_eq!(
            wire(&Message::Status { status }),
            json!({"type": "status", "status": {
                "engine": {"state": "on", "network": {"state": "online", "uplink": "en0", "ipv6": false}},
                "strategy": "alt", "start_at_boot": true, "version": "0.1.0",
                "found": null}})
        );
        let finding = Engine::Finding {
            step: 1,
            of: 14,
            strategy: None,
        };
        assert_eq!(
            serde_json::to_value(&finding).unwrap(),
            json!({"state": "finding", "step": 1, "of": 14, "strategy": null})
        );
        let found = Found {
            result: FindResult::Kept {
                strategy: "alt4".into(),
            },
            checks: 16,
            without: Checks {
                passed: 15,
                failed: vec![FailedCheck {
                    host: "i.ytimg.com".into(),
                    tls: Tls::V12,
                    outcome: Outcome::Cut,
                }],
            },
            tried: vec![Tried {
                strategy: "alt".into(),
                checks: Checks::default(),
                problem: Some(Problem::new("offline", &"no network")),
            }],
        };
        assert_eq!(
            serde_json::to_value(&found).unwrap(),
            json!({"result": "kept", "strategy": "alt4", "checks": 16,
                "without": {"passed": 15, "failed": [
                    {"host": "i.ytimg.com", "tls": "1.2", "outcome": "cut"}]},
                "tried": [{"strategy": "alt", "passed": 0, "failed": [],
                    "problem": {"code": "offline", "detail": "no network"}}]})
        );
        assert_eq!(
            serde_json::to_value(&FindResult::NothingBlocked).unwrap(),
            json!({"result": "nothing_blocked"})
        );
        let failed = Engine::Failed {
            problem: Problem::new("not_root", &"jink needs root"),
        };
        assert_eq!(
            serde_json::to_value(&failed).unwrap(),
            json!({"state": "failed", "problem": {"code": "not_root", "detail": "jink needs root"}})
        );
        assert_eq!(wire(&Message::Done), json!({"type": "done"}));
        assert_eq!(
            wire(&Message::Strategies {
                strategies: vec![StrategyInfo {
                    id: "alt6".into(),
                    name: "ALT6".into(),
                    variant_of: Some("general".into()),
                    support: Support::Partial,
                }]
            }),
            json!({"type": "strategies", "strategies": [
                {"id": "alt6", "name": "ALT6", "variant_of": "general", "support": "partial"}]})
        );
        assert_eq!(
            wire(&Message::Error {
                error: Failure::InvalidSettings {
                    problems: vec![SettingsProblem {
                        field: "my_sites",
                        index: Some(2),
                        code: "no_dot",
                    }]
                }
            }),
            json!({"type": "error", "error": {"code": "invalid_settings", "problems": [
                {"field": "my_sites", "index": 2, "code": "no_dot"}]}})
        );
        assert_eq!(
            wire(&Message::Error {
                error: Failure::UnknownStrategy {
                    strategy: "alt99".into()
                }
            }),
            json!({"type": "error", "error": {"code": "unknown_strategy", "strategy": "alt99"}})
        );
    }

    #[test]
    fn settings_are_checked_entry_by_entry() {
        let wire = SettingsWire {
            my_sites: vec!["https://www.youtube.com/watch".into(), "youtube".into()],
            my_ips: vec!["1.2.3.4/24".into(), "1.2.3".into()],
            excluded_sites: vec!["1.1.1.1".into()],
            excluded_ips: Vec::new(),
            gaming: super::GamingWire {
                mode: GamingModeWire::Udp,
                tcp_ports: "1024-65535".into(),
                udp_ports: "70000".into(),
            },
            ip_list: IpListWire::All,
        };
        let problems = wire.parse().unwrap_err();
        let shown: Vec<_> = problems
            .iter()
            .map(|p| (p.field, p.index, p.code))
            .collect();
        assert_eq!(
            shown,
            [
                ("my_sites", Some(1), "no_dot"),
                ("excluded_sites", Some(0), "ip_address"),
                ("my_ips", Some(1), "invalid_ip"),
                ("gaming.udp_ports", None, "invalid_ports"),
            ]
        );
        // The valid entries are kept, normalized.
        let (valid, _) = wire.parse_valid();
        let back = SettingsWire::from(&valid);
        assert_eq!(back.my_sites, ["www.youtube.com"]);
        assert_eq!(back.my_ips, ["1.2.3.0/24"]);
        assert_eq!(back.gaming.udp_ports, "1024-65535");
        assert_eq!(back.ip_list, IpListWire::All);
        assert_eq!(back.gaming.mode, GamingModeWire::Udp);
        // Defaults round-trip, and an empty object is the defaults.
        let defaults: SettingsWire = serde_json::from_str("{}").unwrap();
        assert_eq!(defaults, SettingsWire::default());
        assert_eq!(SettingsWire::from(&defaults.parse().unwrap()), defaults);
    }
}
