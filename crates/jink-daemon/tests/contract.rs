//! The control protocol's contract (`contract/` at the repository root):
//! the daemon sends exactly the example messages, and understands every
//! example request. The apps' tests check the same files from their side.

use std::collections::BTreeMap;
use std::path::PathBuf;

use jink_daemon::probe::{Outcome, Tls};
use jink_daemon::protocol::{
    Checks, Engine, FailedCheck, Failure, FindResult, Found, GamingModeWire, GamingWire,
    IpListWire, Message, Network, Problem, Request, SettingsProblem, SettingsWire, Status,
    StrategyInfo, Support, Tried,
};
use serde_json::Value;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn contract() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contract")
}

fn status(engine: Engine, strategy: &str, start_at_boot: bool, found: Option<Found>) -> Message {
    Message::Status {
        status: Status {
            engine,
            strategy: strategy.into(),
            start_at_boot,
            version: "0.1.0".into(),
            found,
        },
    }
}

fn failed(host: &str, tls: Tls, outcome: Outcome) -> FailedCheck {
    FailedCheck {
        host: host.into(),
        tls,
        outcome,
    }
}

fn settings() -> SettingsWire {
    SettingsWire {
        my_sites: vec!["youtube.com".into()],
        my_ips: vec!["203.0.113.0/24".into()],
        excluded_sites: vec!["example.com".into()],
        excluded_ips: vec!["198.51.100.7/32".into()],
        gaming: GamingWire {
            mode: GamingModeWire::Both,
            tcp_ports: "1024-65535".into(),
            udp_ports: "27015".into(),
        },
        ip_list: IpListWire::BuiltIn,
    }
}

fn kept() -> Found {
    Found {
        result: FindResult::Kept {
            strategy: "alt4".into(),
        },
        checks: 16,
        without: Checks {
            passed: 14,
            failed: vec![
                failed("i.ytimg.com", Tls::V12, Outcome::Cut),
                failed("redirector.googlevideo.com", Tls::V13, Outcome::TimedOut),
            ],
        },
        tried: vec![
            Tried {
                strategy: "alt".into(),
                checks: Checks {
                    passed: 15,
                    failed: vec![failed("i.ytimg.com", Tls::V12, Outcome::NoReply)],
                },
                problem: None,
            },
            Tried {
                strategy: "alt4".into(),
                checks: Checks {
                    passed: 16,
                    failed: Vec::new(),
                },
                problem: None,
            },
            Tried {
                strategy: "alt2".into(),
                checks: Checks::default(),
                problem: Some(Problem::new("not_online", &"not online within 10 s")),
            },
        ],
    }
}

fn none_helped() -> Found {
    Found {
        result: FindResult::NoneHelped,
        checks: 16,
        without: Checks {
            passed: 0,
            failed: vec![
                failed("discord.com", Tls::V12, Outcome::Certificate),
                failed("discord.com", Tls::V13, Outcome::NoAddress),
                failed("youtu.be", Tls::V12, Outcome::Unreachable),
            ],
        },
        tried: Vec::new(),
    }
}

/// Every example message, by file name.
fn messages() -> BTreeMap<&'static str, Message> {
    let mut messages = statuses();
    messages.extend(others());
    messages
}

fn statuses() -> BTreeMap<&'static str, Message> {
    let on = |network| Engine::On { network };
    BTreeMap::from([
        (
            "status-online",
            status(
                on(Network::Online {
                    uplink: "en0".into(),
                    ipv6: true,
                }),
                "alt",
                true,
                None,
            ),
        ),
        (
            "status-active",
            status(on(Network::Active), "alt", false, None),
        ),
        (
            "status-checking",
            status(on(Network::Checking), "alt", false, None),
        ),
        (
            "status-offline",
            status(on(Network::Offline), "alt", false, None),
        ),
        (
            "status-bypassed",
            status(
                on(Network::Bypassed {
                    problem: Problem::new(
                        "routes_taken",
                        &"another app (a VPN?) has the default routes",
                    ),
                }),
                "alt",
                false,
                None,
            ),
        ),
        ("status-off", status(Engine::Off, "alt4", false, None)),
        (
            "status-starting",
            status(Engine::Starting, "alt4", false, None),
        ),
        (
            "status-failed",
            status(
                Engine::Failed {
                    problem: Problem::new("tun", &"cannot open a utun device"),
                },
                "alt",
                false,
                None,
            ),
        ),
        (
            "status-finding",
            status(
                Engine::Finding {
                    step: 3,
                    of: 14,
                    strategy: Some("alt2".into()),
                },
                "alt",
                false,
                None,
            ),
        ),
        (
            "status-finding-without",
            status(
                Engine::Finding {
                    step: 1,
                    of: 14,
                    strategy: None,
                },
                "alt",
                false,
                None,
            ),
        ),
        (
            "status-found-kept",
            status(Engine::Starting, "alt4", false, Some(kept())),
        ),
        (
            "status-found-other",
            status(Engine::Off, "alt", false, Some(none_helped())),
        ),
    ])
}

fn others() -> BTreeMap<&'static str, Message> {
    let mut gaming_udp = settings();
    gaming_udp.gaming.mode = GamingModeWire::Udp;
    gaming_udp.ip_list = IpListWire::All;
    BTreeMap::from([
        (
            "strategies",
            Message::Strategies {
                strategies: vec![
                    StrategyInfo {
                        id: "general".into(),
                        name: "general".into(),
                        variant_of: None,
                        support: Support::Partial,
                    },
                    StrategyInfo {
                        id: "alt".into(),
                        name: "ALT".into(),
                        variant_of: None,
                        support: Support::Full,
                    },
                    StrategyInfo {
                        id: "alt6".into(),
                        name: "ALT6".into(),
                        variant_of: Some("general".into()),
                        support: Support::Partial,
                    },
                ],
            },
        ),
        (
            "settings",
            Message::Settings {
                settings: gaming_udp,
            },
        ),
        ("done", Message::Done),
        (
            "notice",
            Message::Notice {
                notice: Problem::new(
                    "no_handshake",
                    &"no handshake seen (first seen with 203.0.113.9:443)",
                ),
            },
        ),
        (
            "error-bad-request",
            Message::Error {
                error: Failure::BadRequest {
                    detail: "unknown variant `reboot`".into(),
                },
            },
        ),
        (
            "error-unknown-strategy",
            Message::Error {
                error: Failure::UnknownStrategy {
                    strategy: "alt99".into(),
                },
            },
        ),
        (
            "error-invalid-settings",
            Message::Error {
                error: Failure::InvalidSettings {
                    problems: vec![
                        SettingsProblem {
                            field: "my_sites",
                            index: Some(2),
                            code: "no_dot",
                        },
                        SettingsProblem {
                            field: "gaming.udp_ports",
                            index: None,
                            code: "invalid_ports",
                        },
                    ],
                },
            },
        ),
        (
            "error-failed",
            Message::Error {
                error: Failure::Failed {
                    detail: "cannot save /Library/Application Support/jink/state.json: disk full"
                        .into(),
                },
            },
        ),
    ])
}

#[test]
fn the_daemon_sends_exactly_the_example_messages() -> Result<()> {
    let expected = messages();
    let mut files = Vec::new();
    for entry in std::fs::read_dir(contract().join("messages"))? {
        let path = entry?.path();
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or("odd file name")?
            .to_owned();
        let message = expected
            .get(name.as_str())
            .ok_or_else(|| format!("no message for {name}.json"))?;
        let file: Value = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
        assert_eq!(serde_json::to_value(message)?, file, "{name}.json");
        files.push(name);
    }
    files.sort();
    let names: Vec<&str> = expected.keys().copied().collect();
    assert_eq!(files, names, "every message has its file");
    Ok(())
}

#[test]
fn the_daemon_understands_every_example_request() -> Result<()> {
    let expected = [
        Request::Status,
        Request::Strategies,
        Request::Start { strategy: None },
        Request::Start {
            strategy: Some("alt13".into()),
        },
        Request::Stop,
        Request::Settings,
        Request::UpdateSettings {
            settings: settings(),
        },
        Request::SetStartAtBoot { on: true },
        Request::Find,
        Request::CancelFind,
        Request::Watch,
    ];
    let text = std::fs::read_to_string(contract().join("requests.jsonl"))?;
    let requests = text
        .lines()
        .map(serde_json::from_str::<Request>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    assert_eq!(requests, expected);
    Ok(())
}
