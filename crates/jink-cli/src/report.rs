//! Human-readable summary of a loaded strategy for `jink check`.

use jink_core::config::platform::Platform;
use jink_core::config::{Config, Cutoff, CutoffMode, Desync, Fooling, Marker, MarkerBase, Split};
use jink_core::desync::unimplemented;
use jink_core::rules::{Match, PortFilter};

/// The lines `jink check` prints.
pub(crate) fn describe(config: &Config, platform: Platform) -> Vec<String> {
    let capture = |f: Option<&PortFilter>| f.map_or_else(|| "none".to_owned(), ports);
    let mut lines = vec![
        format!(
            "Captured ports: TCP {} | UDP {}",
            capture(config.capture.tcp.as_ref()),
            capture(config.capture.udp.as_ref())
        ),
        "Rules (first match wins):".to_owned(),
    ];
    lines.extend(config.rules.iter().zip(1..).map(|(rule, n)| {
        format!(
            "  {n}. {} -> {}",
            matcher(&rule.matcher),
            action(&rule.desync)
        )
    }));

    let unsupported = platform.unsupported(config);
    lines.push(String::new());
    if unsupported.is_empty() {
        lines.push(format!("{platform:?}: every technique used is possible."));
    } else {
        lines.push(format!(
            "{platform:?}: techniques this platform cannot perform:"
        ));
        lines.extend(
            unsupported
                .iter()
                .map(|u| format!("  rule {}: {:?}", u.rule.saturating_add(1), u.technique)),
        );
    }

    let missing: Vec<String> = config
        .rules
        .iter()
        .zip(1..)
        .filter_map(|(rule, n)| {
            let m = unimplemented(rule);
            (!m.is_empty()).then(|| format!("  rule {n}: {}", m.join(", ")))
        })
        .collect();
    if missing.is_empty() {
        lines.push("jink: every rule can be applied.".to_owned());
    } else {
        lines.push(
            "jink: not implemented yet (these rules would pass traffic unchanged):".to_owned(),
        );
        lines.extend(missing);
    }
    if !config.warnings.is_empty() {
        lines.push("Warnings:".to_owned());
        lines.extend(config.warnings.iter().map(|w| format!("  {w}")));
    }
    lines
}

fn ports(filter: &PortFilter) -> String {
    let Some(items) = filter.items() else {
        return "any".to_owned();
    };
    if items.iter().all(|r| r.denies_all()) {
        return "none".to_owned();
    }
    items
        .iter()
        .map(|r| {
            let neg = if r.negated() { "~" } else { "" };
            if r.from() == r.to() {
                format!("{neg}{}", r.from())
            } else {
                format!("{neg}{}-{}", r.from(), r.to())
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn matcher(m: &Match) -> String {
    let tcp = ports(&m.tcp_ports);
    let udp = ports(&m.udp_ports);
    let mut parts = vec![match (tcp.as_str(), udp.as_str()) {
        ("none", "none") => "nothing".to_owned(),
        (t, "none") => format!("TCP {t}"),
        ("none", u) => format!("UDP {u}"),
        (t, u) => format!("TCP {t}, UDP {u}"),
    }];
    if let Some(l7) = &m.l7 {
        let mut names: Vec<String> = l7.iter().map(|p| format!("{p:?}").to_lowercase()).collect();
        names.sort();
        parts.push(format!("protocols {}", names.join(",")));
    }
    let lists = |inc: usize, exc: usize, what: &str| match (inc, exc) {
        (0, 0) => None,
        (0, e) => Some(format!("{what}: not in {e} excluded list(s)")),
        (i, 0) => Some(format!("{what}: in {i} list(s)")),
        (i, e) => Some(format!("{what}: in {i} list(s), not in {e}")),
    };
    parts.extend(lists(
        m.hostlists.include.len(),
        m.hostlists.exclude.len(),
        "domains",
    ));
    parts.extend(lists(m.ipsets.include.len(), m.ipsets.exclude.len(), "IPs"));
    if !m.ipv6 {
        parts.push("IPv4 only".to_owned());
    }
    parts.join(" | ")
}

fn action(d: &Desync) -> String {
    let mut parts = Vec::new();
    if d.modes.syndata {
        parts.push("syndata".to_owned());
    }
    if d.modes.fake {
        let fooling = fooling_names(d.fooling);
        let fooled = if fooling.is_empty() {
            String::new()
        } else {
            format!(", fooling {}", fooling.join(","))
        };
        parts.push(format!("fake x{}{fooled}", d.repeats));
    }
    if let Some(split) = d.modes.split {
        let name = match split {
            Split::MultiSplit => "multisplit",
            Split::MultiDisorder => "multidisorder",
            Split::FakedSplit => "fakedsplit",
            Split::HostFakeSplit => "hostfakesplit",
        };
        let at: Vec<String> = d.split_positions.iter().map(|m| marker(*m)).collect();
        let overlap = d
            .seqovl
            .map_or_else(String::new, |m| format!(", seqovl {}", marker(m)));
        // fakedsplit and hostfakesplit send fooled fakes of their own; show
        // the fooling if the fake phase has not already.
        let fooling = fooling_names(d.fooling);
        let own_fooling = if d.modes.fake || fooling.is_empty() {
            String::new()
        } else {
            format!(", fooling {}", fooling.join(","))
        };
        parts.push(match split {
            Split::HostFakeSplit => {
                let host = d.hostfakesplit.host.as_deref().unwrap_or("random");
                let order = if d.hostfakesplit.alt_order {
                    ", altorder"
                } else {
                    ""
                };
                format!("{name} around the host name (fake host {host}{order}){own_fooling}")
            }
            Split::FakedSplit => format!("{name} at {}{overlap}{own_fooling}", at.join(",")),
            Split::MultiSplit | Split::MultiDisorder => {
                format!("{name} at {}{overlap}", at.join(","))
            }
        });
    }
    if parts.is_empty() {
        return "pass unchanged".to_owned();
    }
    if let Some(c) = d.cutoff {
        parts.push(cutoff(c));
    }
    if d.any_protocol {
        parts.push("any protocol".to_owned());
    }
    parts.join("; ")
}

fn marker(m: Marker) -> String {
    let base = match m.base {
        MarkerBase::Absolute => return m.offset.to_string(),
        MarkerBase::Method => "method",
        MarkerBase::Host => "host",
        MarkerBase::EndHost => "endhost",
        MarkerBase::Sld => "sld",
        MarkerBase::MidSld => "midsld",
        MarkerBase::EndSld => "endsld",
        MarkerBase::SniExt => "sniext",
    };
    match m.offset {
        0 => base.to_owned(),
        o if o > 0 => format!("{base}+{o}"),
        o => format!("{base}{o}"),
    }
}

fn cutoff(c: Cutoff) -> String {
    let unit = match c.mode {
        CutoffMode::Packets => "packets",
        CutoffMode::DataPackets => "data packets",
        CutoffMode::SeqBytes => "bytes",
    };
    format!("first {} {unit} only", c.limit)
}

fn fooling_names(f: Fooling) -> Vec<&'static str> {
    [(f.ts, "ts"), (f.badseq, "badseq"), (f.md5sig, "md5sig")]
        .into_iter()
        .filter_map(|(on, name)| on.then_some(name))
        .collect()
}
