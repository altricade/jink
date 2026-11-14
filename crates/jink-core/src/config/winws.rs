//! Parses a zapret `winws`/`nfqws` argument list into a [`Config`].
//!
//! Only the options zapret-discord-youtube's strategies use are accepted;
//! anything else is an error naming the argument, never silently ignored.
//! Semantics follow zapret v72.9 (`nfq/nfqws.c`):
//! - `--new` starts the next rule;
//! - `--filter-tcp` alone makes the rule ignore UDP, and vice versa;
//! - `--dpi-desync-fake-tls-mod` applies to the TLS fake just before it and to
//!   every later one;
//! - fakes not given fall back to zapret's built-in defaults.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use super::{
    Blob, Capture, Config, Cutoff, CutoffMode, Desync, FakeData, Fooling, HostFakeSplitMods,
    IpIdMode, Marker, MarkerBase, Modes, Rule, Split, TlsFake, TlsMods,
};
use crate::l7::Protocol;
use crate::lists::{DomainList, IpList};
use crate::rules::{Match, PortFilter};

/// Where file arguments (fakes, patterns, lists) are read from.
pub trait FileSource {
    /// # Errors
    /// Any I/O error reading `path`.
    fn read(&self, path: &str) -> std::io::Result<Vec<u8>>;
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ErrorKind {
    #[error("unknown or unsupported option")]
    UnknownOption,
    #[error("expected --option or --option=value")]
    NotAnOption,
    #[error("missing value")]
    MissingValue,
    #[error("invalid value: {0}")]
    BadValue(String),
    #[error("not supported by jink: {0}")]
    Unsupported(String),
    #[error("cannot read {path}: {reason}")]
    File { path: String, reason: String },
}

/// A rejected argument, with its position in the argument list.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("argument {index} `{arg}`: {kind}")]
pub struct ConfigError {
    pub index: usize,
    pub arg: String,
    pub kind: ErrorKind,
}

/// Parses `args` (without the program name).
///
/// # Errors
/// The first argument that is unknown, malformed, unsupported, or names an
/// unreadable file.
pub fn parse(args: &[String], files: &dyn FileSource) -> Result<Config, ConfigError> {
    let mut parser = Parser {
        files,
        domain_lists: HashMap::new(),
        ip_lists: HashMap::new(),
        warnings: Vec::new(),
    };
    let mut capture = Capture::default();
    let mut rules = Vec::new();
    let mut rule = RuleBuilder::default();
    for (index, arg) in args.iter().enumerate() {
        let fail = |kind| ConfigError {
            index,
            arg: arg.clone(),
            kind,
        };
        let opt = arg
            .strip_prefix("--")
            .ok_or_else(|| fail(ErrorKind::NotAnOption))?;
        let (name, value) = match opt.split_once('=') {
            Some((n, v)) => (n, Some(v)),
            None => (opt, None),
        };
        match name {
            "new" => {
                let done = std::mem::take(&mut rule);
                rules.push(done.finish().map_err(fail)?);
            }
            "wf-tcp" => capture.tcp = Some(ports(required(value).map_err(fail)?).map_err(fail)?),
            "wf-udp" => capture.udp = Some(ports(required(value).map_err(fail)?).map_err(fail)?),
            _ => parser.rule_option(&mut rule, name, value).map_err(fail)?,
        }
    }
    let last = args.len().saturating_sub(1);
    rules.push(rule.finish().map_err(|kind| ConfigError {
        index: last,
        arg: args.last().cloned().unwrap_or_default(),
        kind,
    })?);
    Ok(Config {
        capture,
        rules,
        warnings: parser.warnings,
    })
}

fn required(value: Option<&str>) -> Result<&str, ErrorKind> {
    value
        .filter(|v| !v.is_empty())
        .ok_or(ErrorKind::MissingValue)
}

fn bad(what: &str) -> ErrorKind {
    ErrorKind::BadValue(what.to_owned())
}

fn ports(spec: &str) -> Result<PortFilter, ErrorKind> {
    PortFilter::parse(spec).map_err(|_| bad("port filter"))
}

#[derive(Debug, Default)]
struct RuleBuilder {
    matcher: Match,
    desync: Desync,
    tcp_ports: Option<PortFilter>,
    udp_ports: Option<PortFilter>,
    split_positions_given: bool,
    /// The last `--dpi-desync-fake-tls-mod`, applied to later TLS fakes.
    tls_mods: Option<TlsMods>,
}

impl RuleBuilder {
    fn finish(mut self) -> Result<Rule, ErrorKind> {
        // zapret: --filter-tcp alone denies UDP, and vice versa.
        let (tcp, udp) = match (self.tcp_ports, self.udp_ports) {
            (None, None) => (PortFilter::Any, PortFilter::Any),
            (tcp, udp) => (
                tcp.unwrap_or_else(PortFilter::deny_all),
                udp.unwrap_or_else(PortFilter::deny_all),
            ),
        };
        self.matcher.tcp_ports = tcp;
        self.matcher.udp_ports = udp;

        // zapret `split_compat`: seqovl with split modes is a plain byte count.
        let plain_split = matches!(
            self.desync.modes.split,
            Some(Split::MultiSplit | Split::FakedSplit)
        );
        if plain_split
            && self
                .desync
                .seqovl
                .is_some_and(|m| m.base != MarkerBase::Absolute || m.offset < 0)
        {
            return Err(bad("split seqovl must be a positive byte count"));
        }

        // zapret `dp_fake_defaults`: a built-in fake for every protocol not
        // given one. The built-in TLS fake gets rnd,rndsni,dupsid unless a
        // tls mod was set.
        let fakes = &mut self.desync.fakes;
        if fakes.tls.is_empty() {
            fakes.tls.push(TlsFake {
                data: FakeData::Builtin,
                mods: self.tls_mods.unwrap_or(TlsMods {
                    rnd: true,
                    rnd_sni: true,
                    dup_sid: true,
                    sni: None,
                }),
            });
        }
        for list in [
            &mut fakes.http,
            &mut fakes.quic,
            &mut fakes.discord,
            &mut fakes.stun,
            &mut fakes.unknown_tcp,
            &mut fakes.unknown_udp,
        ] {
            if list.is_empty() {
                list.push(FakeData::Builtin);
            }
        }
        Ok(Rule {
            matcher: self.matcher,
            desync: self.desync,
        })
    }
}

struct Parser<'f> {
    files: &'f dyn FileSource,
    /// Each list file is loaded once and shared, as in zapret.
    domain_lists: HashMap<String, Arc<DomainList>>,
    ip_lists: HashMap<String, Arc<IpList>>,
    warnings: Vec<String>,
}

impl Parser<'_> {
    fn rule_option(
        &mut self,
        rule: &mut RuleBuilder,
        name: &str,
        value: Option<&str>,
    ) -> Result<(), ErrorKind> {
        if name == "ip-id" || name.starts_with("dpi-desync") {
            self.desync_option(rule, name, value)
        } else {
            self.filter_option(rule, name, value)
        }
    }

    /// Options deciding which flows the rule applies to.
    fn filter_option(
        &mut self,
        rule: &mut RuleBuilder,
        name: &str,
        value: Option<&str>,
    ) -> Result<(), ErrorKind> {
        match name {
            "filter-l3" => {
                let v = required(value)?;
                let families: HashSet<&str> = v.split(',').collect();
                if families.is_empty() || !families.iter().all(|f| matches!(*f, "ipv4" | "ipv6")) {
                    return Err(bad("expected ipv4, ipv6 or both"));
                }
                rule.matcher.ipv4 = families.contains("ipv4");
                rule.matcher.ipv6 = families.contains("ipv6");
            }
            "filter-tcp" => {
                rule.tcp_ports = Some(merge_ports(rule.tcp_ports.take(), required(value)?)?);
            }
            "filter-udp" => {
                rule.udp_ports = Some(merge_ports(rule.udp_ports.take(), required(value)?)?);
            }
            "filter-l7" => {
                let set = required(value)?
                    .split(',')
                    .map(l7_protocol)
                    .collect::<Result<HashSet<_>, _>>()?;
                rule.matcher.l7.get_or_insert_with(HashSet::new).extend(set);
            }
            "hostlist" => {
                let list = self.domain_list(required(value)?)?;
                rule.matcher.hostlists.include.push(list);
            }
            "hostlist-exclude" => {
                let list = self.domain_list(required(value)?)?;
                rule.matcher.hostlists.exclude.push(list);
            }
            "hostlist-domains" => {
                let list = DomainList::from_entries(required(value)?.split(','));
                rule.matcher.hostlists.include.push(Arc::new(list));
            }
            "hostlist-exclude-domains" => {
                let list = DomainList::from_entries(required(value)?.split(','));
                rule.matcher.hostlists.exclude.push(Arc::new(list));
            }
            "ipset" => {
                let list = self.ip_list(required(value)?)?;
                rule.matcher.ipsets.include.push(list);
            }
            "ipset-exclude" => {
                let list = self.ip_list(required(value)?)?;
                rule.matcher.ipsets.exclude.push(list);
            }
            _ => return Err(ErrorKind::UnknownOption),
        }
        Ok(())
    }

    /// Options deciding what the rule does to matching flows.
    fn desync_option(
        &mut self,
        rule: &mut RuleBuilder,
        name: &str,
        value: Option<&str>,
    ) -> Result<(), ErrorKind> {
        let d = &mut rule.desync;
        match name {
            "ip-id" => {
                d.ip_id = match required(value)? {
                    "seq" => IpIdMode::Seq,
                    "seqgroup" => IpIdMode::SeqGroup,
                    "rnd" => IpIdMode::Random,
                    "zero" => IpIdMode::Zero,
                    _ => return Err(bad("expected seq, seqgroup, rnd or zero")),
                };
            }
            "dpi-desync" => d.modes = modes(required(value)?)?,
            "dpi-desync-repeats" => {
                d.repeats = required(value)?
                    .parse::<u16>()
                    .ok()
                    .filter(|&n| n > 0)
                    .ok_or_else(|| bad("repeats must be 1..65535"))?;
            }
            "dpi-desync-fooling" => d.fooling = fooling(required(value)?)?,
            "dpi-desync-badseq-increment" => {
                d.badseq_increment = required(value)?
                    .parse::<i32>()
                    .map_err(|_| bad("expected a 32-bit integer"))?;
            }
            "dpi-desync-split-pos" => {
                let positions = required(value)?
                    .split(',')
                    .map(marker)
                    .collect::<Result<Vec<_>, _>>()?;
                if !rule.split_positions_given {
                    d.split_positions.clear();
                    rule.split_positions_given = true;
                }
                d.split_positions.extend(positions);
            }
            "dpi-desync-split-seqovl" => {
                let v = required(value)?;
                d.seqovl = if v == "0" { None } else { Some(marker(v)?) };
            }
            "dpi-desync-split-seqovl-pattern" => {
                d.seqovl_pattern = Some(self.blob(required(value)?)?);
            }
            "dpi-desync-fakedsplit-pattern" => {
                d.fakedsplit_pattern = Some(FakeData::Bytes(self.blob(required(value)?)?));
            }
            "dpi-desync-hostfakesplit-mod" => {
                d.hostfakesplit = hostfakesplit_mods(required(value)?)?;
            }
            "dpi-desync-fake-tls" => {
                let v = required(value)?;
                let data = if v == "!" {
                    FakeData::Builtin
                } else {
                    FakeData::Bytes(self.blob(v)?)
                };
                d.fakes.tls.push(TlsFake {
                    data,
                    mods: rule.tls_mods.clone().unwrap_or_default(),
                });
            }
            "dpi-desync-fake-tls-mod" => {
                let mods = tls_mods(required(value)?)?;
                if let Some(last) = d.fakes.tls.last_mut() {
                    last.mods = mods.clone();
                }
                rule.tls_mods = Some(mods);
            }
            "dpi-desync-fake-http" => d.fakes.http.push(self.fake(required(value)?)?),
            "dpi-desync-fake-quic" => d.fakes.quic.push(self.fake(required(value)?)?),
            "dpi-desync-fake-discord" => d.fakes.discord.push(self.fake(required(value)?)?),
            "dpi-desync-fake-stun" => d.fakes.stun.push(self.fake(required(value)?)?),
            "dpi-desync-fake-unknown" => d.fakes.unknown_tcp.push(self.fake(required(value)?)?),
            "dpi-desync-fake-unknown-udp" => d.fakes.unknown_udp.push(self.fake(required(value)?)?),
            "dpi-desync-cutoff" => d.cutoff = Some(cutoff(required(value)?)?),
            "dpi-desync-any-protocol" => {
                d.any_protocol = match value {
                    None | Some("" | "1") => true,
                    Some("0") => false,
                    Some(_) => return Err(bad("expected 0 or 1")),
                };
            }
            _ => return Err(ErrorKind::UnknownOption),
        }
        Ok(())
    }

    fn read(&self, path: &str) -> Result<Vec<u8>, ErrorKind> {
        self.files.read(path).map_err(|e| ErrorKind::File {
            path: path.to_owned(),
            reason: e.to_string(),
        })
    }

    fn read_text(&self, path: &str) -> Result<String, ErrorKind> {
        String::from_utf8(self.read(path)?).map_err(|_| ErrorKind::File {
            path: path.to_owned(),
            reason: "not UTF-8 text".to_owned(),
        })
    }

    fn domain_list(&mut self, path: &str) -> Result<Arc<DomainList>, ErrorKind> {
        if let Some(list) = self.domain_lists.get(path) {
            return Ok(Arc::clone(list));
        }
        let list = Arc::new(DomainList::parse(&self.read_text(path)?));
        self.domain_lists.insert(path.to_owned(), Arc::clone(&list));
        Ok(list)
    }

    fn ip_list(&mut self, path: &str) -> Result<Arc<IpList>, ErrorKind> {
        if let Some(list) = self.ip_lists.get(path) {
            return Ok(Arc::clone(list));
        }
        let (list, invalid) = IpList::parse(&self.read_text(path)?);
        self.warnings.extend(
            invalid
                .into_iter()
                .map(|l| format!("{path}:{}: skipped `{}`", l.line, l.text)),
        );
        let list = Arc::new(list);
        self.ip_lists.insert(path.to_owned(), Arc::clone(&list));
        Ok(list)
    }

    /// `0x`-prefixed hex, or a file path.
    fn blob(&self, value: &str) -> Result<Blob, ErrorKind> {
        let bytes = match value.strip_prefix("0x") {
            Some(hex) => decode_hex(hex)?,
            None => self.read(value)?,
        };
        if bytes.is_empty() {
            return Err(bad("empty payload"));
        }
        Ok(bytes.into())
    }

    fn fake(&self, value: &str) -> Result<FakeData, ErrorKind> {
        self.blob(value).map(FakeData::Bytes)
    }
}

fn merge_ports(existing: Option<PortFilter>, spec: &str) -> Result<PortFilter, ErrorKind> {
    let added = ports(spec)?;
    Ok(match (existing, added) {
        (Some(PortFilter::Items(mut a)), PortFilter::Items(b)) => {
            a.extend(b);
            PortFilter::Items(a)
        }
        (_, added) => added,
    })
}

fn l7_protocol(name: &str) -> Result<Protocol, ErrorKind> {
    match name {
        "http" => Ok(Protocol::Http),
        "tls" => Ok(Protocol::Tls),
        "quic" => Ok(Protocol::Quic),
        "stun" => Ok(Protocol::Stun),
        "discord" => Ok(Protocol::Discord),
        "unknown" => Ok(Protocol::Unknown),
        "wireguard" | "dht" => Err(ErrorKind::Unsupported(format!("--filter-l7={name}"))),
        _ => Err(bad("unknown protocol")),
    }
}

/// `--dpi-desync=a[,b[,c]]`: up to one mode per phase, phases ascending.
fn modes(spec: &str) -> Result<Modes, ErrorKind> {
    let mut modes = Modes::default();
    let mut last_phase = None;
    for name in spec.split(',') {
        let phase = match name {
            "syndata" => {
                modes.syndata = true;
                0
            }
            "fake" => {
                modes.fake = true;
                1
            }
            "multisplit" | "multidisorder" | "fakedsplit" | "hostfakesplit" => {
                modes.split = Some(match name {
                    "multisplit" => Split::MultiSplit,
                    "multidisorder" => Split::MultiDisorder,
                    "fakedsplit" => Split::FakedSplit,
                    _ => Split::HostFakeSplit,
                });
                2
            }
            "" => return Err(bad("empty mode")),
            other => return Err(ErrorKind::Unsupported(format!("desync mode `{other}`"))),
        };
        if last_phase.is_some_and(|p| p >= phase) {
            return Err(bad("modes must be in phase order, one per phase"));
        }
        last_phase = Some(phase);
    }
    Ok(modes)
}

fn fooling(spec: &str) -> Result<Fooling, ErrorKind> {
    spec.split(',')
        .try_fold(Fooling::default(), |f, name| match name {
            "ts" => Ok(Fooling { ts: true, ..f }),
            "badseq" => Ok(Fooling { badseq: true, ..f }),
            "md5sig" => Ok(Fooling { md5sig: true, ..f }),
            "none" => Ok(f),
            other => Err(ErrorKind::Unsupported(format!("fooling `{other}`"))),
        })
}

/// zapret `parse_split_pos`: a non-zero integer, or `marker[+|-n]`.
fn marker(spec: &str) -> Result<Marker, ErrorKind> {
    if let Ok(offset) = spec.parse::<i16>() {
        return if offset == 0 {
            Err(bad("absolute position 0"))
        } else {
            Ok(Marker {
                base: MarkerBase::Absolute,
                offset,
            })
        };
    }
    let split_at = spec.find(['+', '-']).unwrap_or(spec.len());
    let (name, rest) = spec.split_at(split_at);
    let base = match name {
        "method" => MarkerBase::Method,
        "host" => MarkerBase::Host,
        "endhost" => MarkerBase::EndHost,
        "sld" => MarkerBase::Sld,
        "midsld" => MarkerBase::MidSld,
        "endsld" => MarkerBase::EndSld,
        "sniext" => MarkerBase::SniExt,
        _ => return Err(bad("position marker")),
    };
    let offset = if rest.is_empty() {
        0
    } else {
        rest.parse::<i16>().map_err(|_| bad("marker offset"))?
    };
    Ok(Marker { base, offset })
}

fn tls_mods(spec: &str) -> Result<TlsMods, ErrorKind> {
    spec.split(',')
        .try_fold(TlsMods::default(), |m, item| match item.split_once('=') {
            Some(("sni", name)) if !name.is_empty() => Ok(TlsMods {
                sni: Some(name.to_owned()),
                ..m
            }),
            None if item == "rnd" => Ok(TlsMods { rnd: true, ..m }),
            None if item == "rndsni" => Ok(TlsMods { rnd_sni: true, ..m }),
            None if item == "dupsid" => Ok(TlsMods { dup_sid: true, ..m }),
            None if item == "none" => Ok(m),
            _ => Err(ErrorKind::Unsupported(format!("tls mod `{item}`"))),
        })
}

fn hostfakesplit_mods(spec: &str) -> Result<HostFakeSplitMods, ErrorKind> {
    spec.split(',')
        .try_fold(HostFakeSplitMods::default(), |m, item| {
            match item.split_once('=') {
                Some(("host", name)) if !name.is_empty() => Ok(HostFakeSplitMods {
                    host: Some(name.to_owned()),
                    ..m
                }),
                Some(("altorder", "0")) => Ok(HostFakeSplitMods {
                    alt_order: false,
                    ..m
                }),
                Some(("altorder", "1")) => Ok(HostFakeSplitMods {
                    alt_order: true,
                    ..m
                }),
                _ => Err(ErrorKind::Unsupported(format!(
                    "hostfakesplit mod `{item}`"
                ))),
            }
        })
}

/// `nN`, `dN`, `sN`, or a bare `N` (packets).
fn cutoff(spec: &str) -> Result<Cutoff, ErrorKind> {
    let (mode, number) = match spec.split_at_checked(1) {
        Some(("n", n)) => (CutoffMode::Packets, n),
        Some(("d", n)) => (CutoffMode::DataPackets, n),
        Some(("s", n)) => (CutoffMode::SeqBytes, n),
        _ => (CutoffMode::Packets, spec),
    };
    let limit = number.parse::<u32>().map_err(|_| bad("cutoff"))?;
    Ok(Cutoff { mode, limit })
}

fn decode_hex(hex: &str) -> Result<Vec<u8>, ErrorKind> {
    if !hex.len().is_multiple_of(2) {
        return Err(bad("odd number of hex digits"));
    }
    hex.as_bytes()
        .chunks(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|s| u8::from_str_radix(s, 16).ok())
                .ok_or_else(|| bad("hex digit"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{cutoff, decode_hex, marker, modes};
    use crate::config::{CutoffMode, MarkerBase, Split};

    #[test]
    fn markers() {
        let m = marker("sniext+1").unwrap();
        assert_eq!((m.base, m.offset), (MarkerBase::SniExt, 1));
        let m = marker("midsld").unwrap();
        assert_eq!((m.base, m.offset), (MarkerBase::MidSld, 0));
        let m = marker("endhost-2").unwrap();
        assert_eq!((m.base, m.offset), (MarkerBase::EndHost, -2));
        let m = marker("-10").unwrap();
        assert_eq!((m.base, m.offset), (MarkerBase::Absolute, -10));
        assert!(marker("0").is_err());
        assert!(marker("middle").is_err());
        assert!(marker("host+x").is_err());
    }

    #[test]
    fn mode_order() {
        let m = modes("syndata,fake,multisplit").unwrap();
        assert!(m.syndata && m.fake && m.split == Some(Split::MultiSplit));
        assert!(modes("multisplit,fake").is_err(), "phase 2 before phase 1");
        assert!(modes("multisplit,fakedsplit").is_err(), "two phase-2 modes");
        assert!(modes("fake,").is_err());
        assert!(modes("rst").is_err(), "not supported");
    }

    #[test]
    fn cutoffs_and_hex() {
        assert_eq!(cutoff("n4").unwrap().mode, CutoffMode::Packets);
        assert_eq!(cutoff("d3").unwrap().limit, 3);
        assert_eq!(cutoff("7").unwrap().mode, CutoffMode::Packets);
        assert!(cutoff("x4").is_err());
        assert_eq!(decode_hex("00ff10").unwrap(), vec![0, 0xff, 0x10]);
        assert!(decode_hex("0").is_err() && decode_hex("zz").is_err());
    }
}
