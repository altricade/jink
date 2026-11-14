//! Which rule (zapret "desync profile") applies to a flow.
//!
//! Mirrors zapret's `dp_match` (`nfq/desync.c`): rules are tried in order and
//! the first match wins. A rule with a domain list cannot match until the
//! flow's host name is known, so the engine asks again once the ClientHello
//! (or HTTP `Host`, or QUIC Initial) has been read.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use crate::l7::Protocol;
use crate::lists::{DomainList, IpList};

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PortFilterError {
    #[error("invalid port filter item")]
    Invalid,
}

/// One port filter item: `443`, `1024-65535`, `*`, or negated `~22`.
/// Built only through [`PortFilter::parse`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    from: u16,
    to: u16,
    negated: bool,
}

impl PortRange {
    #[must_use]
    pub const fn from(self) -> u16 {
        self.from
    }

    #[must_use]
    pub const fn to(self) -> u16 {
        self.to
    }

    #[must_use]
    pub const fn negated(self) -> bool {
        self.negated
    }

    /// zapret's deny-all item (`0`): matches no port at all.
    #[must_use]
    pub const fn denies_all(self) -> bool {
        self.from == 0 && self.to == 0 && self.negated
    }

    fn parse(item: &str) -> Result<Self, PortFilterError> {
        if item == "*" {
            return Ok(Self {
                from: 1,
                to: u16::MAX,
                negated: false,
            });
        }
        let (negated, spec) = match item.strip_prefix('~') {
            Some(rest) => (true, rest),
            None => (false, item),
        };
        let parse = |s: &str| s.parse::<u16>().map_err(|_| PortFilterError::Invalid);
        let (from, to) = if let Some((a, b)) = spec.split_once('-') {
            (parse(a)?, parse(b)?)
        } else {
            let p = parse(spec)?;
            (p, p)
        };
        if from > to {
            return Err(PortFilterError::Invalid);
        }
        // zapret: "0" means deny all, even without `~`.
        let negated = negated || (from == 0 && to == 0);
        Ok(Self { from, to, negated })
    }

    /// zapret `pf_in_range`: port 0 never matches; `0`/`0-0` covers all ports
    /// before negation.
    fn contains(self, port: u16) -> bool {
        let in_range = (self.from == 0 && self.to == 0) || (self.from..=self.to).contains(&port);
        port != 0 && (in_range != self.negated)
    }
}

/// Ports a rule accepts for one transport protocol.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum PortFilter {
    /// No filter given: every port.
    #[default]
    Any,
    /// Matches if any item matches. Empty means no port at all, which zapret
    /// applies to UDP when a rule only gives `--filter-tcp`, and vice versa.
    Items(Vec<PortRange>),
}

impl PortFilter {
    /// Parses a comma-separated filter such as `80,443,2053-2096,~22`.
    ///
    /// # Errors
    /// [`PortFilterError::Invalid`] for any item that is not a port, range,
    /// `*`, or one of those negated with `~`.
    pub fn parse(spec: &str) -> Result<Self, PortFilterError> {
        spec.split(',')
            .map(PortRange::parse)
            .collect::<Result<Vec<_>, _>>()
            .map(Self::Items)
    }

    #[must_use]
    pub const fn deny_all() -> Self {
        Self::Items(Vec::new())
    }

    /// The items of an explicit filter; `None` for [`PortFilter::Any`].
    #[must_use]
    pub fn items(&self) -> Option<&[PortRange]> {
        match self {
            Self::Any => None,
            Self::Items(items) => Some(items),
        }
    }

    #[must_use]
    pub fn contains(&self, port: u16) -> bool {
        match self {
            Self::Any => true,
            Self::Items(items) => items.iter().any(|r| r.contains(port)),
        }
    }
}

/// Include and exclude lists of one kind. A flow is admitted if no exclude
/// list matches and, when any include list is given, one of them matches.
/// Lists are shared: zapret loads each file once for all rules using it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListSet<L> {
    pub include: Vec<Arc<L>>,
    pub exclude: Vec<Arc<L>>,
}

impl<L> Default for ListSet<L> {
    fn default() -> Self {
        Self {
            include: Vec::new(),
            exclude: Vec::new(),
        }
    }
}

impl<L> ListSet<L> {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.include.is_empty() && self.exclude.is_empty()
    }

    fn admits(&self, listed: impl Fn(&L) -> bool) -> bool {
        !self.exclude.iter().any(|l| listed(l))
            && (self.include.is_empty() || self.include.iter().any(|l| listed(l)))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transport {
    Tcp,
    Udp,
}

/// What is known about a flow when a rule is chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Flow<'a> {
    pub transport: Transport,
    /// The server side of the flow.
    pub dst: SocketAddr,
    pub l7: Protocol,
    /// Normalized with [`normalize_host`]; `None` until it has been read.
    pub hostname: Option<&'a str>,
}

/// The conditions of one rule (one `--new` section of a zapret command line).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match {
    pub ipv4: bool,
    pub ipv6: bool,
    pub tcp_ports: PortFilter,
    pub udp_ports: PortFilter,
    /// `None` accepts every protocol, including not-yet-identified ones.
    pub l7: Option<HashSet<Protocol>>,
    pub hostlists: ListSet<DomainList>,
    pub ipsets: ListSet<IpList>,
}

impl Default for Match {
    fn default() -> Self {
        Self {
            ipv4: true,
            ipv6: true,
            tcp_ports: PortFilter::Any,
            udp_ports: PortFilter::Any,
            l7: None,
            hostlists: ListSet::default(),
            ipsets: ListSet::default(),
        }
    }
}

impl Match {
    /// zapret `dp_match`, minus auto-hostlists and Wi-Fi filters.
    #[must_use]
    pub fn matches(&self, flow: &Flow<'_>) -> bool {
        let family_ok = match flow.dst.ip() {
            IpAddr::V4(_) => self.ipv4,
            IpAddr::V6(_) => self.ipv6,
        };
        let ports = match flow.transport {
            Transport::Tcp => &self.tcp_ports,
            Transport::Udp => &self.udp_ports,
        };
        if !family_ok || !ports.contains(flow.dst.port()) {
            return false;
        }
        if self.l7.as_ref().is_some_and(|set| !set.contains(&flow.l7)) {
            return false;
        }
        if !self.hostlists.is_empty() && flow.hostname.is_none() {
            return false;
        }
        if !self.ipsets.admits(|l| l.contains(flow.dst.ip())) {
            return false;
        }
        match flow.hostname {
            Some(host) => self.hostlists.admits(|l| l.matches(host)),
            None => true,
        }
    }
}

/// The index of the first rule that matches, as zapret `dp_find`.
#[must_use]
pub fn first_match(rules: &[Match], flow: &Flow<'_>) -> Option<usize> {
    rules.iter().position(|r| r.matches(flow))
}

/// Lowercases a host name and strips an HTTP `:port` (keeping a bracketed
/// IPv6 literal's address).
#[must_use]
pub fn normalize_host(raw: &str) -> String {
    let host = match raw.strip_prefix('[') {
        Some(rest) => rest.split_once(']').map_or(rest, |(addr, _)| addr),
        None => match raw.split_once(':') {
            Some((name, port)) if !port.contains(':') => name,
            _ => raw,
        },
    };
    host.to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::{PortFilter, normalize_host};

    #[test]
    fn port_filters_follow_zapret() {
        let f = PortFilter::parse("80,443,2053-2096").unwrap();
        assert!(f.contains(80) && f.contains(2053) && f.contains(2096));
        assert!(!f.contains(8080) && !f.contains(2097));
        let not_ssh = PortFilter::parse("~22").unwrap();
        assert!(not_ssh.contains(443) && !not_ssh.contains(22));
        let star = PortFilter::parse("*").unwrap();
        assert!(star.contains(1) && star.contains(65535) && !star.contains(0));
        let zero = PortFilter::parse("0").unwrap();
        assert!(!zero.contains(443), "'0' denies everything");
        assert!(PortFilter::Any.contains(5) && !PortFilter::deny_all().contains(5));
        for bad in ["", "70000", "9-1", "a", "1-", "~"] {
            assert!(PortFilter::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn host_normalization() {
        assert_eq!(normalize_host("WWW.Example.COM"), "www.example.com");
        assert_eq!(normalize_host("example.com:8080"), "example.com");
        assert_eq!(normalize_host("[2001:DB8::1]:443"), "2001:db8::1");
        assert_eq!(normalize_host("2001:db8::1"), "2001:db8::1");
    }
}
