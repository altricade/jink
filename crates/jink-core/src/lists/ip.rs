//! IP lists, as zapret ipsets (`nfq/ipset.c`).
//!
//! One address or CIDR network per line (`1.2.3.0/24`, `2001:db8::/32`,
//! `::1`). Lines starting with `#`, `;` or `/` are comments. Unparsable lines
//! are skipped like in zapret, but reported back to the caller instead of
//! only being logged.

use std::collections::{BTreeMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A list line that is neither a comment nor a valid address/network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidLine {
    /// 1-based line number.
    pub line: usize,
    pub text: String,
}

/// Networks grouped by prefix length; a lookup masks the address once per
/// distinct prefix length present (at most 33 for IPv4, 129 for IPv6).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IpList {
    v4: BTreeMap<u8, HashSet<u32>>,
    v6: BTreeMap<u8, HashSet<u128>>,
}

impl IpList {
    /// Parses list-file text; returns the list and the lines it skipped.
    #[must_use]
    pub fn parse(text: &str) -> (Self, Vec<InvalidLine>) {
        text.lines().enumerate().fold(
            (Self::default(), Vec::new()),
            |(mut list, mut invalid), (idx, raw)| {
                let line = raw.trim();
                if !line.is_empty() && !line.starts_with(['#', ';', '/']) && !list.insert(line) {
                    invalid.push(InvalidLine {
                        line: idx.saturating_add(1),
                        text: line.to_owned(),
                    });
                }
                (list, invalid)
            },
        )
    }

    /// Adds one `addr` or `addr/len`; `false` if it does not parse.
    fn insert(&mut self, cidr: &str) -> bool {
        let (addr, prefix) = match cidr.split_once('/') {
            Some((a, p)) => match p.parse::<u8>() {
                Ok(len) => (a, Some(len)),
                Err(_) => return false,
            },
            None => (cidr, None),
        };
        match addr.parse::<IpAddr>() {
            Ok(IpAddr::V4(a)) => {
                let len = prefix.unwrap_or(32);
                let Some(net) = mask_v4(a, len) else {
                    return false;
                };
                self.v4.entry(len).or_default().insert(net);
                true
            }
            Ok(IpAddr::V6(a)) => {
                let len = prefix.unwrap_or(128);
                let Some(net) = mask_v6(a, len) else {
                    return false;
                };
                self.v6.entry(len).or_default().insert(net);
                true
            }
            Err(_) => false,
        }
    }

    /// Number of distinct networks.
    #[must_use]
    pub fn len(&self) -> usize {
        let v4: usize = self.v4.values().map(HashSet::len).sum();
        let v6: usize = self.v6.values().map(HashSet::len).sum();
        v4.saturating_add(v6)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    #[must_use]
    pub fn contains(&self, addr: IpAddr) -> bool {
        match addr {
            IpAddr::V4(a) => self
                .v4
                .iter()
                .any(|(&len, nets)| mask_v4(a, len).is_some_and(|n| nets.contains(&n))),
            IpAddr::V6(a) => self
                .v6
                .iter()
                .any(|(&len, nets)| mask_v6(a, len).is_some_and(|n| nets.contains(&n))),
        }
    }
}

/// The network address of `a/len`; `None` for an invalid prefix length.
fn mask_v4(a: Ipv4Addr, len: u8) -> Option<u32> {
    let host_bits = 32_u32.checked_sub(u32::from(len))?;
    Some(u32::from(a) & u32::MAX.checked_shl(host_bits).unwrap_or(0))
}

fn mask_v6(a: Ipv6Addr, len: u8) -> Option<u128> {
    let host_bits = 128_u32.checked_sub(u32::from(len))?;
    Some(u128::from(a) & u128::MAX.checked_shl(host_bits).unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::{InvalidLine, IpList};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn networks_hosts_and_comments() {
        let (list, invalid) = IpList::parse(
            "# c\r\n1.1.1.0/24\r\n10.0.0.0/8\r\n8.8.8.8\r\n::1\r\nfc00::/7\r\n0.0.0.0/0x\r\n",
        );
        assert_eq!(list.len(), 5);
        assert_eq!(
            invalid,
            vec![InvalidLine {
                line: 7,
                text: "0.0.0.0/0x".into()
            }]
        );
        assert!(list.contains(ip("1.1.1.1")));
        assert!(list.contains(ip("10.200.3.4")));
        assert!(list.contains(ip("8.8.8.8")));
        assert!(!list.contains(ip("8.8.8.9")));
        assert!(!list.contains(ip("1.1.2.1")));
        assert!(list.contains(ip("::1")));
        assert!(list.contains(ip("fd12::5")));
        assert!(!list.contains(ip("fe80::1")));
    }

    #[test]
    fn host_bits_are_masked_and_bad_prefixes_rejected() {
        let (list, invalid) = IpList::parse("192.168.1.77/24\n1.2.3.4/33\n::/129\nnot-an-ip\n");
        assert!(list.contains(ip("192.168.1.1")), "stored as 192.168.1.0/24");
        assert_eq!(invalid.len(), 3);
    }

    #[test]
    fn zero_prefix_matches_everything_of_that_family() {
        let (list, _) = IpList::parse("0.0.0.0/0\n");
        assert!(list.contains(ip("203.0.113.9")));
        assert!(!list.contains(ip("2001:db8::1")));
    }
}
