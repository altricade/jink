//! Domain lists, as zapret hostlists (`nfq/hostlist.c`).
//!
//! One name per line, case-insensitive. Lines starting with `#`, `;` or `/`
//! are comments. A name matches itself and its subdomains; a leading `^`
//! restricts it to the exact name. Unlike zapret, surrounding whitespace on a
//! line is ignored rather than becoming part of the name.

use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scope {
    WithSubdomains,
    ExactOnly,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DomainList {
    names: HashMap<String, Scope>,
}

impl DomainList {
    /// Parses list-file text. Every non-comment line is a name, so this cannot
    /// fail; an odd line simply never matches anything.
    #[must_use]
    pub fn parse(text: &str) -> Self {
        Self::from_entries(text.lines())
    }

    /// Builds a list from individual entries, as `--hostlist-domains=a,b`.
    #[must_use]
    pub fn from_entries<'a>(entries: impl IntoIterator<Item = &'a str>) -> Self {
        let names = entries
            .into_iter()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with(['#', ';', '/']))
            .map(|line| match line.strip_prefix('^') {
                Some(exact) => (exact.to_ascii_lowercase(), Scope::ExactOnly),
                None => (line.to_ascii_lowercase(), Scope::WithSubdomains),
            })
            .fold(HashMap::new(), |mut names, (name, scope)| {
                // Listed both ways: the broader entry wins.
                names
                    .entry(name)
                    .and_modify(|s| {
                        if scope == Scope::WithSubdomains {
                            *s = scope;
                        }
                    })
                    .or_insert(scope);
                names
            });
        Self { names }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.names.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// Whether `host` (any case) is listed, directly or as a subdomain of a
    /// listed name. An IP-literal host only matches an identical entry, as in
    /// zapret.
    #[must_use]
    pub fn matches(&self, host: &str) -> bool {
        let host = host.to_ascii_lowercase();
        if host.parse::<IpAddr>().is_ok() {
            return self.names.contains_key(&host);
        }
        // "a.b.c" -> "b.c" -> "c": drop one leading label at a time.
        std::iter::successors(Some(host.as_str()), |h| {
            h.split_once('.').map(|(_, rest)| rest)
        })
        .enumerate()
        .any(|(depth, candidate)| match self.names.get(candidate) {
            Some(Scope::WithSubdomains) => true,
            Some(Scope::ExactOnly) => depth == 0,
            None => false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::DomainList;

    #[test]
    fn subdomains_and_exact_entries() {
        let list = DomainList::parse(
            "# comment\r\n; also\r\n/ and this\r\n\r\nGoogle.com\r\n^dns.google\r\n",
        );
        assert_eq!(list.len(), 2);
        assert!(list.matches("google.com"));
        assert!(list.matches("WWW.Google.COM"));
        assert!(list.matches("a.b.google.com"));
        assert!(
            !list.matches("notgoogle.com"),
            "suffix must be a whole label"
        );
        assert!(list.matches("dns.google"));
        assert!(
            !list.matches("x.dns.google"),
            "^ entries do not cover subdomains"
        );
        assert!(!list.matches("google"));
    }

    #[test]
    fn ip_literals_match_exactly() {
        let list = DomainList::from_entries(["1.2.3.4", "3.4"]);
        assert!(list.matches("1.2.3.4"));
        assert!(!list.matches("5.6.3.4"), "no label stripping for IP hosts");
        // Not a valid IP, so it is a name and label stripping applies.
        assert!(list.matches("9.1.2.3.4"));
    }

    #[test]
    fn broader_duplicate_wins() {
        let list = DomainList::from_entries(["^a.com", "a.com"]);
        assert!(list.matches("x.a.com"));
    }
}
