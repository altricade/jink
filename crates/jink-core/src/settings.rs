//! What the user sets on top of a strategy: their own sites and IPs, the
//! sites and IPs to leave alone, gaming mode and the IP list mode (zapret's
//! `*-user.txt` lists, game filter and IP set switch). Every value is
//! validated when parsed, so a [`Settings`] always builds a working
//! configuration (see [`crate::catalog::build`]).

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

/// A site: a domain name, which also covers its subdomains.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Site(String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SiteError {
    #[error("empty")]
    Empty,
    #[error("an IP address: add it to the IPs instead")]
    IpAddress,
    #[error("a name with non-Latin letters: enter its xn-- form")]
    NotAscii,
    #[error("needs its ending too, like example.com")]
    NoDot,
    #[error("not a valid domain name")]
    Invalid,
}

impl Site {
    /// The site in `input`: a domain (`youtube.com`), or a link to it
    /// (`https://www.youtube.com/watch?v=…`), whose domain is taken.
    ///
    /// # Errors
    /// If `input` holds no valid domain name.
    pub fn parse(input: &str) -> Result<Self, SiteError> {
        let text = input.trim();
        let text = text.split_once("://").map_or(text, |(_, rest)| rest);
        let authority = text.split(['/', '?', '#']).next().unwrap_or_default();
        let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
        if host.starts_with('[') {
            return Err(SiteError::IpAddress);
        }
        let host = host.split_once(':').map_or(host, |(name, _)| name);
        let host = host
            .trim_start_matches("*.")
            .trim_start_matches('.')
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if host.is_empty() {
            return Err(SiteError::Empty);
        }
        if host.parse::<IpAddr>().is_ok() {
            return Err(SiteError::IpAddress);
        }
        if !host.is_ascii() {
            return Err(SiteError::NotAscii);
        }
        if !host.contains('.') {
            return Err(SiteError::NoDot);
        }
        let label_ok = |label: &str| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        };
        if host.len() > 253 || !host.split('.').all(label_ok) {
            return Err(SiteError::Invalid);
        }
        Ok(Self(host))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Site {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An IP address or network (`1.2.3.4`, `1.2.3.0/24`, `2001:db8::/32`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpNet {
    network: IpAddr,
    prefix: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("not an IP address or network (like 1.2.3.4 or 1.2.3.0/24)")]
pub struct IpNetError;

impl IpNet {
    /// # Errors
    /// If `input` is not an address, or an address with a prefix length the
    /// address family allows. Host bits are cleared (`1.2.3.4/24` is
    /// `1.2.3.0/24`).
    pub fn parse(input: &str) -> Result<Self, IpNetError> {
        let text = input.trim();
        let (address, prefix) = match text.split_once('/') {
            Some((a, p)) => (a, Some(p.parse::<u8>().map_err(|_| IpNetError)?)),
            None => (text, None),
        };
        let address: IpAddr = address.parse().map_err(|_| IpNetError)?;
        let (bits, max) = match address {
            IpAddr::V4(a) => (u128::from(a.to_bits()), 32),
            IpAddr::V6(a) => (a.to_bits(), 128),
        };
        let prefix = prefix.unwrap_or(max);
        let host_bits = u32::from(max.checked_sub(prefix).ok_or(IpNetError)?);
        let network = bits
            .checked_shr(host_bits)
            .and_then(|b| b.checked_shl(host_bits))
            .unwrap_or(0);
        let network = match address {
            IpAddr::V4(_) => IpAddr::V4(u32::try_from(network).map_err(|_| IpNetError)?.into()),
            IpAddr::V6(_) => IpAddr::V6(network.into()),
        };
        Ok(Self { network, prefix })
    }
}

impl fmt::Display for IpNet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let full = if self.network.is_ipv4() { 32 } else { 128 };
        if self.prefix == full {
            write!(f, "{}", self.network)
        } else {
            write!(f, "{}/{}", self.network, self.prefix)
        }
    }
}

/// A port range, `from-to` or one port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ports {
    from: u16,
    to: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("not a port range (like 1024-65535)")]
pub struct PortsError;

impl Ports {
    /// The ports gaming mode covers unless changed.
    pub const GAMES: Self = Self {
        from: 1024,
        to: u16::MAX,
    };

    /// # Errors
    /// If `input` is not `from-to` with `1 <= from <= to`, or one port.
    pub fn parse(input: &str) -> Result<Self, PortsError> {
        let text = input.trim();
        let (from, to) = text.split_once('-').unwrap_or((text, text));
        let port = |p: &str| p.trim().parse::<u16>().map_err(|_| PortsError);
        let (from, to) = (port(from)?, port(to)?);
        if from == 0 || from > to {
            return Err(PortsError);
        }
        Ok(Self { from, to })
    }
}

impl fmt::Display for Ports {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.from == self.to {
            write!(f, "{}", self.from)
        } else {
            write!(f, "{}-{}", self.from, self.to)
        }
    }
}

/// Which game traffic gets desync: any port in the ranges, to IPs of the IP
/// list (zapret's game filter).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GamingMode {
    #[default]
    Off,
    Tcp,
    Udp,
    Both,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gaming {
    pub mode: GamingMode,
    /// Kept while the mode leaves TCP out, so switching back restores them.
    pub tcp_ports: Ports,
    pub udp_ports: Ports,
}

impl Default for Gaming {
    fn default() -> Self {
        Self {
            mode: GamingMode::Off,
            tcp_ports: Ports::GAMES,
            udp_ports: Ports::GAMES,
        }
    }
}

impl Gaming {
    /// The TCP ports, if the mode covers TCP.
    #[must_use]
    pub const fn tcp(&self) -> Option<Ports> {
        match self.mode {
            GamingMode::Tcp | GamingMode::Both => Some(self.tcp_ports),
            GamingMode::Off | GamingMode::Udp => None,
        }
    }

    /// The UDP ports, if the mode covers UDP.
    #[must_use]
    pub const fn udp(&self) -> Option<Ports> {
        match self.mode {
            GamingMode::Udp | GamingMode::Both => Some(self.udp_ports),
            GamingMode::Off | GamingMode::Tcp => None,
        }
    }
}

/// Which IPs the IP rules (and gaming mode) cover, besides the user's own
/// (zapret's IP set switch: none / loaded / any).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IpListMode {
    /// Only the user's own IPs.
    #[default]
    Off,
    /// The built-in list (Discord, Cloudflare and other networks).
    BuiltIn,
    /// Every IP.
    All,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Settings {
    /// Sites to desync besides the built-in list.
    pub my_sites: Vec<Site>,
    /// IPs to desync besides the IP list.
    pub my_ips: Vec<IpNet>,
    /// Sites never to desync.
    pub excluded_sites: Vec<Site>,
    /// IPs never to desync.
    pub excluded_ips: Vec<IpNet>,
    pub gaming: Gaming,
    pub ip_list: IpListMode,
}

impl FromStr for Site {
    type Err = SiteError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl FromStr for IpNet {
    type Err = IpNetError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl FromStr for Ports {
    type Err = PortsError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::{Gaming, GamingMode, IpNet, IpNetError, Ports, PortsError, Site, SiteError};

    fn site(input: &str) -> Result<String, SiteError> {
        Site::parse(input).map(|s| s.to_string())
    }

    #[test]
    fn sites_come_from_domains_and_links() {
        for (input, expected) in [
            ("youtube.com", "youtube.com"),
            ("  YouTube.COM  ", "youtube.com"),
            (
                "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
                "www.youtube.com",
            ),
            ("http://user:pass@discord.gg:8080/invite", "discord.gg"),
            ("rutracker.org/forum/index.php", "rutracker.org"),
            ("*.googlevideo.com", "googlevideo.com"),
            (".example.org.", "example.org"),
            ("example.com#top", "example.com"),
            ("my_host.example.com", "my_host.example.com"),
        ] {
            assert_eq!(site(input).as_deref(), Ok(expected), "{input}");
        }
    }

    #[test]
    fn bad_sites_say_why() {
        assert_eq!(site("   "), Err(SiteError::Empty));
        assert_eq!(site("https:///path"), Err(SiteError::Empty));
        assert_eq!(site("1.2.3.4"), Err(SiteError::IpAddress));
        assert_eq!(
            site("https://[2001:db8::1]:443/"),
            Err(SiteError::IpAddress)
        );
        assert_eq!(site("пример.рф"), Err(SiteError::NotAscii));
        assert_eq!(site("youtube"), Err(SiteError::NoDot));
        assert_eq!(site("bad..example.com"), Err(SiteError::Invalid));
        assert_eq!(site("-bad.example.com"), Err(SiteError::Invalid));
        assert_eq!(site("bad-.example.com"), Err(SiteError::Invalid));
        assert_eq!(site("sp ace.example.com"), Err(SiteError::Invalid));
        assert_eq!(
            site(&format!("{}.com", "a".repeat(64))),
            Err(SiteError::Invalid)
        );
        let long = format!("{}.com", vec!["a".repeat(60); 5].join("."));
        assert_eq!(site(&long), Err(SiteError::Invalid));
    }

    #[test]
    fn ip_networks_are_normalized() {
        let ip = |input: &str| IpNet::parse(input).map(|n| n.to_string());
        assert_eq!(ip("1.2.3.4").as_deref(), Ok("1.2.3.4"));
        assert_eq!(ip(" 1.2.3.4/24 ").as_deref(), Ok("1.2.3.0/24"));
        assert_eq!(ip("1.2.3.4/32").as_deref(), Ok("1.2.3.4"));
        assert_eq!(ip("0.0.0.0/0").as_deref(), Ok("0.0.0.0/0"));
        assert_eq!(ip("2001:db8::1/32").as_deref(), Ok("2001:db8::/32"));
        assert_eq!(ip("2001:db8::1").as_deref(), Ok("2001:db8::1"));
        for bad in ["1.2.3.4/33", "2001:db8::/129", "1.2.3", "1.2.3.4/", "x", ""] {
            assert_eq!(ip(bad), Err(IpNetError), "{bad}");
        }
    }

    #[test]
    fn port_ranges() {
        let ports = |input: &str| Ports::parse(input).map(|p| p.to_string());
        assert_eq!(ports("1024-65535").as_deref(), Ok("1024-65535"));
        assert_eq!(ports(" 27015 ").as_deref(), Ok("27015"));
        assert_eq!(ports("27015-27015").as_deref(), Ok("27015"));
        for bad in ["0", "0-100", "200-100", "1-65536", "a-b", "", "-5"] {
            assert_eq!(ports(bad), Err(PortsError), "{bad}");
        }
    }

    #[test]
    fn gaming_mode_picks_the_protocols() {
        let tcp = Ports::parse("27015-27030").unwrap();
        let with = |mode| Gaming {
            mode,
            tcp_ports: tcp,
            udp_ports: Ports::GAMES,
        };
        assert_eq!(with(GamingMode::Off).tcp(), None);
        assert_eq!(with(GamingMode::Off).udp(), None);
        assert_eq!(with(GamingMode::Tcp).tcp(), Some(tcp));
        assert_eq!(with(GamingMode::Tcp).udp(), None);
        assert_eq!(with(GamingMode::Udp).tcp(), None);
        assert_eq!(with(GamingMode::Udp).udp(), Some(Ports::GAMES));
        assert_eq!(with(GamingMode::Both).tcp(), Some(tcp));
        assert_eq!(with(GamingMode::Both).udp(), Some(Ports::GAMES));
        assert_eq!(Gaming::default().mode, GamingMode::Off);
    }
}
