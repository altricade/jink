//! WinDivert filter for a configuration, as zapret's `wf_make_filter`
//! (`nfq/nfqws.c`):
//!
//! - outbound: SYN, RST, FIN and data packets (not bare ACKs) to the
//!   `--wf-tcp` ports, and UDP to the `--wf-udp` ports;
//! - inbound: SYN-ACK, RST and FIN from the `--wf-tcp` ports, which the
//!   engine uses to track connections;
//! - never loopback or packets other WinDivert handles injected (`impostor`);
//! - by default never LAN, link-local or loopback addresses.
//!
//! The filter string is built and tested on every platform; only opening it
//! needs Windows.

use jink_core::config::Capture;
use jink_core::rules::PortFilter;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FilterOptions {
    pub ipv4: bool,
    pub ipv6: bool,
    /// Skip LAN/loopback/link-local addresses (zapret `--wf-filter-lan=1`,
    /// its default).
    pub exclude_lan: bool,
}

impl Default for FilterOptions {
    fn default() -> Self {
        Self {
            ipv4: true,
            ipv6: true,
            exclude_lan: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FilterError {
    #[error("the strategy captures nothing: no --wf-tcp or --wf-udp ports")]
    NothingCaptured,
    #[error("both IPv4 and IPv6 are disabled")]
    NoAddressFamily,
}

// zapret DIVERT_NO_LOCALNETS*, verbatim.
const NO_LAN_V4_DST: &str = "((ip.DstAddr < 127.0.0.1 or ip.DstAddr > 127.255.255.255) and \
(ip.DstAddr < 10.0.0.0 or ip.DstAddr > 10.255.255.255) and \
(ip.DstAddr < 192.168.0.0 or ip.DstAddr > 192.168.255.255) and \
(ip.DstAddr < 172.16.0.0 or ip.DstAddr > 172.31.255.255) and \
(ip.DstAddr < 169.254.0.0 or ip.DstAddr > 169.254.255.255))";
const NO_LAN_V4_SRC: &str = "((ip.SrcAddr < 127.0.0.1 or ip.SrcAddr > 127.255.255.255) and \
(ip.SrcAddr < 10.0.0.0 or ip.SrcAddr > 10.255.255.255) and \
(ip.SrcAddr < 192.168.0.0 or ip.SrcAddr > 192.168.255.255) and \
(ip.SrcAddr < 172.16.0.0 or ip.SrcAddr > 172.31.255.255) and \
(ip.SrcAddr < 169.254.0.0 or ip.SrcAddr > 169.254.255.255))";
const NO_LAN_V6_DST: &str = "((ipv6.DstAddr > ::1) and \
(ipv6.DstAddr < 2001::0 or ipv6.DstAddr >= 2001:1::0) and \
(ipv6.DstAddr < fc00::0 or ipv6.DstAddr >= fe00::0) and \
(ipv6.DstAddr < fe80::0 or ipv6.DstAddr >= fec0::0) and \
(ipv6.DstAddr < ff00::0 or ipv6.DstAddr >= ffff::0))";
const NO_LAN_V6_SRC: &str = "((ipv6.SrcAddr > ::1) and \
(ipv6.SrcAddr < 2001::0 or ipv6.SrcAddr >= 2001:1::0) and \
(ipv6.SrcAddr < fc00::0 or ipv6.SrcAddr >= fe00::0) and \
(ipv6.SrcAddr < fe80::0 or ipv6.SrcAddr >= fec0::0) and \
(ipv6.SrcAddr < ff00::0 or ipv6.SrcAddr >= ffff::0))";

/// The WinDivert filter string for `capture`.
///
/// # Errors
/// [`FilterError::NothingCaptured`] if neither TCP nor UDP ports are given;
/// [`FilterError::NoAddressFamily`] if both families are disabled.
pub fn build(capture: &Capture, options: FilterOptions) -> Result<String, FilterError> {
    let family = match (options.ipv4, options.ipv6) {
        (true, true) => "",
        (true, false) => "ip and ",
        (false, true) => "ipv6 and ",
        (false, false) => return Err(FilterError::NoAddressFamily),
    };
    let tcp_dst = capture.tcp.as_ref().map(|f| ports(f, "tcp.DstPort"));
    let udp_dst = capture.udp.as_ref().map(|f| ports(f, "udp.DstPort"));
    let outbound_ports = match (&tcp_dst, &udp_dst) {
        (Some(t), Some(u)) => format!("({t} or {u})"),
        (Some(only), None) | (None, Some(only)) => only.clone(),
        (None, None) => return Err(FilterError::NothingCaptured),
    };
    // Bare ACKs carry nothing the engine needs.
    let outbound = format!(
        "(outbound and (!tcp or tcp.Syn or tcp.Rst or tcp.Fin or tcp.PayloadLength > 0) and {outbound_ports})"
    );
    let inbound = capture.tcp.as_ref().map(|f| {
        format!(
            "(inbound and tcp and (tcp.Ack and tcp.Syn or tcp.Rst or tcp.Fin) and {})",
            ports(f, "tcp.SrcPort")
        )
    });
    let traffic = match inbound {
        Some(inbound) => format!("({outbound} or {inbound})"),
        None => outbound,
    };
    let lan = if options.exclude_lan {
        let (dst, src) = match (options.ipv4, options.ipv6) {
            (true, false) => (NO_LAN_V4_DST.to_owned(), NO_LAN_V4_SRC.to_owned()),
            (false, true) => (NO_LAN_V6_DST.to_owned(), NO_LAN_V6_SRC.to_owned()),
            _ => (
                format!("({NO_LAN_V4_DST} or {NO_LAN_V6_DST})"),
                format!("({NO_LAN_V4_SRC} or {NO_LAN_V6_SRC})"),
            ),
        };
        format!(" and (outbound and {dst} or inbound and {src})")
    } else {
        String::new()
    };
    Ok(format!(
        "!impostor and !loopback and {family}{traffic}{lan}"
    ))
}

/// zapret `wf_make_pf`: one comparison per port item, OR-ed.
fn ports(filter: &PortFilter, field: &str) -> String {
    let Some(items) = filter.items() else {
        return "true".to_owned();
    };
    if items.is_empty() {
        return "false".to_owned();
    }
    let parts: Vec<String> = items
        .iter()
        .map(|r| {
            if r.denies_all() {
                "false".to_owned()
            } else if r.from() == r.to() {
                let op = if r.negated() { "!=" } else { "==" };
                format!("{field} {op} {}", r.from())
            } else if r.negated() {
                format!("({field} < {} or {field} > {})", r.from(), r.to())
            } else {
                format!("({field} >= {} and {field} <= {})", r.from(), r.to())
            }
        })
        .collect();
    format!("({})", parts.join(" or "))
}

#[cfg(test)]
mod tests {
    use jink_core::config::Capture;
    use jink_core::rules::PortFilter;

    use super::{FilterError, FilterOptions, build, ports};

    fn capture(tcp: Option<&str>, udp: Option<&str>) -> Capture {
        Capture {
            tcp: tcp.map(|s| PortFilter::parse(s).unwrap()),
            udp: udp.map(|s| PortFilter::parse(s).unwrap()),
        }
    }

    #[test]
    fn port_expressions() {
        let f = PortFilter::parse("80,443,19294-19344,~22").unwrap();
        assert_eq!(
            ports(&f, "udp.DstPort"),
            "(udp.DstPort == 80 or udp.DstPort == 443 or \
             (udp.DstPort >= 19294 and udp.DstPort <= 19344) or udp.DstPort != 22)"
        );
        assert_eq!(
            ports(&PortFilter::parse("0").unwrap(), "tcp.DstPort"),
            "(false)"
        );
        assert_eq!(ports(&PortFilter::Any, "tcp.DstPort"), "true");
    }

    #[test]
    fn tcp_and_udp_with_lan_exclusion() {
        let f = build(&capture(Some("443"), Some("443")), FilterOptions::default()).unwrap();
        assert!(f.starts_with("!impostor and !loopback and ((outbound and "));
        assert!(f.contains("((tcp.DstPort == 443) or (udp.DstPort == 443))"));
        assert!(f.contains(
            "(inbound and tcp and (tcp.Ack and tcp.Syn or tcp.Rst or tcp.Fin) and (tcp.SrcPort == 443))"
        ));
        assert!(f.contains("ip.DstAddr < 192.168.0.0") && f.contains("ipv6.SrcAddr < fe80::0"));
        assert_eq!(
            f.matches('(').count(),
            f.matches(')').count(),
            "balanced: {f}"
        );
    }

    #[test]
    fn udp_only_has_no_inbound_part() {
        let opts = FilterOptions {
            ipv6: false,
            exclude_lan: false,
            ..FilterOptions::default()
        };
        let f = build(&capture(None, Some("50000-50100")), opts).unwrap();
        assert_eq!(
            f,
            "!impostor and !loopback and ip and (outbound and (!tcp or tcp.Syn or tcp.Rst or \
             tcp.Fin or tcp.PayloadLength > 0) and ((udp.DstPort >= 50000 and udp.DstPort <= 50100)))"
        );
    }

    #[test]
    fn errors() {
        assert_eq!(
            build(&capture(None, None), FilterOptions::default()),
            Err(FilterError::NothingCaptured)
        );
        let none = FilterOptions {
            ipv4: false,
            ipv6: false,
            exclude_lan: true,
        };
        assert_eq!(
            build(&capture(Some("443"), None), none),
            Err(FilterError::NoAddressFamily)
        );
    }
}
