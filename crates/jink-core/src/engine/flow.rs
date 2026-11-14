//! Per-connection state shared by the packet-mode (Windows) and stream-mode
//! (macOS) drivers: flow tracking with zapret's timeouts, what has been
//! learned about the flow, rule selection, and `--dpi-desync-cutoff`.
//!
//! Mirrors zapret `nfq/conntrack.c` and the rule search in `desync.c`:
//! - TCP flows start at the client's SYN; UDP flows at any client datagram.
//! - A rule is searched when the flow starts and searched again once its
//!   protocol or host name is first discovered.
//! - Counters include every client packet (the SYN too), as zapret's
//!   `pcounter_orig`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::config::{Config, Cutoff, CutoffMode};
use crate::l7::Protocol;
use crate::packet::TcpFlags;
use crate::rules::{Flow as RuleFlow, Transport};

/// zapret `CTRACK_T_SYN`, `CTRACK_T_EST`, `CTRACK_T_FIN`, `CTRACK_T_UDP`.
pub const TIMEOUT_SYN: Duration = Duration::from_secs(60);
pub const TIMEOUT_ESTABLISHED: Duration = Duration::from_secs(300);
pub const TIMEOUT_CLOSING: Duration = Duration::from_secs(60);
pub const TIMEOUT_UDP: Duration = Duration::from_secs(60);
/// How often expired flows are swept (zapret's purge interval).
pub const PURGE_INTERVAL: Duration = Duration::from_secs(10);

/// A connection, oriented from the client (us) to the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub transport: Transport,
    pub client: SocketAddr,
    pub server: SocketAddr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    Syn,
    Established,
    Closing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleChoice {
    Unsearched,
    Searched(Option<usize>),
}

/// What is known about one tracked flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flow {
    last_seen: Instant,
    /// `None` for UDP.
    tcp_state: Option<TcpState>,
    client_packets: u32,
    client_data_packets: u32,
    /// Client's initial sequence number, for byte-based cutoff.
    seq0: Option<u32>,
    seq_last: u32,
    protocol: Protocol,
    hostname: Option<String>,
    rule: RuleChoice,
    cut: bool,
}

impl Flow {
    fn new(now: Instant, tcp_state: Option<TcpState>) -> Self {
        Self {
            last_seen: now,
            tcp_state,
            client_packets: 0,
            client_data_packets: 0,
            seq0: None,
            seq_last: 0,
            protocol: Protocol::Unknown,
            hostname: None,
            rule: RuleChoice::Unsearched,
            cut: false,
        }
    }

    #[must_use]
    pub const fn tcp_state(&self) -> Option<TcpState> {
        self.tcp_state
    }

    #[must_use]
    pub const fn client_data_packets(&self) -> u32 {
        self.client_data_packets
    }

    #[must_use]
    pub fn hostname(&self) -> Option<&str> {
        self.hostname.as_deref()
    }

    fn expired(&self, now: Instant) -> bool {
        let timeout = match self.tcp_state {
            Some(TcpState::Syn) => TIMEOUT_SYN,
            Some(TcpState::Established) => TIMEOUT_ESTABLISHED,
            Some(TcpState::Closing) => TIMEOUT_CLOSING,
            None => TIMEOUT_UDP,
        };
        now.checked_duration_since(self.last_seen)
            .is_some_and(|idle| idle > timeout)
    }

    /// Records the protocol and host name the first time they are learned.
    /// Returns whether anything new was learned (which re-opens the rule
    /// search, as in zapret).
    pub fn discover(&mut self, protocol: Protocol, hostname: Option<&str>) -> bool {
        let mut learned = false;
        if self.protocol == Protocol::Unknown && protocol != Protocol::Unknown {
            self.protocol = protocol;
            learned = true;
        }
        if self.hostname.is_none()
            && let Some(host) = hostname
        {
            self.hostname = Some(host.to_owned());
            learned = true;
        }
        if learned {
            self.rule = RuleChoice::Unsearched;
        }
        learned
    }

    /// The flow's rule, searching (again) if nothing was searched since the
    /// last discovery.
    pub fn rule(&mut self, config: &Config, key: &FlowKey) -> Option<usize> {
        if let RuleChoice::Searched(choice) = self.rule {
            return choice;
        }
        let choice = choose_rule(config, key, self.protocol, self.hostname.as_deref());
        self.rule = RuleChoice::Searched(choice);
        choice
    }

    /// zapret `cutoff_test`: once the limit is reached the flow is cut for
    /// good.
    pub fn cut_off(&mut self, cutoff: Cutoff) -> bool {
        if !self.cut {
            let progress = match cutoff.mode {
                CutoffMode::Packets => self.client_packets,
                CutoffMode::DataPackets => self.client_data_packets,
                CutoffMode::SeqBytes => {
                    self.seq0.map_or(0, |seq0| self.seq_last.wrapping_sub(seq0))
                }
            };
            self.cut = cutoff.limit > 0 && progress >= cutoff.limit;
        }
        self.cut
    }
}

/// The first rule matching what is known about a connection.
#[must_use]
pub fn choose_rule(
    config: &Config,
    key: &FlowKey,
    protocol: Protocol,
    hostname: Option<&str>,
) -> Option<usize> {
    let flow = RuleFlow {
        transport: key.transport,
        dst: key.server,
        l7: protocol,
        hostname,
    };
    config.rules.iter().position(|r| r.matcher.matches(&flow))
}

/// A client packet as the flow table needs to see it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientPacket {
    pub flags: TcpFlags,
    pub seq: u32,
    pub has_payload: bool,
}

/// All tracked flows.
#[derive(Debug, Default)]
pub struct FlowTable {
    flows: HashMap<FlowKey, Flow>,
    last_purge: Option<Instant>,
}

impl FlowTable {
    #[must_use]
    pub fn len(&self) -> usize {
        self.flows.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    #[must_use]
    pub fn get(&self, key: &FlowKey) -> Option<&Flow> {
        self.flows.get(key)
    }

    pub fn get_mut(&mut self, key: &FlowKey) -> Option<&mut Flow> {
        self.flows.get_mut(key)
    }

    /// Feeds a TCP packet sent by the client. A SYN starts (or restarts) the
    /// flow; other packets only update an existing one. Returns whether the
    /// flow is tracked.
    pub fn client_tcp(&mut self, key: FlowKey, p: ClientPacket, now: Instant) -> bool {
        let syn = p.flags.contains(TcpFlags::SYN);
        if syn && !p.flags.contains(TcpFlags::ACK) {
            let flow = self
                .flows
                .entry(key)
                .or_insert_with(|| Flow::new(now, Some(TcpState::Syn)));
            if flow.tcp_state != Some(TcpState::Syn) {
                *flow = Flow::new(now, Some(TcpState::Syn));
            }
            flow.seq0 = Some(p.seq);
        }
        let Some(flow) = self.flows.get_mut(&key) else {
            return false;
        };
        count(flow, p.has_payload, now);
        flow.seq_last = p.seq;
        if p.flags.contains(TcpFlags::FIN) || p.flags.contains(TcpFlags::RST) {
            flow.tcp_state = Some(TcpState::Closing);
        } else if !syn && flow.tcp_state == Some(TcpState::Syn) {
            flow.tcp_state = Some(TcpState::Established);
        }
        true
    }

    /// Feeds a UDP datagram sent by the client, starting the flow if needed.
    pub fn client_udp(&mut self, key: FlowKey, has_payload: bool, now: Instant) {
        let flow = self
            .flows
            .entry(key)
            .or_insert_with(|| Flow::new(now, None));
        count(flow, has_payload, now);
    }

    /// Feeds a packet from the server (`key` is still client-oriented).
    pub fn server_packet(&mut self, key: &FlowKey, fin_or_rst: bool, now: Instant) {
        if let Some(flow) = self.flows.get_mut(key) {
            flow.last_seen = now;
            if fin_or_rst && flow.tcp_state.is_some() {
                flow.tcp_state = Some(TcpState::Closing);
            }
        }
    }

    /// Drops flows idle past their timeout, at most every [`PURGE_INTERVAL`].
    pub fn purge(&mut self, now: Instant) {
        let due = self.last_purge.is_none_or(|last| {
            now.checked_duration_since(last)
                .is_some_and(|d| d >= PURGE_INTERVAL)
        });
        if due {
            self.flows.retain(|_, f| !f.expired(now));
            self.last_purge = Some(now);
        }
    }
}

fn count(flow: &mut Flow, has_payload: bool, now: Instant) {
    flow.last_seen = now;
    flow.client_packets = flow.client_packets.saturating_add(1);
    if has_payload {
        flow.client_data_packets = flow.client_data_packets.saturating_add(1);
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::{ClientPacket, FlowKey, FlowTable, TcpState};
    use crate::config::{Cutoff, CutoffMode};
    use crate::l7::Protocol;
    use crate::packet::TcpFlags;
    use crate::rules::Transport;

    fn key() -> FlowKey {
        FlowKey {
            transport: Transport::Tcp,
            client: "192.168.1.10:50000".parse().unwrap(),
            server: "1.1.1.1:443".parse().unwrap(),
        }
    }

    const fn pkt(syn: bool, has_payload: bool) -> ClientPacket {
        ClientPacket {
            flags: if syn { TcpFlags::SYN } else { TcpFlags::ACK },
            seq: 100,
            has_payload,
        }
    }

    #[test]
    fn tcp_flows_start_at_syn_and_expire() {
        let now = Instant::now();
        let mut t = FlowTable::default();
        assert!(!t.client_tcp(key(), pkt(false, true), now), "no SYN seen");
        assert!(t.client_tcp(key(), pkt(true, false), now));
        assert!(t.client_tcp(key(), pkt(false, true), now));
        let flow = t.get(&key()).unwrap();
        assert_eq!(flow.tcp_state(), Some(TcpState::Established));
        assert_eq!(flow.client_data_packets(), 1);
        t.server_packet(&key(), true, now);
        assert_eq!(t.get(&key()).unwrap().tcp_state(), Some(TcpState::Closing));
        t.purge(now);
        t.purge(now + Duration::from_secs(61));
        assert!(t.is_empty(), "closing flows expire after 60 s");
    }

    #[test]
    fn purge_is_rate_limited() {
        let now = Instant::now();
        let mut t = FlowTable::default();
        t.client_tcp(key(), pkt(true, false), now);
        t.purge(now + Duration::from_secs(55)); // sweep: not expired yet
        // Expired at 61 s, but the next sweep is only due at 65 s.
        t.purge(now + Duration::from_secs(61));
        assert_eq!(t.len(), 1);
        t.purge(now + Duration::from_secs(65));
        assert!(t.is_empty());
    }

    #[test]
    fn discovery_reopens_rule_search_once() {
        let now = Instant::now();
        let mut t = FlowTable::default();
        t.client_tcp(key(), pkt(true, false), now);
        let flow = t.get_mut(&key()).unwrap();
        assert!(flow.discover(Protocol::Tls, Some("a.com")));
        assert!(
            !flow.discover(Protocol::Http, Some("b.com")),
            "first values stick"
        );
        assert_eq!(flow.hostname(), Some("a.com"));
    }

    #[test]
    fn cutoff_counts_every_client_packet() {
        let now = Instant::now();
        let mut t = FlowTable::default();
        let n2 = Cutoff {
            mode: CutoffMode::Packets,
            limit: 2,
        };
        t.client_tcp(key(), pkt(true, false), now); // packet 1: the SYN
        assert!(!t.get_mut(&key()).unwrap().cut_off(n2));
        t.client_tcp(key(), pkt(false, true), now); // packet 2
        assert!(t.get_mut(&key()).unwrap().cut_off(n2));
    }
}
