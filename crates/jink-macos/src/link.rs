//! Following the network: what ties jink to one uplink (handshake capture,
//! raw socket, scoped routes), replaced when the default route moves (another
//! Wi-Fi network, Ethernet plugged in, waking up elsewhere), and the utun
//! routes, removed while there is no network or jink cannot work (so apps
//! see the network as it is rather than a jink that cannot relay).

use std::io;
use std::num::NonZeroU32;
use std::sync::Arc;

use route_manager::Route;

use crate::fake::RawSender;
use crate::handshake::{CaptureError, Handshakes, Watcher};
use crate::instance::Leftovers;
use crate::route::{self, Existing, Installed, Uplink};
use crate::run::{Event, OnEvent};

/// Why jink cannot work on the current network. It stays out of the way and
/// tries again when the routing table changes, and every few seconds.
#[derive(Debug, thiserror::Error)]
pub enum LinkError {
    #[error("cannot read the routing table: {0}")]
    RouteTable(io::Error),
    #[error(transparent)]
    Capture(#[from] CaptureError),
    #[error("cannot open a raw socket for fake packets: {0}")]
    RawSocket(io::Error),
    #[error("another VPN already routes all traffic; jink waits until it stops")]
    RoutesTaken,
    #[error("cannot add routes: {0}")]
    Routes(io::Error),
}

/// What a new connection needs: the uplink to pin its socket to, and the
/// raw socket for its fakes. A connection keeps them when the uplink changes.
#[derive(Debug, Clone)]
pub(crate) struct Path {
    pub(crate) uplink: NonZeroU32,
    pub(crate) raw: Arc<RawSender>,
}

/// Everything tied to one uplink.
#[derive(Debug)]
struct Link {
    uplink: Uplink,
    raw: Arc<RawSender>,
    watcher: Watcher,
    scoped: Installed,
}

impl Link {
    fn open(uplink: Uplink, handshakes: &Arc<Handshakes>) -> Result<Self, LinkError> {
        let watcher = Watcher::start(&uplink.name, Arc::clone(handshakes))?;
        let raw = RawSender::open(uplink.index).map_err(LinkError::RawSocket)?;
        // Routes last: if anything above failed, nothing was changed.
        let scoped = Installed::add(route::scoped_halves(&uplink), Existing::Replace)
            .map_err(LinkError::Routes)?;
        Ok(Self {
            uplink,
            raw: Arc::new(raw),
            watcher,
            scoped,
        })
    }

    fn close(self) -> (Vec<io::Error>, Result<(), pcap::Error>) {
        (self.scoped.remove(), self.watcher.stop())
    }
}

/// What to do after looking at the routing table.
#[derive(Debug, PartialEq, Eq)]
enum Step {
    /// Already on the uplink, routes in place.
    Keep,
    /// Move to (or set up again on) this uplink.
    Connect(Uplink),
    /// The network went away.
    Disconnect,
    /// Still no network.
    Wait,
}

/// `current` is the uplink jink is on, `intact` whether all of its routes
/// are still there, `wanted` the uplink the default route now names.
fn decide(current: Option<&Uplink>, intact: bool, wanted: Option<Uplink>) -> Step {
    match (current, wanted) {
        (None, None) => Step::Wait,
        (Some(_), None) => Step::Disconnect,
        (Some(current), Some(wanted)) if *current == wanted && intact => Step::Keep,
        (_, Some(wanted)) => Step::Connect(wanted),
    }
}

/// jink's hold on the network, kept in step with the routing table by
/// [`Network::refresh`].
pub(crate) struct Network {
    tun_index: u32,
    handshakes: Arc<Handshakes>,
    /// Where the link's scoped routes are recorded, for after a crash.
    leftovers: Leftovers,
    on_event: OnEvent,
    link: Option<Link>,
    /// The utun halves, and whether they include IPv6's; present exactly
    /// while there is a link.
    captured: Option<(bool, Installed)>,
    /// Whether [`Event::Offline`] was the last state reported.
    offline_reported: bool,
}

impl std::fmt::Debug for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Network")
            .field("link", &self.link)
            .field("captured", &self.captured)
            .finish_non_exhaustive()
    }
}

impl Network {
    pub(crate) fn new(
        tun_index: u32,
        handshakes: Arc<Handshakes>,
        leftovers: Leftovers,
        on_event: OnEvent,
    ) -> Self {
        Self {
            tun_index,
            handshakes,
            leftovers,
            on_event,
            link: None,
            captured: None,
            offline_reported: false,
        }
    }

    /// The path for a new connection, or `None` while jink is out of the way.
    pub(crate) fn path(&self) -> Option<Path> {
        self.link.as_ref().map(|link| Path {
            uplink: link.uplink.index,
            raw: Arc::clone(&link.raw),
        })
    }

    /// Looks at the routing table and follows it: sets up on a new uplink,
    /// restores routes something deleted, or steps aside.
    pub(crate) fn refresh(&mut self) {
        let table = match route::table() {
            Ok(table) => table,
            Err(e) => {
                (self.on_event)(Event::Unavailable(LinkError::RouteTable(e)));
                return;
            }
        };
        let intact = self.link.as_ref().is_some_and(|l| l.scoped.intact(&table));
        let current = self.link.as_ref().map(|l| &l.uplink);
        let mut changed = match decide(current, intact, route::default_route(&table)) {
            Step::Keep => false,
            Step::Wait => {
                self.report_offline();
                return;
            }
            Step::Disconnect => {
                self.step_aside();
                self.report_offline();
                return;
            }
            Step::Connect(uplink) => {
                // The old link first: on the same interface through a new
                // gateway, its scoped routes are in the new ones' place.
                self.close_link();
                match Link::open(uplink, &self.handshakes) {
                    Ok(link) => {
                        if let Err(e) = self.leftovers.record(link.scoped.routes()) {
                            (self.on_event)(Event::StateFile(e));
                        }
                        self.link = Some(link);
                    }
                    Err(e) => return self.unavailable(e),
                }
                true
            }
        };
        let ipv6 = route::has_ipv6(&table);
        match self.capture(ipv6, &table) {
            Ok(added) => changed |= added,
            Err(e) => return self.unavailable(e),
        }
        if changed {
            self.offline_reported = false;
            if let Some(link) = &self.link {
                (self.on_event)(Event::Online {
                    uplink: link.uplink.name.clone(),
                    ipv6,
                });
            }
        }
    }

    /// Puts the utun halves in place (with IPv6's if `ipv6`), returning
    /// whether they had to be added.
    fn capture(&mut self, ipv6: bool, table: &[Route]) -> Result<bool, LinkError> {
        if self
            .captured
            .as_ref()
            .is_some_and(|(had_ipv6, c)| *had_ipv6 == ipv6 && c.intact(table))
        {
            return Ok(false);
        }
        if let Some((_, old)) = self.captured.take() {
            self.report_left(old.remove());
        }
        let added = Installed::add(route::tun_halves(self.tun_index, ipv6), Existing::Refuse)
            .map_err(|e| match e.kind() {
                io::ErrorKind::AlreadyExists => LinkError::RoutesTaken,
                _ => LinkError::Routes(e),
            })?;
        self.captured = Some((ipv6, added));
        Ok(true)
    }

    fn unavailable(&mut self, error: LinkError) {
        self.step_aside();
        (self.on_event)(Event::Unavailable(error));
    }

    /// Removes the utun halves first (apps' traffic goes back to normal
    /// routing), then the link.
    fn step_aside(&mut self) {
        if let Some((_, captured)) = self.captured.take() {
            self.report_left(captured.remove());
        }
        self.close_link();
    }

    fn close_link(&mut self) {
        if let Some(link) = self.link.take() {
            let (left, capture) = link.close();
            self.report_left(left);
            if let Err(e) = capture {
                (self.on_event)(Event::CaptureEnded(e));
            }
            self.forget_routes();
        }
    }

    fn forget_routes(&self) {
        if let Err(e) = self.leftovers.forget() {
            (self.on_event)(Event::StateFile(e));
        }
    }

    fn report_left(&self, left: Vec<io::Error>) {
        if !left.is_empty() {
            (self.on_event)(Event::RoutesLeft(left));
        }
    }

    fn report_offline(&mut self) {
        if !self.offline_reported {
            self.offline_reported = true;
            (self.on_event)(Event::Offline);
        }
    }

    /// Removes everything, returning the routes that could not be deleted.
    pub(crate) fn shut_down(mut self) -> Vec<io::Error> {
        let mut left = match self.captured.take() {
            Some((_, captured)) => captured.remove(),
            None => Vec::new(),
        };
        if let Some(link) = self.link.take() {
            let (link_left, capture) = link.close();
            left.extend(link_left);
            if let Err(e) = capture {
                (self.on_event)(Event::CaptureEnded(e));
            }
            // Routes that could not be deleted stay recorded for next time.
            if left.is_empty() {
                self.forget_routes();
            }
        }
        left
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::{Step, decide};
    use crate::route::Uplink;

    fn uplink(name: &str, index: u32, gateway: [u8; 4]) -> Uplink {
        Uplink {
            name: name.into(),
            index: index.try_into().unwrap(),
            gateway: Some(IpAddr::V4(Ipv4Addr::from(gateway))),
        }
    }

    #[test]
    fn follows_the_default_route() {
        let home = uplink("en0", 14, [192, 168, 1, 1]);
        // Same uplink, routes in place: nothing to do.
        assert_eq!(decide(Some(&home), true, Some(home.clone())), Step::Keep);
        // Same uplink, but the kernel deleted a route: set up again.
        assert_eq!(
            decide(Some(&home), false, Some(home.clone())),
            Step::Connect(home.clone())
        );
        // Another Wi-Fi network: same interface, new gateway.
        let cafe = uplink("en0", 14, [10, 0, 0, 1]);
        assert_eq!(
            decide(Some(&home), true, Some(cafe.clone())),
            Step::Connect(cafe)
        );
        // Ethernet plugged in.
        let wired = uplink("en7", 20, [192, 168, 1, 1]);
        assert_eq!(
            decide(Some(&home), true, Some(wired.clone())),
            Step::Connect(wired)
        );
        // The network went away, and came back.
        assert_eq!(decide(Some(&home), true, None), Step::Disconnect);
        assert_eq!(decide(None, false, None), Step::Wait);
        assert_eq!(decide(None, false, Some(home.clone())), Step::Connect(home));
    }
}
