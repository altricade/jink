//! The uplink (the physical interface the IPv4 default route uses) and the
//! routes that send all other IPv4 traffic into jink's utun interface.
//!
//! jink adds `0.0.0.0/1` and `128.0.0.0/1` through the utun interface: more
//! specific than the default route, so they win, while the default route
//! itself stays in place. Local networks keep their more specific routes and
//! never reach jink.
//!
//! jink's own sockets are pinned to the uplink (`IP_BOUND_IF`). A pinned
//! socket's route lookup only takes routes on its interface, preferring ones
//! scoped to it (`RTF_IFSCOPE`), so jink also adds the same two halves scoped
//! to the uplink, through its gateway: they only serve sockets pinned there.
//! (Without them, pinned connects failed with "Network is unreachable" on a
//! Mac whose only uplink route was the unscoped default.)

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU32;

use route_manager::{Route, RouteChange, RouteManager};

/// The interface traffic leaves through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Uplink {
    pub(crate) name: String,
    pub(crate) index: NonZeroU32,
    /// The default route's gateway; `None` on a point-to-point uplink.
    pub(crate) gateway: Option<IpAddr>,
}

/// The routing socket's error for a route that is not in the table.
const ESRCH: i32 = 3;

/// `0.0.0.0/1` and `128.0.0.0/1`: together, every IPv4 address.
const HALVES: [(Ipv4Addr, u8); 2] = [(Ipv4Addr::UNSPECIFIED, 1), (Ipv4Addr::new(128, 0, 0, 0), 1)];
/// `::/1` and `8000::/1`: together, every IPv6 address.
const HALVES_V6: [(Ipv6Addr, u8); 2] = [
    (Ipv6Addr::UNSPECIFIED, 1),
    (Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0), 1),
];

/// The routing table.
///
/// # Errors
/// If it cannot be read.
pub(crate) fn table() -> io::Result<Vec<Route>> {
    RouteManager::new()?.list()
}

/// The uplink: the interface of the (unscoped) IPv4 default route.
pub(crate) fn default_route(routes: &[Route]) -> Option<Uplink> {
    routes
        .iter()
        .filter(|r| r.destination().is_ipv4() && r.prefix() == 0 && !r.if_scope())
        .find_map(|r| {
            let index = NonZeroU32::new(r.if_index()?)?;
            let name = r
                .if_name()
                .cloned()
                .unwrap_or_else(|| format!("interface #{index}"));
            Some(Uplink {
                name,
                index,
                gateway: r.gateway(),
            })
        })
}

/// Whether the network has IPv6: an (unscoped) IPv6 default route. macOS
/// keeps scoped ones on its own utun interfaces even without IPv6.
pub(crate) fn has_ipv6(routes: &[Route]) -> bool {
    routes
        .iter()
        .any(|r| r.destination().is_ipv6() && r.prefix() == 0 && !r.if_scope())
}

/// Whether a routing table change can concern jink: a default route (the
/// uplink) or a half (jink's own routes, or another VPN's). Host and network
/// routes, which change all the time, cannot.
pub(crate) fn concerns_jink(change: &RouteChange) -> bool {
    let (RouteChange::Add(route) | RouteChange::Delete(route) | RouteChange::Change(route)) =
        change;
    route.prefix() <= 1
}

/// The halves scoped to the uplink, through its gateway: they keep jink's
/// pinned sockets on it.
pub(crate) fn scoped_halves(uplink: &Uplink) -> Vec<Route> {
    HALVES
        .iter()
        .map(|&(network, prefix)| {
            let route = Route::new(IpAddr::V4(network), prefix)
                .with_if_index(uplink.index.get())
                .with_if_scope(true);
            match uplink.gateway {
                Some(gateway) => route.with_gateway(gateway),
                None => route,
            }
        })
        .collect()
}

/// The halves through the utun interface: they bring apps' traffic to jink.
/// With `ipv6`, the IPv6 halves too, so IPv6 is turned away rather than
/// leaving without desync.
pub(crate) fn tun_halves(tun_index: u32, ipv6: bool) -> Vec<Route> {
    let v4 = HALVES
        .iter()
        .map(|&(network, prefix)| (IpAddr::V4(network), prefix));
    let v6 = HALVES_V6
        .iter()
        .filter(|_| ipv6)
        .map(|&(network, prefix)| (IpAddr::V6(network), prefix));
    v4.chain(v6)
        .map(|(network, prefix)| Route::new(network, prefix).with_if_index(tun_index))
        .collect()
}

/// What to do when a route jink adds is already there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Existing {
    /// Delete it and add jink's: it is a leftover of a jink that was killed
    /// (the scoped halves), maybe through an old gateway.
    Replace,
    /// Fail with [`io::ErrorKind::AlreadyExists`]: someone else's (another
    /// VPN that routes all traffic).
    Refuse,
}

/// Routes jink added. [`Installed::remove`] deletes them; dropping does too,
/// as a fallback.
pub(crate) struct Installed {
    manager: RouteManager,
    routes: Vec<Route>,
}

impl std::fmt::Debug for Installed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Installed")
            .field("routes", &self.routes)
            .finish_non_exhaustive()
    }
}

impl Installed {
    /// Adds `routes` in order.
    ///
    /// # Errors
    /// If a route cannot be added (routes added before it are deleted).
    pub(crate) fn add(routes: Vec<Route>, existing: Existing) -> io::Result<Self> {
        let mut installed = Self {
            manager: RouteManager::new()?,
            routes: Vec::with_capacity(routes.len()),
        };
        for route in routes {
            match installed.manager.add(&route) {
                Err(e)
                    if e.kind() == io::ErrorKind::AlreadyExists
                        && existing == Existing::Replace =>
                {
                    installed.manager.delete(&route)?;
                    installed.manager.add(&route)?;
                }
                result => result?,
            }
            installed.routes.push(route);
        }
        Ok(installed)
    }

    /// Takes charge of `routes`, already in the table (left by a jink that
    /// was killed), so that they can be deleted.
    ///
    /// # Errors
    /// If the routing socket cannot be opened.
    pub(crate) fn adopt(routes: Vec<Route>) -> io::Result<Self> {
        Ok(Self {
            manager: RouteManager::new()?,
            routes,
        })
    }

    /// The routes, in the order they were added.
    pub(crate) fn routes(&self) -> &[Route] {
        &self.routes
    }

    /// Whether every route is still in `table`: the kernel deletes routes
    /// through a gateway when the interface loses its address.
    pub(crate) fn intact(&self, table: &[Route]) -> bool {
        self.routes
            .iter()
            .all(|ours| table.iter().any(|listed| same_route(ours, listed)))
    }

    /// Deletes the routes, reporting the ones that could not be deleted.
    pub(crate) fn remove(mut self) -> Vec<io::Error> {
        self.delete_all()
    }

    fn delete_all(&mut self) -> Vec<io::Error> {
        // In reverse: the routes that bring traffic in go first.
        let routes = std::mem::take(&mut self.routes);
        routes
            .iter()
            .rev()
            .filter_map(|r| self.manager.delete(r).err())
            // Already gone (the kernel deletes routes along with addresses
            // and interfaces): what deleting was for.
            .filter(|e| e.raw_os_error() != Some(ESRCH))
            .collect()
    }
}

impl Drop for Installed {
    fn drop(&mut self) {
        // Nothing can be reported from a destructor; see `Installed`.
        let _ = self.delete_all();
    }
}

/// Whether `listed` (from the routing table) is the route jink added as
/// `ours`. The table fills in more (flags, names, a link-layer gateway for an
/// interface route), so only what jink set is compared.
fn same_route(ours: &Route, listed: &Route) -> bool {
    ours.destination() == listed.destination()
        && ours.prefix() == listed.prefix()
        && ours.if_index() == listed.if_index()
        && ours.if_scope() == listed.if_scope()
        && ours.gateway().is_none_or(|g| listed.gateway() == Some(g))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use route_manager::{Route, RouteChange};

    use super::{
        Uplink, concerns_jink, default_route, has_ipv6, same_route, scoped_halves, tun_halves,
    };

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn en0() -> Uplink {
        Uplink {
            name: "en0".into(),
            index: 14.try_into().unwrap(),
            gateway: Some(v4(192, 168, 1, 1)),
        }
    }

    #[test]
    fn default_route_is_the_unscoped_ipv4_one() {
        let routes = [
            Route::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
                .with_if_index(20)
                .with_if_name("en7".into()),
            Route::new(v4(0, 0, 0, 0), 0)
                .with_if_index(15)
                .with_if_name("en1".into())
                .with_if_scope(true),
            Route::new(v4(10, 0, 0, 0), 8)
                .with_gateway(v4(10, 49, 0, 1))
                .with_if_index(30)
                .with_if_name("utun4".into()),
            Route::new(v4(0, 0, 0, 0), 0)
                .with_gateway(v4(192, 168, 1, 1))
                .with_if_index(14)
                .with_if_name("en0".into()),
        ];
        assert_eq!(default_route(&routes), Some(en0()));
        assert_eq!(default_route(&routes[..3]), None);
        // The first route is an unscoped IPv6 default.
        assert!(has_ipv6(&routes));
        assert!(!has_ipv6(&routes[1..]));
    }

    #[test]
    fn scoped_ipv6_defaults_are_not_ipv6() {
        // What macOS keeps on its own utun interfaces without IPv6.
        let scoped = Route::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
            .with_gateway(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)))
            .with_if_index(9)
            .with_if_scope(true);
        assert!(!has_ipv6(&[scoped]));
    }

    /// Scoped halves on the uplink through its gateway; the utun halves
    /// unscoped.
    #[test]
    fn halves_keep_pinned_sockets_on_the_uplink() {
        let shown = |routes: Vec<Route>| -> Vec<_> {
            routes
                .iter()
                .map(|r| {
                    (
                        r.destination(),
                        r.prefix(),
                        r.gateway(),
                        r.if_index(),
                        r.if_scope(),
                    )
                })
                .collect()
        };
        let gw = Some(v4(192, 168, 1, 1));
        assert_eq!(
            shown(scoped_halves(&en0())),
            vec![
                (v4(0, 0, 0, 0), 1, gw, Some(14), true),
                (v4(128, 0, 0, 0), 1, gw, Some(14), true),
            ]
        );
        let v4_halves = vec![
            (v4(0, 0, 0, 0), 1, None, Some(7), false),
            (v4(128, 0, 0, 0), 1, None, Some(7), false),
        ];
        assert_eq!(shown(tun_halves(7, false)), v4_halves);
        let v6 = |first| IpAddr::V6(Ipv6Addr::new(first, 0, 0, 0, 0, 0, 0, 0));
        let mut all = v4_halves;
        all.extend([
            (v6(0), 1, None, Some(7), false),
            (v6(0x8000), 1, None, Some(7), false),
        ]);
        assert_eq!(shown(tun_halves(7, true)), all);
    }

    #[test]
    fn listed_routes_match_on_what_jink_set() {
        let ours = scoped_halves(&en0()).remove(0);
        let listed = ours.clone().with_if_name("en0".into());
        assert!(same_route(&ours, &listed));
        // Another gateway (the network changed), interface, scope or prefix.
        for other in [
            ours.clone().with_gateway(v4(10, 0, 0, 1)),
            ours.clone().with_if_index(15),
            ours.clone().with_if_scope(false),
            Route::new(v4(0, 0, 0, 0), 0)
                .with_gateway(v4(192, 168, 1, 1))
                .with_if_index(14)
                .with_if_scope(true),
        ] {
            assert!(!same_route(&ours, &other), "{other:?}");
        }
        // A utun half has no gateway of jink's; the table's is ignored.
        let tun = tun_halves(7, false).remove(0);
        assert!(same_route(
            &tun,
            &tun.clone().with_gateway(v4(198, 18, 0, 1))
        ));
    }

    #[test]
    fn only_default_routes_and_halves_concern_jink() {
        let route = |prefix| Route::new(v4(0, 0, 0, 0), prefix);
        assert!(concerns_jink(&RouteChange::Delete(route(0))));
        assert!(concerns_jink(&RouteChange::Add(route(1))));
        assert!(concerns_jink(&RouteChange::Change(route(0))));
        assert!(!concerns_jink(&RouteChange::Add(Route::new(
            v4(142, 250, 74, 4),
            32
        ))));
        assert!(!concerns_jink(&RouteChange::Delete(Route::new(
            v4(192, 168, 1, 0),
            24
        ))));
    }
}
