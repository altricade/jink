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
use std::net::{IpAddr, Ipv4Addr};
use std::num::NonZeroU32;

use route_manager::{Route, RouteManager};

/// The interface traffic leaves through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Uplink {
    pub(crate) name: String,
    pub(crate) index: NonZeroU32,
    /// The default route's gateway; `None` on a point-to-point uplink.
    pub(crate) gateway: Option<IpAddr>,
}

/// `0.0.0.0/1` and `128.0.0.0/1`: together, every IPv4 address.
const HALVES: [(Ipv4Addr, u8); 2] = [(Ipv4Addr::UNSPECIFIED, 1), (Ipv4Addr::new(128, 0, 0, 0), 1)];

/// The uplink as the current IPv4 default route names it.
///
/// # Errors
/// If the routing table cannot be read, or has no IPv4 default route.
pub(crate) fn uplink() -> io::Result<Uplink> {
    let routes = RouteManager::new()?.list()?;
    default_route(&routes).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "no IPv4 default route: is the Mac connected to a network?",
        )
    })
}

/// The interface of the (unscoped) IPv4 default route.
fn default_route(routes: &[Route]) -> Option<Uplink> {
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

/// The routes jink adds, in order: the halves scoped to the uplink first (so
/// jink's sockets work the moment traffic arrives), then the halves through
/// the utun interface.
fn routes_for(tun_index: u32, uplink: &Uplink) -> Vec<Route> {
    let scoped = HALVES.map(|(network, prefix)| {
        let route = Route::new(IpAddr::V4(network), prefix)
            .with_if_index(uplink.index.get())
            .with_if_scope(true);
        match uplink.gateway {
            Some(gateway) => route.with_gateway(gateway),
            None => route,
        }
    });
    let captured = HALVES
        .map(|(network, prefix)| Route::new(IpAddr::V4(network), prefix).with_if_index(tun_index));
    scoped.into_iter().chain(captured).collect()
}

/// The routes jink added. [`Captured::remove`] deletes them; dropping does
/// too, as a fallback. If jink dies without either, the kernel deletes the
/// utun routes along with the interface; the scoped uplink routes stay, are
/// harmless (they lead where the default route does), and are taken over by
/// the next run.
pub(crate) struct Captured {
    manager: RouteManager,
    routes: Vec<Route>,
}

impl std::fmt::Debug for Captured {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Captured")
            .field("routes", &self.routes)
            .finish_non_exhaustive()
    }
}

impl Captured {
    /// Routes all IPv4 traffic through the interface `tun_index`, keeping
    /// sockets pinned to `uplink` on it.
    ///
    /// # Errors
    /// If a route cannot be added (routes added before it are deleted).
    /// [`io::ErrorKind::AlreadyExists`] means another VPN already routes all
    /// traffic.
    pub(crate) fn add(tun_index: u32, uplink: &Uplink) -> io::Result<Self> {
        let routes = routes_for(tun_index, uplink);
        let mut captured = Self {
            manager: RouteManager::new()?,
            routes: Vec::with_capacity(routes.len()),
        };
        for route in routes {
            match captured.manager.add(&route) {
                Ok(()) => {}
                // Left behind by a jink that was killed: take it over.
                Err(e) if route.if_scope() && e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
            captured.routes.push(route);
        }
        Ok(captured)
    }

    /// Deletes the routes, reporting the ones that could not be deleted.
    pub(crate) fn remove(mut self) -> Vec<io::Error> {
        self.delete_all()
    }

    fn delete_all(&mut self) -> Vec<io::Error> {
        // The utun halves first: normal routing is back before anything else.
        let routes = std::mem::take(&mut self.routes);
        routes
            .iter()
            .rev()
            .filter_map(|r| self.manager.delete(r).err())
            .collect()
    }
}

impl Drop for Captured {
    fn drop(&mut self) {
        // Nothing can be reported from a destructor; see `Captured`.
        let _ = self.delete_all();
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use route_manager::Route;

    use super::{Uplink, default_route, routes_for};

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
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
        assert_eq!(
            default_route(&routes),
            Some(Uplink {
                name: "en0".into(),
                index: 14.try_into().unwrap(),
                gateway: Some(v4(192, 168, 1, 1)),
            })
        );
        assert_eq!(default_route(&routes[..3]), None);
    }

    /// Scoped halves on the uplink through its gateway, then the halves
    /// through the utun interface (unscoped).
    #[test]
    fn routes_keep_pinned_sockets_on_the_uplink() {
        let uplink = Uplink {
            name: "en0".into(),
            index: 14.try_into().unwrap(),
            gateway: Some(v4(192, 168, 1, 1)),
        };
        let shown: Vec<_> = routes_for(7, &uplink)
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
            .collect();
        let gw = Some(v4(192, 168, 1, 1));
        assert_eq!(
            shown,
            vec![
                (v4(0, 0, 0, 0), 1, gw, Some(14), true),
                (v4(128, 0, 0, 0), 1, gw, Some(14), true),
                (v4(0, 0, 0, 0), 1, None, Some(7), false),
                (v4(128, 0, 0, 0), 1, None, Some(7), false),
            ]
        );
    }
}
