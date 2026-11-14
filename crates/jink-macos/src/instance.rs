//! One jink at a time, and the routes a killed jink left behind.
//!
//! The utun routes go away with the interface when jink dies, but the
//! scoped halves on the uplink (see [`crate::route`]) stay. jink records them
//! in a file while they exist, so the next start can delete exactly those,
//! and nothing that another program added.

use std::fs::{File, TryLockError};
use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use route_manager::Route;

use crate::route::Installed;

/// Held while jink runs (the service, or `jink run`).
pub(crate) const LOCK: &str = "/var/run/jink.lock";
/// The scoped routes of the current uplink. `/var/run` is cleared at boot,
/// as are routes.
pub(crate) const LEFTOVERS: &str = "/var/run/jink.routes";

#[derive(Debug, thiserror::Error)]
pub(crate) enum ClaimError {
    #[error("another jink is already running")]
    Taken,
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// The lock that makes this jink the only one; released when dropped (or
/// when the process dies).
#[derive(Debug)]
pub(crate) struct Lock {
    _held: File,
}

impl Lock {
    pub(crate) fn claim(path: &Path) -> Result<Self, ClaimError> {
        let file = File::options()
            .create(true)
            .truncate(false)
            .write(true)
            .open(path)?;
        match file.try_lock() {
            Ok(()) => Ok(Self { _held: file }),
            Err(TryLockError::WouldBlock) => Err(ClaimError::Taken),
            Err(TryLockError::Error(e)) => Err(e.into()),
        }
    }
}

/// The file of routes to delete after a crash. Only the holder of the
/// [`Lock`] may use it: another jink's routes are not leftovers.
#[derive(Debug)]
pub(crate) struct Leftovers {
    path: PathBuf,
}

impl Leftovers {
    pub(crate) fn new(_lock: &Lock, path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Deletes the routes a killed jink left, returning the ones that could
    /// not be deleted.
    pub(crate) fn sweep(&self) -> Vec<io::Error> {
        let text = match std::fs::read_to_string(&self.path) {
            Ok(text) => text,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Vec::new(),
            Err(e) => return vec![e],
        };
        let mut left = match Installed::adopt(parse(&text)) {
            Ok(routes) => routes.remove(),
            Err(e) => vec![e],
        };
        left.extend(self.forget().err());
        left
    }

    /// Records the scoped routes now in place (replacing any before).
    pub(crate) fn record(&self, routes: &[Route]) -> io::Result<()> {
        std::fs::write(&self.path, format(routes))
    }

    /// Forgets the routes: jink deleted them itself.
    pub(crate) fn forget(&self) -> io::Result<()> {
        match std::fs::remove_file(&self.path) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }
}

/// One scoped route per line: destination, prefix, interface index, and
/// gateway (`-` for none).
fn format(routes: &[Route]) -> String {
    routes
        .iter()
        .map(|r| {
            let gateway = r
                .gateway()
                .map_or_else(|| "-".to_owned(), |g| g.to_string());
            format!(
                "{} {} {} {gateway}\n",
                r.destination(),
                r.prefix(),
                r.if_index().unwrap_or_default()
            )
        })
        .collect::<Vec<_>>()
        .concat()
}

/// The routes [`format`] wrote; lines that do not parse are skipped.
fn parse(text: &str) -> Vec<Route> {
    text.lines()
        .filter_map(|line| {
            let mut fields = line.split(' ');
            let destination: IpAddr = fields.next()?.parse().ok()?;
            let prefix: u8 = fields.next()?.parse().ok()?;
            let if_index: u32 = fields.next()?.parse().ok()?;
            let gateway = match fields.next()? {
                "-" => None,
                g => Some(g.parse::<IpAddr>().ok()?),
            };
            if fields.next().is_some() || if_index == 0 {
                return None;
            }
            let route = Route::new(destination, prefix)
                .with_if_index(if_index)
                .with_if_scope(true);
            Some(match gateway {
                Some(g) => route.with_gateway(g),
                None => route,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::PathBuf;

    use super::{ClaimError, Leftovers, Lock, format, parse};
    use crate::route::{Uplink, scoped_halves};

    fn scratch(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("jink-test-{}-{name}", std::process::id()))
    }

    #[test]
    fn recorded_routes_read_back_the_same() {
        let uplink = Uplink {
            name: "en0".into(),
            index: 14.try_into().unwrap(),
            gateway: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
        };
        let routes = scoped_halves(&uplink);
        let text = format(&routes);
        assert_eq!(
            text,
            "0.0.0.0 1 14 192.168.1.1\n128.0.0.0 1 14 192.168.1.1\n"
        );
        assert_eq!(parse(&text), routes);
        // A point-to-point uplink has no gateway.
        let p2p = scoped_halves(&Uplink {
            gateway: None,
            ..uplink
        });
        assert_eq!(parse(&format(&p2p)), p2p);
    }

    #[test]
    fn damaged_lines_are_skipped() {
        let text = "0.0.0.0 1 14 192.168.1.1\n\
                    garbage\n\
                    0.0.0.0 1 0 -\n\
                    0.0.0.0 1 14 - extra\n\
                    0.0.0.0 x 14 -\n";
        assert_eq!(parse(text).len(), 1);
    }

    #[test]
    fn only_one_holds_the_lock() {
        let path = scratch("lock");
        let first = Lock::claim(&path).unwrap();
        assert!(matches!(Lock::claim(&path), Err(ClaimError::Taken)));
        drop(first);
        let again = Lock::claim(&path).unwrap();
        drop(again);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn forgotten_routes_are_not_swept() {
        let lock_path = scratch("lock2");
        let lock = Lock::claim(&lock_path).unwrap();
        let leftovers = Leftovers::new(&lock, scratch("routes"));
        // Nothing recorded: nothing to do, no error.
        assert!(leftovers.sweep().is_empty());
        leftovers.record(&[]).unwrap();
        leftovers.forget().unwrap();
        leftovers.forget().unwrap();
        assert!(leftovers.sweep().is_empty());
        std::fs::remove_file(lock_path).unwrap();
    }

    #[test]
    fn an_unreadable_record_is_reported() {
        let lock_path = scratch("lock3");
        let lock = Lock::claim(&lock_path).unwrap();
        // A folder where the file should be cannot be read.
        let record = scratch("record-dir");
        std::fs::create_dir_all(&record).unwrap();
        assert_eq!(Leftovers::new(&lock, &record).sweep().len(), 1);
        std::fs::remove_dir(record).unwrap();
        std::fs::remove_file(lock_path).unwrap();
    }
}
