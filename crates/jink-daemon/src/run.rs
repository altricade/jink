//! The daemon on macOS: the control socket, the state in jink's folder, and
//! a clean stop on SIGTERM (launchd stopping the service), SIGINT or SIGHUP.

use std::io;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use tokio::net::UnixListener;
use tokio::signal::unix::{SignalKind, signal};

use crate::daemon::{Setup, spawn};
use crate::macos::MacOs;
use crate::server;

/// The control socket.
pub const SOCKET: &str = "/var/run/jink.sock";
/// The group allowed to use it: every user account of a Mac is in `staff`.
const STAFF: u32 = 20;
/// The state file, inside the daemon's folder.
const STATE: &str = "state.json";

#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    #[error("the jink daemon is already running")]
    AlreadyRunning,
    #[error("the daemon needs root: run it with sudo")]
    NotRoot,
    #[error("cannot set up the control socket {SOCKET}: {0}")]
    Socket(io::Error),
    #[error("cannot create the daemon's folder {path}: {source}")]
    Folder { path: String, source: io::Error },
    #[error("cannot start the async runtime or signal handlers: {0}")]
    Runtime(io::Error),
}

/// Runs the daemon until a signal, keeping its state in `home`.
///
/// # Errors
/// If it cannot set up, or the control socket fails.
pub fn run(home: &Path) -> Result<(), DaemonError> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(DaemonError::Runtime)?
        .block_on(serve(home))
}

async fn serve(home: &Path) -> Result<(), DaemonError> {
    std::fs::create_dir_all(home).map_err(|source| match source.kind() {
        io::ErrorKind::PermissionDenied => DaemonError::NotRoot,
        _ => DaemonError::Folder {
            path: home.display().to_string(),
            source,
        },
    })?;
    let listener = bind(Path::new(SOCKET))?;
    let mut interrupt = signal(SignalKind::interrupt()).map_err(DaemonError::Runtime)?;
    let mut terminate = signal(SignalKind::terminate()).map_err(DaemonError::Runtime)?;
    let mut hangup = signal(SignalKind::hangup()).map_err(DaemonError::Runtime)?;
    let (handle, task) = spawn(Setup {
        backend: MacOs,
        saved_at: home.join(STATE),
        log: Box::new(log),
    });
    log("started");
    let ended = loop {
        tokio::select! {
            _ = interrupt.recv() => break Ok(()),
            _ = terminate.recv() => break Ok(()),
            _ = hangup.recv() => break Ok(()),
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    let handle = handle.clone();
                    tokio::spawn(async move {
                        let (read, write) = stream.into_split();
                        // An app that goes away mid-request is no news.
                        let _ = server::connection(read, write, &handle).await;
                    });
                }
                Err(e) => break Err(DaemonError::Socket(e)),
            },
        }
    };
    handle.shut_down().await;
    if let Err(e) = task.await {
        log(&format!("the daemon's task failed: {e}"));
    }
    if let Err(e) = std::fs::remove_file(SOCKET) {
        log(&format!("cannot remove {SOCKET}: {e}"));
    }
    log("stopped");
    ended
}

/// Listens on `path`, open to the Mac's users. A socket left by a daemon
/// that died is replaced; a live daemon's is not.
fn bind(path: &Path) -> Result<UnixListener, DaemonError> {
    if std::os::unix::net::UnixStream::connect(path).is_ok() {
        return Err(DaemonError::AlreadyRunning);
    }
    match std::fs::remove_file(path) {
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => return Err(DaemonError::NotRoot),
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(DaemonError::Socket(e)),
        _ => {}
    }
    let listener = UnixListener::bind(path).map_err(|e| match e.kind() {
        io::ErrorKind::PermissionDenied => DaemonError::NotRoot,
        _ => DaemonError::Socket(e),
    })?;
    std::os::unix::fs::chown(path, None, Some(STAFF)).map_err(DaemonError::Socket)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))
        .map_err(DaemonError::Socket)?;
    Ok(listener)
}

/// A line in the daemon's log (its standard error, which launchd sends to
/// the log file). A log that cannot be written cannot report that either.
fn log(line: &str) {
    let _ = writeln!(io::stderr().lock(), "jink: {line}");
}
