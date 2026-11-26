//! jink's background service, shared by the platforms: its state
//! ([`daemon`]), the control channel's messages ([`protocol`]) and
//! connections ([`server`]), what it keeps between runs ([`saved`]), and the
//! finder's host checks ([`probe`]).
//! [`run`] runs it with this system's engine: on macOS as a launchd daemon
//! (see `jink_macos::service`), on Windows as a Windows service
//! ([`service`]).

pub mod daemon;
pub mod entropy;
mod finder;
pub mod probe;
pub mod protocol;
pub mod saved;
pub mod server;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
mod run;

#[cfg(target_os = "macos")]
pub use run::{DaemonError, SOCKET, run};

#[cfg(windows)]
pub mod service;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
mod windows_run;

#[cfg(windows)]
pub use windows_run::{DaemonError, PIPE, SERVICE, home, run};
