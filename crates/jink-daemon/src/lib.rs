//! jink's background service, shared by the platforms: its state
//! ([`daemon`]), the control channel's messages ([`protocol`]) and
//! connections ([`server`]), and what it keeps between runs ([`saved`]).
//! On macOS, [`run`] runs it with the macOS engine.

pub mod daemon;
pub mod entropy;
pub mod protocol;
pub mod saved;
pub mod server;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
mod run;

#[cfg(target_os = "macos")]
pub use run::{DaemonError, SOCKET, run};
