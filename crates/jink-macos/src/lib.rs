//! macOS backend: a utun interface takes all IPv4 traffic, a userspace
//! TCP/IP stack ends each app connection inside jink, and jink relays it to
//! the server through its own socket, pinned to the physical interface.
//!
//! Owning the server-side socket is what lets jink desync on macOS, where no
//! WinDivert-style packet diversion exists: it sends fake packets (raw
//! socket) before the real data and chooses how the data is split into
//! segments. The fakes carry the connection's real sequence numbers and
//! timestamps, which a BPF capture of each handshake provides. For UDP it
//! sends decoys from the flow's own socket before the real datagrams.
//!
//! Everything here is macOS-only; on other systems the crate is empty.

#[cfg(target_os = "macos")]
mod desync;
#[cfg(target_os = "macos")]
mod fake;
#[cfg(target_os = "macos")]
mod handshake;
#[cfg(target_os = "macos")]
mod relay;
#[cfg(target_os = "macos")]
mod route;
#[cfg(target_os = "macos")]
mod run;
#[cfg(target_os = "macos")]
mod tun;

#[cfg(target_os = "macos")]
pub use desync::DesyncError;
#[cfg(target_os = "macos")]
pub use handshake::CaptureError;
#[cfg(target_os = "macos")]
pub use relay::RelayError;
#[cfg(target_os = "macos")]
pub use run::{Event, RunError, Summary, run};
