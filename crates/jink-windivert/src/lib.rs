//! Windows backend: captures traffic with WinDivert, runs it through
//! [`jink_core::engine::PacketEngine`], and sends the result.
//!
//! [`filter`] builds the WinDivert filter and works on every platform; the
//! capture loop (`run`) is Windows-only.

pub mod filter;

#[cfg(windows)]
mod capture;
#[cfg(windows)]
mod timestamps;

#[cfg(windows)]
pub use capture::{Event, RunError, Stop, run};
#[cfg(windows)]
pub use timestamps::enable_tcp_timestamps;
