//! The flow engine: per-connection state and the drivers that turn captured
//! traffic into desync actions.
//!
//! [`flow`] is shared by every backend. [`packet`] drives backends that see
//! each packet (WinDivert on Windows). A stream-mode driver for the macOS
//! backend, which owns its connections, will reuse [`flow`].

pub mod flow;
mod inspect;
pub mod packet;
pub mod stream;

pub use flow::{FlowKey, FlowTable, TcpState};
pub use packet::{Direction, Outgoing, Output, PacketEngine, Released};
