//! jink core: everything that does not depend on the operating system.
//!
//! - [`packet`]: read-only dissection of raw IPv4/IPv6 TCP/UDP packets.
//! - [`l7`]: TLS ClientHello, QUIC Initial (decrypted), HTTP, STUN and Discord
//!   recognition, with the byte positions split markers refer to.
//! - [`lists`] and [`rules`]: domain/IP lists and first-match rule selection.
//! - [`config`]: the typed configuration, a zapret `winws` command-line
//!   importer and per-platform technique support.
//! - [`desync`]: turns an outgoing packet into the forged packets to send and
//!   a verdict for the original.
//! - [`engine`]: per-connection state and the packet-mode driver that applies
//!   all of the above to captured traffic, holding and replaying split hellos.
//!
//! OS backends (WinDivert on Windows, utun + raw sockets on macOS) live in
//! their own crates and feed this one.

pub mod catalog;
pub mod config;
mod cursor;
pub mod desync;
pub mod engine;
pub mod l7;
pub mod lists;
pub mod packet;
pub mod rules;
pub mod settings;
