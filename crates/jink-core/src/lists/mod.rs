//! Domain and IP lists that decide which flows a rule applies to.

pub mod domain;
pub mod ip;

pub use domain::DomainList;
pub use ip::{InvalidLine, IpList};
