//! Desync planning: from a rule and an outgoing packet to the packets that
//! actually go on the wire.

mod craft;
pub mod plan;
pub mod positions;

pub use craft::CraftError;
pub use plan::{Entropy, Message, Plan, PlanError, Verdict, plan, unimplemented};
pub use positions::Positions;
