//! Which desync techniques each platform backend can perform.
//!
//! Windows (WinDivert) sees and rewrites every packet the kernel sends, so it
//! supports everything the configuration can express. The macOS backend
//! (design B: utun + userspace TCP/IP + raw sockets) owns the connection
//! instead: it can add forged packets anywhere (before, between and after its
//! writes) and choose where its writes split the stream, but it cannot shift
//! the kernel's sequence numbers, reorder its segments, or put data into its
//! SYN. Techniques that need that are reported here so a configuration fails
//! at load time rather than silently doing less.

use super::{Config, Desync, Split};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Windows,
    MacOs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Technique {
    /// Overlapping sequence numbers on a real segment.
    SeqOvl,
    /// Data in the SYN packet.
    SynData,
    /// Real segments sent in reverse order.
    MultiDisorder,
    /// `hostfakesplit` with `altorder`: the rest of the message sent before
    /// the real host name.
    HostFakeSplitAltOrder,
}

/// A technique a rule asks for that the platform cannot do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unsupported {
    /// Index into [`Config::rules`].
    pub rule: usize,
    pub technique: Technique,
}

impl Platform {
    #[must_use]
    pub const fn supports(self, technique: Technique) -> bool {
        match self {
            Self::Windows => true,
            Self::MacOs => match technique {
                Technique::SeqOvl
                | Technique::SynData
                | Technique::MultiDisorder
                | Technique::HostFakeSplitAltOrder => false,
            },
        }
    }

    /// Every rule/technique pair in `config` this platform cannot perform.
    #[must_use]
    pub fn unsupported(self, config: &Config) -> Vec<Unsupported> {
        config
            .rules
            .iter()
            .enumerate()
            .flat_map(|(rule, r)| {
                techniques(&r.desync)
                    .into_iter()
                    .filter(move |&t| !self.supports(t))
                    .map(move |technique| Unsupported { rule, technique })
            })
            .collect()
    }
}

/// Techniques a rule actually uses that some platform lacks. A seqovl
/// setting has an effect with `multisplit`, `multidisorder` and
/// `fakedsplit`.
fn techniques(d: &Desync) -> Vec<Technique> {
    let split = d.modes.split.map(|s| match s {
        Split::MultiSplit | Split::FakedSplit => None,
        Split::MultiDisorder => Some(Technique::MultiDisorder),
        Split::HostFakeSplit => d
            .hostfakesplit
            .alt_order
            .then_some(Technique::HostFakeSplitAltOrder),
    });
    let overlaps = matches!(
        d.modes.split,
        Some(Split::MultiSplit | Split::MultiDisorder | Split::FakedSplit)
    );
    [
        d.modes.syndata.then_some(Technique::SynData),
        (overlaps && d.seqovl.is_some()).then_some(Technique::SeqOvl),
        split.flatten(),
    ]
    .into_iter()
    .flatten()
    .collect()
}
