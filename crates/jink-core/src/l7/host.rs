//! A host name located inside a payload, with the byte positions zapret's
//! split markers refer to (`host`, `endhost`, `sld`, `midsld`, `endsld`).

use std::ops::Range;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostName<'a> {
    /// The name exactly as sent (ASCII; not lowercased).
    pub name: &'a str,
    /// `host`..`endhost`: where the name sits in the payload.
    pub range: Range<usize>,
    /// `sld`..`endsld`: the second-level label, e.g. `google` in
    /// `www.google.com`. `None` when the name has no usable dot, which makes
    /// these markers unresolvable (as in zapret).
    pub sld_range: Option<Range<usize>>,
}

impl<'a> HostName<'a> {
    /// `bytes` is the name, found at absolute offset `start` in the payload.
    /// Non-ASCII names are rejected: SNI and HTTP Host are ASCII by spec.
    pub(crate) fn at(bytes: &'a [u8], start: usize) -> Option<Self> {
        if !bytes.is_ascii() {
            return None;
        }
        let name = std::str::from_utf8(bytes).ok()?;
        let end = start.checked_add(name.len())?;
        let sld_range = match second_level_label(name) {
            Some(r) => Some(start.checked_add(r.start)?..start.checked_add(r.end)?),
            None => None,
        };
        Some(Self {
            name,
            range: start..end,
            sld_range,
        })
    }

    /// `midsld`: middle of the second-level label (`sld+1` for a 1-byte label).
    #[must_use]
    pub fn mid_sld(&self) -> Option<usize> {
        let sld = self.sld_range.as_ref()?;
        let len = sld.len();
        let step = if len == 1 { 1 } else { len / 2 };
        sld.start.checked_add(step)
    }
}

/// zapret `FindNLD(level = 2)`: the label before the last dot.
/// `None` if there is no dot, or the only dot is the first byte.
fn second_level_label(host: &str) -> Option<Range<usize>> {
    let bytes = host.as_bytes();
    let last_dot = bytes.iter().rposition(|&b| b == b'.')?;
    if last_dot == 0 {
        return None;
    }
    let before = bytes.get(..last_dot)?;
    let start = before
        .iter()
        .rposition(|&b| b == b'.')
        .map_or(0, |dot| dot.saturating_add(1));
    Some(start..last_dot)
}

#[cfg(test)]
mod tests {
    use super::{HostName, second_level_label};

    #[test]
    fn sld_matches_zapret_find_nld() {
        assert_eq!(second_level_label("www.google.com"), Some(4..10));
        assert_eq!(second_level_label("4pda.to"), Some(0..4));
        assert_eq!(second_level_label("a.b"), Some(0..1));
        // Leading dot is skipped, empty label between dots is empty.
        assert_eq!(second_level_label(".a.com"), Some(1..2));
        assert_eq!(second_level_label("x..com"), Some(2..2));
        assert_eq!(second_level_label("localhost"), None);
        assert_eq!(second_level_label(".com"), None);
    }

    #[test]
    fn positions_are_absolute() {
        let h = HostName::at(b"www.google.com", 100).unwrap();
        assert_eq!(h.range, 100..114);
        assert_eq!(h.sld_range, Some(104..110));
        assert_eq!(h.mid_sld(), Some(107));
        // One-letter label: midsld is sld+1, as in zapret.
        assert_eq!(HostName::at(b"x.ru", 0).unwrap().mid_sld(), Some(1));
        assert_eq!(HostName::at("é.ru".as_bytes(), 0), None);
    }
}
