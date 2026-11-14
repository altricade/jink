//! Bounds-checked big-endian reader over untrusted bytes.
//!
//! Every read returns `None` instead of panicking when the input is too short,
//! so parsers built on it can never index out of bounds or overflow an offset.

#[derive(Debug, Clone)]
pub(crate) struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Offset of the next unread byte, relative to the start of `data`.
    pub(crate) fn pos(&self) -> usize {
        self.pos
    }

    pub(crate) fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let out = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(out)
    }

    pub(crate) fn skip(&mut self, n: usize) -> Option<()> {
        self.take(n).map(|_| ())
    }

    pub(crate) fn u8(&mut self) -> Option<u8> {
        self.take(1)?.first().copied()
    }

    pub(crate) fn u16(&mut self) -> Option<u16> {
        let b: [u8; 2] = self.take(2)?.try_into().ok()?;
        Some(u16::from_be_bytes(b))
    }

    pub(crate) fn u24(&mut self) -> Option<u32> {
        let [a, b, c]: [u8; 3] = self.take(3)?.try_into().ok()?;
        Some(u32::from_be_bytes([0, a, b, c]))
    }

    pub(crate) fn u32(&mut self) -> Option<u32> {
        let b: [u8; 4] = self.take(4)?.try_into().ok()?;
        Some(u32::from_be_bytes(b))
    }

    /// QUIC variable-length integer (RFC 9000 §16): the two high bits of the
    /// first byte give the total length (1, 2, 4 or 8 bytes). At most 62 bits
    /// of value, so the shifts below cannot lose bits.
    pub(crate) fn varint(&mut self) -> Option<u64> {
        let first = *self.data.get(self.pos)?;
        let len = match first >> 6 {
            0 => 1,
            1 => 2,
            2 => 4,
            _ => 8,
        };
        let bytes = self.take(len)?;
        Some(
            bytes
                .iter()
                .skip(1)
                .fold(u64::from(first & 0x3f), |acc, &b| {
                    acc.wrapping_shl(8) | u64::from(b)
                }),
        )
    }

    /// A varint used as a memory length or offset.
    pub(crate) fn varint_usize(&mut self) -> Option<usize> {
        usize::try_from(self.varint()?).ok()
    }

    /// A cursor over at most `n` following bytes (fewer if the input ends
    /// first), advancing this cursor past them. Positions reported by the
    /// sub-cursor stay relative to the original `data`.
    pub(crate) fn sub_truncated(&mut self, n: usize) -> Cursor<'a> {
        let end = self.pos.saturating_add(n).min(self.data.len());
        let sub = Cursor {
            data: self.data.get(..end).unwrap_or(self.data),
            pos: self.pos,
        };
        self.pos = end;
        sub
    }
}

#[cfg(test)]
mod tests {
    use super::Cursor;

    #[test]
    fn reads_are_bounds_checked() {
        let mut c = Cursor::new(&[0x01, 0x02, 0x03]);
        assert_eq!(c.u16(), Some(0x0102));
        assert_eq!(c.u16(), None, "only one byte left");
        assert_eq!(c.pos(), 2, "failed read must not advance");
        assert_eq!(c.u8(), Some(0x03));
        assert_eq!(c.u8(), None);
    }

    #[test]
    fn varints_follow_rfc9000_appendix_a() {
        // Examples from RFC 9000 §A.1.
        let mut c = Cursor::new(&[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c]);
        assert_eq!(c.varint(), Some(151_288_809_941_952_652));
        assert_eq!(
            Cursor::new(&[0x9d, 0x7f, 0x3e, 0x7d]).varint(),
            Some(494_878_333)
        );
        assert_eq!(Cursor::new(&[0x7b, 0xbd]).varint(), Some(15_293));
        assert_eq!(Cursor::new(&[0x25]).varint(), Some(37));
        // A truncated 4-byte varint fails without advancing.
        let mut short = Cursor::new(&[0x9d, 0x7f]);
        assert_eq!(short.varint(), None);
        assert_eq!(short.pos(), 0);
    }

    #[test]
    fn fixed_width_reads() {
        let mut c = Cursor::new(&[0x01, 0x02, 0x03, 0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(c.u24(), Some(0x0001_0203));
        assert_eq!(c.u32(), Some(0xdead_beef));
        assert_eq!(c.u8(), None);
    }

    #[test]
    fn huge_take_does_not_overflow() {
        let mut c = Cursor::new(&[0; 4]);
        c.skip(2).unwrap();
        assert_eq!(c.take(usize::MAX), None);
    }

    #[test]
    fn sub_truncated_keeps_absolute_positions() {
        let mut c = Cursor::new(&[9, 8, 7, 6, 5]);
        c.skip(1).unwrap();
        let mut sub = c.sub_truncated(100);
        assert_eq!(sub.pos(), 1);
        assert_eq!(sub.u16(), Some(0x0807));
        assert_eq!(sub.take(2), Some([6, 5].as_slice()));
        assert_eq!(sub.u8(), None, "sub-cursor ends with the data");
        assert_eq!(c.u8(), None, "outer cursor advanced past the sub-range");
    }
}
