//! Randomness for MD5 signatures and random IP ids: xorshift64*, seeded once
//! from the OS. These values only need to look random to a DPI box, not be
//! cryptographically strong.

use jink_core::desync::Entropy;

#[derive(Debug)]
pub struct OsSeeded(u64);

impl OsSeeded {
    /// # Errors
    /// If the OS has no randomness to give.
    pub fn new() -> Result<Self, getrandom::Error> {
        // xorshift needs a non-zero state.
        Ok(Self(getrandom::u64()? | 1))
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x.wrapping_shr(12);
        x ^= x.wrapping_shl(25);
        x ^= x.wrapping_shr(27);
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
}

impl Entropy for OsSeeded {
    fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            for (b, r) in chunk.iter_mut().zip(self.next().to_le_bytes()) {
                *b = r;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use jink_core::desync::Entropy;

    use super::OsSeeded;

    #[test]
    fn fills_every_byte_and_varies() {
        let mut rng = OsSeeded::new().unwrap();
        let (mut a, mut b) = ([0_u8; 19], [0_u8; 19]);
        rng.fill(&mut a);
        rng.fill(&mut b);
        assert_ne!(a, b);
        assert!(a.iter().any(|&x| x != 0));
    }
}
