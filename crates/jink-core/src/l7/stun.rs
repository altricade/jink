//! STUN message detection (RFC 8489 §5), as zapret `IsStunMessage`.

use crate::cursor::Cursor;

const HEADER_LEN: usize = 20;
const MAGIC_COOKIE: u32 = 0x2112_a442;

#[must_use]
pub fn is_message(payload: &[u8]) -> bool {
    let mut c = Cursor::new(payload);
    let (Some(msg_type), Some(msg_len), Some(cookie)) = (c.u16(), c.u16(), c.u32()) else {
        return false;
    };
    msg_type & 0xc000 == 0
        && msg_len % 4 == 0
        && cookie == MAGIC_COOKIE
        && payload.len().checked_sub(HEADER_LEN) == Some(usize::from(msg_len))
}
