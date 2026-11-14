//! Discord voice IP-discovery request, as zapret `IsDiscordIpDiscoveryRequest`:
//! the first UDP packet a client sends to a voice server.

const LEN: usize = 74;
/// Type 0x0001 (request), length 70.
const HEADER: [u8; 4] = [0x00, 0x01, 0x00, 0x46];
/// After the 4-byte SSRC, the 64-byte address field is empty in a request.
const ADDRESS: std::ops::Range<usize> = 8..72;

#[must_use]
pub fn is_ip_discovery_request(payload: &[u8]) -> bool {
    payload.len() == LEN
        && payload.starts_with(&HEADER)
        && payload
            .get(ADDRESS)
            .is_some_and(|addr| addr.iter().all(|&b| b == 0))
}
