//! Sending fake packets: complete IPv4 packets from the engine, through a
//! raw socket pinned to the uplink, so they leave next to jink's real
//! segments of the same connection.

use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::num::NonZeroU32;

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

/// `IPPROTO_RAW`: the caller supplies the whole IP header.
const IPPROTO_RAW: i32 = 255;

#[derive(Debug)]
pub(crate) struct RawSender(Socket);

impl RawSender {
    /// A raw IPv4 socket (needs root) pinned to the interface `uplink`.
    pub(crate) fn open(uplink: NonZeroU32) -> io::Result<Self> {
        let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(IPPROTO_RAW)))?;
        socket.set_header_included_v4(true)?;
        socket.bind_device_by_index_v4(Some(uplink))?;
        Ok(Self(socket))
    }

    /// Sends one complete IPv4 packet as it is.
    pub(crate) fn send(&self, packet: &[u8]) -> io::Result<()> {
        let (destination, wire) = for_raw_socket(packet)?;
        let sent = self
            .0
            .send_to(&wire, &SockAddr::from(SocketAddrV4::new(destination, 0)))?;
        if sent == wire.len() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "fake packet cut short",
            ))
        }
    }
}

/// The packet's destination, and the packet as a macOS raw socket wants it:
/// with `IP_HDRINCL`, the kernel reads the total length and fragment offset
/// fields in host byte order (as BSD always has; Linux differs) and turns
/// them back to network order on the way out, so the checksum, computed
/// over the network-order header, stays right.
fn for_raw_socket(packet: &[u8]) -> io::Result<(Ipv4Addr, Vec<u8>)> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidInput, "not an IPv4 packet");
    if packet.first().map(|b| b >> 4) != Some(4) {
        return Err(invalid());
    }
    let destination: [u8; 4] = packet
        .get(16..20)
        .and_then(|d| d.try_into().ok())
        .ok_or_else(invalid)?;
    let mut wire = packet.to_vec();
    for field in [2..4, 6..8] {
        let bytes = wire.get_mut(field).ok_or_else(invalid)?;
        let value = <[u8; 2]>::try_from(&*bytes).map_err(|_| invalid())?;
        bytes.copy_from_slice(&u16::from_be_bytes(value).to_ne_bytes());
    }
    Ok((Ipv4Addr::from(destination), wire))
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::for_raw_socket;

    #[test]
    fn length_and_fragment_fields_are_in_host_order() {
        // 20-byte header: total length 0x0102, flags/offset 0x4000 (DF).
        let mut packet = vec![
            0x45, 0, 0x01, 0x02, 0xab, 0xcd, 0x40, 0x00, 64, 6, 0x12, 0x34, 192, 168, 1, 10, 142,
            250, 74, 4,
        ];
        packet.resize(0x0102, 0);
        let (destination, wire) = for_raw_socket(&packet).unwrap();
        assert_eq!(destination, Ipv4Addr::new(142, 250, 74, 4));
        assert_eq!(wire[2..4], 0x0102_u16.to_ne_bytes());
        assert_eq!(wire[6..8], 0x4000_u16.to_ne_bytes());
        // Everything else, checksum and id included, is untouched.
        assert_eq!(wire[4..6], packet[4..6]);
        assert_eq!(wire[8..], packet[8..]);
    }

    #[test]
    fn rejects_non_ipv4() {
        assert!(for_raw_socket(&[0x60; 40]).is_err());
        assert!(for_raw_socket(&[0x45; 10]).is_err());
    }
}
