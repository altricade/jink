//! What the kernel chose for jink's own connections: sequence numbers, TCP
//! timestamps, TTL. Fake packets must carry them to look like part of the
//! connection, and macOS does not expose them to the socket's owner, so a
//! BPF capture on the uplink watches every handshake (SYN and SYN-ACK only).
//!
//! A connection registers before it connects ([`Handshakes::expect`], keyed
//! by its local port and server), the capture thread fills it in, and the
//! connection collects it once it has the app's first message.

use std::collections::HashMap;
use std::net::{SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::Duration;

use jink_core::engine::stream::TcpConnection;
use jink_core::packet::{IpHeader, TcpFlags, TcpTimestamps, Transport, dissect};
use pcap::{Active, Capture, Linktype};
use tokio::sync::oneshot;

/// One SYN or SYN-ACK, as captured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Seen {
    src: SocketAddrV4,
    dst: SocketAddrV4,
    ttl: u8,
    flags: TcpFlags,
    seq: u32,
    ack: u32,
    window: u16,
    mss: Option<u16>,
    timestamps: Option<TcpTimestamps>,
}

/// The IPv4 packet inside a captured frame.
fn ip_packet(linktype: Linktype, frame: &[u8]) -> Option<&[u8]> {
    const ETHERTYPE_IPV4: [u8; 2] = [0x08, 0x00];
    const ETHERTYPE_VLAN: [u8; 2] = [0x81, 0x00];
    match linktype {
        Linktype::ETHERNET => match frame.get(12..14)? {
            t if t == ETHERTYPE_IPV4 => frame.get(14..),
            t if t == ETHERTYPE_VLAN && frame.get(16..18)? == ETHERTYPE_IPV4 => frame.get(18..),
            _ => None,
        },
        // Point-to-point and loopback: a 4-byte address family, host order.
        Linktype::NULL => {
            let family = u32::from_ne_bytes(frame.get(..4)?.try_into().ok()?);
            (family == 2).then(|| frame.get(4..)).flatten()
        }
        _ => None,
    }
}

/// A captured IPv4 SYN or SYN-ACK.
fn handshake_segment(linktype: Linktype, frame: &[u8]) -> Option<Seen> {
    let packet = dissect(ip_packet(linktype, frame)?).ok()?;
    let IpHeader::V4 { src, dst, ttl, .. } = packet.ip else {
        return None;
    };
    let Transport::Tcp { header, .. } = packet.transport else {
        return None;
    };
    header.flags.contains(TcpFlags::SYN).then_some(Seen {
        src: SocketAddrV4::new(src, header.src_port),
        dst: SocketAddrV4::new(dst, header.dst_port),
        ttl,
        flags: header.flags,
        seq: header.seq,
        ack: header.ack,
        window: header.window,
        mss: header.options.mss,
        timestamps: header.options.timestamps,
    })
}

/// Local port and server of one of jink's connections.
type Key = (u16, SocketAddr);

#[derive(Debug)]
struct Slot {
    syn: Option<Seen>,
    done: Option<oneshot::Sender<TcpConnection>>,
}

/// Connections waiting for their handshake.
#[derive(Debug, Default)]
pub(crate) struct Handshakes {
    pending: Mutex<HashMap<Key, Slot>>,
}

/// One connection's claim on its handshake; dropping it unregisters.
#[derive(Debug)]
pub(crate) struct Expected {
    handshakes: Arc<Handshakes>,
    key: Key,
    done: oneshot::Receiver<TcpConnection>,
}

impl Expected {
    /// The connection as its handshake showed it, or `None` if it was not
    /// seen within `timeout`.
    pub(crate) async fn wait(&mut self, timeout: Duration) -> Option<TcpConnection> {
        tokio::time::timeout(timeout, &mut self.done)
            .await
            .ok()?
            .ok()
    }
}

impl Drop for Expected {
    fn drop(&mut self) {
        self.handshakes.slots().remove(&self.key);
    }
}

impl Handshakes {
    fn slots(&self) -> std::sync::MutexGuard<'_, HashMap<Key, Slot>> {
        // A panic elsewhere cannot leave the map inconsistent: every update
        // is a single insert, remove or field write.
        self.pending.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Registers a connection about to be made from `local_port` to
    /// `server`.
    pub(crate) fn expect(self: &Arc<Self>, local_port: u16, server: SocketAddr) -> Expected {
        let (tx, rx) = oneshot::channel();
        let key = (local_port, server);
        self.slots().insert(
            key,
            Slot {
                syn: None,
                done: Some(tx),
            },
        );
        Expected {
            handshakes: Arc::clone(self),
            key,
            done: rx,
        }
    }

    /// Takes in one captured SYN or SYN-ACK.
    fn observe(&self, seen: &Seen) {
        let mut slots = self.slots();
        if seen.flags.contains(TcpFlags::ACK) {
            // SYN-ACK from the server, for the SYN it acknowledges.
            let key = (seen.dst.port(), SocketAddr::V4(seen.src));
            let Some(slot) = slots.get_mut(&key) else {
                return;
            };
            let Some(syn) = slot.syn.filter(|s| s.seq.wrapping_add(1) == seen.ack) else {
                return;
            };
            if let Some(done) = slot.done.take() {
                // The connection may have given up waiting; nothing to do.
                let _ = done.send(connection(&syn, seen));
            }
        } else if let Some(slot) = slots.get_mut(&(seen.src.port(), SocketAddr::V4(seen.dst))) {
            // jink's SYN (the latest, if retransmitted).
            slot.syn = Some(*seen);
        }
    }
}

/// The connection right after its handshake: nothing sent yet but the SYN,
/// nothing received but the SYN-ACK.
fn connection(syn: &Seen, syn_ack: &Seen) -> TcpConnection {
    // In use only if both sides sent the option.
    let timestamps = syn
        .timestamps
        .zip(syn_ack.timestamps)
        .map(|(ours, theirs)| TcpTimestamps {
            value: ours.value,
            echo_reply: theirs.value,
        });
    TcpConnection {
        local: SocketAddr::V4(syn.src),
        server: SocketAddr::V4(syn.dst),
        seq: syn.seq.wrapping_add(1),
        ack: syn_ack.seq.wrapping_add(1),
        window: syn.window,
        ttl: syn.ttl,
        timestamps,
        mss: segment_payload(syn.mss, syn_ack.mss, timestamps.is_some()),
    }
}

/// How much payload the kernel puts in one segment: the smaller of the two
/// advertised MSS values (RFC 9293's 536 if the server gave none), less the
/// 12 bytes the timestamps option takes in every segment.
fn segment_payload(ours: Option<u16>, theirs: Option<u16>, timestamps: bool) -> u16 {
    const DEFAULT_MSS: u16 = 536;
    const TIMESTAMPS_SPACE: u16 = 12;
    let mss = theirs.unwrap_or(DEFAULT_MSS).min(ours.unwrap_or(u16::MAX));
    if timestamps {
        mss.saturating_sub(TIMESTAMPS_SPACE)
    } else {
        mss
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    #[error("cannot capture on {interface}: {source}")]
    Open {
        interface: String,
        source: pcap::Error,
    },
    #[error("cannot capture on {interface}: unsupported link type {linktype:?}")]
    LinkType {
        interface: String,
        linktype: Linktype,
    },
}

/// The capture thread; [`Watcher::stop`] ends it, and so does dropping (the
/// thread then ends on its own within a read timeout).
#[derive(Debug)]
pub(crate) struct Watcher {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<Result<(), pcap::Error>>>,
}

/// How long a capture read waits before checking whether to stop.
const READ_TIMEOUT_MS: i32 = 100;

impl Watcher {
    /// Starts watching handshakes on `interface` (needs root).
    pub(crate) fn start(
        interface: &str,
        handshakes: Arc<Handshakes>,
    ) -> Result<Self, CaptureError> {
        let open = |source| CaptureError::Open {
            interface: interface.to_owned(),
            source,
        };
        let mut capture = Capture::from_device(interface)
            .and_then(|c| {
                c.immediate_mode(true)
                    .snaplen(256)
                    .timeout(READ_TIMEOUT_MS)
                    .open()
            })
            .map_err(open)?;
        capture
            .filter("ip and tcp[tcpflags] & tcp-syn != 0", true)
            .map_err(open)?;
        let linktype = capture.get_datalink();
        if !matches!(linktype, Linktype::ETHERNET | Linktype::NULL) {
            return Err(CaptureError::LinkType {
                interface: interface.to_owned(),
                linktype,
            });
        }
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || watch(&mut capture, linktype, &handshakes, &stop))
        };
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }

    /// Stops the thread, returning how it ended.
    pub(crate) fn stop(mut self) -> Result<(), pcap::Error> {
        self.stop.store(true, Ordering::Relaxed);
        self.thread.take().map_or(Ok(()), |thread| {
            thread.join().unwrap_or(Err(pcap::Error::PcapError(
                "capture thread panicked".into(),
            )))
        })
    }
}

impl Drop for Watcher {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn watch(
    capture: &mut Capture<Active>,
    linktype: Linktype,
    handshakes: &Handshakes,
    stop: &AtomicBool,
) -> Result<(), pcap::Error> {
    while !stop.load(Ordering::Relaxed) {
        match capture.next_packet() {
            Ok(packet) => {
                if let Some(seen) = handshake_segment(linktype, packet.data) {
                    handshakes.observe(&seen);
                }
            }
            Err(pcap::Error::TimeoutExpired) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::sync::Arc;
    use std::time::Duration;

    use etherparse::PacketBuilder;
    use jink_core::packet::TcpTimestamps;
    use pcap::Linktype;

    use super::{Handshakes, handshake_segment};

    const MAC: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 10);
    const SERVER: Ipv4Addr = Ipv4Addr::new(142, 250, 74, 4);

    /// An Ethernet frame holding a TCP segment with the timestamps option.
    fn frame(from_mac: bool, syn_ack: bool, seq: u32, ack: u32, tsval: u32) -> Vec<u8> {
        let (src, dst, sport, dport) = if from_mac {
            (MAC, SERVER, 50_123, 443)
        } else {
            (SERVER, MAC, 443, 50_123)
        };
        let builder = PacketBuilder::ethernet2([1; 6], [2; 6])
            .ipv4(src.octets(), dst.octets(), 64)
            .tcp(sport, dport, seq, 65_535)
            .syn()
            .options(&[
                etherparse::TcpOptionElement::MaximumSegmentSize(if from_mac {
                    1460
                } else {
                    1412
                }),
                etherparse::TcpOptionElement::Timestamp(tsval, 0),
            ])
            .unwrap();
        let builder = if syn_ack { builder.ack(ack) } else { builder };
        let mut out = Vec::new();
        builder.write(&mut out, &[]).unwrap();
        out
    }

    fn server() -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(SERVER, 443))
    }

    #[tokio::test]
    async fn syn_and_syn_ack_give_the_connection() {
        let handshakes = Arc::new(Handshakes::default());
        let mut expected = handshakes.expect(50_123, server());
        for f in [
            frame(true, false, 1000, 0, 7000),
            frame(false, true, 9000, 1001, 8000),
        ] {
            let seen = handshake_segment(Linktype::ETHERNET, &f).unwrap();
            handshakes.observe(&seen);
        }
        let conn = expected.wait(Duration::from_secs(1)).await.unwrap();
        assert_eq!(conn.local, SocketAddr::V4(SocketAddrV4::new(MAC, 50_123)));
        assert_eq!(conn.server, server());
        assert_eq!(
            (conn.seq, conn.ack, conn.ttl, conn.window),
            (1001, 9001, 64, 65_535)
        );
        // The server's 1412 less 12 for timestamps: what the user's capture
        // showed (1400-byte segments).
        assert_eq!(conn.mss, 1400);
        assert_eq!(
            conn.timestamps,
            Some(TcpTimestamps {
                value: 7000,
                echo_reply: 8000,
            })
        );
        drop(expected);
        assert!(handshakes.slots().is_empty());
    }

    /// A SYN-ACK for another SYN (wrong ack), or for a connection nobody
    /// expects, is ignored.
    #[tokio::test]
    async fn unrelated_segments_are_ignored() {
        let handshakes = Arc::new(Handshakes::default());
        let mut expected = handshakes.expect(50_123, server());
        for f in [
            frame(true, false, 1000, 0, 7000),
            frame(false, true, 9000, 5555, 8000),
        ] {
            handshakes.observe(&handshake_segment(Linktype::ETHERNET, &f).unwrap());
        }
        assert_eq!(expected.wait(Duration::from_millis(50)).await, None);
    }

    #[test]
    fn non_syn_and_non_ipv4_frames_are_skipped() {
        let mut data = Vec::new();
        PacketBuilder::ethernet2([1; 6], [2; 6])
            .ipv4(MAC.octets(), SERVER.octets(), 64)
            .tcp(50_123, 443, 1, 100)
            .ack(5)
            .write(&mut data, b"hi")
            .unwrap();
        assert_eq!(handshake_segment(Linktype::ETHERNET, &data), None);
        let mut arp = frame(true, false, 1, 0, 1);
        arp[12..14].copy_from_slice(&[0x08, 0x06]);
        assert_eq!(handshake_segment(Linktype::ETHERNET, &arp), None);
    }

    #[test]
    fn segment_payload_follows_the_smaller_mss() {
        use super::segment_payload;
        assert_eq!(segment_payload(Some(1460), Some(1412), true), 1400);
        assert_eq!(segment_payload(Some(1460), Some(1460), false), 1460);
        assert_eq!(segment_payload(Some(1200), Some(1460), false), 1200);
        assert_eq!(segment_payload(Some(1460), None, false), 536);
    }
}
