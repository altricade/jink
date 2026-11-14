//! Relaying one app connection (TCP) or flow (UDP) to its server through a
//! socket pinned to the uplink.
//!
//! For TCP, the app's first message is held back until a [`FirstMessage`]
//! hook has planned it: fake packets and writes, in the order to send them.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroU32;
use std::ops::Range;
use std::time::Duration;

use jink_core::engine::stream::{MAX_MESSAGE, TcpStep, wanted_len};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

/// How long to wait for a server to accept a connection.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long to wait for the rest of a first message (a ClientHello the app
/// writes in pieces) once it has started.
const MESSAGE_WAIT: Duration = Duration::from_millis(500);
/// The largest UDP payload.
const MAX_DATAGRAM: usize = 65_535;

#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    #[error("TCP connect failed: {0}")]
    TcpConnect(io::Error),
    #[error("TCP connection ended with an error: {0}")]
    TcpTransfer(io::Error),
    #[error("UDP socket failed: {0}")]
    UdpSocket(io::Error),
    #[error("UDP flow ended with an error: {0}")]
    UdpTransfer(io::Error),
}

/// What a TCP relay asks before sending the app's first message.
pub(crate) trait FirstMessage {
    /// A registration made before connecting.
    type Ticket;

    /// Called once the socket has its local address, before it connects.
    fn expect(&self, local: SocketAddr, server: SocketAddr) -> Self::Ticket;

    /// The steps to send `message` with: fakes, and writes that cover it in
    /// order (otherwise it is written whole, without fakes).
    fn prepare(
        &self,
        ticket: Self::Ticket,
        server: SocketAddr,
        message: &[u8],
    ) -> impl Future<Output = Vec<TcpStep>>;

    /// Sends one fake packet (reporting a failure is up to the hook).
    fn fake(&self, server: SocketAddr, packet: &[u8]);
}

/// Connects to `server` through the uplink (then calls `connected`), sends
/// the app's first message as `first` prepares it, and copies both ways
/// until both sides have closed.
///
/// # Errors
/// If the connection cannot be made or fails midway.
pub(crate) async fn tcp<A, F>(
    mut app: A,
    server: SocketAddr,
    uplink: NonZeroU32,
    first: &F,
    connected: impl FnOnce(),
) -> Result<(), RelayError>
where
    A: AsyncRead + AsyncWrite + Unpin,
    F: FirstMessage,
{
    let (socket, local) = tcp_socket(server, uplink).map_err(RelayError::TcpConnect)?;
    let ticket = first.expect(local, server);
    let mut upstream = tokio::time::timeout(CONNECT_TIMEOUT, socket.connect(server))
        .await
        .map_err(|_| RelayError::TcpConnect(io::ErrorKind::TimedOut.into()))?
        .map_err(RelayError::TcpConnect)?;
    connected();
    match first_message(&mut app, &upstream)
        .await
        .map_err(RelayError::TcpTransfer)?
    {
        Some(message) => {
            let steps = first.prepare(ticket, server, &message).await;
            send_steps(&mut upstream, &message, &steps, |packet| {
                first.fake(server, packet);
            })
            .await
            .map_err(RelayError::TcpTransfer)?;
        }
        None => drop(ticket),
    }
    tokio::io::copy_bidirectional(&mut app, &mut upstream)
        .await
        .map_err(RelayError::TcpTransfer)?;
    Ok(())
}

/// A TCP socket for `server` that leaves through the interface `uplink`,
/// whatever the routing table says, already bound to a local port. Each
/// write goes out without waiting to be coalesced (`TCP_NODELAY`).
fn tcp_socket(server: SocketAddr, uplink: NonZeroU32) -> io::Result<(TcpSocket, SocketAddr)> {
    let socket = pinned(server, Type::STREAM, Protocol::TCP, uplink)?;
    socket.set_tcp_nodelay(true)?;
    let any = match server {
        SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
    };
    socket.bind(&any.into())?;
    let local = socket
        .local_addr()?
        .as_socket()
        .ok_or_else(|| io::Error::other("bound socket has no IP address"))?;
    Ok((TcpSocket::from_std_stream(socket.into()), local))
}

/// The app's first message: one read, completed to a whole TLS record if it
/// starts one (waiting up to [`MESSAGE_WAIT`]). `None` if the server speaks
/// first or the app closes without sending: nothing to prepare then.
async fn first_message<A>(app: &mut A, upstream: &TcpStream) -> io::Result<Option<Vec<u8>>>
where
    A: AsyncRead + Unpin,
{
    let mut message = vec![0_u8; MAX_MESSAGE];
    let mut have = tokio::select! {
        read = app.read(&mut message) => read?,
        ready = upstream.readable() => {
            ready?;
            return Ok(None);
        }
    };
    if have == 0 {
        return Ok(None);
    }
    let want = message.get(..have).and_then(wanted_len).unwrap_or(have);
    let read_rest = async {
        while have < want {
            let Some(rest) = message.get_mut(have..want) else {
                break;
            };
            match app.read(rest).await? {
                0 => break,
                n => have = have.saturating_add(n),
            }
        }
        io::Result::Ok(())
    };
    // On timeout, go with what has arrived.
    if let Ok(Err(e)) = tokio::time::timeout(MESSAGE_WAIT, read_rest).await {
        return Err(e);
    }
    message.truncate(have);
    Ok(Some(message))
}

/// Sends `message` as `steps` say: each fake through `fake`, each write as
/// its own write. If the writes do not cover the message in order, it is
/// written whole and no fake is sent.
async fn send_steps<W: AsyncWrite + Unpin>(
    upstream: &mut W,
    message: &[u8],
    steps: &[TcpStep],
    mut fake: impl FnMut(&[u8]),
) -> io::Result<()> {
    let writes = steps.iter().filter_map(|s| match s {
        TcpStep::Write(range) => Some(range),
        TcpStep::Fake(_) => None,
    });
    let end = writes.clone().try_fold(0, |at, range: &Range<usize>| {
        (range.start == at && range.start < range.end).then_some(range.end)
    });
    if end != Some(message.len()) {
        return upstream.write_all(message).await;
    }
    for step in steps {
        match step {
            TcpStep::Fake(packet) => fake(packet),
            TcpStep::Write(range) => {
                let part = message.get(range.clone()).unwrap_or_default();
                upstream.write_all(part).await?;
            }
        }
    }
    Ok(())
}

/// Relays the datagrams of one UDP flow (an app's local port talking to
/// `server`) through a socket pinned to the uplink (calling `connected` once
/// it is set up), until the app side ends (the stack closes flows idle for
/// its UDP timeout).
///
/// The app side must return one datagram per read; an empty read ends the
/// flow.
///
/// # Errors
/// If the socket cannot be set up or fails.
pub(crate) async fn udp<A>(
    mut app: A,
    server: SocketAddr,
    uplink: NonZeroU32,
    connected: impl FnOnce(),
) -> Result<(), RelayError>
where
    A: AsyncRead + AsyncWrite + Unpin,
{
    let socket = udp_socket(server, uplink).map_err(RelayError::UdpSocket)?;
    connected();
    let mut up = vec![0_u8; MAX_DATAGRAM];
    let mut down = vec![0_u8; MAX_DATAGRAM];
    loop {
        tokio::select! {
            read = app.read(&mut up) => match read {
                Ok(0) => return Ok(()),
                Ok(n) => {
                    socket.send(filled(&up, n)?).await.map_err(RelayError::UdpTransfer)?;
                }
                Err(e) if e.kind() == io::ErrorKind::TimedOut => return Ok(()),
                Err(e) => return Err(RelayError::UdpTransfer(e)),
            },
            received = socket.recv(&mut down) => match received {
                Ok(n) => app.write_all(filled(&down, n)?).await.map_err(RelayError::UdpTransfer)?,
                // A stray ICMP "port unreachable" for an earlier datagram:
                // not a reason to end the flow.
                Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {}
                Err(e) => return Err(RelayError::UdpTransfer(e)),
            },
        }
    }
}

fn udp_socket(server: SocketAddr, uplink: NonZeroU32) -> io::Result<UdpSocket> {
    let socket = pinned(server, Type::DGRAM, Protocol::UDP, uplink)?;
    socket.connect(&server.into())?;
    UdpSocket::from_std(socket.into())
}

/// A non-blocking socket for talking to `server`, pinned to the interface
/// `uplink` (`IP_BOUND_IF`/`IPV6_BOUND_IF`) so jink's own traffic never
/// loops back into its utun interface.
fn pinned(
    server: SocketAddr,
    ty: Type,
    protocol: Protocol,
    uplink: NonZeroU32,
) -> io::Result<Socket> {
    let socket = match server {
        SocketAddr::V4(_) => {
            let socket = Socket::new(Domain::IPV4, ty, Some(protocol))?;
            socket.bind_device_by_index_v4(Some(uplink))?;
            socket
        }
        SocketAddr::V6(_) => {
            let socket = Socket::new(Domain::IPV6, ty, Some(protocol))?;
            socket.bind_device_by_index_v6(Some(uplink))?;
            socket
        }
    };
    socket.set_nonblocking(true)?;
    Ok(socket)
}

fn filled(buf: &[u8], n: usize) -> Result<&[u8], RelayError> {
    buf.get(..n).ok_or_else(|| {
        RelayError::UdpTransfer(io::Error::new(
            io::ErrorKind::InvalidData,
            "read past the buffer",
        ))
    })
}

#[cfg(test)]
mod tests {
    use std::io::ErrorKind;
    use std::net::SocketAddr;
    use std::num::NonZeroU32;

    use route_manager::RouteManager;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
    use tokio::net::{TcpListener, UdpSocket};

    use std::cell::RefCell;
    use std::rc::Rc;
    use std::sync::Mutex;

    use jink_core::engine::stream::TcpStep;

    use super::{FirstMessage, RelayError, send_steps, tcp, udp};

    /// Records every write, and every fake sent in between, in order.
    #[derive(Default, Clone)]
    struct Wire(Rc<RefCell<Vec<String>>>);

    impl tokio::io::AsyncWrite for Wire {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            self.0
                .borrow_mut()
                .push(String::from_utf8_lossy(buf).into_owned());
            std::task::Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    async fn sent(message: &[u8], steps: &[TcpStep]) -> Vec<String> {
        let wire = Wire::default();
        let log = Rc::clone(&wire.0);
        send_steps(&mut wire.clone(), message, steps, |p| {
            log.borrow_mut()
                .push(format!("fake:{}", String::from_utf8_lossy(p)));
        })
        .await
        .unwrap();
        wire.0.take()
    }

    /// Each write is its own write, fakes go where the plan puts them;
    /// writes that do not cover the message in order (gap, overlap, empty,
    /// short, none) give one whole write and no fakes.
    #[tokio::test]
    async fn steps_are_sent_in_order_or_not_at_all() {
        use TcpStep::{Fake, Write};
        let message = b"0123456789";
        let steps = [
            Fake(b"x".to_vec()),
            Write(0..2),
            Fake(b"y".to_vec()),
            Write(2..7),
            Write(7..10),
            Fake(b"z".to_vec()),
        ];
        assert_eq!(
            sent(message, &steps).await,
            ["fake:x", "01", "fake:y", "23456", "789", "fake:z"]
        );
        for bad in [
            vec![Fake(b"x".to_vec()), Write(0..2), Write(3..10)],
            vec![Write(0..5), Write(4..10)],
            vec![Write(0..0), Write(0..10)],
            vec![Fake(b"x".to_vec()), Write(0..9)],
            vec![Fake(b"x".to_vec())],
        ] {
            assert_eq!(sent(message, &bad).await, ["0123456789"], "{bad:?}");
        }
    }

    /// Writes as given, recording each first message it saw.
    #[derive(Default)]
    struct Recorder {
        split_at: Option<usize>,
        seen: Mutex<Vec<Vec<u8>>>,
    }

    impl FirstMessage for Recorder {
        type Ticket = ();

        fn expect(&self, local: SocketAddr, _: SocketAddr) {
            assert_ne!(local.port(), 0, "registered before binding");
        }

        fn prepare(
            &self,
            (): (),
            _: SocketAddr,
            message: &[u8],
        ) -> impl Future<Output = Vec<TcpStep>> {
            self.seen.lock().unwrap().push(message.to_vec());
            std::future::ready(match self.split_at {
                Some(at) => vec![TcpStep::Write(0..at), TcpStep::Write(at..message.len())],
                None => vec![TcpStep::Write(0..message.len())],
            })
        }

        fn fake(&self, _: SocketAddr, _: &[u8]) {}
    }

    /// An echo server on 127.0.0.1; with `greeting`, it speaks first.
    async fn echo_server(greeting: Option<&'static [u8]>) -> SocketAddr {
        let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut conn, _) = server.accept().await.unwrap();
            if let Some(greeting) = greeting {
                conn.write_all(greeting).await.unwrap();
            }
            let (mut r, mut w) = conn.split();
            tokio::io::copy(&mut r, &mut w).await.unwrap();
        });
        addr
    }

    /// The loopback interface's index, from the routing table.
    fn lo0() -> NonZeroU32 {
        RouteManager::new()
            .unwrap()
            .list()
            .unwrap()
            .iter()
            .find(|r| r.if_name().is_some_and(|n| n == "lo0"))
            .and_then(|r| NonZeroU32::new(r.if_index()?))
            .unwrap()
    }

    /// An app connection relayed to a local echo server through a socket
    /// pinned to lo0, its first message split in two writes.
    #[tokio::test]
    async fn tcp_relays_both_ways() {
        let addr = echo_server(None).await;
        let first = Recorder {
            split_at: Some(2),
            ..Recorder::default()
        };
        let (mut app, stack_side) = duplex(1024);
        let relay = tcp(stack_side, addr, lo0(), &first, || ());
        let talk = async {
            app.write_all(b"hello through jink").await.unwrap();
            let mut echoed = [0_u8; 18];
            app.read_exact(&mut echoed).await.unwrap();
            assert_eq!(&echoed, b"hello through jink");
            app.write_all(b", again").await.unwrap();
            let mut echoed = [0_u8; 7];
            app.read_exact(&mut echoed).await.unwrap();
            assert_eq!(&echoed, b", again");
            drop(app);
        };
        let (relayed, ()) = tokio::join!(relay, talk);
        relayed.unwrap();
        assert_eq!(
            *first.seen.lock().unwrap(),
            vec![b"hello through jink".to_vec()]
        );
    }

    /// A TLS record written in two pieces reaches the hook whole.
    #[tokio::test]
    async fn first_message_waits_for_the_whole_record() {
        let addr = echo_server(None).await;
        let first = Recorder::default();
        // A handshake record header announcing 6 bytes, then a ClientHello
        // header (type 1) and 2 more bytes.
        let record: &[u8] = &[
            0x16, 0x03, 0x01, 0x00, 0x06, 0x01, 0x00, 0x00, 0x02, 0xaa, 0xbb,
        ];
        let (mut app, stack_side) = duplex(1024);
        let relay = tcp(stack_side, addr, lo0(), &first, || ());
        let talk = async {
            app.write_all(&record[..7]).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            app.write_all(&record[7..]).await.unwrap();
            let mut echoed = vec![0_u8; record.len()];
            app.read_exact(&mut echoed).await.unwrap();
            assert_eq!(echoed, record);
            drop(app);
        };
        let (relayed, ()) = tokio::join!(relay, talk);
        relayed.unwrap();
        assert_eq!(*first.seen.lock().unwrap(), vec![record.to_vec()]);
    }

    /// When the server speaks first, nothing is held back or prepared.
    #[tokio::test]
    async fn server_first_protocols_are_not_prepared() {
        let addr = echo_server(Some(b"220 ready\r\n")).await;
        let first = Recorder::default();
        let (mut app, stack_side) = duplex(1024);
        let relay = tcp(stack_side, addr, lo0(), &first, || ());
        let talk = async {
            let mut greeting = [0_u8; 11];
            app.read_exact(&mut greeting).await.unwrap();
            assert_eq!(&greeting, b"220 ready\r\n");
            app.write_all(b"HELO").await.unwrap();
            let mut echoed = [0_u8; 4];
            app.read_exact(&mut echoed).await.unwrap();
            drop(app);
        };
        let (relayed, ()) = tokio::join!(relay, talk);
        relayed.unwrap();
        assert!(first.seen.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn tcp_connect_failure_is_reported() {
        // Bind then drop: nothing listens on this port any more.
        let addr = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        let (_app, stack_side) = duplex(1024);
        let result = tcp(stack_side, addr, lo0(), &Recorder::default(), || ()).await;
        assert!(
            matches!(result, Err(RelayError::TcpConnect(_))),
            "{result:?}"
        );
    }

    /// Pinned to lo0, a socket cannot reach an outside address at once (lo0
    /// has no route there), while the routing table would send it out the
    /// default route and leave it waiting: pinning overrides routing.
    #[tokio::test]
    async fn pinning_overrides_routing() {
        let addr: SocketAddr = "192.0.2.1:9".parse().unwrap();
        let (_app, stack_side) = duplex(1024);
        let result = tcp(stack_side, addr, lo0(), &Recorder::default(), || ()).await;
        let Err(RelayError::TcpConnect(e)) = result else {
            panic!("expected a connect error, got {result:?}");
        };
        assert!(
            matches!(
                e.kind(),
                ErrorKind::NetworkUnreachable | ErrorKind::HostUnreachable
            ),
            "{e:?}"
        );
    }

    #[tokio::test]
    async fn udp_relays_datagrams_both_ways() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0_u8; 64];
            loop {
                let (n, from) = server.recv_from(&mut buf).await.unwrap();
                server.send_to(&buf[..n], from).await.unwrap();
            }
        });
        let (mut app, stack_side) = duplex(1024);
        let relay = tokio::spawn(udp(stack_side, addr, lo0(), || ()));
        for datagram in [&b"first"[..], b"second datagram"] {
            app.write_all(datagram).await.unwrap();
            let mut echoed = vec![0_u8; datagram.len()];
            app.read_exact(&mut echoed).await.unwrap();
            assert_eq!(echoed, datagram);
        }
        drop(app);
        relay.await.unwrap().unwrap();
    }
}
