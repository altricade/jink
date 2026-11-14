//! jink's utun interface, as the byte stream the userspace stack reads IP
//! packets from and writes them to.

use std::io;
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tun_rs::{AsyncDevice, DeviceBuilder};

/// The interface's own address. Apps' connections through jink come from it:
/// the kernel picks the source address of the interface a route points at.
/// 198.18.0.0/15 is reserved for benchmarking (RFC 2544), so it does not
/// clash with real networks.
pub(crate) const ADDRESS: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 1);
const PREFIX: u8 = 30;
pub(crate) const MTU: u16 = 1500;

/// Creates a utun interface (needs root). It disappears, with every route
/// through it, when the device is dropped or the process exits.
pub(crate) fn create() -> io::Result<AsyncDevice> {
    DeviceBuilder::new()
        .ipv4(ADDRESS, PREFIX, None)
        .mtu(MTU)
        .build_async()
}

/// One IP packet per read and per write.
pub(crate) struct TunIo(pub(crate) AsyncDevice);

impl std::fmt::Debug for TunIo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunIo").finish_non_exhaustive()
    }
}

impl AsyncRead for TunIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let n = ready!(self.0.poll_recv(cx, buf.initialize_unfilled()))?;
        buf.advance(n);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for TunIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.0.poll_send(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
