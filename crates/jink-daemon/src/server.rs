//! The control channel over a local stream socket: one JSON request per
//! line, one reply per request, and after `watch` a stream of updates.

use std::io;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::broadcast::error::RecvError;

use crate::daemon::Handle;
use crate::protocol::{Failure, Message, Request};

/// The longest request line read; a longer one ends the connection.
const MAX_LINE: u64 = 64 * 1024;

/// Answers one app until it disconnects.
///
/// # Errors
/// If the connection fails (the app went away, usually).
pub async fn connection(
    read: impl AsyncRead + Unpin,
    mut write: impl AsyncWrite + Unpin,
    handle: &Handle,
) -> io::Result<()> {
    let mut reader = BufReader::new(read);
    let mut line = Vec::new();
    loop {
        line.clear();
        let read = (&mut reader)
            .take(MAX_LINE)
            .read_until(b'\n', &mut line)
            .await?;
        if read == 0 {
            return Ok(());
        }
        if !line.ends_with(b"\n") && u64::try_from(read) == Ok(MAX_LINE) {
            let reply = bad_request(format!("a request is at most {MAX_LINE} bytes"));
            return send(&mut write, &reply).await;
        }
        let reply = match serde_json::from_slice::<Request>(&line) {
            Ok(Request::Watch) => return watch(&mut write, handle).await,
            Ok(request) => handle.request(request).await,
            Err(e) => bad_request(e.to_string()),
        };
        send(&mut write, &reply).await?;
    }
}

fn bad_request(detail: String) -> Message {
    Message::Error {
        error: Failure::BadRequest { detail },
    }
}

async fn send(write: &mut (impl AsyncWrite + Unpin), message: &Message) -> io::Result<()> {
    let mut text = serde_json::to_vec(message).map_err(io::Error::other)?;
    text.push(b'\n');
    write.write_all(&text).await?;
    write.flush().await
}

/// The status now and at every change, and every notice, until the app
/// goes away or the daemon stops.
async fn watch(write: &mut (impl AsyncWrite + Unpin), handle: &Handle) -> io::Result<()> {
    let (mut status, mut notices) = handle.watch();
    loop {
        let current = status.borrow_and_update().clone();
        send(write, &Message::Status { status: current }).await?;
        loop {
            tokio::select! {
                changed = status.changed() => match changed {
                    Ok(()) => break,
                    Err(_) => return Ok(()),
                },
                notice = notices.recv() => match notice {
                    Ok(notice) => send(write, &Message::Notice { notice }).await?,
                    // Missed some under load: the status still follows.
                    Err(RecvError::Lagged(_)) => {}
                    Err(RecvError::Closed) => return Ok(()),
                },
            }
        }
    }
}
