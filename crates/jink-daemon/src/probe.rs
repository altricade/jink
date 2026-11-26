//! The finder's host checks: does a site answer over TLS 1.2 or TLS 1.3,
//! with its real certificate and an HTTP reply, within a time limit? That
//! is what blocking by name breaks (the connection is cut, or stalls, once
//! the name is seen), and what zapret's own test checks with curl.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::ServerCertVerifier;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, SupportedProtocolVersion};
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio_rustls::TlsConnector;

/// The sites the finder checks: Discord and YouTube, by the names their
/// apps use (all in the built-in lists).
pub const HOSTS: [&str; 8] = [
    "discord.com",
    "gateway.discord.gg",
    "cdn.discordapp.com",
    "updates.discord.com",
    "www.youtube.com",
    "youtu.be",
    "i.ytimg.com",
    "redirector.googlevideo.com",
];

/// A TLS version, checked on its own: blocking may catch one and miss the
/// other, and apps use both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum Tls {
    #[serde(rename = "1.2")]
    V12,
    #[serde(rename = "1.3")]
    V13,
}

impl Tls {
    pub const ALL: [Self; 2] = [Self::V12, Self::V13];
}

/// How a check ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Passed,
    /// The name has no address.
    NoAddress,
    /// No address took the connection (or none came back).
    Unreachable,
    /// The connection was cut, or answered with garbage, during the
    /// handshake.
    Cut,
    /// The certificate is not the site's (a block page, usually).
    Certificate,
    /// The handshake finished, but no HTTP reply came.
    NoReply,
    TimedOut,
}

/// What the finder checks sites with: a [`Prober`] (a fake in tests).
pub trait Probe: Send + Sync + 'static {
    /// Whether `host` answers over `tls`.
    fn check(&self, host: &'static str, tls: Tls) -> impl Future<Output = Outcome> + Send;
}

impl Probe for Prober {
    fn check(&self, host: &'static str, tls: Tls) -> impl Future<Output = Outcome> + Send {
        Self::check(self, host, tls)
    }
}

/// Checks hosts, each with one TLS version at a time.
#[derive(Clone)]
pub struct Prober {
    tls12: TlsConnector,
    tls13: TlsConnector,
    port: u16,
    limit: Duration,
}

impl std::fmt::Debug for Prober {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Prober")
            .field("port", &self.port)
            .field("limit", &self.limit)
            .finish_non_exhaustive()
    }
}

impl Prober {
    /// HTTPS.
    pub const PORT: u16 = 443;
    /// The longest a check may take, from the name lookup to the reply.
    pub const LIMIT: Duration = Duration::from_secs(5);

    /// HTTPS checks, trusting the certificates the system trusts (so that
    /// antivirus that inspects HTTPS with its own root still passes).
    ///
    /// # Errors
    /// If the system's certificate checks cannot be set up.
    pub fn system() -> Result<Self, rustls::Error> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier: Arc<dyn ServerCertVerifier> = Arc::new(
            rustls_platform_verifier::Verifier::new(Arc::clone(&provider))?,
        );
        Self::new(&provider, &verifier, Self::PORT, Self::LIMIT)
    }

    /// Checks on `port`, trusting what `verifier` accepts, each within
    /// `limit`.
    ///
    /// # Errors
    /// If `provider` cannot do TLS 1.2 or TLS 1.3.
    pub fn new(
        provider: &Arc<CryptoProvider>,
        verifier: &Arc<dyn ServerCertVerifier>,
        port: u16,
        limit: Duration,
    ) -> Result<Self, rustls::Error> {
        let connector = |version: &'static SupportedProtocolVersion| {
            let mut config = ClientConfig::builder_with_provider(Arc::clone(provider))
                .with_protocol_versions(&[version])?
                // Not dangerous: the verifier checks certificates in full.
                .dangerous()
                .with_custom_certificate_verifier(Arc::clone(verifier))
                .with_no_client_auth();
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
            Ok::<_, rustls::Error>(TlsConnector::from(Arc::new(config)))
        };
        Ok(Self {
            tls12: connector(&rustls::version::TLS12)?,
            tls13: connector(&rustls::version::TLS13)?,
            port,
            limit,
        })
    }

    /// Whether `host` answers over `tls`.
    pub async fn check(&self, host: &str, tls: Tls) -> Outcome {
        tokio::time::timeout(self.limit, self.attempt(host, tls))
            .await
            .unwrap_or(Outcome::TimedOut)
    }

    async fn attempt(&self, host: &str, tls: Tls) -> Outcome {
        let Ok(name) = ServerName::try_from(host.to_owned()) else {
            return Outcome::NoAddress;
        };
        let addresses: Vec<SocketAddr> = match tokio::net::lookup_host((host, self.port)).await {
            Ok(addresses) => addresses.collect(),
            Err(_) => return Outcome::NoAddress,
        };
        let Some(stream) = first_connected(&addresses, TcpStream::connect).await else {
            return Outcome::Unreachable;
        };
        let connector = match tls {
            Tls::V12 => &self.tls12,
            Tls::V13 => &self.tls13,
        };
        let mut stream = match connector.connect(name, stream).await {
            Ok(stream) => stream,
            Err(e) => return handshake_failure(&e),
        };
        let request = format!("HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        if stream.write_all(request.as_bytes()).await.is_err() {
            return Outcome::NoReply;
        }
        let mut start = [0; 7];
        match stream.read_exact(&mut start).await {
            Ok(_) if &start == b"HTTP/1." => Outcome::Passed,
            _ => Outcome::NoReply,
        }
    }
}

/// How long a connection attempt runs alone before the next address is
/// tried alongside it (RFC 8305 suggests 250 ms).
const STAGGER: Duration = Duration::from_millis(250);

/// A connection to the first address that takes one. As browsers do
/// ("Happy Eyeballs"), the addresses are tried in the system's order, each
/// one when the one before has failed or has not connected within
/// [`STAGGER`]: an address family that is broken here (IPv6 that times out,
/// or that Windows takes 2 s to refuse) does not use up the time limit.
async fn first_connected<T, F, C>(addresses: &[SocketAddr], connect: C) -> Option<T>
where
    T: Send + 'static,
    F: Future<Output = io::Result<T>> + Send + 'static,
    C: Fn(SocketAddr) -> F,
{
    let mut untried = addresses.iter().copied().peekable();
    let mut attempts = JoinSet::new();
    loop {
        if let Some(address) = untried.next() {
            attempts.spawn(connect(address));
        }
        let stagger = tokio::time::sleep(STAGGER);
        tokio::pin!(stagger);
        loop {
            tokio::select! {
                joined = attempts.join_next() => match joined {
                    Some(Ok(Ok(stream))) => return Some(stream),
                    // Failed (or none running): on to the next address at
                    // once, if any.
                    _ if untried.peek().is_some() => break,
                    Some(_) => {}
                    None => return None,
                },
                () = &mut stagger, if untried.peek().is_some() => break,
            }
        }
    }
}

fn handshake_failure(error: &io::Error) -> Outcome {
    let tls = error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>());
    match tls {
        Some(rustls::Error::InvalidCertificate(_)) => Outcome::Certificate,
        _ => Outcome::Cut,
    }
}

#[cfg(test)]
mod tests {
    use std::future::{Future, pending};
    use std::io;
    use std::net::SocketAddr;
    use std::pin::Pin;
    use std::time::Duration;

    use tokio::time::Instant;

    use super::{STAGGER, first_connected};

    type Attempt = Pin<Box<dyn Future<Output = io::Result<u16>> + Send>>;

    fn addresses(ports: &[u16]) -> Vec<SocketAddr> {
        ports
            .iter()
            .map(|&port| SocketAddr::from(([127, 0, 0, 1], port)))
            .collect()
    }

    /// Port 1 never answers, port 2 is refused after `refused`, any other
    /// connects after `delay`.
    fn attempt(address: SocketAddr, refused: Duration, delay: Duration) -> Attempt {
        match address.port() {
            1 => Box::pin(pending()),
            2 => Box::pin(async move {
                tokio::time::sleep(refused).await;
                Err(io::ErrorKind::ConnectionRefused.into())
            }),
            port => Box::pin(async move {
                tokio::time::sleep(delay).await;
                Ok(port)
            }),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn an_address_that_never_answers_does_not_hold_up_the_next() {
        let started = Instant::now();
        let connected = first_connected(&addresses(&[1, 443]), |a| {
            attempt(a, Duration::ZERO, Duration::from_millis(10))
        })
        .await;
        assert_eq!(connected, Some(443));
        assert_eq!(started.elapsed(), STAGGER + Duration::from_millis(10));
    }

    #[tokio::test(start_paused = true)]
    async fn a_refusal_moves_on_at_once() {
        let started = Instant::now();
        let connected = first_connected(&addresses(&[2, 443]), |a| {
            attempt(a, Duration::from_millis(5), Duration::from_millis(10))
        })
        .await;
        assert_eq!(connected, Some(443));
        assert_eq!(started.elapsed(), Duration::from_millis(15));
    }

    #[tokio::test(start_paused = true)]
    async fn the_first_address_wins_when_it_connects_in_time() {
        let connected = first_connected(&addresses(&[80, 443]), |a| {
            attempt(a, Duration::ZERO, Duration::from_millis(100))
        })
        .await;
        assert_eq!(connected, Some(80));
    }

    #[tokio::test(start_paused = true)]
    async fn a_slow_first_address_still_wins_if_it_connects_first() {
        // 80 takes 300 ms; 443, started at 250 ms, would take until 550 ms.
        let connected = first_connected(&addresses(&[80, 443]), |a| {
            attempt(a, Duration::ZERO, Duration::from_millis(300))
        })
        .await;
        assert_eq!(connected, Some(80));
    }

    #[tokio::test(start_paused = true)]
    async fn when_every_address_fails_there_is_no_connection() {
        let connected = first_connected(&addresses(&[2, 2, 2]), |a| {
            attempt(a, Duration::from_secs(2), Duration::ZERO)
        })
        .await;
        assert_eq!(connected, None);
        assert_eq!(
            first_connected(&[], |a| attempt(a, Duration::ZERO, Duration::ZERO)).await,
            None
        );
    }
}
