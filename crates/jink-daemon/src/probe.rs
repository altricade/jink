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
        let Some(stream) = connect(&addresses).await else {
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

/// A connection to the first address that takes one, in the system's order
/// (as apps do).
async fn connect(addresses: &[SocketAddr]) -> Option<TcpStream> {
    for address in addresses {
        if let Ok(stream) = TcpStream::connect(address).await {
            return Some(stream);
        }
    }
    None
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
