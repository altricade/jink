//! The finder's host checks, against local TLS servers that answer, cut,
//! stall, or show the wrong certificate.

use std::sync::Arc;
use std::time::Duration;

use jink_daemon::probe::{Outcome, Prober, Tls};
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::ServerCertVerifier;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::version::{TLS12, TLS13};
use rustls::{RootCertStore, ServerConfig, SupportedProtocolVersion};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const LIMIT: Duration = Duration::from_secs(1);
/// Longer than [`LIMIT`], with room to spare.
const LONG: Duration = Duration::from_secs(3);
const BOTH: &[&SupportedProtocolVersion] = &[&TLS12, &TLS13];
const ONLY_12: &[&SupportedProtocolVersion] = &[&TLS12];
const ONLY_13: &[&SupportedProtocolVersion] = &[&TLS13];

/// What a test server does with a connection.
#[derive(Debug, Clone, Copy)]
enum Serve {
    /// Handshake, then an HTTP reply if the client asked for HTTP/1.1 (by
    /// ALPN, as browsers do).
    Reply,
    /// Handshake, then something that is not HTTP.
    Garbage,
    /// Handshake, then nothing.
    Silent,
    /// Reads the start of the client's hello and closes, as a censor does.
    Hangup,
}

/// A prober for a local server on `localhost` that has a certificate for
/// `name` from a test authority the prober trusts, speaks `versions`, and
/// serves as `serve`.
async fn site(
    name: &str,
    versions: &'static [&'static SupportedProtocolVersion],
    serve: Serve,
) -> Result<Prober> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let (authority, verifier) = authority(&provider)?;
    let key = KeyPair::generate()?;
    let certificate = CertificateParams::new(vec![name.to_owned()])?.signed_by(&key, &authority)?;
    let mut config = ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(versions)?
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(answer(acceptor.clone(), stream, serve));
        }
    });
    Ok(Prober::new(&provider, &verifier, port, LIMIT)?)
}

/// A test certificate authority, and a verifier that trusts it.
fn authority(
    provider: &Arc<CryptoProvider>,
) -> Result<(
    CertifiedIssuer<'static, KeyPair>,
    Arc<dyn ServerCertVerifier>,
)> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let authority = CertifiedIssuer::self_signed(params, KeyPair::generate()?)?;
    let mut roots = RootCertStore::empty();
    roots.add(authority.der().clone())?;
    let verifier =
        WebPkiServerVerifier::builder_with_provider(Arc::new(roots), Arc::clone(provider))
            .build()?;
    Ok((authority, verifier))
}

/// A test server's side of one connection; its failures just end it.
async fn answer(acceptor: TlsAcceptor, mut stream: TcpStream, serve: Serve) {
    if let Serve::Hangup = serve {
        let mut start = [0; 5];
        let _ = stream.read_exact(&mut start).await;
        return;
    }
    let Ok(mut stream) = acceptor.accept(stream).await else {
        return;
    };
    let mut request = [0; 16];
    let _ = stream.read(&mut request).await;
    let http1 = stream.get_ref().1.alpn_protocol() == Some(b"http/1.1");
    let reply: &[u8] = match serve {
        Serve::Reply if http1 => b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        Serve::Reply => b"PRI * HTTP/2.0\r\n\r\n",
        Serve::Garbage => b"SSH-2.0-OpenSSH\r\n",
        Serve::Silent | Serve::Hangup => {
            tokio::time::sleep(LONG).await;
            return;
        }
    };
    let _ = stream.write_all(reply).await;
    let _ = stream.shutdown().await;
}

async fn both(prober: &Prober, host: &str) -> [Outcome; 2] {
    [
        prober.check(host, Tls::V12).await,
        prober.check(host, Tls::V13).await,
    ]
}

#[tokio::test]
async fn a_site_that_answers_passes_over_both_versions() -> Result<()> {
    let prober = site("localhost", BOTH, Serve::Reply).await?;
    assert_eq!(both(&prober, "localhost").await, [Outcome::Passed; 2]);
    Ok(())
}

#[tokio::test]
async fn each_version_is_checked_on_its_own() -> Result<()> {
    let only12 = site("localhost", ONLY_12, Serve::Reply).await?;
    assert_eq!(
        both(&only12, "localhost").await,
        [Outcome::Passed, Outcome::Cut]
    );
    let only13 = site("localhost", ONLY_13, Serve::Reply).await?;
    assert_eq!(
        both(&only13, "localhost").await,
        [Outcome::Cut, Outcome::Passed]
    );
    Ok(())
}

#[tokio::test]
async fn a_certificate_for_another_name_fails() -> Result<()> {
    let prober = site("example.org", BOTH, Serve::Reply).await?;
    assert_eq!(both(&prober, "localhost").await, [Outcome::Certificate; 2]);
    Ok(())
}

#[tokio::test]
async fn a_handshake_cut_after_the_hello_fails() -> Result<()> {
    let prober = site("localhost", BOTH, Serve::Hangup).await?;
    assert_eq!(both(&prober, "localhost").await, [Outcome::Cut; 2]);
    Ok(())
}

#[tokio::test]
async fn an_answer_that_is_not_http_fails() -> Result<()> {
    let prober = site("localhost", BOTH, Serve::Garbage).await?;
    assert_eq!(both(&prober, "localhost").await, [Outcome::NoReply; 2]);
    Ok(())
}

#[tokio::test]
async fn silence_times_out() -> Result<()> {
    let prober = site("localhost", BOTH, Serve::Silent).await?;
    let started = tokio::time::Instant::now();
    assert_eq!(prober.check("localhost", Tls::V13).await, Outcome::TimedOut);
    assert!(started.elapsed() < LONG);
    Ok(())
}

#[tokio::test]
async fn a_closed_port_is_unreachable() -> Result<()> {
    let free = TcpListener::bind("127.0.0.1:0").await?.local_addr()?.port();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let (_, verifier) = authority(&provider)?;
    // The real limit: Windows takes 2 s to refuse a connection to a closed
    // local port.
    let prober = Prober::new(&provider, &verifier, free, Prober::LIMIT)?;
    assert_eq!(
        prober.check("localhost", Tls::V12).await,
        Outcome::Unreachable
    );
    Ok(())
}

#[tokio::test]
async fn a_name_without_an_address_fails() -> Result<()> {
    let prober = site("localhost", BOTH, Serve::Reply).await?;
    // `.invalid` never resolves (RFC 6761).
    assert_eq!(
        prober.check("jink.invalid", Tls::V12).await,
        Outcome::NoAddress
    );
    assert_eq!(
        prober.check("not a name", Tls::V12).await,
        Outcome::NoAddress
    );
    Ok(())
}

#[test]
fn the_system_checker_sets_up() -> Result<()> {
    Prober::system()?;
    Ok(())
}
