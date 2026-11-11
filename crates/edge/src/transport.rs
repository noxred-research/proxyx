//! TLS listener setup. Trusted PROXY headers are consumed before this transport starts.

use std::sync::Arc;

use anyhow::{Context as _, bail};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject as _};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsAcceptor;

use crate::config::{ListenerProtocol, TlsConfig};

/// A bidirectional transport accepted by the protocol handlers.
pub trait Transport: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Transport for T {}

/// Load and validate the complete certificate chain and matching private key.
/// Called while building state, so a failed reload leaves existing listeners intact.
pub fn tls_acceptor(cfg: &TlsConfig, protocol: ListenerProtocol) -> anyhow::Result<TlsAcceptor> {
    let cert_pem = std::fs::read(&cfg.cert)
        .with_context(|| format!("read TLS certificate {}", cfg.cert.display()))?;
    let key_pem = std::fs::read(&cfg.key)
        .with_context(|| format!("read TLS private key {}", cfg.key.display()))?;
    let certs = CertificateDer::pem_slice_iter(&cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .context("parse TLS certificate chain")?;
    if certs.is_empty() {
        bail!("TLS certificate chain is empty");
    }
    let key = PrivateKeyDer::from_pem_slice(&key_pem).context("parse TLS private key")?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut server = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("validate TLS certificate and private key")?;
    // SOCKS has no registered ALPN identifier. An absent ALPN still permits
    // first-byte protocol detection on a mixed listener after TLS completes.
    if protocol != ListenerProtocol::Socks {
        server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    }
    Ok(TlsAcceptor::from(Arc::new(server)))
}
