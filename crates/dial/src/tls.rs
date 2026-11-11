//! TLS to the upstream proxy, independent of target-side TLS in the tunnel.

use std::sync::{Arc, LazyLock};

use common::types::{UpstreamEndpoint, UpstreamScheme};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

use crate::{DialError, ProxyStream};

static SYSTEM_CONFIG: LazyLock<Result<Arc<ClientConfig>, &'static str>> = LazyLock::new(|| {
    let loaded = rustls_native_certs::load_native_certs();
    let mut roots = RootCertStore::empty();
    roots.add_parsable_certificates(loaded.certs);
    if roots.is_empty() {
        return Err("no valid system trust roots for upstream TLS");
    }
    config(roots)
});

/// Build a validating HTTP/1.1 proxy TLS client using the supplied trust roots.
///
/// Certificate chains and the proxy hostname or IP SAN are always verified.
/// The target hostname is never used as the proxy's TLS identity.
///
/// # Errors
/// Returns a protocol error if TLS protocol configuration cannot be built.
pub fn proxy_tls_config(roots: RootCertStore) -> Result<Arc<ClientConfig>, DialError> {
    config(roots).map_err(DialError::Protocol)
}

fn config(roots: RootCertStore) -> Result<Arc<ClientConfig>, &'static str> {
    let mut config = ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| "cannot configure upstream TLS versions")?
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

fn system_config() -> Result<Arc<ClientConfig>, DialError> {
    SYSTEM_CONFIG
        .as_ref()
        .map(Arc::clone)
        .map_err(|message| DialError::Protocol(message))
}

pub(crate) async fn transport(
    stream: ProxyStream,
    up: &UpstreamEndpoint,
    tls: Option<Arc<ClientConfig>>,
) -> Result<ProxyStream, DialError> {
    if up.scheme != UpstreamScheme::Https {
        return Ok(stream);
    }
    let host = up
        .host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(&up.host);
    let name = ServerName::try_from(host.to_owned())
        .map_err(|_| DialError::Protocol("invalid upstream TLS server name"))?;
    let config = match tls {
        Some(config) => config,
        None => system_config()?,
    };
    let stream = TlsConnector::from(config)
        .connect(name, stream)
        .await
        .map_err(DialError::Io)?;
    Ok(ProxyStream::tls(stream))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_config_only_advertises_http11() {
        let config = proxy_tls_config(RootCertStore::empty()).expect("TLS config");
        assert_eq!(config.alpn_protocols, [b"http/1.1".to_vec()]);
        assert!(!config.enable_early_data);
    }
}
