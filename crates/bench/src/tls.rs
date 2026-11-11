//! Locally generated certificate authorities and rustls configurations.
//!
//! The session proxy bench needs two trust roots: the CA the proxy signs its
//! interception certificates with (the load client trusts it in MITM mode) and
//! the CA of the stub origin (the client trusts it in passthrough mode).

use std::io::Write as _;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyIdMethod, KeyPair, KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};

/// A self-signed CA with its key.
pub struct Ca {
    cert: rcgen::Certificate,
    key: KeyPair,
}

impl Ca {
    /// A new ECDSA P-256 CA valid from an hour ago for a day.
    pub fn generate(common_name: &str) -> Result<Self> {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        params.key_identifier_method = KeyIdMethod::Sha256;
        params.use_authority_key_identifier_extension = true;
        validity(&mut params);
        let cert = params.self_signed(&key)?;
        Ok(Self { cert, key })
    }

    pub fn cert_der(&self) -> Vec<u8> {
        self.cert.der().to_vec()
    }

    pub fn key_der(&self) -> Vec<u8> {
        self.key.serialize_der()
    }

    /// Write `ca.der` and `ca.key.der`, the file names the session proxy's
    /// `generate` and `file` CA modes read. The private key is written with mode `0600`.
    pub fn write_to(&self, dir: &Path) -> Result<(std::path::PathBuf, std::path::PathBuf)> {
        std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
        let (cert, key) = (dir.join("ca.der"), dir.join("ca.key.der"));
        std::fs::write(&cert, self.cert_der())?;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options.open(&key)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        file.write_all(&self.key_der())?;
        Ok((cert, key))
    }

    /// A server certificate for `host` signed by this CA.
    pub fn issue_server(&self, host: &str) -> Result<(CertificateDer<'static>, KeyPair)> {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, host);
        params.subject_alt_names = vec![SanType::DnsName(host.try_into()?)];
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        validity(&mut params);
        let cert = params.signed_by(&key, &self.cert, &self.key)?;
        Ok((CertificateDer::from(cert.der().to_vec()), key))
    }
}

fn validity(params: &mut CertificateParams) {
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - Duration::from_secs(3600);
    params.not_after = now + Duration::from_secs(24 * 3600);
}

/// The aws-lc-rs provider, passed explicitly so no process-wide default has to
/// be installed.
fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// A client that trusts exactly `root_der` and speaks HTTP/1.1.
pub fn client_config(root_der: &[u8]) -> Result<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(root_der.to_vec()))
        .context("trust root")?;
    let mut config = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// A server that presents `cert` and answers HTTP/1.1.
pub fn server_config(cert: CertificateDer<'static>, key: &KeyPair) -> Result<Arc<ServerConfig>> {
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key.serialize_der()));
    let mut config = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// The name a client sends as SNI and verifies.
pub fn server_name(host: &str) -> Result<ServerName<'static>> {
    ServerName::try_from(host.to_owned()).with_context(|| format!("invalid server name {host:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn a_client_trusting_the_ca_handshakes_with_a_leaf_it_issued() {
        let ca = Ca::generate("bench test ca").expect("ca");
        let (cert, key) = ca.issue_server("localhost").expect("leaf");
        let server = tokio_rustls::TlsAcceptor::from(server_config(cert, &key).expect("server"));
        let client =
            tokio_rustls::TlsConnector::from(client_config(&ca.cert_der()).expect("client"));

        let (a, b) = tokio::io::duplex(8192);
        let serve = tokio::spawn(async move {
            let mut s = server.accept(b).await.expect("accept");
            s.write_all(b"hi").await.expect("write");
            s.shutdown().await.expect("shutdown");
        });
        let mut c = client
            .connect(server_name("localhost").expect("name"), a)
            .await
            .expect("connect");
        let mut got = Vec::new();
        c.read_to_end(&mut got).await.expect("read");
        assert_eq!(got, b"hi");
        serve.await.expect("server task");
    }

    #[tokio::test]
    async fn a_client_trusting_another_ca_refuses_the_leaf() {
        let ca = Ca::generate("one").expect("ca");
        let other = Ca::generate("two").expect("ca");
        let (cert, key) = ca.issue_server("localhost").expect("leaf");
        let server = tokio_rustls::TlsAcceptor::from(server_config(cert, &key).expect("server"));
        let client =
            tokio_rustls::TlsConnector::from(client_config(&other.cert_der()).expect("client"));
        let (a, b) = tokio::io::duplex(8192);
        tokio::spawn(async move {
            let _ = server.accept(b).await;
        });
        assert!(
            client
                .connect(server_name("localhost").expect("name"), a)
                .await
                .is_err()
        );
    }

    #[test]
    fn the_ca_files_have_the_names_the_proxy_reads() {
        let dir = std::env::temp_dir().join(format!("proxyx-bench-ca-{}", std::process::id()));
        let ca = Ca::generate("files").expect("ca");
        let (cert, key) = ca.write_to(&dir).expect("write");
        assert_eq!(cert.file_name().and_then(|n| n.to_str()), Some("ca.der"));
        assert_eq!(key.file_name().and_then(|n| n.to_str()), Some("ca.key.der"));
        assert_eq!(std::fs::read(&cert).expect("read"), ca.cert_der());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&key)
                    .expect("key metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
