use anyhow::Result;
use boring::ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion};
use rustls::ServerConfig;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::sync::Arc;

use super::ca::CertificateAuthority;

/// A TLS ClientHello profile that approximates a specific browser's fingerprint.
///
/// Controls the outbound TLS handshake from the proxy to the upstream server —
/// the leg that destination servers fingerprint. The inbound leg (client →
/// proxy) is always terminated by rustls and is not affected.
///
/// This is a TLS-only approximation built from the knobs BoringSSL exposes:
/// cipher list, groups, signature algorithms, ALPN, GREASE, extension
/// permutation, OCSP/SCT requests and ECH GREASE. Wire captures against utls
/// parrots and locally installed browsers (see `docs/session-proxy.md`) show
/// the remaining differences: no certificate compression, ALPS,
/// delegated credentials or record-size limit, a BoringSSL-fixed TLS 1.3 suite
/// order, no FFDHE groups, and no HTTP/2 SETTINGS emulation.
/// The integer discriminants must stay in sync with the `ALL` array order —
/// enforced by the compile-time assertion in `MitmHandler::new`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum TlsProfile {
    /// Chrome 133+. Cipher and sigalg order unchanged from 131; curves gain
    /// X25519MLKEM768 (post-quantum hybrid, default since Chrome 131).
    Chrome133 = 0,
    /// Firefox < 128. No post-quantum group; FFDHE groups omitted (BoringSSL
    /// limitation). Cipher order stable across all Firefox versions.
    Firefox120 = 1,
    /// Firefox 128+. Adds X25519MLKEM768 before X25519 in the groups list.
    /// Cipher and sigalg order identical to Firefox120.
    Firefox135 = 2,
    /// Safari 18 (macOS Sequoia / iOS 18). AES-256-first cipher order,
    /// GREASE enabled, no extension permutation.
    Safari18 = 3,
}

impl TlsProfile {
    pub(crate) const ALL: &'static [TlsProfile] = &[
        TlsProfile::Chrome133,
        TlsProfile::Firefox120,
        TlsProfile::Firefox135,
        TlsProfile::Safari18,
    ];

    /// Select a TLS profile from the client's User-Agent string.
    ///
    /// Chrome/Chromium → Chrome133.
    /// Firefox → version-split: Firefox/N where N >= 128 → Firefox135, else Firefox120.
    ///   If no parseable version, defaults to Firefox135 (assume current).
    /// Safari (not Chrome) → Safari18.
    /// None or no match → Chrome133 (most common browser).
    pub fn for_agent(agent: Option<&str>) -> Self {
        let Some(ua) = agent else {
            return TlsProfile::Chrome133;
        };
        let ua_lower = ua.to_ascii_lowercase();
        if ua_lower.contains("chrome") || ua_lower.contains("chromium") {
            TlsProfile::Chrome133
        } else if ua_lower.contains("firefox") {
            // Parse "Firefox/NNN.0" to split on version 128.
            let version = ua
                .split("Firefox/")
                .nth(1)
                .and_then(|s| s.split('.').next())
                .and_then(|s| s.parse::<u32>().ok());
            match version {
                Some(v) if v >= 128 => TlsProfile::Firefox135,
                Some(_) => TlsProfile::Firefox120,
                // No parseable version — assume current.
                None => TlsProfile::Firefox135,
            }
        } else if ua_lower.contains("safari") {
            TlsProfile::Safari18
        } else {
            TlsProfile::Chrome133
        }
    }

    /// TLS 1.2 cipher list in OpenSSL colon-delimited format.
    ///
    /// TLS 1.3 ciphers (AES-128-GCM, AES-256-GCM, CHACHA20) are always
    /// advertised by BoringSSL when TLS 1.3 is enabled; they appear before
    /// these in the ClientHello automatically.
    fn cipher_list(self) -> &'static str {
        match self {
            // Chrome 133: ECDSA suites first, then RSA equivalents, then
            // RSA-only fallbacks. No ECDSA-only CBC suites (unlike Firefox).
            // Verified against utls HelloChrome_133.
            TlsProfile::Chrome133 => concat!(
                "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:",
                "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:",
                "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:",
                "ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:",
                "AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA",
            ),
            // Firefox (all versions): CHACHA20 before AES256, includes
            // ECDSA-only CBC suites. Cipher order stable since ~FF100.
            // Verified against utls HelloFirefox_120 and HelloFirefox_148.
            TlsProfile::Firefox120 | TlsProfile::Firefox135 => concat!(
                "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:",
                "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:",
                "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:",
                "ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:",
                "ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:",
                "AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA",
            ),
            // Safari 18: leads with AES-256 (not AES-128), ECDSA before RSA.
            TlsProfile::Safari18 => concat!(
                "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:",
                "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:",
                "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:",
                "ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:",
                "ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:",
                "AES256-GCM-SHA384:AES128-GCM-SHA256:",
                "AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA",
            ),
        }
    }

    /// Elliptic curve / named-group preference list in OpenSSL colon-delimited format.
    ///
    /// Firefox also advertises ffdhe2048 and ffdhe3072 (finite-field DH groups),
    /// but BoringSSL cannot express these via set_curves_list and they are omitted.
    fn curves_list(self) -> &'static str {
        match self {
            // Chrome 133: X25519MLKEM768 first (post-quantum hybrid, default
            // since Chrome 131 with ML-KEM codepoint 0x11EC), then classical.
            // No P-521: utls HelloChrome_133 and shipping Chrome/Chromium
            // advertise exactly x25519, P-256, P-384 after the hybrid.
            TlsProfile::Chrome133 => "X25519MLKEM768:X25519:P-256:P-384",
            // Firefox < 128: no post-quantum group.
            TlsProfile::Firefox120 => "X25519:P-256:P-384:P-521",
            // Firefox 128+: X25519MLKEM768 added as first group.
            TlsProfile::Firefox135 => "X25519MLKEM768:X25519:P-256:P-384:P-521",
            // Safari 18: no post-quantum group.
            TlsProfile::Safari18 => "X25519:P-256:P-384:P-521",
        }
    }

    /// ALPN protocols in TLS wire format: each entry prefixed with its length.
    ///
    /// h2 is advertised first (matching real browsers) so that servers which
    /// support HTTP/2 will negotiate it. The proxy translates between the
    /// HTTP/1.1 client leg and the HTTP/2 upstream leg transparently.
    fn alpn_wire(self) -> &'static [u8] {
        b"\x02h2\x08http/1.1"
    }

    /// Signature algorithm preference list in OpenSSL colon-delimited format.
    fn sigalgs_list(self) -> &'static str {
        match self {
            // Chrome 133. Verified against utls HelloChrome_133.
            TlsProfile::Chrome133 => concat!(
                "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:",
                "ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:",
                "rsa_pss_rsae_sha512:rsa_pkcs1_sha512",
            ),
            // Firefox (all versions): ECDSA schemes first (including P-521),
            // then RSA-PSS, then RSA-PKCS1, SHA-1 variants at the tail.
            // Verified against utls HelloFirefox_120 and HelloFirefox_148.
            TlsProfile::Firefox120 | TlsProfile::Firefox135 => concat!(
                "ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512:",
                "rsa_pss_rsae_sha256:rsa_pss_rsae_sha384:rsa_pss_rsae_sha512:",
                "rsa_pkcs1_sha256:rsa_pkcs1_sha384:rsa_pkcs1_sha512:",
                "ecdsa_sha1:rsa_pkcs1_sha1",
            ),
            TlsProfile::Safari18 => concat!(
                "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:",
                "ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512:",
                "rsa_pss_rsae_sha384:rsa_pss_rsae_sha512:",
                "rsa_pkcs1_sha384:rsa_pkcs1_sha512",
            ),
        }
    }

    /// Whether to inject GREASE values into the ClientHello (RFC 8701).
    ///
    /// Chrome and Safari use GREASE to exercise server tolerance of unknown
    /// extension/cipher/group values. Firefox does not.
    fn grease_enabled(self) -> bool {
        matches!(self, TlsProfile::Chrome133 | TlsProfile::Safari18)
    }

    /// Whether to permute ClientHello extension order on each handshake.
    ///
    /// Chrome has randomised extension ordering since Chrome 110 (March 2023).
    /// Firefox and Safari do not permute.
    fn permute_extensions(self) -> bool {
        matches!(self, TlsProfile::Chrome133)
    }

    /// Whether to send a `status_request` (OCSP stapling) extension.
    ///
    /// Present in the captured utls HelloChrome_133 / HelloFirefox_120 parrots and
    /// in locally installed Chrome, Chromium and Firefox. No Safari 18 reference
    /// could be captured, so that profile is left unchanged.
    fn requests_ocsp_stapling(self) -> bool {
        !matches!(self, TlsProfile::Safari18)
    }

    /// Whether to send a `signed_certificate_timestamp` extension.
    ///
    /// Chrome only: utls HelloFirefox_120 does not send it.
    fn requests_signed_cert_timestamps(self) -> bool {
        matches!(self, TlsProfile::Chrome133)
    }

    /// Whether to send an ECH GREASE `encrypted_client_hello` extension.
    ///
    /// Present in the captured Chrome and Firefox parrots and browsers.
    fn sends_ech_grease(self) -> bool {
        !matches!(self, TlsProfile::Safari18)
    }
}

/// Build a pre-configured outbound `SslConnector` for the given profile.
///
/// The connector is built once per profile at startup and reused for all
/// connections — `SslConnector::configure()` produces a per-connection
/// `ConnectConfiguration` from the shared context cheaply.
pub fn build_connector(
    profile: TlsProfile,
    ca_bundle: Option<&std::path::Path>,
) -> Result<SslConnector> {
    let mut builder = SslConnector::builder(SslMethod::tls())?;

    // SslConnector loads system roots and enables hostname verification by default.
    builder.set_verify(SslVerifyMode::PEER);
    if let Some(bundle) = ca_bundle {
        builder.set_ca_file(bundle)?;
    }

    // Enforce TLS 1.2 minimum; TLS 1.3 is automatically available.
    builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;

    // Apply browser-profile parameters.
    builder.set_cipher_list(profile.cipher_list())?;
    builder.set_curves_list(profile.curves_list())?;
    builder.set_alpn_protos(profile.alpn_wire())?;
    builder.set_sigalgs_list(profile.sigalgs_list())?;
    builder.set_grease_enabled(profile.grease_enabled());
    builder.set_permute_extensions(profile.permute_extensions());

    if profile.requests_ocsp_stapling() {
        builder.enable_ocsp_stapling();
    }
    if profile.requests_signed_cert_timestamps() {
        builder.enable_signed_cert_timestamps();
    }

    Ok(builder.build())
}

/// Derive one connection's policy without changing its browser fingerprint.
///
/// `profile` must be the profile `connector` was built for: ECH GREASE is a
/// per-connection setting that `SslConnector` cannot carry.
pub(super) fn configure_upstream(
    connector: &SslConnector,
    profile: TlsProfile,
    insecure: bool,
) -> Result<boring::ssl::ConnectConfiguration> {
    let mut config = connector.configure()?;
    config.set_enable_ech_grease(profile.sends_ech_grease());
    config.set_verify_hostname(!insecure);
    config.set_verify(if insecure {
        SslVerifyMode::NONE
    } else {
        SslVerifyMode::PEER
    });
    Ok(config)
}

#[derive(Debug, thiserror::Error)]
#[error("upstream TLS handshake failed")]
pub(super) struct UpstreamTlsFailure;

/// Create TLS server config for accepting connections from clients.
/// Uses dynamic certificate resolution based on SNI.
pub fn make_server_config(ca: Arc<CertificateAuthority>) -> Result<ServerConfig> {
    let resolver = Arc::new(CertResolver::new(ca));

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);

    Ok(config)
}

/// Hostname of the one certificate the in-band proxy error responses use.
const ERROR_CERT_HOST: &str = "proxyx-error.invalid";

/// TLS server config for in-band proxy error responses: one CA-signed
/// certificate for `ERROR_CERT_HOST`, minted once, whatever the SNI, so
/// clients reaching the error path cannot drive per-SNI cert generation or
/// evict MITM certs from the CA cache. The name never matches the SNI; the
/// browsers run with `--ignore-certificate-errors`. ALPN `http/1.1` only.
pub(super) fn make_error_server_config(ca: &CertificateAuthority) -> Result<ServerConfig> {
    let cert = ca.generate_cert(ERROR_CERT_HOST)?;
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(cert)));
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

/// Resolves server certificates dynamically based on SNI.
///
/// A single instance is shared across all MITM connections. Hostname-specific
/// certificates are generated on-demand from the CA's cert cache.
struct CertResolver {
    ca: Arc<CertificateAuthority>,
}

impl std::fmt::Debug for CertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertResolver")
            .field("ca_cache_size", &self.ca.cache_len())
            .finish()
    }
}

impl CertResolver {
    fn new(ca: Arc<CertificateAuthority>) -> Self {
        Self { ca }
    }
}

impl ResolvesServerCert for CertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // Get hostname from SNI; fall back to "localhost" for the rare case
        // of a client that doesn't send SNI (effectively all modern TLS clients do).
        let hostname = client_hello.server_name().unwrap_or("localhost");

        // The CA cache stores fully-built rustls CertifiedKeys — repeat
        // handshakes to the same SNI are a DashMap lookup + Arc clone.
        match self.ca.get_cert(hostname) {
            Ok(cert_key) => Some(cert_key),
            Err(e) => {
                tracing::error!(%hostname, error=?e, "failed to generate cert");
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    fn test_ca() -> (rcgen::Certificate, rcgen::KeyPair) {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "ProxyX test root");
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let key = rcgen::KeyPair::generate().unwrap();
        (params.self_signed(&key).unwrap(), key)
    }

    fn origin_config(ca: &rcgen::Certificate, key: &rcgen::KeyPair) -> Arc<ServerConfig> {
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf = rcgen::CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .signed_by(&leaf_key, ca, key)
            .unwrap();
        Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![CertificateDer::from(leaf.der().to_vec())],
                    PrivatePkcs8KeyDer::from(leaf_key.serialize_der()).into(),
                )
                .unwrap(),
        )
    }

    async fn connect_origin(
        connector: &SslConnector,
        profile: TlsProfile,
        config: Arc<ServerConfig>,
        host: &str,
        insecure: bool,
    ) -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let _ = tokio_rustls::TlsAcceptor::from(config).accept(tcp).await;
        });
        let tcp = TcpStream::connect(address).await.unwrap();
        let config = configure_upstream(connector, profile, insecure).unwrap();
        let accepted = tokio_boring::connect(config, host, tcp)
            .await
            .map(|_| ())
            .map_err(|error| anyhow::anyhow!("TLS connection to {host}: {error}"));
        server.await.unwrap();
        accepted
    }

    #[tokio::test]
    async fn upstream_tls_verifies_chain_and_hostname_for_browser_profiles() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let (ca, key) = test_ca();
        let origin = origin_config(&ca, &key);
        let bundle =
            std::env::temp_dir().join(format!("proxyx-roots-{}.pem", uuid::Uuid::new_v4()));
        std::fs::write(&bundle, ca.pem()).unwrap();
        for profile in TlsProfile::ALL {
            let system = build_connector(*profile, None).unwrap();
            assert!(
                connect_origin(&system, *profile, origin.clone(), "localhost", false)
                    .await
                    .is_err()
            );
            let trusted = build_connector(*profile, Some(&bundle)).unwrap();
            connect_origin(&trusted, *profile, origin.clone(), "localhost", false)
                .await
                .unwrap();
            assert!(
                connect_origin(&trusted, *profile, origin.clone(), "wrong.example", false)
                    .await
                    .is_err()
            );
            connect_origin(&system, *profile, origin.clone(), "localhost", true)
                .await
                .unwrap();
        }
        std::fs::remove_file(bundle).unwrap();
    }

    #[tokio::test]
    async fn upstream_tls_failure_returns_502_without_capture() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let (mitm_ca, mitm_key) = test_ca();
        let authority =
            CertificateAuthority::from_der(mitm_ca.der().as_ref(), &mitm_key.serialize_der())
                .unwrap();
        let (origin_ca, origin_key) = test_ca();
        let origin = origin_config(&origin_ca, &origin_key);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let _ = tokio_rustls::TlsAcceptor::from(origin).accept(tcp).await;
        });
        let network = crate::config::NetworkConfig::default();
        let handler = super::super::MitmHandler::new(
            Arc::new(authority),
            1024,
            1024,
            crate::egress::Egress::new(&network, &crate::breaker::BreakerConfig::default()),
            &network,
            &crate::config::TlsConfig::default(),
        )
        .unwrap();
        let (client, proxy) = tokio::io::duplex(65536);
        let (exchange_tx, mut exchange_rx) = tokio::sync::mpsc::channel(4);
        let intercept = tokio::spawn(async move {
            handler
                .intercept(
                    proxy,
                    tcp,
                    super::super::MitmParams {
                        host: "localhost",
                        port: 443,
                        inject_headers: &[],
                        tls_profile: TlsProfile::Chrome133,
                        exchange_tx,
                        exchange_ratelimit: None,
                        ws_sink: None,
                        serial_lock: None,
                        egress_proxy: None,
                        upstream_tls: true,
                        insecure_upstream_tls: false,
                    },
                )
                .await
        });
        let mut roots = rustls::RootCertStore::empty();
        roots.add(mitm_ca.der().clone()).unwrap();
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let mut tls = tokio_rustls::TlsConnector::from(Arc::new(client_config))
            .connect(ServerName::try_from("localhost").unwrap(), client)
            .await
            .unwrap();
        tls.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        tls.read_to_end(&mut response).await.unwrap();
        let response = String::from_utf8(response).unwrap();
        assert!(response.starts_with("HTTP/1.1 502"));
        assert!(response.contains("X-ProxyX-Error: upstream_tls"));
        assert!(intercept.await.unwrap().is_err());
        assert!(exchange_rx.recv().await.is_none());
        server.await.unwrap();
    }
}

#[cfg(test)]
mod client_hello_tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::net::{TcpListener, TcpStream};

    const SUPPORTED_GROUPS: u16 = 10;
    const STATUS_REQUEST: u16 = 5;
    const SIGNED_CERTIFICATE_TIMESTAMP: u16 = 18;
    const ENCRYPTED_CLIENT_HELLO: u16 = 0xFE0D;

    struct WireHello {
        /// `supported_groups` in wire order, GREASE removed.
        groups: Vec<u16>,
        /// Extension types, GREASE removed, sorted (Chrome permutes the order).
        extensions: Vec<u16>,
    }

    fn is_grease(value: u16) -> bool {
        value & 0x0F0F == 0x0A0A
    }

    /// Send one real ClientHello for `profile` through the production
    /// `configure_upstream` path and parse what reached the wire.
    async fn wire_hello(profile: TlsProfile) -> WireHello {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut tcp, _) = listener.accept().await.unwrap();
            let mut header = [0_u8; 5];
            tcp.read_exact(&mut header).await.unwrap();
            let mut record = vec![0_u8; usize::from(u16::from_be_bytes([header[3], header[4]]))];
            tcp.read_exact(&mut record).await.unwrap();
            record
        });
        let connector = build_connector(profile, None).unwrap();
        let tcp = TcpStream::connect(address).await.unwrap();
        // The server closes after reading the hello, so the handshake fails; only the bytes matter.
        let config = configure_upstream(&connector, profile, false).unwrap();
        let _ = tokio_boring::connect(config, "localhost", tcp).await;
        let hello = server.await.unwrap();
        // handshake header(4) + version(2) + random(32), then session id, suites, compression.
        let mut at = 4 + 2 + 32;
        at += 1 + usize::from(hello[at]);
        at += 2 + usize::from(u16::from_be_bytes([hello[at], hello[at + 1]]));
        at += 1 + usize::from(hello[at]);
        let end = at + 2 + usize::from(u16::from_be_bytes([hello[at], hello[at + 1]]));
        at += 2;
        let mut wire = WireHello {
            groups: Vec::new(),
            extensions: Vec::new(),
        };
        while at + 4 <= end {
            let kind = u16::from_be_bytes([hello[at], hello[at + 1]]);
            let len = usize::from(u16::from_be_bytes([hello[at + 2], hello[at + 3]]));
            if !is_grease(kind) {
                wire.extensions.push(kind);
            }
            if kind == SUPPORTED_GROUPS {
                wire.groups = hello[at + 6..at + 4 + len]
                    .chunks_exact(2)
                    .map(|group| u16::from_be_bytes([group[0], group[1]]))
                    .filter(|group| !is_grease(*group))
                    .collect();
            }
            at += 4 + len;
        }
        wire.extensions.sort_unstable();
        wire
    }

    #[tokio::test]
    async fn client_hello_groups_match_the_reference_browsers() {
        const X25519: u16 = 29;
        const P256: u16 = 23;
        const P384: u16 = 24;
        const P521: u16 = 25;
        const X25519_MLKEM768: u16 = 0x11EC;
        for (profile, expected) in [
            // utls HelloChrome_133 and shipping Chrome: no P-521.
            (
                TlsProfile::Chrome133,
                vec![X25519_MLKEM768, X25519, P256, P384],
            ),
            (TlsProfile::Firefox120, vec![X25519, P256, P384, P521]),
            (
                TlsProfile::Firefox135,
                vec![X25519_MLKEM768, X25519, P256, P384, P521],
            ),
            (TlsProfile::Safari18, vec![X25519, P256, P384, P521]),
        ] {
            assert_eq!(wire_hello(profile).await.groups, expected, "{profile:?}");
        }
    }

    #[tokio::test]
    async fn client_hello_carries_the_reference_status_sct_and_ech_extensions() {
        for (profile, status, sct, ech) in [
            (TlsProfile::Chrome133, true, true, true),
            (TlsProfile::Firefox120, true, false, true),
            (TlsProfile::Firefox135, true, false, true),
            (TlsProfile::Safari18, false, false, false),
        ] {
            let extensions = wire_hello(profile).await.extensions;
            assert_eq!(
                extensions.contains(&STATUS_REQUEST),
                status,
                "{profile:?} status_request"
            );
            assert_eq!(
                extensions.contains(&SIGNED_CERTIFICATE_TIMESTAMP),
                sct,
                "{profile:?} signed_certificate_timestamp"
            );
            assert_eq!(
                extensions.contains(&ENCRYPTED_CLIENT_HELLO),
                ech,
                "{profile:?} encrypted_client_hello"
            );
        }
    }
}
