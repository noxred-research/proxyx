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
/// Extension ordering is BoringSSL-native, which matches Chrome exactly.
/// Firefox profiles omit FFDHE groups (ffdhe2048/ffdhe3072) because BoringSSL
/// cannot express them via set_curves_list; all other parameters match live
/// captures from utls/curl-impersonate.
/// The integer discriminants must stay in sync with the `ALL` array order —
/// enforced by the compile-time assertion in `MitmHandler::new`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum TlsProfile {
    /// Chrome 133+. Cipher and sigalg order unchanged from 131; curves gain
    /// X25519MLKEM768 (post-quantum hybrid, default since Chrome 131) and P-521.
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
            // P-521 added in Chrome 133. Verified against utls HelloChrome_133.
            TlsProfile::Chrome133 => "X25519MLKEM768:X25519:P-256:P-384:P-521",
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
}

/// Build a pre-configured outbound `SslConnector` for the given profile.
///
/// The connector is built once per profile at startup and reused for all
/// connections — `SslConnector::configure()` produces a per-connection
/// `ConnectConfiguration` from the shared context cheaply.
pub fn build_connector(profile: TlsProfile) -> Result<SslConnector> {
    let mut builder = SslConnector::builder(SslMethod::tls())?;

    // Certificate verification is intentionally disabled. The proxy performs
    // MITM interception by design; verifying upstream certs would break
    // connections to targets with self-signed or mismatched certificates.
    builder.set_verify(SslVerifyMode::NONE);

    // Enforce TLS 1.2 minimum; TLS 1.3 is automatically available.
    builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;

    // Apply browser-profile parameters.
    builder.set_cipher_list(profile.cipher_list())?;
    builder.set_curves_list(profile.curves_list())?;
    builder.set_alpn_protos(profile.alpn_wire())?;
    builder.set_sigalgs_list(profile.sigalgs_list())?;
    builder.set_grease_enabled(profile.grease_enabled());
    builder.set_permute_extensions(profile.permute_extensions());

    Ok(builder.build())
}

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
