//! Certificate Authority for MITM certificate generation.

use anyhow::{Context, Result};
use dashmap::DashMap;
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Maximum number of cached certificates before eviction.
const MAX_CACHE_SIZE: usize = 10_000;

/// Evict entries older than this when cache is full.
const EVICTION_AGE: Duration = Duration::from_secs(3600);

/// Certificate Authority for generating MITM certificates.
pub struct CertificateAuthority {
    /// CA certificate (for signing child certs)
    ca_cert: rcgen::Certificate,
    /// CA key pair
    ca_key: KeyPair,
    /// Cache of fully-built rustls CertifiedKeys: hostname -> (key, last_access).
    /// Repeat handshakes to a cached SNI do zero keygen/parse — just an Arc clone.
    cache: DashMap<String, CachedCert>,
}

/// Cached certificate with access time for LRU eviction.
struct CachedCert {
    cert: Arc<CertifiedKey>,
    last_access: Instant,
}

impl CertificateAuthority {
    /// Create CA from DER-encoded certificate and PKCS8 key received from orchestrator.
    ///
    /// This reconstructs the CA Certificate by parsing the params from the DER
    /// and re-self-signing with the provided key.
    pub fn from_der(cert_der: &[u8], key_der: &[u8]) -> Result<Self> {
        let ca_key = KeyPair::try_from(key_der).context("parse CA key from DER")?;

        // Parse CA params from the existing certificate
        let cert_der_ref = CertificateDer::from(cert_der.to_vec());
        let ca_params =
            CertificateParams::from_ca_cert_der(&cert_der_ref).context("parse CA cert from DER")?;

        // Re-create the Certificate object by self-signing with the same key
        // This is necessary because rcgen::Certificate cannot be deserialized directly
        let ca_cert = ca_params
            .self_signed(&ca_key)
            .context("re-create CA certificate")?;

        tracing::info!("loaded CA from orchestrator");

        Ok(Self {
            ca_cert,
            ca_key,
            cache: DashMap::new(),
        })
    }

    /// Get the number of cached certificates.
    pub fn cache_len(&self) -> usize {
        self.cache.len()
    }

    /// Get the CA certificate in PEM format.
    pub fn cert_pem(&self) -> String {
        self.ca_cert.pem()
    }

    /// Get or generate a fully-built `rustls::sign::CertifiedKey` for the given
    /// hostname. Results are cached — repeat calls for the same SNI are a
    /// DashMap lookup + Arc clone with zero keygen or key-parsing.
    pub fn get_cert(&self, hostname: &str) -> Result<Arc<CertifiedKey>> {
        // Check cache first, updating access time
        if let Some(mut cached) = self.cache.get_mut(hostname) {
            cached.last_access = Instant::now();
            return Ok(cached.cert.clone());
        }

        // Evict old entries if cache is full
        if self.cache.len() >= MAX_CACHE_SIZE {
            self.evict_old_entries();
        }

        // Generate new cert and build the full rustls CertifiedKey
        let cert_key = self.generate_cert(hostname)?;
        let cert_key = Arc::new(cert_key);
        self.cache.insert(
            hostname.to_string(),
            CachedCert {
                cert: cert_key.clone(),
                last_access: Instant::now(),
            },
        );
        Ok(cert_key)
    }

    /// Evict entries older than EVICTION_AGE, or oldest half if none qualify.
    ///
    /// The age-based pass uses `DashMap::retain` (O(n) scan, no allocation).
    /// The fallback "oldest half" pass collects only the keys (no Arc clone)
    /// and partitions by median via `select_nth_unstable` (O(n)) instead of
    /// a full sort, avoiding the previous O(n log n) clone+sort on the hot path.
    fn evict_old_entries(&self) {
        let now = Instant::now();
        let before_len = self.cache.len();

        // First pass: remove entries older than threshold
        self.cache
            .retain(|_, v| now.duration_since(v.last_access) < EVICTION_AGE);

        // If we didn't evict enough, remove oldest half
        if self.cache.len() >= MAX_CACHE_SIZE {
            let mut entries: Vec<_> = self
                .cache
                .iter()
                .map(|e| (e.key().clone(), e.value().last_access))
                .collect();

            // Partition around the median timestamp in O(n) — no full sort.
            let mid = entries.len() / 2;
            entries.select_nth_unstable_by_key(mid, |(_, t)| *t);

            // Remove the older half (indices 0..mid)
            for (key, _) in &entries[..mid] {
                self.cache.remove(key);
            }
        }

        tracing::debug!(
            before = before_len,
            after = self.cache.len(),
            "evicted old certificate cache entries"
        );
    }

    /// Generate a leaf certificate for `hostname` signed by this CA, returning
    /// a fully-built `rustls::sign::CertifiedKey` (ECDSA P-256 key already
    /// parsed into a signing key). This is called only on cache miss.
    pub(super) fn generate_cert(&self, hostname: &str) -> Result<CertifiedKey> {
        let mut params = CertificateParams::default();

        // Distinguished name with hostname as CN
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.distinguished_name.push(
            rcgen::DnType::CommonName,
            rcgen::DnValue::Utf8String(hostname.to_string()),
        );

        // Set validity period
        params.not_before = time::OffsetDateTime::now_utc() - Duration::from_secs(3600);
        params.not_after = time::OffsetDateTime::now_utc() + Duration::from_secs(24 * 3600);

        // Subject Alternative Names (required for modern TLS)
        params.subject_alt_names = vec![rcgen::SanType::DnsName(hostname.try_into()?)];

        // Key usage for end-entity cert
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];

        // Enable Authority Key Identifier extension - required by some TLS libraries
        params.use_authority_key_identifier_extension = true;

        // Generate key pair for this cert
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;

        // Sign with CA
        let cert = params.signed_by(&key_pair, &self.ca_cert, &self.ca_key)?;

        tracing::debug!(%hostname, "generated MITM certificate");

        let cert_der = CertificateDer::from(cert.der().to_vec());
        let key_der = PrivatePkcs8KeyDer::from(key_pair.serialize_der());

        // Parse the signing key once here so cached lookups never re-parse.
        let signing_key = rustls::crypto::aws_lc_rs::sign::any_supported_type(&key_der.into())
            .map_err(|e| anyhow::anyhow!("parse signing key for {hostname}: {e:?}"))?;

        Ok(CertifiedKey::new(vec![cert_der], signing_key))
    }
}
