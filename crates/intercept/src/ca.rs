//! Certificate Authority loading for the proxy.
//!
//! CA cert+key can come from:
//! - Environment variables (PROXYX_INTERCEPT_CA_CERT, PROXYX_INTERCEPT_CA_KEY) - base64-encoded DER
//! - Local DER files
//! - Auto-generated (for local dev)

use anyhow::{Context, Result};
use base64::Engine;
use rcgen::{CertificateParams, KeyPair};
use std::path::Path;
use std::time::Duration;

use crate::config::CaConfig;
use crate::mitm::CertificateAuthority;

/// Load CA certificate based on configuration.
pub fn load(config: &CaConfig) -> Result<CertificateAuthority> {
    match config {
        CaConfig::Env => load_from_env(),
        CaConfig::File {
            cert_path,
            key_path,
        } => load_from_files(cert_path, key_path),
        CaConfig::Generate { data_dir } => load_or_generate(data_dir),
    }
}

fn load_from_env() -> Result<CertificateAuthority> {
    let cert = std::env::var("PROXYX_INTERCEPT_CA_CERT")
        .context("PROXYX_INTERCEPT_CA_CERT env var not set")?;
    let key = std::env::var("PROXYX_INTERCEPT_CA_KEY")
        .context("PROXYX_INTERCEPT_CA_KEY env var not set")?;

    // Accept either PEM (-----BEGIN ...-----) or base64-encoded DER.
    let cert_der = decode_cert_material(&cert, "PROXYX_INTERCEPT_CA_CERT")?;
    let key_der = decode_key_material(&key, "PROXYX_INTERCEPT_CA_KEY")?;

    tracing::info!("loaded CA from environment variables");
    CertificateAuthority::from_der(&cert_der, &key_der)
}

fn decode_cert_material(value: &str, var_name: &str) -> Result<Vec<u8>> {
    let trimmed = value.trim();
    if trimmed.starts_with("-----BEGIN") {
        // Strip PEM armor and decode the base64 body.
        let body: String = trimmed
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        base64::engine::general_purpose::STANDARD
            .decode(body.trim())
            .with_context(|| format!("invalid PEM body in {}", var_name))
    } else {
        base64::engine::general_purpose::STANDARD
            .decode(trimmed)
            .with_context(|| format!("invalid base64 in {}", var_name))
    }
}

fn decode_key_material(value: &str, var_name: &str) -> Result<Vec<u8>> {
    decode_cert_material(value, var_name)
}

fn load_from_files(cert_path: &Path, key_path: &Path) -> Result<CertificateAuthority> {
    let cert_der =
        std::fs::read(cert_path).with_context(|| format!("read CA cert: {:?}", cert_path))?;
    let key_der =
        std::fs::read(key_path).with_context(|| format!("read CA key: {:?}", key_path))?;

    tracing::info!(?cert_path, ?key_path, "loaded CA from files");
    CertificateAuthority::from_der(&cert_der, &key_der)
}

fn generate() -> Result<(Vec<u8>, Vec<u8>)> {
    // ECDSA P256, self-signed, 10-year validity, CA constraints
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let mut params = CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        rcgen::DnValue::Utf8String("ProxyX MITM CA".to_string()),
    );
    params.distinguished_name.push(
        rcgen::DnType::OrganizationName,
        rcgen::DnValue::Utf8String("ProxyX Proxy".to_string()),
    );
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    // SKI is required by modern TLS stacks (OpenSSL 3.x rejects CA certs without it).
    params.key_identifier_method = rcgen::KeyIdMethod::Sha256;
    params.use_authority_key_identifier_extension = true;
    params.not_before = time::OffsetDateTime::now_utc() - Duration::from_secs(3600);
    params.not_after = time::OffsetDateTime::now_utc() + Duration::from_secs(10 * 365 * 24 * 3600);
    let cert = params.self_signed(&key_pair)?;
    tracing::info!("generated new MITM CA certificate");
    Ok((cert.der().to_vec(), key_pair.serialize_der()))
}

fn load_or_generate(data_dir: &Path) -> Result<CertificateAuthority> {
    let cert_path = data_dir.join("ca.der");
    let key_path = data_dir.join("ca.key.der");

    if cert_path.exists() && key_path.exists() {
        load_from_files(&cert_path, &key_path)
    } else {
        let (cert_der, key_der) = generate()?;
        std::fs::create_dir_all(data_dir)?;
        std::fs::write(&cert_path, &cert_der)?;
        std::fs::write(&key_path, &key_der)?;
        tracing::info!(?cert_path, ?key_path, "saved generated CA to files");
        CertificateAuthority::from_der(&cert_der, &key_der)
    }
}
