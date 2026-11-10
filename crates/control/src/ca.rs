//! The CA certificate the control plane hands to session clients.
//!
//! In `generate` mode the control plane and the session proxy share one data
//! directory and one CA: `ca.der` (certificate, DER) and `ca.key.der` (PKCS#8
//! key, DER). Whichever process starts first creates them; the other loads them.
//! Production deployments use `env` or `file` with the same CA on both sides.

use std::path::Path;

use anyhow::Result;
use base64::Engine as _;

pub fn load_ca_cert_pem(ca_config: &crate::config::CaConfig) -> Result<String> {
    match ca_config {
        crate::config::CaConfig::Env => {
            let pem = std::env::var("PROXYX_CONTROL_CA_CERT")
                .map_err(|_| anyhow::anyhow!("PROXYX_CONTROL_CA_CERT env var not set"))?;
            tracing::info!("loaded CA cert PEM from environment");
            Ok(pem)
        }
        crate::config::CaConfig::File { cert_path } => {
            let pem = std::fs::read_to_string(cert_path).map_err(|e| {
                anyhow::anyhow!("failed to read CA cert from {:?}: {}", cert_path, e)
            })?;
            tracing::info!(?cert_path, "loaded CA cert PEM from file");
            Ok(pem)
        }
        crate::config::CaConfig::Generate { data_dir } => load_or_generate_shared(data_dir),
    }
}

fn load_or_generate_shared(data_dir: &Path) -> Result<String> {
    let cert_path = data_dir.join("ca.der");
    let key_path = data_dir.join("ca.key.der");
    if cert_path.exists() {
        let der = std::fs::read(&cert_path)?;
        tracing::info!(?cert_path, "loaded shared CA certificate");
        return Ok(der_to_pem(&der));
    }
    let (cert_der, key_der) = generate()?;
    std::fs::create_dir_all(data_dir)?;
    // `create_new` so a session proxy that generated concurrently wins and we
    // read its certificate rather than overwrite it.
    match write_new(&key_path, &key_der).and_then(|()| write_new(&cert_path, &cert_der)) {
        Ok(()) => {
            tracing::info!(?cert_path, ?key_path, "generated shared CA material");
            Ok(der_to_pem(&cert_der))
        }
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            Ok(der_to_pem(&std::fs::read(&cert_path)?))
        }
        Err(err) => Err(err.into()),
    }
}

fn write_new(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)
}

/// The same CA the session proxy generates: ECDSA P-256, 10 years, with the
/// subject key identifier modern TLS stacks require.
fn generate() -> Result<(Vec<u8>, Vec<u8>)> {
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let mut params = rcgen::CertificateParams::default();
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
    params.key_identifier_method = rcgen::KeyIdMethod::Sha256;
    params.use_authority_key_identifier_extension = true;
    params.not_before = time::OffsetDateTime::now_utc() - std::time::Duration::from_secs(3600);
    params.not_after =
        time::OffsetDateTime::now_utc() + std::time::Duration::from_secs(10 * 365 * 86400);
    let cert = params.self_signed(&key_pair)?;
    Ok((cert.der().to_vec(), key_pair.serialize_der()))
}

fn der_to_pem(der: &[u8]) -> String {
    let body = base64::engine::general_purpose::STANDARD.encode(der);
    let mut pem = String::with_capacity(body.len() + body.len() / 64 + 64);
    pem.push_str("-----BEGIN CERTIFICATE-----\n");
    for line in body.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).unwrap_or_default());
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_mode_reuses_the_session_proxy_files() -> Result<()> {
        let dir = std::env::temp_dir().join(format!("proxyx-ca-{}", uuid::Uuid::new_v4()));
        let first = load_or_generate_shared(&dir)?;
        assert!(dir.join("ca.der").exists() && dir.join("ca.key.der").exists());
        // A second start (or the session proxy) sees the same certificate.
        let second = load_or_generate_shared(&dir)?;
        assert_eq!(first, second);
        let der = std::fs::read(dir.join("ca.der"))?;
        assert_eq!(first, der_to_pem(&der));
        assert!(first.starts_with("-----BEGIN CERTIFICATE-----\n"));
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }
}
