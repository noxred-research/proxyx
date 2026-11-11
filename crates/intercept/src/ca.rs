//! Certificate Authority loading for the proxy.
//!
//! CA cert+key can come from:
//! - Environment variables (PROXYX_INTERCEPT_CA_CERT, PROXYX_INTERCEPT_CA_KEY) - base64-encoded DER
//! - Local DER files
//! - Auto-generated (for local dev)

use anyhow::{Context, Result};
use base64::Engine;
use rcgen::{CertificateParams, KeyPair};
use std::io::{Read as _, Write as _};
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
    let mut key_file = open_private_key(key_path)?;
    let mut key_der = Vec::new();
    key_file
        .read_to_end(&mut key_der)
        .with_context(|| format!("read CA key: {:?}", key_path))?;

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

    if cert_path.exists() || key_path.exists() {
        return load_from_files(&cert_path, &key_path);
    }

    let (cert_der, key_der) = generate()?;
    create_private_dir(data_dir)?;
    // Claim the key first, without truncating another process's CA material.
    match write_new(&key_path, &key_der).and_then(|()| write_new(&cert_path, &cert_der)) {
        Ok(()) => {
            tracing::info!(?cert_path, ?key_path, "saved generated CA to files");
            CertificateAuthority::from_der(&cert_der, &key_der)
        }
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            load_from_files(&cert_path, &key_path)
        }
        Err(err) => Err(err.into()),
    }
}

fn create_private_dir(path: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(path)
}

fn write_new(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path)?.write_all(bytes)
}

fn open_private_key(path: &Path) -> Result<std::fs::File> {
    let file = std::fs::File::open(path)
        .inspect_err(|error| {
            tracing::warn!(?path, %error, "refusing to load unreadable CA private key");
        })
        .with_context(|| format!("open CA key: {:?}", path))?;
    #[cfg(unix)]
    validate_key_metadata(&file.metadata()?, path, nix::unistd::geteuid().as_raw())?;
    Ok(file)
}

#[cfg(unix)]
fn validate_key_metadata(metadata: &std::fs::Metadata, path: &Path, uid: u32) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;
    if metadata.uid() != uid || metadata.mode() & 0o077 != 0 {
        tracing::warn!(
            ?path,
            owner_uid = metadata.uid(),
            expected_uid = uid,
            mode = format_args!("{:o}", metadata.mode() & 0o777),
            "refusing to load insecure CA private key"
        );
        anyhow::bail!(
            "insecure CA private key {:?}: must be owned by uid {} with no group or other permissions",
            path,
            uid
        );
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};

    #[test]
    fn generated_ca_uses_private_directories_and_files() -> Result<()> {
        let root = std::env::temp_dir().join(format!("proxyx-ca-{}", uuid::Uuid::new_v4()));
        let dir = root.join("nested");
        load_or_generate(&dir)?;
        for path in [&root, &dir] {
            assert_eq!(std::fs::metadata(path)?.mode() & 0o777, 0o700);
        }
        let key_path = dir.join("ca.key.der");
        let key_metadata = std::fs::metadata(&key_path)?;
        assert_eq!(key_metadata.mode() & 0o777, 0o600);
        assert_eq!(key_metadata.uid(), nix::unistd::geteuid().as_raw());
        let key = std::fs::read(&key_path)?;
        load_or_generate(&dir)?;
        assert_eq!(std::fs::read(&key_path)?, key);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn loading_rejects_group_or_world_accessible_keys() -> Result<()> {
        let dir = std::env::temp_dir().join(format!("proxyx-ca-{}", uuid::Uuid::new_v4()));
        load_or_generate(&dir)?;
        let cert_path = dir.join("ca.der");
        let key_path = dir.join("ca.key.der");
        let key = std::fs::read(&key_path)?;
        for mode in [0o640, 0o604, 0o620, 0o602] {
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(mode))?;
            let error = load_from_files(&cert_path, &key_path)
                .err()
                .expect("unsafe key rejected");
            assert!(error.to_string().contains("insecure CA private key"));
            assert!(load_or_generate(&dir).is_err());
            assert_eq!(std::fs::read(&key_path)?, key);
        }
        std::fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[test]
    fn key_metadata_rejects_another_owner() -> Result<()> {
        let dir = std::env::temp_dir().join(format!("proxyx-ca-{}", uuid::Uuid::new_v4()));
        load_or_generate(&dir)?;
        let path = dir.join("ca.key.der");
        let metadata = std::fs::metadata(&path)?;
        let error = validate_key_metadata(&metadata, &path, metadata.uid().wrapping_add(1))
            .expect_err("another owner's key rejected");
        assert!(error.to_string().contains("insecure CA private key"));
        std::fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[test]
    fn exclusive_key_creation_does_not_overwrite_files_or_follow_symlinks() -> Result<()> {
        let dir = std::env::temp_dir().join(format!("proxyx-ca-{}", uuid::Uuid::new_v4()));
        create_private_dir(&dir)?;
        let key_path = dir.join("ca.key.der");
        write_new(&key_path, b"original")?;
        assert_eq!(
            write_new(&key_path, b"replacement").unwrap_err().kind(),
            std::io::ErrorKind::AlreadyExists
        );
        let link = dir.join("key-link");
        symlink(&key_path, &link)?;
        assert_eq!(
            write_new(&link, b"replacement").unwrap_err().kind(),
            std::io::ErrorKind::AlreadyExists
        );
        assert_eq!(std::fs::read(&key_path)?, b"original");
        std::fs::remove_dir_all(dir)?;
        Ok(())
    }
}
