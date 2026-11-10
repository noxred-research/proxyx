//! CA material: present, parses, not expired, and the key matches the certificate.

use std::path::PathBuf;

use base64::Engine as _;
use x509_parser::prelude::{FromDer as _, X509Certificate};

use crate::report::Check;

const DAY: i64 = 86_400;

/// Days left at which the CA warns / fails (a CA that expires takes every
/// interception certificate it signed down with it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpiryThresholds {
    pub warn_days: i64,
    pub fail_days: i64,
}

impl Default for ExpiryThresholds {
    /// Warn below 30 days, fail below 7 days or when expired.
    fn default() -> Self {
        Self {
            warn_days: 30,
            fail_days: 7,
        }
    }
}

/// How the certificate and key are encoded where the role reads them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaEncoding {
    /// Raw DER bytes (the session proxy's `ca.der` and `ca.key.der`).
    Der,
    /// PEM text (the control plane's CA file and variable).
    Pem,
    /// PEM text, or base64 of the DER (the session proxy's environment variables).
    PemOrBase64,
}

/// Where the material comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaSource {
    /// Files: the certificate, and the key when the role also holds the key.
    Files { cert: PathBuf, key: Option<PathBuf> },
    /// Values already read from variables (`label` names them in messages).
    Values {
        label: String,
        cert: String,
        key: Option<String>,
    },
}

impl CaSource {
    /// Read the variables `cert_var` and, when given, `key_var`.
    pub fn from_env(cert_var: &str, key_var: Option<&str>) -> Result<Self, String> {
        let get = |name: &str| {
            std::env::var(name).map_err(|_| format!("the environment variable {name} is not set"))
        };
        Ok(Self::Values {
            label: cert_var.to_owned(),
            cert: get(cert_var)?,
            key: key_var.map(get).transpose()?,
        })
    }
}

/// Days until `not_after` (Unix seconds), judged against `th`: negative once
/// expired. Pure, so the windows are testable.
pub fn expiry(not_after: i64, now: i64, th: ExpiryThresholds) -> (crate::Status, i64) {
    let left = (not_after - now).div_euclid(DAY);
    let status = if not_after <= now || left < th.fail_days {
        crate::Status::Fail
    } else if left < th.warn_days {
        crate::Status::Warn
    } else {
        crate::Status::Pass
    };
    (status, left)
}

/// The `ca.*` checks, with `now` as Unix seconds: `ca.cert` (present and parses),
/// `ca.expiry` (validity window against `th`), `ca.key` (the key parses and is
/// the certificate's). A certificate that cannot be read ends the list.
pub fn ca_checks(
    source: &CaSource,
    encoding: CaEncoding,
    now: i64,
    th: ExpiryThresholds,
) -> Vec<Check> {
    let Raw {
        cert: cert_raw,
        key: key_raw,
        what,
    } = match load(source) {
        Ok(loaded) => loaded,
        Err(check) => return vec![check],
    };
    let cert_der = match decode(&cert_raw, encoding, Kind::Certificate) {
        Ok(der) => der,
        Err(error) => {
            return vec![Check::fail("ca.cert", format!("{what}: {error}")).hint(
                "the role expects a certificate in this encoding; regenerate or re-encode it",
            )];
        }
    };
    let cert = match X509Certificate::from_der(&cert_der) {
        Ok((_, cert)) => cert,
        Err(error) => {
            return vec![Check::fail(
                "ca.cert",
                format!("{what} is not an X.509 certificate: {error}"),
            )];
        }
    };
    let subject = cert.subject().to_string();
    let is_ca = cert.is_ca();
    let mut out = vec![if is_ca {
        Check::pass("ca.cert", format!("{what} parses: {subject}"))
    } else {
        Check::warn(
            "ca.cert",
            format!("{what} parses ({subject}) but is not a CA certificate"),
        )
        .hint(
            "a certificate without basicConstraints CA:TRUE cannot sign interception certificates",
        )
    }];

    let validity = cert.validity();
    let (not_before, not_after) = (
        validity.not_before.timestamp(),
        validity.not_after.timestamp(),
    );
    let end = validity.not_after.to_datetime().date();
    out.push(if not_before > now {
        Check::fail(
            "ca.expiry",
            format!(
                "the certificate is not valid until {}",
                validity.not_before.to_datetime().date()
            ),
        )
        .hint("check the clock of this host, or reissue the certificate")
    } else {
        let (status, days) = expiry(not_after, now, th);
        let message = if days < 0 || not_after <= now {
            format!("the certificate expired on {end}")
        } else {
            format!("the certificate expires on {end} ({days} days left)")
        };
        match status {
            crate::Status::Pass => Check::pass("ca.expiry", message),
            crate::Status::Warn => Check::warn("ca.expiry", message).hint(
                "plan the CA rotation: clients must trust the new CA before the old one expires",
            ),
            _ => Check::fail("ca.expiry", message).hint("rotate the CA now"),
        }
    });

    if let Some(key_raw) = key_raw {
        out.push(key_check(&key_raw, encoding, &cert));
    }
    out
}

fn key_check(raw: &[u8], encoding: CaEncoding, cert: &X509Certificate<'_>) -> Check {
    let id = "ca.key";
    let der = match decode(raw, encoding, Kind::Key) {
        Ok(der) => der,
        Err(error) => {
            return Check::fail(id, format!("the CA key: {error}"))
                .hint("the role expects a PKCS#8 key in this encoding");
        }
    };
    let pair = match rcgen::KeyPair::try_from(der.as_slice()) {
        Ok(pair) => pair,
        Err(error) => {
            return Check::fail(
                id,
                format!("the CA key does not parse as a PKCS#8 private key: {error}"),
            );
        }
    };
    if pair.public_key_raw() == cert.public_key().subject_public_key.data.as_ref() {
        Check::pass(id, "the CA key matches the certificate")
    } else {
        Check::fail(id, "the CA key does not belong to the CA certificate")
            .hint("clients would see certificates the CA did not sign: pair the right key and certificate")
    }
}

/// The bytes as the role reads them, and the name of the certificate for messages.
struct Raw {
    cert: Vec<u8>,
    key: Option<Vec<u8>>,
    what: String,
}

fn load(source: &CaSource) -> Result<Raw, Check> {
    match source {
        CaSource::Files { cert, key } => {
            let read = |path: &PathBuf, what: &str| {
                std::fs::read(path).map_err(|error| {
                    Check::fail(
                        "ca.cert",
                        format!("cannot read the CA {what} {}: {error}", path.display()),
                    )
                    .hint("mount the CA files, or point the CA configuration at them")
                })
            };
            let cert_bytes = read(cert, "certificate")?;
            let key_bytes = key.as_ref().map(|k| read(k, "key")).transpose()?;
            Ok(Raw {
                cert: cert_bytes,
                key: key_bytes,
                what: cert.display().to_string(),
            })
        }
        CaSource::Values { label, cert, key } => Ok(Raw {
            cert: cert.clone().into_bytes(),
            key: key.clone().map(String::into_bytes),
            what: label.clone(),
        }),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Certificate,
    Key,
}

/// DER of a certificate or key in `encoding`.
fn decode(raw: &[u8], encoding: CaEncoding, kind: Kind) -> Result<Vec<u8>, String> {
    let text = std::str::from_utf8(raw).ok().map(str::trim);
    let armored = text.is_some_and(|t| t.starts_with("-----BEGIN"));
    match encoding {
        CaEncoding::Der => {
            if armored {
                Err("the file is PEM text but the role reads raw DER".to_owned())
            } else if raw.is_empty() {
                Err("the file is empty".to_owned())
            } else {
                Ok(raw.to_vec())
            }
        }
        CaEncoding::Pem if !armored => Err("not PEM text (no -----BEGIN line)".to_owned()),
        CaEncoding::Pem | CaEncoding::PemOrBase64 if armored => pem_der(raw, kind),
        _ => {
            let text = text.ok_or("not text: expected base64 of the DER")?;
            if text.is_empty() {
                return Err("the value is empty".to_owned());
            }
            base64::engine::general_purpose::STANDARD
                .decode(text)
                .map_err(|e| format!("not valid base64: {e}"))
        }
    }
}

fn pem_der(raw: &[u8], kind: Kind) -> Result<Vec<u8>, String> {
    use rustls_pki_types::pem::{Error as PemError, PemObject as _};
    use rustls_pki_types::{CertificateDer, PrivateKeyDer};
    match kind {
        Kind::Certificate => match CertificateDer::from_pem_slice(raw) {
            Ok(cert) => Ok(cert.as_ref().to_vec()),
            Err(PemError::NoItemsFound) => Err("no CERTIFICATE block in the PEM".to_owned()),
            Err(e) => Err(format!("bad PEM: {e}")),
        },
        Kind::Key => match PrivateKeyDer::from_pem_slice(raw) {
            Ok(key) => Ok(key.secret_der().to_vec()),
            Err(PemError::NoItemsFound) => Err("no private key block in the PEM".to_owned()),
            Err(e) => Err(format!("bad PEM: {e}")),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Status;
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
    use time::{Duration as TimeDuration, OffsetDateTime};

    const NOW: i64 = 1_800_000_000;

    fn ca(not_before_days: i64, not_after_days: i64, is_ca: bool) -> (rcgen::Certificate, KeyPair) {
        let key = KeyPair::generate().expect("key");
        let mut params = CertificateParams::default();
        params.is_ca = if is_ca {
            IsCa::Ca(BasicConstraints::Unconstrained)
        } else {
            IsCa::NoCa
        };
        let now = OffsetDateTime::from_unix_timestamp(NOW).expect("time");
        params.not_before = now + TimeDuration::days(not_before_days);
        params.not_after = now + TimeDuration::days(not_after_days);
        (params.self_signed(&key).expect("cert"), key)
    }

    fn status_of(checks: &[Check], id: &str) -> Status {
        checks
            .iter()
            .find(|c| c.id == id)
            .unwrap_or_else(|| panic!("no {id} in {checks:?}"))
            .status
    }

    fn values(cert: &rcgen::Certificate, key: Option<&KeyPair>, pem: bool) -> CaSource {
        let b64 = |der: &[u8]| base64::engine::general_purpose::STANDARD.encode(der);
        CaSource::Values {
            label: "TEST_CA".to_owned(),
            cert: if pem { cert.pem() } else { b64(cert.der()) },
            key: key.map(|k| {
                if pem {
                    k.serialize_pem()
                } else {
                    b64(&k.serialize_der())
                }
            }),
        }
    }

    #[test]
    fn the_expiry_windows() {
        let th = ExpiryThresholds::default();
        let at = |days: i64| expiry(NOW + days * DAY + 60, NOW, th);
        assert_eq!(at(365).0, Status::Pass);
        assert_eq!(at(30).0, Status::Pass);
        assert_eq!(at(29).0, Status::Warn);
        assert_eq!(at(7).0, Status::Warn);
        assert_eq!(at(6).0, Status::Fail);
        assert_eq!(expiry(NOW - 1, NOW, th).0, Status::Fail);
        assert_eq!(expiry(NOW, NOW, th).0, Status::Fail);
    }

    #[test]
    fn rcgen_certificates_at_several_validity_windows() {
        let th = ExpiryThresholds::default();
        for (days, want) in [
            (3650, Status::Pass),
            (45, Status::Pass),
            (20, Status::Warn),
            (3, Status::Fail),
            (-2, Status::Fail),
        ] {
            let (cert, key) = ca(-400, days, true);
            let checks = ca_checks(
                &values(&cert, Some(&key), false),
                CaEncoding::PemOrBase64,
                NOW,
                th,
            );
            assert_eq!(status_of(&checks, "ca.cert"), Status::Pass, "{checks:?}");
            assert_eq!(
                status_of(&checks, "ca.expiry"),
                want,
                "{days} days: {checks:?}"
            );
            assert_eq!(status_of(&checks, "ca.key"), Status::Pass, "{checks:?}");
        }
    }

    #[test]
    fn a_certificate_from_the_future_fails() {
        let (cert, key) = ca(5, 400, true);
        let checks = ca_checks(
            &values(&cert, Some(&key), true),
            CaEncoding::Pem,
            NOW,
            ExpiryThresholds::default(),
        );
        assert_eq!(status_of(&checks, "ca.expiry"), Status::Fail, "{checks:?}");
    }

    #[test]
    fn a_key_of_another_certificate_fails() {
        let (cert, _) = ca(-1, 400, true);
        let other = KeyPair::generate().expect("key");
        let checks = ca_checks(
            &values(&cert, Some(&other), true),
            CaEncoding::Pem,
            NOW,
            ExpiryThresholds::default(),
        );
        assert_eq!(status_of(&checks, "ca.key"), Status::Fail, "{checks:?}");
    }

    #[test]
    fn a_leaf_certificate_warns() {
        let (cert, key) = ca(-1, 400, false);
        let checks = ca_checks(
            &values(&cert, Some(&key), true),
            CaEncoding::Pem,
            NOW,
            ExpiryThresholds::default(),
        );
        assert_eq!(status_of(&checks, "ca.cert"), Status::Warn, "{checks:?}");
    }

    #[test]
    fn encodings_are_enforced() {
        let (cert, key) = ca(-1, 400, true);
        let th = ExpiryThresholds::default();
        // PEM given where the role reads raw DER, and base64 where it reads PEM.
        let pem = values(&cert, Some(&key), true);
        assert_eq!(
            status_of(&ca_checks(&pem, CaEncoding::Der, NOW, th), "ca.cert"),
            Status::Fail
        );
        let b64 = values(&cert, Some(&key), false);
        assert_eq!(
            status_of(&ca_checks(&b64, CaEncoding::Pem, NOW, th), "ca.cert"),
            Status::Fail
        );
        // Garbage.
        let junk = CaSource::Values {
            label: "X".into(),
            cert: "!!!".into(),
            key: None,
        };
        assert_eq!(
            status_of(
                &ca_checks(&junk, CaEncoding::PemOrBase64, NOW, th),
                "ca.cert"
            ),
            Status::Fail
        );
    }

    #[test]
    fn files_in_der_and_missing_files() {
        let (cert, key) = ca(-1, 400, true);
        let dir = std::env::temp_dir().join(format!("proxyx-diag-ca-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let (cp, kp) = (dir.join("ca.der"), dir.join("ca.key.der"));
        std::fs::write(&cp, cert.der()).expect("write");
        std::fs::write(&kp, key.serialize_der()).expect("write");
        let th = ExpiryThresholds::default();
        let source = CaSource::Files {
            cert: cp.clone(),
            key: Some(kp),
        };
        let checks = ca_checks(&source, CaEncoding::Der, NOW, th);
        assert!(
            checks.iter().all(|c| c.status == Status::Pass),
            "{checks:?}"
        );
        let missing = CaSource::Files {
            cert: dir.join("nope.der"),
            key: None,
        };
        let checks = ca_checks(&missing, CaEncoding::Der, NOW, th);
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].status, Status::Fail);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_missing_variable_is_named() {
        let error = CaSource::from_env("PROXYX_DIAG_TEST_NO_SUCH_VAR", None).expect_err("unset");
        assert!(error.contains("PROXYX_DIAG_TEST_NO_SUCH_VAR"), "{error}");
    }
}
