//! Short-lived credentials of the probe listener.
//!
//! The prober hands its browsers a proxy password, and the browser pool copies
//! it into the BrowserInstance object, which every workload with the pool's
//! writer role can read. A static probe key there would be an open proxy
//! credential, so the control API issues a **token** per browser instead:
//! `pt1.<expiry>.<mac>`, where `expiry` is a Unix time in seconds and `mac` is
//! the HMAC-SHA256 of `pt1.<expiry>` under the probe secret (the Vault
//! `PROBE_ORG_KEY`, mounted into the gateway pods only), base64url without
//! padding.
//!
//! The probe listener accepts nothing else. A leaked token stops working at its
//! expiry, opens only the probe-target hosts (`ProbeTargets::allows`) and, being
//! signed, needs no row in Postgres. Rotating the secret invalidates every
//! token at once.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::Secret;
use crate::config::{Settings, read_secret_file};

/// The probe secret (`settings.probe_key_file`), or `None` when the file does
/// not exist: no prober in this environment, so no token is issued and the
/// probe listener refuses every login. Fails when the file is unreadable or
/// empty.
pub fn load_secret(settings: &Settings) -> anyhow::Result<Option<Secret>> {
    if !settings.probe_key_file.try_exists()? {
        tracing::info!(
            path = %settings.probe_key_file.display(),
            "no probe secret file; the probe listener refuses every login"
        );
        return Ok(None);
    }
    read_secret_file(&settings.probe_key_file).map(Some)
}

const PREFIX: &str = "pt1";

/// How long an issued token is valid. At least the prober's longest browser
/// lifetime (`PROXYX_PROBER_BROWSER_TTL_S`, at most this).
pub const TOKEN_TTL: Duration = Duration::from_secs(30 * 60);

fn mac_of(secret: &Secret, signed: &str) -> Hmac<Sha256> {
    // HMAC takes a key of any length
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.expose().as_bytes())
        .unwrap_or_else(|_| unreachable!("HMAC accepts every key length"));
    mac.update(signed.as_bytes());
    mac
}

fn unix(at: SystemTime) -> u64 {
    at.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// A token for `secret` that expires [`TOKEN_TTL`] after `now`.
pub fn issue(secret: &Secret, now: SystemTime) -> Secret {
    let expiry = unix(now) + TOKEN_TTL.as_secs();
    let signed = format!("{PREFIX}.{expiry}");
    let mac = mac_of(secret, &signed).finalize().into_bytes();
    Secret::new(format!("{signed}.{}", URL_SAFE_NO_PAD.encode(mac)))
}

/// True when `token` was issued under `secret` and has not expired at `now`.
/// The comparison of the MAC is constant-time.
pub fn verify(secret: &Secret, token: &str, now: SystemTime) -> bool {
    let mut parts = token.split('.');
    let (Some(PREFIX), Some(expiry), Some(mac), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let Ok(expiry_secs) = expiry.parse::<u64>() else {
        return false;
    };
    let Ok(mac) = URL_SAFE_NO_PAD.decode(mac) else {
        return false;
    };
    let signed = format!("{PREFIX}.{expiry}");
    mac_of(secret, &signed).verify_slice(&mac).is_ok() && unix(now) < expiry_secs
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> Secret {
        Secret::new("probe-secret")
    }

    #[test]
    fn a_fresh_token_verifies_until_it_expires() {
        let now = SystemTime::now();
        let token = issue(&secret(), now);
        assert!(verify(&secret(), token.expose(), now));
        assert!(verify(
            &secret(),
            token.expose(),
            now + TOKEN_TTL - Duration::from_secs(2)
        ));
        assert!(!verify(
            &secret(),
            token.expose(),
            now + TOKEN_TTL + Duration::from_secs(1)
        ));
    }

    #[test]
    fn a_token_of_another_secret_or_a_tampered_one_is_refused() {
        let now = SystemTime::now();
        let token = issue(&secret(), now);
        assert!(!verify(&Secret::new("other"), token.expose(), now));
        // a later expiry with the old MAC
        let mut parts: Vec<&str> = token.expose().split('.').collect();
        let later = (unix(now) + 10 * TOKEN_TTL.as_secs()).to_string();
        parts[1] = &later;
        assert!(!verify(&secret(), &parts.join("."), now));
    }

    #[test]
    fn the_secret_itself_and_malformed_tokens_are_refused() {
        let now = SystemTime::now();
        for bad in [
            "probe-secret",
            "",
            "pt1",
            "pt1.1.2.3",
            "pt1.x.AAAA",
            "pt2.9999999999.AAAA",
            "pt1.9999999999.!!!",
        ] {
            assert!(!verify(&secret(), bad, now), "{bad:?}");
        }
    }
}
