//! Small helpers of the JSON wire format shared by the routes.

use std::fmt::Display;
use std::net::IpAddr;
use std::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::types::OrgId;
use rand::RngCore as _;
use rand::rngs::OsRng;
use serde_json::{Value, json};
use store::{BlockScope, OrgBlock};
use time::OffsetDateTime;

use crate::error::ApiError;

/// Longest session or job id a client may name.
pub(crate) const MAX_ID_LEN: usize = 64;

/// A session or job id: 1 to [`MAX_ID_LEN`] of `[A-Za-z0-9_-]`, so it is safe
/// as a part of a Redis key.
pub(crate) fn plain_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_ID_LEN
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// A path or query value that must parse as `T`.
pub(crate) fn parse_arg<T: FromStr>(text: &str) -> Result<T, ApiError>
where
    T::Err: Display,
{
    text.parse()
        .map_err(|e: T::Err| ApiError::bad_request(e.to_string()))
}

pub(crate) fn parse_org(org: &str) -> Result<OrgId, ApiError> {
    parse_arg(org)
}

/// Timestamps go out as Unix seconds.
pub(crate) fn unix_opt(t: Option<OffsetDateTime>) -> Option<i64> {
    t.map(OffsetDateTime::unix_timestamp)
}

/// Longest free-text name a client may send (policy name, plan, label).
pub(crate) const MAX_NAME_LEN: usize = 128;

/// Client text that Postgres can store: at most `max` bytes and no NUL byte
/// (`text` and `jsonb` refuse it, which would surface as a `503`).
pub(crate) fn ensure_text(field: &str, value: &str, max: usize) -> Result<(), ApiError> {
    if value.len() > max {
        return Err(ApiError::bad_request(format!(
            "{field} is at most {max} bytes"
        )));
    }
    if value.contains('\0') {
        return Err(ApiError::bad_request(format!(
            "{field} must not contain a NUL byte"
        )));
    }
    Ok(())
}

/// The host as an IP literal without brackets or a plain DNS name; refuses
/// anything that could smuggle a scheme, a path, a login or a second host.
pub(crate) fn plain_host(raw: &str) -> Result<String, ApiError> {
    let host = raw.trim();
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if bare.parse::<IpAddr>().is_ok() {
        return Ok(bare.to_ascii_lowercase());
    }
    let name = !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        });
    if name {
        Ok(host.to_ascii_lowercase())
    } else {
        Err(ApiError::bad_request(
            "host must be an IP address or a DNS name, without scheme, port or path",
        ))
    }
}

/// Refuse an address that can never be the exit of a rented or customer
/// proxy: unspecified, loopback, private, link-local, multicast, broadcast.
pub(crate) fn is_unusable_exit(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_multicast()
        }
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_multicast()
                || first & 0xfe00 == 0xfc00
                || first & 0xffc0 == 0xfe80
        }
    }
}

/// A file name in the secrets directory: plain characters, no path.
pub(crate) fn ensure_secret_name(field: &str, value: &str) -> Result<(), ApiError> {
    let plain = !value.is_empty()
        && value.len() <= MAX_NAME_LEN
        && !value.starts_with('.')
        && !value.contains("..")
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
    if plain {
        Ok(())
    } else {
        Err(ApiError::bad_request(format!(
            "{field} must be a plain file name of letters, digits, '.', '_' or '-'"
        )))
    }
}

/// `prefix` and 32 random bytes (256 bits) as URL-safe base64: an org key.
pub(crate) fn random_token(prefix: &str) -> String {
    let mut raw = [0u8; 32];
    OsRng.fill_bytes(&mut raw);
    format!("{prefix}{}", URL_SAFE_NO_PAD.encode(raw))
}

pub(crate) fn block_json(b: &OrgBlock) -> Value {
    let (scope, value) = b.scope.parts();
    json!({
        "id": b.id,
        "org": b.org,
        "scope": scope,
        "value": value,
        "reason": b.reason,
        "operator": b.operator,
        "created_at": b.created_at.unix_timestamp(),
        "expires_at": unix_opt(b.expires_at),
        "revoked_at": unix_opt(b.revoked_at),
    })
}

/// `scope` and `value` as an org-block request writes them.
pub(crate) fn parse_scope(scope: &str, value: &str) -> Result<BlockScope, String> {
    use policy::Pool;
    let bad = |e: &dyn std::fmt::Display| format!("block value: {e}");
    Ok(match scope {
        "ip" => BlockScope::Ip(value.parse().map_err(|e| bad(&e))?),
        "provider" => BlockScope::Provider(value.parse().map_err(|e| bad(&e))?),
        "route_class" => {
            let (provider, region) = value
                .split_once(':')
                .ok_or("a route_class value is provider:region")?;
            BlockScope::RouteClass(common::types::Partition {
                provider: provider.parse().map_err(|e| bad(&e))?,
                region: region.parse().map_err(|e| bad(&e))?,
            })
        }
        "pool" => match value {
            "shared" => BlockScope::Pool(Pool::Shared),
            "private" => BlockScope::Pool(Pool::Private),
            other => return Err(format!("a pool value is shared or private, not {other:?}")),
        },
        other => {
            return Err(format!(
                "scope must be ip, provider, route_class or pool, not {other:?}"
            ));
        }
    })
}

/// The host of `host`, `host:port` or `[v6]:port`, lowercase; `None` for
/// anything that is not a plausible host name or address.
pub(crate) fn parse_host(text: &str) -> Option<String> {
    let text = text.trim();
    let host = if let Some(rest) = text.strip_prefix('[') {
        rest.split_once(']')?.0
    } else if text.matches(':').count() == 1 {
        text.split_once(':')?.0
    } else {
        text
    };
    let plausible = !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-:".contains(&b));
    plausible.then(|| host.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_id_is_a_short_plain_token() {
        for ok in ["a", "8f14e45f-ceea-467a-9575-1a3f1d4d9d0e", "s_1-2"] {
            assert!(plain_id(ok), "{ok}");
        }
        for bad in [
            "",
            "a b",
            "a/b",
            "canary:fr",
            "é",
            &"x".repeat(MAX_ID_LEN + 1),
        ] {
            assert!(!plain_id(bad), "{bad:?}");
        }
    }

    #[test]
    fn hosts_parse_from_target_forms_and_reject_junk() {
        assert_eq!(
            parse_host("Example.COM:443").as_deref(),
            Some("example.com")
        );
        assert_eq!(parse_host("example.com").as_deref(), Some("example.com"));
        assert_eq!(
            parse_host("[2001:db8::1]:443").as_deref(),
            Some("2001:db8::1")
        );
        assert_eq!(parse_host("2001:db8::1").as_deref(), Some("2001:db8::1"));
        for bad in ["", ":443", "a b:443", "exa/mple.com", "[::1"] {
            assert_eq!(parse_host(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn scopes_parse_like_the_store_writes_them() {
        for (scope, value) in [
            ("ip", "203.0.113.9"),
            ("provider", "isp_static_port"),
            ("route_class", "isp_static_port:fr/paris"),
            ("pool", "private"),
        ] {
            let parsed = parse_scope(scope, value).expect("scope");
            assert_eq!(parsed.parts(), (scope, value.to_owned()));
        }
        for (scope, value) in [
            ("ip", "nope"),
            ("pool", "all"),
            ("route_class", "x"),
            ("zone", "x"),
        ] {
            assert!(parse_scope(scope, value).is_err(), "{scope} {value}");
        }
    }

    #[test]
    fn client_text_has_no_nul_and_a_length_bound() {
        assert!(ensure_text("f", "plain text\nwith a newline", 64).is_ok());
        assert!(ensure_text("f", "a\0b", 64).is_err(), "NUL");
        assert!(ensure_text("f", &"n".repeat(65), 64).is_err(), "too long");
        assert!(ensure_text("f", &"n".repeat(64), 64).is_ok());
    }

    #[test]
    fn secret_names_are_plain_file_names() {
        for ok in ["st-203-0-113-70", "oxy_1.cred", "a"] {
            assert!(ensure_secret_name("c", ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "../../etc/passwd",
            "/etc/passwd",
            "a/b",
            ".hidden",
            "a..b",
            "a b",
            &"x".repeat(129),
        ] {
            assert!(ensure_secret_name("c", bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn an_exit_address_is_never_private_loopback_or_unspecified() {
        for bad in [
            "0.0.0.0",
            "127.0.0.1",
            "10.0.0.1",
            "192.168.1.1",
            "172.16.0.1",
            "169.254.1.1",
            "224.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "fd00::1",
            "fe80::1",
            "ff02::1",
        ] {
            assert!(is_unusable_exit(bad.parse().expect("ip")), "{bad}");
        }
        for ok in ["93.184.216.34", "203.0.113.10", "2606:4700::1111"] {
            assert!(!is_unusable_exit(ok.parse().expect("ip")), "{ok}");
        }
    }
}
