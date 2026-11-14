//! Opaque client-supplied sticky key for per-client capture correlation.
//!
//! A session proxy credential's username is normally the bare control-plane
//! session id. A client that multiplexes many of its own sessions over one
//! control-plane session can append an opaque key of its own choosing:
//!
//! ```text
//! <session-uuid>-sid-<key>
//! ```
//!
//! The key is a correlation label only. It does not select a different
//! session, does not change routing, and grants no authority: the credential
//! authenticates exactly as the bare session id does. The proxy copies the key
//! onto each captured exchange as a capture-only header ([`HEADER`]); the
//! control plane maps it to `correlation_id` when no explicit correlation
//! header was captured. Because the value is client-chosen it is a hint, never
//! evidence of identity.

use uuid::Uuid;

/// Capture-only header that carries the sticky key into the pipeline. It is
/// never forwarded to the target; any client-sent header of this name is
/// dropped from the captured copy so the value always comes from the
/// credential.
pub const HEADER: &str = "X-ProxyX-Sticky-Key";

/// Separator between the session id and the key in the username.
const MARKER: &str = "-sid-";

/// Longest accepted key, in bytes.
pub const MAX_KEY_LEN: usize = 64;

/// A parsed proxy username.
#[derive(Debug, PartialEq, Eq)]
pub struct Username<'a> {
    pub session_id: Uuid,
    pub sticky_key: Option<&'a str>,
}

/// Whether `key` is an acceptable sticky key: 1..=[`MAX_KEY_LEN`] bytes of
/// `[A-Za-z0-9_-]`.
pub fn is_valid_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= MAX_KEY_LEN
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Parse `<session-uuid>` or `<session-uuid>-sid-<key>`. Returns `None` for
/// anything else, including an invalid key; a malformed credential is never
/// silently downgraded to the bare session.
pub fn parse_username(username: &str) -> Option<Username<'_>> {
    if let Ok(session_id) = username.parse::<Uuid>() {
        return Some(Username {
            session_id,
            sticky_key: None,
        });
    }
    let session_id = username.get(..36)?.parse::<Uuid>().ok()?;
    let key = username.get(36..)?.strip_prefix(MARKER)?;
    is_valid_key(key).then_some(Username {
        session_id,
        sticky_key: Some(key),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "0b7d6b1e-4c1f-4d5a-9a3e-6f1c2d3e4f50";

    #[test]
    fn bare_session_id_has_no_key() {
        let u = parse_username(ID).unwrap();
        assert_eq!(u.session_id, ID.parse::<Uuid>().unwrap());
        assert_eq!(u.sticky_key, None);
    }

    #[test]
    fn suffix_yields_key_and_same_session() {
        let name = format!("{ID}-sid-a1B2_c-3");
        let u = parse_username(&name).unwrap();
        assert_eq!(u.session_id, ID.parse::<Uuid>().unwrap());
        assert_eq!(u.sticky_key, Some("a1B2_c-3"));
    }

    #[test]
    fn malformed_credentials_are_rejected() {
        for bad in [
            String::new(),
            "alice".to_string(),
            format!("{ID}-sid-"),
            format!("{ID}-sid-bad key"),
            format!("{ID}-sid-bad:key"),
            format!("{ID}-sid-ключ"),
            format!("{ID}-sid-{}", "a".repeat(MAX_KEY_LEN + 1)),
            format!("{ID}-other-abc"),
            format!("{ID}x"),
            format!("{ID}-sid-abc-sid-"),
            format!("é{ID}"),
        ] {
            let parsed = parse_username(&bad);
            // `-sid-abc-sid-` is a valid key charset-wise; only the others fail.
            if bad.ends_with("abc-sid-") {
                assert!(parsed.is_some(), "{bad}");
            } else {
                assert!(parsed.is_none(), "{bad}");
            }
        }
    }

    #[test]
    fn max_length_key_is_accepted() {
        let key = "k".repeat(MAX_KEY_LEN);
        let name = format!("{ID}-sid-{key}");
        let u = parse_username(&name).unwrap();
        assert_eq!(u.sticky_key, Some(key.as_str()));
    }
}
