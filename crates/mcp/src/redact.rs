//! Secret redaction for audit entries, error messages and tool output.
//!
//! Two passes: object members whose name says they hold a secret are replaced wholesale, and
//! every remaining string is scanned for the credential shapes ProxyX issues (org keys,
//! control-plane keys, probe tokens, bearer headers, URL userinfo).

use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;

/// The replacement text.
pub const REDACTED: &str = "[redacted]";

/// Member names that hold a secret. Names ending in `_ref`, `_file`, `_path`, `_hint` or
/// `_fingerprint` hold a reference to one, not the secret itself.
static SECRET_NAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(^|_|-)(pass(word|wd)?|secret|token|authorization|api_?key|private_?key|credential|cookie|proxy_?url(_socks5)?|key)$",
    )
    .expect("secret-name pattern is valid")
});

static SAFE_SUFFIX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(_ref|_file|_path|_hint|_fingerprint|_present|_configured)$")
        .expect("reference suffix pattern is valid")
});

/// Credential shapes found inside free text.
static SECRET_TEXT: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    let rules: [(&str, &str); 6] = [
        (r"\bak_[A-Za-z0-9_-]{16,}", REDACTED),
        (r"\bpxk_[A-Za-z0-9_-]{16,}", REDACTED),
        (r"\bpt1\.\d+\.[A-Za-z0-9_-]{8,}", REDACTED),
        (r"\bsk-[A-Za-z0-9_-]{16,}", REDACTED),
        (
            r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}",
            "Bearer [redacted]",
        ),
        (
            r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s:@]*:[^/\s@]*@",
            "${1}[redacted]@",
        ),
    ];
    rules
        .into_iter()
        .filter_map(|(pattern, replacement)| {
            Regex::new(pattern).ok().map(|regex| (regex, replacement))
        })
        .collect()
});

/// True when a member with this name must not be shown.
pub fn is_secret_name(name: &str) -> bool {
    !SAFE_SUFFIX.is_match(name) && SECRET_NAME.is_match(name)
}

/// `text` with credential shapes replaced.
pub fn redact_text(text: &str) -> String {
    let mut out = text.to_owned();
    for (regex, replacement) in SECRET_TEXT.iter() {
        if let std::borrow::Cow::Owned(replaced) = regex.replace_all(&out, *replacement) {
            out = replaced;
        }
    }
    out
}

/// The member that carries a secret the caller is meant to see once. Redaction passes over it;
/// nothing else is exempt.
pub const REVEALED: &str = "revealed_once";

/// The member that carries generated username-only proxy endpoints. A field inside it may be
/// called `proxy_url`, which the name rule would hide; the tool that produces it has already
/// refused any entry with a password or key, so only the text patterns apply to it.
pub const ENDPOINTS: &str = "endpoints";

fn redact_text_only(value: &mut Value) {
    match value {
        Value::Object(map) => map.values_mut().for_each(redact_text_only),
        Value::Array(items) => items.iter_mut().for_each(redact_text_only),
        Value::String(text) => {
            let redacted = redact_text(text);
            if redacted != *text {
                *text = redacted;
            }
        }
        _ => {}
    }
}

/// Redact `value` in place.
pub fn redact_value(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (name, member) in map.iter_mut() {
                if name == REVEALED {
                    continue;
                }
                if name == ENDPOINTS {
                    redact_text_only(member);
                    continue;
                }
                if is_secret_name(name) && !member.is_null() && !member.is_boolean() {
                    *member = Value::String(REDACTED.to_owned());
                } else {
                    redact_value(member);
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(redact_value),
        Value::String(text) => {
            let redacted = redact_text(text);
            if redacted != *text {
                *text = redacted;
            }
        }
        _ => {}
    }
}

/// A redacted copy of `value`.
pub fn redacted(value: &Value) -> Value {
    let mut copy = value.clone();
    redact_value(&mut copy);
    copy
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn secret_members_are_replaced() {
        let value = json!({
            "org": "acme",
            "password": "hunter2",
            "key": "ak_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "proxy_url": "http://0f6d:password@localhost:8443",
            "password_file": "/etc/secret",
            "credential_ref": "acme-upstream",
            "has_login": true,
            "nested": [{"api_key": "x"}, {"label": "ci"}],
        });
        let out = redacted(&value);
        assert_eq!(out["org"], "acme");
        assert_eq!(out["password"], REDACTED);
        assert_eq!(out["key"], REDACTED);
        assert_eq!(out["proxy_url"], REDACTED);
        assert_eq!(out["password_file"], "/etc/secret");
        assert_eq!(out["credential_ref"], "acme-upstream");
        assert_eq!(out["has_login"], true);
        assert_eq!(out["nested"][0]["api_key"], REDACTED);
        assert_eq!(out["nested"][1]["label"], "ci");
    }

    #[test]
    fn credential_shapes_inside_text_are_replaced() {
        let text = "failed: Authorization: Bearer abcdefghijklmnop via http://user:pw@host/x \
                    with ak_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBB and pxk_CCCCCCCCCCCCCCCCCCCCCCCC";
        let out = redact_text(text);
        for secret in ["abcdefghijklmnop", "user:pw", "ak_BBBB", "pxk_CCCC"] {
            assert!(!out.contains(secret), "{secret} leaked in {out}");
        }
        assert!(out.contains("http://[redacted]@host/x"));
    }
}
