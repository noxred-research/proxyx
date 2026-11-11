//! Secret redaction for audit entries, error messages, tool output and LLM prompt inputs.
//!
//! Output redaction hides secret members and recognizable credentials, including session
//! authentication contexts. Prompt redaction additionally handles header collections and
//! structured JSON bodies before clipping. Query and form credentials are redacted by name.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;

/// The replacement text.
pub const REDACTED: &str = "[redacted]";

/// Member names that hold a secret. Names ending in `_ref`, `_file`, `_path`, `_hint` or
/// `_fingerprint` hold a reference to one, not the secret itself.
static SECRET_NAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(^|_|-)(pass(word|wd)?|secret|token|authorization|api[_-]?key|private[_-]?key|credential|cookie|proxy_?url(_socks5)?|key)$",
    )
    .expect("secret-name pattern is valid")
});

static SAFE_SUFFIX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(_ref|_file|_path|_hint|_fingerprint|_present|_configured)$")
        .expect("reference suffix pattern is valid")
});

/// Credential shapes found inside free text.
static SECRET_TEXT: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    let rules: [(&str, &str); 10] = [
        (r"\bak_[A-Za-z0-9_-]{16,}", REDACTED),
        (r"\bpxk_[A-Za-z0-9_-]{16,}", REDACTED),
        (r"\bpt1\.\d+\.[A-Za-z0-9_-]{8,}", REDACTED),
        (r"\bsk-[A-Za-z0-9_-]{16,}", REDACTED),
        (
            r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}",
            "Bearer [redacted]",
        ),
        (r"(?i)\bBasic\s+[A-Za-z0-9+/]+={0,2}", "Basic [redacted]"),
        (
            concat!(
                r"(?i)\b([a-z][a-z0-9+.-]*://)",
                r"(?:[0-9a-f]|%3[0-9]|%[46][1-6]){8}(?:-|%2d)",
                r"(?:[0-9a-f]|%3[0-9]|%[46][1-6]){4}(?:-|%2d)",
                r"(?:[0-9a-f]|%3[0-9]|%[46][1-6]){4}(?:-|%2d)",
                r"(?:[0-9a-f]|%3[0-9]|%[46][1-6]){4}(?:-|%2d)",
                r"(?:[0-9a-f]|%3[0-9]|%[46][1-6]){12}@"
            ),
            "${1}[redacted]@",
        ),
        (
            r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s:@]*:[^/\s@]*@",
            "${1}[redacted]@",
        ),
        (
            r"(?i)(/rpc/sessions/)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            "${1}[redacted]",
        ),
        (
            r"(?i)\b(session(?:[\s_-]+id)?[\s:=]+)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            "${1}[redacted]",
        ),
    ];
    rules
        .into_iter()
        .filter_map(|(pattern, replacement)| {
            Regex::new(pattern).ok().map(|regex| (regex, replacement))
        })
        .collect()
});

static QUERY_MEMBER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?m)(^|[?&])([^=\s?&#"'<>]+)=([^&#\s"'<>]*)"#)
        .expect("query-member pattern is valid")
});

static HEADER_LINE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^([A-Za-z0-9_-]+):[^\r\n]*").expect("header-line pattern is valid")
});

/// True when a member with this name must not be shown.
pub fn is_secret_name(name: &str) -> bool {
    !SAFE_SUFFIX.is_match(name) && SECRET_NAME.is_match(name)
}

fn is_secret_query_name(name: &str) -> bool {
    is_secret_name(name)
        || matches!(
            name.to_ascii_lowercase().as_str(),
            "auth" | "jwt" | "sid" | "session" | "session_id" | "signature" | "x-amz-signature"
        )
}

/// `text` with credential shapes replaced.
pub fn redact_text(text: &str) -> String {
    let mut out = text.to_owned();
    for (regex, replacement) in SECRET_TEXT.iter() {
        if let std::borrow::Cow::Owned(replaced) = regex.replace_all(&out, *replacement) {
            out = replaced;
        }
    }
    if let std::borrow::Cow::Owned(replaced) =
        QUERY_MEMBER.replace_all(&out, |captures: &regex::Captures<'_>| {
            let name = &captures[2];
            let sensitive = if name.contains('%') || name.contains('+') {
                reqwest::Url::parse(&format!("http://redaction.invalid/?{name}=x"))
                    .ok()
                    .and_then(|url| {
                        url.query_pairs()
                            .next()
                            .map(|(key, _)| is_secret_query_name(&key))
                    })
                    .unwrap_or(true)
            } else {
                is_secret_query_name(name)
            };
            if sensitive {
                format!("{}{name}={REDACTED}", &captures[1])
            } else {
                captures[0].to_owned()
            }
        })
    {
        out = replaced;
    }
    if let std::borrow::Cow::Owned(replaced) =
        HEADER_LINE.replace_all(&out, |captures: &regex::Captures<'_>| {
            if is_sensitive_header(&captures[1]) {
                format!("{}: {REDACTED}", &captures[1])
            } else {
                captures[0].to_owned()
            }
        })
    {
        out = replaced;
    }
    out
}

/// Whether an HTTP header may carry authentication or proxy credentials.
pub fn is_sensitive_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let compact = lower.replace(['-', '_'], "");
    lower.starts_with("proxy-")
        || matches!(compact.as_str(), "authorization" | "cookie" | "setcookie")
        || compact.contains("apikey")
        || is_secret_name(name)
}

/// Redact header objects and `[name, value]` lists before constructing a prompt.
pub fn redact_headers(headers: &mut Value) {
    match headers {
        Value::Object(map) => {
            for (name, value) in map {
                if is_sensitive_header(name) {
                    *value = Value::String(REDACTED.to_owned());
                } else {
                    redact_prompt_value(value);
                }
            }
        }
        Value::Array(pairs) => {
            for pair in pairs {
                if let Some(fields) = pair.as_array_mut()
                    && fields
                        .first()
                        .and_then(Value::as_str)
                        .is_some_and(is_sensitive_header)
                {
                    for field in fields.iter_mut().skip(1) {
                        *field = Value::String(REDACTED.to_owned());
                    }
                } else {
                    redact_prompt_value(pair);
                }
            }
        }
        _ => redact_prompt_value(headers),
    }
}

/// Redact structured JSON bodies, form/query secrets and recognizable credentials.
pub fn redact_body(text: &str) -> String {
    if matches!(text.trim_start().as_bytes().first(), Some(b'{' | b'['))
        && let Ok(mut value) = serde_json::from_str::<Value>(text)
    {
        redact_prompt_value(&mut value);
        return value.to_string();
    }
    redact_text(text)
}

/// Redact all prompt data, without the one-time-reveal exemptions used for tool output.
pub fn redact_prompt_value(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (name, member) in map {
                if matches!(
                    name.as_str(),
                    "headers" | "request_headers" | "response_headers"
                ) {
                    redact_headers(member);
                } else if (matches!(name.as_str(), "session" | "session_id")
                    && member
                        .as_str()
                        .is_some_and(|text| uuid::Uuid::parse_str(text).is_ok()))
                    || (is_secret_name(name) && !member.is_null() && !member.is_boolean())
                {
                    *member = Value::String(REDACTED.to_owned());
                } else {
                    redact_prompt_value(member);
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(redact_prompt_value),
        Value::String(text) => *text = redact_body(text),
        _ => {}
    }
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
                if (matches!(name.as_str(), "session" | "session_id")
                    && member
                        .as_str()
                        .is_some_and(|text| uuid::Uuid::parse_str(text).is_ok()))
                    || (is_secret_name(name) && !member.is_null() && !member.is_boolean())
                {
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

    #[test]
    fn session_credentials_are_hidden_only_in_authentication_contexts() {
        let session = "0f6d3a4e-5b1c-4d52-9a0e-7c1b2e8d4f10";
        // Base64 for the session UUID followed by ":password".
        let basic = "MGY2ZDNhNGUtNWIxYy00ZDUyLTlhMGUtN2MxYjJlOGQ0ZjEwOnBhc3N3b3Jk";
        let text = format!(
            "socks5://{session}@gateway:1080 http://{session}:password@gateway \
             Basic {basic} basic YWJjOnBhc3N3b3Jk"
        );
        let out = redact_text(&text);
        assert!(!out.contains(session), "{out}");
        assert!(!out.contains(basic), "{out}");
        assert!(!out.contains("YWJjOnBhc3N3b3Jk"), "{out}");
        assert!(out.contains("socks5://[redacted]@gateway:1080"));
        assert!(out.contains("http://[redacted]@gateway"));
        let encoded_hyphens = session.replace('-', "%2D");
        let encoded_all: String = session.bytes().map(|byte| format!("%{byte:02X}")).collect();
        for username in [encoded_hyphens, encoded_all] {
            let url = format!("socks5://{username}@gateway:1080");
            assert_eq!(redact_text(&url), "socks5://[redacted]@gateway:1080");
        }
        assert_eq!(
            redact_text("socks5://px-cc-fr-sid-gen0@gateway:1080"),
            "socks5://px-cc-fr-sid-gen0@gateway:1080"
        );
        assert_eq!(redact_text(session), session);
        assert_eq!(redact_text("session_opaque-alias"), "session_opaque-alias");
        assert_eq!(
            redact_text("socks5://session_opaque-alias@gateway:1080"),
            "socks5://session_opaque-alias@gateway:1080"
        );
        let path = format!("GET /rpc/sessions/{session}/status failed");
        assert_eq!(
            redact_text(&path),
            "GET /rpc/sessions/[redacted]/status failed"
        );
        for prefix in ["extend session ", "release SESSION ID: ", "session_id="] {
            let summary = redact_text(&format!("{prefix}{session}"));
            assert!(!summary.contains(session), "{summary}");
        }
        let value = json!({
            "session_id": session,
            "nested": {"session": session},
            "ordinary_id": session,
            "alias": {"session_id": "session_opaque-alias"}
        });
        for out in [redacted(&value), {
            let mut prompt = value.clone();
            redact_prompt_value(&mut prompt);
            prompt
        }] {
            assert_eq!(out["session_id"], REDACTED);
            assert_eq!(out["nested"]["session"], REDACTED);
            assert_eq!(out["ordinary_id"], session);
            assert_eq!(out["alias"]["session_id"], "session_opaque-alias");
        }
    }

    #[test]
    fn prompt_headers_bodies_and_queries_are_redacted_structurally() {
        for mut headers in [
            json!({
                "Authorization": "short-auth", "Cookie": "sid=opaque-cookie",
                "Set-Cookie": ["a=first-cookie", "b=second-cookie"],
                "Proxy-Connection": "proxy-value", "X-Api-Key-Id": "api-value",
                "Content-Type": "application/json",
                "Location": "/login?%74oken=query-value&safe=visible"
            }),
            json!([
                ["Authorization", "short-auth"],
                ["Cookie", "sid=opaque-cookie"],
                ["Set-Cookie", "a=first-cookie", "b=second-cookie"],
                ["Proxy-Connection", "proxy-value"],
                ["X-Api-Key-Id", "api-value"],
                ["Content-Type", "application/json"],
                ["Location", "/login?%74oken=query-value&safe=visible"]
            ]),
        ] {
            redact_headers(&mut headers);
            let text = headers.to_string();
            for secret in [
                "short-auth",
                "opaque-cookie",
                "first-cookie",
                "second-cookie",
                "proxy-value",
                "api-value",
                "query-value",
            ] {
                assert!(!text.contains(secret), "{secret} leaked in {text}");
            }
            assert!(text.contains("application/json"));
            assert!(text.contains("safe=visible"));
        }
        let body = redact_body(
            r#"{"password":"opaque-password","nested":[{"apiKey":"opaque-api"}],"trace":"Cookie: sid=trace-cookie\nX-Api-Key: trace-key","url":"/x?sid=query-session&safe=visible","revealed_once":{"token":"never-reveal"}}"#,
        );
        for secret in [
            "opaque-password",
            "opaque-api",
            "trace-cookie",
            "trace-key",
            "query-session",
            "never-reveal",
        ] {
            assert!(!body.contains(secret), "{secret} leaked in {body}");
        }
        assert!(body.contains("safe=visible"));
        assert_eq!(
            redact_body("password=form-secret&safe=visible&api-key=second-secret"),
            "password=[redacted]&safe=visible&api-key=[redacted]"
        );
    }
}
