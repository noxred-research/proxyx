//! Domain types for ProxyX proxy system.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

/// Session identifier type.
pub type SessionId = uuid::Uuid;

/// Protocol for a second-hop egress proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyType {
    /// SOCKS5 proxy (RFC 1928).
    Socks5,
    /// HTTP CONNECT proxy.
    Http,
}

/// Second-hop egress proxy configuration.
/// Stored on the org row in Postgres and propagated to `SessionConfig` in Redis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressProxy {
    pub proxy_type: ProxyType,
    /// `host:port` of the upstream proxy.
    pub address: String,
    pub username: Option<String>,
    pub password: Option<String>,
}

/// What API responses show instead of a stored upstream password.
pub const REDACTED: &str = "<redacted>";

impl EgressProxy {
    /// The same proxy with its password replaced by [`REDACTED`], for API
    /// responses: the password is write-only once stored.
    pub fn redacted(mut self) -> Self {
        if self.password.is_some() {
            self.password = Some(REDACTED.to_owned());
        }
        self
    }
}

/// Rate limiting configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RateLimitSettings {
    pub requests_per_minute: u32,
    pub burst: u32,
}

/// Organization configuration and settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Org {
    pub org_id: String,
    pub rate_limit_settings: RateLimitSettings,
    pub egress_proxy: Option<EgressProxy>,
}

/// Request to create a new proxy session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSessionRequest {
    pub captured_hosts: Vec<String>,
    /// Host patterns to exclude from capture, even if they match `captured_hosts`.
    /// Uses the same syntax: exact match, `*.example.com`, or `*`.
    #[serde(default)]
    pub excluded_hosts: Vec<String>,
    /// Exact logical `host:port` authorities mapped to private plain-HTTP upstream URLs.
    #[serde(default)]
    pub upstream_overrides: HashMap<String, String>,
    /// Disable upstream TLS certificate verification only for authorized self-signed testing.
    /// Defaults to false; normal sessions verify upstream certificates.
    #[serde(default)]
    pub insecure_upstream_tls: bool,
    pub inject_headers: Vec<(String, String)>,
    pub serialize: bool,
    pub org_id: String,
    pub source: String,
    pub source_id: String,
    pub agent: Option<String>,
    pub ttl_secs: u32,
}

fn default_true() -> bool {
    true
}

/// Response from session creation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSessionResponse {
    pub session_id: SessionId,
    pub ca_cert_pem: String,
    pub expires_at_ms: i64,
    /// Authenticated proxy URL clients use to tunnel traffic.
    /// Form: `http://{session_id}:password@{proxy_host}:{port}`.
    pub proxy_url: String,
    /// Authenticated SOCKS5 URL.
    /// Form: `socks5://{session_id}:password@{proxy_host}:{port}`.
    pub proxy_url_socks5: String,
    /// True when this response reuses an existing session (ref_count > 1).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub attached: bool,
    #[serde(default = "default_true")]
    pub success: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Non-fatal warnings (e.g. config mismatch on attach).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
    /// Session-scoped routes actually accepted by the API.
    #[serde(default)]
    pub upstream_overrides: HashMap<String, String>,
}

/// Session configuration stored as a plain Redis STRING.
/// Key format: `proxyx:session:{session_id}:data`
/// Value: JSON-serialized `SessionConfig`.
/// The sequence counter lives at a separate key (`proxyx:session:{session_id}:seq`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    pub session_id: SessionId,
    pub org_id: String,
    pub source: String,
    pub source_id: String,
    pub agent: Option<String>,
    pub captured_hosts: Vec<String>,
    pub excluded_hosts: Vec<String>,
    #[serde(default)]
    pub upstream_overrides: HashMap<String, String>,
    /// Explicit opt-in to disable upstream certificate verification for authorized self-signed testing.
    #[serde(default)]
    pub insecure_upstream_tls: bool,
    pub inject_headers: Vec<(String, String)>,
    pub serialize: bool,
    pub expires_at_ms: i64,
    /// Second-hop egress proxy resolved from the org at session creation.
    /// None = direct egress.
    pub egress_proxy: Option<EgressProxy>,
    /// Rate limit settings for this session's org.
    pub rate_limit: Option<RateLimitSettings>,
}

/// Validated session-scoped route from a logical authority to a plain-HTTP upstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedUpstreamOverride {
    pub logical_host: String,
    pub logical_port: u16,
    pub upstream_host: String,
    pub upstream_port: u16,
}

/// Validate one `upstream_overrides` entry at the session API boundary.
pub fn parse_upstream_override(
    logical_authority: &str,
    destination: &str,
) -> anyhow::Result<ParsedUpstreamOverride> {
    let (logical_host, logical_port) = parse_exact_authority(logical_authority)?;
    let upstream_authority = destination
        .strip_prefix("http://")
        .ok_or_else(|| anyhow::anyhow!("destination must use http://"))?;
    if upstream_authority
        .chars()
        .any(|c| matches!(c, '/' | '?' | '#' | '@'))
    {
        anyhow::bail!("destination must not contain credentials, path, query, or fragment");
    }
    let (upstream_host, upstream_port) = parse_exact_authority(upstream_authority)?;
    Ok(ParsedUpstreamOverride {
        logical_host,
        logical_port,
        upstream_host,
        upstream_port,
    })
}

fn parse_exact_authority(authority: &str) -> anyhow::Result<(String, u16)> {
    if authority.is_empty() || authority.trim() != authority {
        anyhow::bail!("authority must be a non-empty host:port without whitespace");
    }
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, suffix) = rest
            .split_once(']')
            .ok_or_else(|| anyhow::anyhow!("invalid bracketed IPv6 authority"))?;
        let port = suffix
            .strip_prefix(':')
            .ok_or_else(|| anyhow::anyhow!("authority must include an explicit port"))?;
        (host, port)
    } else {
        let (host, port) = authority
            .rsplit_once(':')
            .ok_or_else(|| anyhow::anyhow!("authority must include an explicit port"))?;
        if host.contains(':') {
            anyhow::bail!("IPv6 authorities must use brackets");
        }
        (host, port)
    };
    if !valid_host(host) || host != host.to_ascii_lowercase() {
        anyhow::bail!("authority host is invalid or non-canonical");
    }
    let port = port
        .parse::<u16>()
        .map_err(|_| anyhow::anyhow!("authority port is invalid"))?;
    if port == 0 {
        anyhow::bail!("authority port must be non-zero");
    }
    Ok((host.to_string(), port))
}

fn valid_host(host: &str) -> bool {
    if host.parse::<IpAddr>().is_ok() {
        return true;
    }
    !host.is_empty()
        && host.len() <= 253
        && !host.ends_with('.')
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

#[cfg(test)]
mod upstream_override_tests {
    use super::parse_upstream_override;

    #[test]
    fn accepts_exact_authority_to_plain_http_target() {
        let parsed = parse_upstream_override(
            "lab.example.test:443",
            "http://docs-app.lab.svc.cluster.local:8000",
        )
        .unwrap();
        assert_eq!(parsed.logical_port, 443);
        assert_eq!(parsed.upstream_port, 8000);
    }

    #[test]
    fn rejects_unsafe_override_shapes() {
        for (authority, destination) in [
            ("*.example.com:443", "http://private:8000"),
            ("example.com", "http://private:8000"),
            ("example.com:443", "https://private:8000"),
            ("example.com:443", "http://user@private:8000"),
            ("example.com:443", "http://private:8000/path"),
            ("example.com:443", "http://private:8000?query"),
            ("example.com:443", "http://private:8000#fragment"),
        ] {
            assert!(parse_upstream_override(authority, destination).is_err());
        }
    }

    #[test]
    fn legacy_session_config_defaults_to_no_overrides() {
        let config: super::SessionConfig = serde_json::from_value(serde_json::json!({
            "session_id": uuid::Uuid::nil(),
            "org_id": "org",
            "source": "test",
            "source_id": "run",
            "agent": null,
            "captured_hosts": [],
            "excluded_hosts": [],
            "inject_headers": [],
            "serialize": false,
            "expires_at_ms": 1,
            "egress_proxy": null,
            "rate_limit": null
        }))
        .unwrap();
        assert!(config.upstream_overrides.is_empty());
        assert!(!config.insecure_upstream_tls);
        let mut config = config;
        config.insecure_upstream_tls = true;
        let persisted = serde_json::to_string(&config).unwrap();
        let restored: super::SessionConfig = serde_json::from_str(&persisted).unwrap();
        assert!(restored.insecure_upstream_tls);
    }

    #[test]
    fn session_request_defaults_to_verified_upstream_tls() {
        let mut json = serde_json::json!({
            "captured_hosts": [],
            "inject_headers": [],
            "serialize": false,
            "org_id": "org",
            "source": "test",
            "source_id": "run",
            "ttl_secs": 60
        });
        let request: super::CreateSessionRequest = serde_json::from_value(json.clone()).unwrap();
        assert!(!request.insecure_upstream_tls);
        json["insecure_upstream_tls"] = serde_json::json!(true);
        let request: super::CreateSessionRequest = serde_json::from_value(json).unwrap();
        assert!(request.insecure_upstream_tls);
    }
}
// Wire format — `CapturedRequest`, `SessionEndEvent`, `RequestLogMessage`
// — lives in `crate::wire` and is generated from `proto/proxyx.proto`.
