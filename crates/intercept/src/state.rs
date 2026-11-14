use anyhow::{Result, anyhow};
use moka::sync::Cache;
use std::sync::Arc;
use std::sync::atomic::AtomicI64;
use std::time::Duration;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::mitm::TlsProfile;
use common::types::{
    EgressProxy, ParsedUpstreamOverride, RateLimitSettings, SessionConfig, parse_upstream_override,
};

/// Maximum number of sessions cached per proxy process.
const SESSION_CACHE_MAX: u64 = 100_000;
/// Idle eviction — sessions untouched for this long are dropped.
const SESSION_CACHE_TTI: Duration = Duration::from_secs(3600);
/// Negative-miss cache TTL — bogus session IDs are remembered for this long.
const NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(5);
/// Maximum entries in the negative-miss cache.
const NEGATIVE_CACHE_MAX: u64 = 50_000;
/// Bound on the Redis part of a session lookup (GET plus its one retry).
/// A stalled backend becomes `SessionLookup::BackendUnavailable` instead of a hang.
const SESSION_LOOKUP_TIMEOUT: Duration = Duration::from_secs(2);
/// Session stored locally in the proxy.
#[derive(Debug, Clone)]
pub struct LocalSession {
    pub session_id: Uuid,
    pub org_id: Arc<str>,
    pub source: String,
    pub source_id: String,
    pub agent: Option<String>,
    pub captured_hosts: Vec<String>,
    pub excluded_hosts: Vec<String>,
    pub upstream_overrides: Arc<[Arc<ParsedUpstreamOverride>]>,
    /// Disable upstream certificate verification only for authorized self-signed testing.
    pub insecure_upstream_tls: bool,
    pub inject_headers: Arc<[(String, String)]>,
    pub serialize: bool,
    pub serial_lock: Option<Arc<Mutex<()>>>,
    pub expires_at_ms: Arc<AtomicI64>,
    /// Egress proxy configuration (SOCKS5 or HTTP CONNECT).
    pub egress_proxy: Option<Arc<EgressProxy>>,
    /// Resolved per-org rate-limit settings (None = use proxy defaults).
    pub rate_limit: Option<RateLimitSettings>,
}

/// Routing decision for a proxied request.
#[derive(Debug, Clone)]
pub struct RoutingDecision {
    pub org_id: Arc<str>,
    pub mitm: bool,
    pub log: bool,
    pub inject_headers: Arc<[(String, String)]>,
    pub serialize: bool,
    pub egress_proxy: Option<Arc<EgressProxy>>,
    pub upstream_override: Option<Arc<ParsedUpstreamOverride>>,
    pub has_upstream_overrides: bool,
    /// Explicit session opt-in for authorized self-signed upstream testing.
    pub insecure_upstream_tls: bool,
    pub rate_limit: Option<RateLimitSettings>,
    pub tls_profile: TlsProfile,
    /// Opaque client-supplied correlation key from the credential's username
    /// (`<session-id>-sid-<key>`). A label only: it never selects a session or
    /// widens what the session may do.
    pub sticky_key: Option<Arc<str>>,
}

pub struct AuthResult {
    pub session_id: Uuid,
    pub decision: RoutingDecision,
}

/// Result of a session lookup — distinguishes genuine miss from backend failure.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)] // transient return value, never stored
pub enum SessionLookup {
    Found(LocalSession),
    NotFound,
    BackendUnavailable,
}

/// Error type for authentication/routing failures.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("session not found: {0}")]
    SessionNotFound(Uuid),
    #[error("backend unavailable")]
    BackendUnavailable,
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

#[derive(Clone)]
pub struct ProxyState {
    pub proxy_id: String,
    pub sessions: Cache<Uuid, LocalSession>,
    /// Short-lived negative cache for session IDs confirmed absent in Redis.
    negative_sessions: Cache<Uuid, ()>,
    pub redis: redis::aio::ConnectionManager,
    no_capture_hosts: Arc<[String]>,
    redis_key_prefix: String,
}

impl ProxyState {
    pub fn new(
        proxy_id: String,
        redis: redis::aio::ConnectionManager,
        no_capture_hosts: Vec<String>,
        redis_key_prefix: String,
    ) -> Self {
        let sessions = Cache::builder()
            .max_capacity(SESSION_CACHE_MAX)
            .time_to_idle(SESSION_CACHE_TTI)
            .build();
        let negative_sessions = Cache::builder()
            .max_capacity(NEGATIVE_CACHE_MAX)
            .time_to_live(NEGATIVE_CACHE_TTL)
            .build();
        Self {
            proxy_id,
            sessions,
            negative_sessions,
            redis,
            no_capture_hosts: Arc::from(no_capture_hosts),
            redis_key_prefix,
        }
    }

    pub async fn get_session(&self, session_id: &Uuid) -> SessionLookup {
        // Local cache: TTI eviction + pubsub invalidation. No Redis hop on hit.
        if let Some(s) = self.sessions.get(session_id) {
            if !is_expired(s.expires_at_ms.load(std::sync::atomic::Ordering::Relaxed)) {
                return SessionLookup::Found(s);
            }
            // Local entry is stale, but the API may have extended
            // the session in Redis since we cached it. Evict the local
            // copy and fall through so Redis is the source of truth.
            self.sessions.invalidate(session_id);
        }

        // Short-circuit if we recently confirmed this ID is absent.
        if self.negative_sessions.get(session_id).is_some() {
            return SessionLookup::NotFound;
        }

        // Fallback to Redis.
        let data_key = format!("{}:session:{session_id}:data", self.redis_key_prefix);
        let mut conn = self.redis.clone();
        let lookup = async {
            let result = redis::cmd("GET")
                .arg(&data_key)
                .query_async::<Option<String>>(&mut conn)
                .await;
            match result {
                Err(e) => {
                    // ConnectionManager reconnects in the background, so a transient
                    // drop (e.g. a broken pipe on an idle-reaped connection) clears on
                    // the next call. Retry once before declaring the backend
                    // unavailable, so a single dropped connection doesn't 503 a live
                    // session whose data is still in Redis.
                    tracing::warn!(error = %e, session_id = %session_id, "session data GET failed; retrying once");
                    redis::cmd("GET")
                        .arg(&data_key)
                        .query_async::<Option<String>>(&mut conn)
                        .await
                }
                ok => ok,
            }
        };
        let json: Option<String> = match tokio::time::timeout(SESSION_LOOKUP_TIMEOUT, lookup).await
        {
            Ok(Ok(value)) => value,
            Ok(Err(e)) => {
                tracing::warn!(error = %e, session_id = %session_id, "failed to GET session data");
                return SessionLookup::BackendUnavailable;
            }
            Err(_) => {
                tracing::warn!(session_id = %session_id, timeout = ?SESSION_LOOKUP_TIMEOUT, "session data GET timed out");
                return SessionLookup::BackendUnavailable;
            }
        };

        let json = match json {
            Some(j) => j,
            None => {
                // Genuine miss — cache it to throttle bogus-id floods.
                self.negative_sessions.insert(*session_id, ());
                return SessionLookup::NotFound;
            }
        };

        let config: SessionConfig = match serde_json::from_str(&json) {
            Ok(config) => config,
            Err(e) => {
                tracing::warn!(error = %e, session_id = %session_id, "failed to deserialize session config");
                return SessionLookup::NotFound;
            }
        };

        if is_expired(config.expires_at_ms) {
            self.negative_sessions.insert(*session_id, ());
            return SessionLookup::NotFound;
        }

        let session = match Self::from_session_config(config) {
            Ok(session) => session,
            Err(e) => {
                tracing::warn!(error = %e, session_id = %session_id, "invalid upstream override in session config");
                return SessionLookup::NotFound;
            }
        };
        self.sessions.insert(*session_id, session.clone());
        SessionLookup::Found(session)
    }

    /// Get the serialization lock for a session, if serialization is enabled.
    pub fn get_serial_lock(&self, session_id: &Uuid) -> Option<Arc<Mutex<()>>> {
        self.sessions
            .get(session_id)
            .and_then(|s| s.serial_lock.clone())
    }

    fn from_session_config(config: SessionConfig) -> Result<LocalSession> {
        let serial_lock = if config.serialize {
            Some(Arc::new(Mutex::new(())))
        } else {
            None
        };
        let upstream_overrides = config
            .upstream_overrides
            .iter()
            .map(|(authority, destination)| {
                parse_upstream_override(authority, destination).map(Arc::new)
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(LocalSession {
            session_id: config.session_id,
            org_id: Arc::from(config.org_id.as_str()),
            source: config.source,
            source_id: config.source_id,
            agent: config.agent,
            captured_hosts: config.captured_hosts,
            excluded_hosts: config.excluded_hosts,
            upstream_overrides: Arc::from(upstream_overrides),
            insecure_upstream_tls: config.insecure_upstream_tls,
            inject_headers: Arc::from(config.inject_headers),
            serialize: config.serialize,
            serial_lock,
            expires_at_ms: Arc::new(AtomicI64::new(config.expires_at_ms)),
            egress_proxy: config.egress_proxy.map(Arc::new),
            rate_limit: config.rate_limit,
        })
    }

    /// Authenticate via Proxy-Authorization header and produce a routing decision.
    /// Single session lookup — replaces separate Authenticator + Router.
    pub async fn authenticate_and_route(
        &self,
        proxy_auth_header: Option<&str>,
        host: &str,
        port: u16,
    ) -> std::result::Result<AuthResult, AuthError> {
        let header =
            proxy_auth_header.ok_or_else(|| anyhow!("missing Proxy-Authorization header"))?;
        let encoded = header
            .strip_prefix("Basic ")
            .ok_or_else(|| anyhow!("expected Basic auth"))?;
        let decoded = base64_decode(encoded)?;
        let (username, _password) = decoded
            .split_once(':')
            .ok_or_else(|| anyhow!("invalid Basic auth format"))?;
        let common::sticky::Username {
            session_id,
            sticky_key,
        } = common::sticky::parse_username(username)
            .ok_or_else(|| anyhow!("invalid session_id"))?;

        let session = match self.get_session(&session_id).await {
            SessionLookup::Found(s) => s,
            SessionLookup::NotFound => return Err(AuthError::SessionNotFound(session_id)),
            SessionLookup::BackendUnavailable => return Err(AuthError::BackendUnavailable),
        };

        let decision = self.build_routing_decision(&session, host, port, sticky_key.map(Arc::from));
        Ok(AuthResult {
            session_id,
            decision,
        })
    }

    pub async fn authenticate_socks_and_route(
        &self,
        session_id: Uuid,
        sticky_key: Option<Arc<str>>,
        host: &str,
        port: u16,
    ) -> std::result::Result<AuthResult, AuthError> {
        let session = match self.get_session(&session_id).await {
            SessionLookup::Found(s) => s,
            SessionLookup::NotFound => return Err(AuthError::SessionNotFound(session_id)),
            SessionLookup::BackendUnavailable => return Err(AuthError::BackendUnavailable),
        };

        let decision = self.build_routing_decision(&session, host, port, sticky_key);
        Ok(AuthResult {
            session_id,
            decision,
        })
    }

    fn build_routing_decision(
        &self,
        session: &LocalSession,
        host: &str,
        port: u16,
        sticky_key: Option<Arc<str>>,
    ) -> RoutingDecision {
        // ponytail: maps are normally two entries (:80/:443); scan to avoid a hot-path key allocation.
        let request_host = host.strip_suffix('.').unwrap_or(host);
        let upstream_override = session
            .upstream_overrides
            .iter()
            .find(|route| {
                route.logical_port == port && route.logical_host.eq_ignore_ascii_case(request_host)
            })
            .cloned();
        let is_whitelisted = session.captured_hosts.iter().any(|h| host_matches(h, host));
        let is_session_excluded = session.excluded_hosts.iter().any(|h| host_matches(h, host));
        let is_globally_excluded = self.no_capture_hosts.iter().any(|h| host_matches(h, host));
        let is_captured = upstream_override.is_some()
            || is_captured_host(
                &session.captured_hosts,
                &session.excluded_hosts,
                &self.no_capture_hosts,
                host,
            );

        tracing::debug!(
            %host,
            %port,
            %is_captured,
            %is_whitelisted,
            %is_session_excluded,
            %is_globally_excluded,
            has_upstream_override = upstream_override.is_some(),
            has_egress_proxy = session.egress_proxy.is_some(),
            "routing decision"
        );

        RoutingDecision {
            org_id: session.org_id.clone(),
            mitm: is_captured,
            log: is_captured,
            inject_headers: if is_captured {
                session.inject_headers.clone()
            } else {
                Arc::from([] as [(String, String); 0])
            },
            serialize: is_captured && session.serialize,
            egress_proxy: session.egress_proxy.clone(),
            has_upstream_overrides: !session.upstream_overrides.is_empty(),
            upstream_override,
            insecure_upstream_tls: session.insecure_upstream_tls,
            rate_limit: session.rate_limit.clone(),
            tls_profile: TlsProfile::for_agent(session.agent.as_deref()),
            sticky_key,
        }
    }

    /// Spawn a long-lived task that subscribes to Redis pubsub
    /// `{prefix}:session_invalidations` and drops local cache entries on receipt.
    /// Idempotent: missed messages are caught by the local TTI fallback.
    pub fn spawn_invalidation_subscriber(
        &self,
        client: redis::Client,
        cancel: tokio_util::sync::CancellationToken,
    ) {
        let sessions = self.sessions.clone();
        let invalidation_channel = format!("{}:session_invalidations", self.redis_key_prefix);
        tokio::spawn(async move {
            loop {
                if cancel.is_cancelled() {
                    return;
                }
                let mut pubsub = match client.get_async_pubsub().await {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::warn!(error = %e, "pubsub connect failed; retrying");
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        continue;
                    }
                };
                if let Err(e) = pubsub.subscribe(&invalidation_channel).await {
                    tracing::warn!(error = %e, "pubsub subscribe failed; retrying");
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    continue;
                }
                tracing::info!(channel = %invalidation_channel, "subscribed to session invalidations");
                let mut stream = pubsub.on_message();
                use futures_util::StreamExt as _;
                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => return,
                        msg = stream.next() => {
                            let Some(msg) = msg else { break };
                            let payload: String = match msg.get_payload() {
                                Ok(p) => p,
                                Err(e) => {
                                    tracing::warn!(error = %e, "invalid pubsub payload");
                                    continue;
                                }
                            };
                            match payload.parse::<Uuid>() {
                                Ok(id) => {
                                    sessions.invalidate(&id);
                                    tracing::debug!(session_id = %id, "local session invalidated by pubsub");
                                }
                                Err(_) => tracing::warn!(payload, "non-uuid invalidation payload"),
                            }
                        }
                    }
                }
                tracing::warn!("pubsub stream ended; reconnecting");
            }
        });
    }
}

fn base64_decode(input: &str) -> Result<String> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(input)
        .map_err(|_| anyhow!("invalid base64"))?;
    String::from_utf8(bytes).map_err(|_| anyhow!("invalid utf8"))
}

fn host_matches(pattern: &str, host: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        host == suffix
            || (host.len() > suffix.len()
                && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
                && host.ends_with(suffix))
    } else {
        pattern == host
    }
}

fn is_captured_host(
    captured_hosts: &[String],
    excluded_hosts: &[String],
    no_capture_hosts: &[String],
    host: &str,
) -> bool {
    captured_hosts.iter().any(|h| host_matches(h, host))
        && !excluded_hosts.iter().any(|h| host_matches(h, host))
        && !no_capture_hosts.iter().any(|h| host_matches(h, host))
}

fn is_expired(expires_at_ms: i64) -> bool {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;
    expires_at_ms < now_ms
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_matches_wildcard_all() {
        assert!(host_matches("*", "anything.example.com"));
        assert!(host_matches("*", ""));
    }

    #[test]
    fn host_matches_exact() {
        assert!(host_matches("example.com", "example.com"));
        assert!(!host_matches("example.com", "sub.example.com"));
        assert!(!host_matches("example.com", "other.com"));
    }

    #[test]
    fn host_matches_wildcard_suffix() {
        // *.example.com matches the bare domain itself
        assert!(host_matches("*.example.com", "example.com"));
        // *.example.com matches any subdomain
        assert!(host_matches("*.example.com", "sub.example.com"));
        assert!(host_matches("*.example.com", "deep.sub.example.com"));
        // must not match a different domain that merely ends with the suffix string
        assert!(!host_matches("*.example.com", "notexample.com"));
        assert!(!host_matches("*.example.com", "other.com"));
    }

    #[test]
    fn host_matches_wildcard_no_partial() {
        // "fooexample.com" ends with "example.com" but lacks a dot separator
        assert!(!host_matches("*.example.com", "fooexample.com"));
    }

    #[test]
    fn host_matches_case_sensitive() {
        // current impl is case-sensitive
        assert!(!host_matches("*.Example.com", "sub.example.com"));
        assert!(!host_matches("example.com", "Example.com"));
    }

    #[test]
    fn global_no_capture_overrides_wildcard_capture() {
        let captured_hosts = vec!["*".to_string()];
        let excluded_hosts = Vec::new();
        let no_capture_hosts = vec![
            "*.pypi.org".to_string(),
            "files.pythonhosted.org".to_string(),
        ];

        assert!(!is_captured_host(
            &captured_hosts,
            &excluded_hosts,
            &no_capture_hosts,
            "pypi.org"
        ));
        assert!(!is_captured_host(
            &captured_hosts,
            &excluded_hosts,
            &no_capture_hosts,
            "files.pythonhosted.org"
        ));
        assert!(is_captured_host(
            &captured_hosts,
            &excluded_hosts,
            &no_capture_hosts,
            "example.com"
        ));
    }

    #[test]
    fn global_no_capture_does_not_capture_unlisted_hosts() {
        let captured_hosts = vec!["example.com".to_string()];
        let excluded_hosts = Vec::new();
        let no_capture_hosts = vec!["*.npmjs.org".to_string()];

        assert!(!is_captured_host(
            &captured_hosts,
            &excluded_hosts,
            &no_capture_hosts,
            "registry.npmjs.org"
        ));
    }

    #[test]
    fn session_config_materializes_validated_override() {
        let session_id = Uuid::new_v4();
        let config = SessionConfig {
            session_id,
            org_id: "org".into(),
            source: "test".into(),
            source_id: "run".into(),
            agent: None,
            captured_hosts: Vec::new(),
            excluded_hosts: Vec::new(),
            upstream_overrides: std::collections::HashMap::from([(
                "lab.example.test:443".into(),
                "http://docs-app.lab.svc.cluster.local:8000".into(),
            )]),
            insecure_upstream_tls: true,
            inject_headers: Vec::new(),
            serialize: false,
            expires_at_ms: i64::MAX,
            egress_proxy: None,
            rate_limit: None,
        };
        let persisted = serde_json::to_string(&config).unwrap();
        let config: SessionConfig = serde_json::from_str(&persisted).unwrap();
        let local = ProxyState::from_session_config(config).unwrap();
        assert!(local.insecure_upstream_tls);
        let route = &local.upstream_overrides[0];
        assert_eq!(route.logical_port, 443);
        assert_eq!(route.upstream_port, 8000);
    }
}
