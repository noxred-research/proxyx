//! The session control plane: create, keep alive and release capture sessions.
//!
//! A session is a capture scope for one `(org_id, source, source_id)`. Creating it returns a
//! proxy URL (HTTP CONNECT) and a SOCKS5 URL whose username is the session id, plus the CA the
//! proxy signs intercepted TLS with. The id in those URLs is the whole proxy credential: never
//! log them. [`Secret`] and every `Debug` impl here keep them out of logs.
//!
//! ```no_run
//! use proxyx_client::sessions::{CreateSessionRequest, SessionsClient};
//!
//! # async fn run() -> Result<(), proxyx_client::Error> {
//! let client = SessionsClient::new("https://control.example.com", "pxk_...")?;
//! let request = CreateSessionRequest::new("acme", "crawl", "crawl-42").captured_hosts(["*"]);
//! let session = client.open_session(request).await?;
//! let proxy = session.proxy_url(); // point the crawler here
//! # let _ = proxy;
//! session.end().await?;
//! # Ok(()) }
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use reqwest::header::HeaderValue;
use reqwest::{RequestBuilder, Response, Url};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tokio::sync::{Mutex, OnceCell, watch};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::env::{self, ProxyEnv, TempCaBundle};
use crate::error::{Error, Result};
use crate::http;
use crate::secret::Secret;

/// Session lifetime the client asks for and renews to: 30 minutes.
pub const DEFAULT_TTL_SECS: u32 = 1800;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Response header the session proxy sets when it cannot set up a tunnel.
pub const PROXY_ERROR_HEADER: &str = "X-ProxyX-Error";

// --- models ---------------------------------------------------------------------------------

/// Header name and value pairs a session injects into captured requests. Values can be
/// secrets, so `Debug` lists names only.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct InjectHeaders(pub Vec<(String, String)>);

impl std::fmt::Debug for InjectHeaders {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.0.iter().map(|(name, _)| name))
            .finish()
    }
}

/// Body of `POST /rpc/sessions`.
///
/// Creating a session for a `(org_id, source, source_id)` that already has an active one
/// attaches to it (see [`CreatedSession::attached`]); each create needs one
/// [`Session::end`] or [`SessionsClient::delete_session`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CreateSessionRequest {
    /// Host patterns to capture: `*`, an exact host, or `*.suffix`. Empty captures nothing;
    /// the traffic is tunnelled untouched.
    pub captured_hosts: Vec<String>,
    /// Patterns excluded from capture even when `captured_hosts` matches.
    pub excluded_hosts: Vec<String>,
    /// Logical `host:port` mapped to a private `http://host:port` upstream.
    pub upstream_overrides: HashMap<String, String>,
    /// Headers added to captured requests.
    pub inject_headers: InjectHeaders,
    /// Serialize the session's requests, one at a time.
    pub serialize: bool,
    /// Org of the service key.
    pub org_id: String,
    /// What the traffic is for, for example `crawl`.
    pub source: String,
    /// Caller's id of the work unit, for example the crawl id. Captures are queried by it.
    pub source_id: String,
    /// Browser user agent; selects the outbound TLS fingerprint.
    pub agent: Option<String>,
    /// Lifetime in seconds. `0` is the server default (600 s).
    pub ttl_secs: u32,
    /// Accept upstream TLS certificates that fail verification (self-signed test targets).
    /// For authorized testing only; omitted from the request when `false`.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub insecure_upstream_tls: bool,
}

impl CreateSessionRequest {
    /// A request with no captured host and a [`DEFAULT_TTL_SECS`] lifetime.
    pub fn new(
        org_id: impl Into<String>,
        source: impl Into<String>,
        source_id: impl Into<String>,
    ) -> Self {
        Self {
            captured_hosts: Vec::new(),
            excluded_hosts: Vec::new(),
            upstream_overrides: HashMap::new(),
            inject_headers: InjectHeaders::default(),
            serialize: false,
            org_id: org_id.into(),
            source: source.into(),
            source_id: source_id.into(),
            agent: None,
            ttl_secs: DEFAULT_TTL_SECS,
            insecure_upstream_tls: false,
        }
    }

    /// Hosts to capture.
    #[must_use]
    pub fn captured_hosts<I, S>(mut self, hosts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.captured_hosts = hosts.into_iter().map(Into::into).collect();
        self
    }

    /// Hosts never captured.
    #[must_use]
    pub fn excluded_hosts<I, S>(mut self, hosts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.excluded_hosts = hosts.into_iter().map(Into::into).collect();
        self
    }

    /// Route a logical `host:port` to a private `http://host:port`. The create call fails
    /// with [`Error::UpstreamOverridesMismatch`] unless the server accepts it verbatim.
    #[must_use]
    pub fn upstream_override(
        mut self,
        logical: impl Into<String>,
        destination: impl Into<String>,
    ) -> Self {
        self.upstream_overrides
            .insert(logical.into(), destination.into());
        self
    }

    /// Add a header to captured requests. Repeating a name adds a second header.
    #[must_use]
    pub fn inject_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.inject_headers.0.push((name.into(), value.into()));
        self
    }

    /// Serialize the session's requests.
    #[must_use]
    pub fn serialize(mut self, serialize: bool) -> Self {
        self.serialize = serialize;
        self
    }

    /// Browser user agent for the TLS fingerprint.
    #[must_use]
    pub fn agent(mut self, agent: impl Into<String>) -> Self {
        self.agent = Some(agent.into());
        self
    }

    /// Lifetime in seconds. `0` is the server default.
    #[must_use]
    pub fn ttl_secs(mut self, ttl_secs: u32) -> Self {
        self.ttl_secs = ttl_secs;
        self
    }

    /// Accept upstream certificates that fail verification for this session (self-signed
    /// test targets). Authorized testing only; the proxy verifies by default.
    #[must_use]
    pub fn insecure_upstream_tls(mut self, insecure: bool) -> Self {
        self.insecure_upstream_tls = insecure;
        self
    }

    fn validate(&self) -> Result<()> {
        if self.org_id.trim().is_empty() {
            return Err(Error::InvalidInput("org_id must be non-empty".into()));
        }
        if self.source_id.trim().is_empty() {
            return Err(Error::InvalidInput("source_id must be non-empty".into()));
        }
        Ok(())
    }
}

/// The raw create response. Fields the safety checks read default to "absent" so that a
/// response that lacks them is refused instead of read as success.
#[derive(Deserialize)]
struct WireCreateResponse {
    session_id: Uuid,
    #[serde(default)]
    ca_cert_pem: String,
    expires_at_ms: i64,
    #[serde(default)]
    proxy_url: String,
    #[serde(default)]
    proxy_url_socks5: String,
    #[serde(default)]
    attached: bool,
    #[serde(default)]
    success: bool,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    warning: Option<String>,
    #[serde(default)]
    upstream_overrides: HashMap<String, String>,
}

fn url_scheme_ok(value: &str, schemes: &[&str]) -> bool {
    Url::parse(value).is_ok_and(|url| schemes.contains(&url.scheme()) && url.host_str().is_some())
}

impl WireCreateResponse {
    /// The first reason this response cannot be used, if any. Never names a URL.
    fn refusal(&self, request: &CreateSessionRequest) -> Option<Error> {
        if !self.success {
            let reason = self.error.as_deref().unwrap_or("`success` is not true");
            return Some(Error::InvalidCreateResponse(reason.to_owned()));
        }
        if self.proxy_url.is_empty() || !url_scheme_ok(&self.proxy_url, &["http", "https"]) {
            return Some(Error::InvalidCreateResponse(
                "`proxy_url` is missing or not an http(s) URL".into(),
            ));
        }
        if self.proxy_url_socks5.is_empty()
            || !url_scheme_ok(&self.proxy_url_socks5, &["socks5", "socks5h"])
        {
            return Some(Error::InvalidCreateResponse(
                "`proxy_url_socks5` is missing or not a socks5 URL".into(),
            ));
        }
        if self.upstream_overrides != request.upstream_overrides {
            return Some(Error::UpstreamOverridesMismatch);
        }
        None
    }
}

/// A session the server created or attached to, after the fail-closed checks.
///
/// `Debug` hides the session id as well as the proxy URLs: the id is the proxy credential.
#[derive(Clone)]
pub struct CreatedSession {
    session_id: Uuid,
    ca_cert_pem: String,
    expires_at_ms: i64,
    proxy_url: Secret,
    proxy_url_socks5: Secret,
    attached: bool,
    warning: Option<String>,
    upstream_overrides: HashMap<String, String>,
}

impl std::fmt::Debug for CreatedSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreatedSession")
            .field("session_id", &"[redacted]")
            .field("expires_at_ms", &self.expires_at_ms)
            .field("attached", &self.attached)
            .field("warning", &self.warning)
            .field("upstream_overrides", &self.upstream_overrides)
            .finish_non_exhaustive()
    }
}

impl CreatedSession {
    /// Session id.
    pub fn session_id(&self) -> Uuid {
        self.session_id
    }

    /// PEM of the CA that signs intercepted TLS. Trust it for captured hosts.
    pub fn ca_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    /// Expiry, Unix milliseconds.
    pub fn expires_at_ms(&self) -> i64 {
        self.expires_at_ms
    }

    /// HTTP proxy URL `http://<session id>:password@host:port`. Contains the credential.
    pub fn proxy_url(&self) -> &str {
        self.proxy_url.expose()
    }

    /// SOCKS5 proxy URL. Contains the credential.
    pub fn proxy_url_socks5(&self) -> &str {
        self.proxy_url_socks5.expose()
    }

    /// True when the server reused an active session of the same source; its configuration
    /// won, and [`CreatedSession::warning`] lists what differs from the request.
    pub fn attached(&self) -> bool {
        self.attached
    }

    /// Non-fatal note from the server, for example a configuration mismatch on attach.
    pub fn warning(&self) -> Option<&str> {
        self.warning.as_deref()
    }

    /// The overrides the server accepted. Equal to the request's.
    pub fn upstream_overrides(&self) -> &HashMap<String, String> {
        &self.upstream_overrides
    }
}

/// How to change a session's lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Extend {
    /// Add seconds to the current expiry.
    AdditionalSecs(u32),
    /// Set the expiry to now plus this many seconds.
    NewTtlSecs(u32),
}

#[derive(Deserialize)]
struct ExtendResponse {
    expires_at_ms: i64,
}

/// Egress proxy of an org: a second hop after the session proxy.
#[derive(Debug, Clone, Deserialize)]
pub struct EgressProxy {
    /// `socks5` or `http`.
    pub proxy_type: ProxyType,
    /// `host:port`.
    pub address: String,
    /// Username, if the proxy needs one.
    pub username: Option<String>,
    /// Password, if the proxy needs one.
    pub password: Option<Secret>,
}

/// Protocol of an egress proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyType {
    /// SOCKS5.
    Socks5,
    /// HTTP CONNECT.
    Http,
}

/// Org rate limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub struct RateLimitSettings {
    /// Sustained rate.
    pub requests_per_minute: u32,
    /// Burst size.
    pub burst: u32,
}

/// `GET /rpc/sessions/{id}`: the stored configuration of a session.
#[derive(Debug, Clone, Deserialize)]
pub struct SessionConfig {
    /// Session id.
    pub session_id: Uuid,
    /// Org.
    pub org_id: String,
    /// Source label.
    pub source: String,
    /// Source id.
    pub source_id: String,
    /// User agent.
    pub agent: Option<String>,
    /// Captured host patterns.
    pub captured_hosts: Vec<String>,
    /// Excluded host patterns.
    pub excluded_hosts: Vec<String>,
    /// Accepted upstream overrides.
    #[serde(default)]
    pub upstream_overrides: HashMap<String, String>,
    /// Injected headers.
    pub inject_headers: InjectHeaders,
    /// Whether requests are serialized.
    pub serialize: bool,
    /// Whether upstream certificate verification is off for this session.
    #[serde(default)]
    pub insecure_upstream_tls: bool,
    /// Expiry, Unix milliseconds.
    pub expires_at_ms: i64,
    /// The org's second-hop proxy, if any.
    pub egress_proxy: Option<EgressProxy>,
    /// The org's rate limit.
    pub rate_limit: Option<RateLimitSettings>,
}

/// Lifecycle state of a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    /// Open; the proxy accepts it.
    Active,
    /// Released by its last holder; captures are draining.
    Consuming,
    /// Closed.
    Closed,
    /// A state this client version does not know.
    #[serde(other)]
    Unknown,
}

/// `GET /rpc/sessions/{id}/status`.
#[derive(Debug, Clone, Deserialize)]
pub struct SessionStatus {
    /// Lifecycle state.
    pub state: SessionState,
    /// When the session opened.
    #[serde(with = "time::serde::rfc3339")]
    pub opened_at: OffsetDateTime,
    /// When the last holder released it.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub closing_at: Option<OffsetDateTime>,
    /// When it closed.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub closed_at: Option<OffsetDateTime>,
}

#[derive(Deserialize)]
struct ProcessedResponse {
    all_processed: bool,
}

/// `GET /rpc/sequence`: the capture watermark of a source.
#[derive(Debug, Clone, Deserialize)]
pub struct Sequence {
    /// Org.
    pub org_id: String,
    /// Source id.
    pub source_id: String,
    /// Opaque cursor after the newest capture, `None` before the first. Pass it as
    /// `cursor` of a search to read only what arrives later.
    pub cursor: Option<String>,
    /// Deduplicated captures stored so far.
    pub count: u64,
}

/// Why the session proxy could not set up a tunnel, from its `X-ProxyX-Error` header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProxyErrorCause {
    /// The session is unknown or expired.
    SessionNotFound,
    /// The session store is unreachable.
    SessionBackendUnavailable,
    /// The target refused the connection.
    UpstreamRefused,
    /// The target name did not resolve.
    UpstreamDns,
    /// Any other upstream failure.
    UpstreamError,
    /// The target did not answer in time.
    UpstreamTimeout,
}

impl ProxyErrorCause {
    /// The header value.
    pub const fn code(self) -> &'static str {
        match self {
            Self::SessionNotFound => "session_not_found",
            Self::SessionBackendUnavailable => "session_backend_unavailable",
            Self::UpstreamRefused => "upstream_refused",
            Self::UpstreamDns => "upstream_dns",
            Self::UpstreamError => "upstream_error",
            Self::UpstreamTimeout => "upstream_timeout",
        }
    }

    /// The cause named by a header value.
    pub fn from_code(code: &str) -> Option<Self> {
        [
            Self::SessionNotFound,
            Self::SessionBackendUnavailable,
            Self::UpstreamRefused,
            Self::UpstreamDns,
            Self::UpstreamError,
            Self::UpstreamTimeout,
        ]
        .into_iter()
        .find(|cause| cause.code() == code.trim())
    }

    /// The cause in a response's headers, if the proxy set one.
    pub fn from_headers(headers: &reqwest::header::HeaderMap) -> Option<Self> {
        headers
            .get(PROXY_ERROR_HEADER)
            .and_then(|v| v.to_str().ok())
            .and_then(Self::from_code)
    }

    /// True when the same request can succeed later: a store outage, a refused or failed
    /// upstream, or a timeout. An unknown session and a name that does not resolve are not.
    pub const fn is_retryable(self) -> bool {
        matches!(
            self,
            Self::SessionBackendUnavailable
                | Self::UpstreamRefused
                | Self::UpstreamError
                | Self::UpstreamTimeout
        )
    }
}

// --- client ---------------------------------------------------------------------------------

/// Client of the session control plane (`/rpc`), authenticated by a service key
/// (`Authorization: Bearer pxk_...`). Cheap to clone.
#[derive(Debug, Clone)]
pub struct SessionsClient {
    pub(crate) inner: Arc<Inner>,
}

#[derive(Debug)]
pub(crate) struct Inner {
    http: reqwest::Client,
    base: Url,
    key: Secret,
}

impl SessionsClient {
    /// A client for the control plane at `base_url` (for example `https://control.example.com`).
    pub fn new(base_url: &str, service_key: impl Into<Secret>) -> Result<Self> {
        let http = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .build()?;
        Self::with_http_client(base_url, service_key, http)
    }

    /// Like [`SessionsClient::new`] with a caller-built `reqwest::Client`, for a private CA,
    /// a proxy, or other timeouts.
    pub fn with_http_client(
        base_url: &str,
        service_key: impl Into<Secret>,
        http: reqwest::Client,
    ) -> Result<Self> {
        let base =
            Url::parse(base_url).map_err(|err| Error::InvalidInput(format!("base_url: {err}")))?;
        if !matches!(base.scheme(), "http" | "https") || base.cannot_be_a_base() {
            return Err(Error::InvalidInput(
                "base_url must be an http or https URL".into(),
            ));
        }
        let key = service_key.into();
        if key.expose().is_empty()
            || HeaderValue::from_str(&format!("Bearer {}", key.expose())).is_err()
        {
            return Err(Error::InvalidInput(
                "service key is empty or not a valid header value".into(),
            ));
        }
        Ok(Self {
            inner: Arc::new(Inner { http, base, key }),
        })
    }

    /// `<base>/rpc/<segments...>`, each segment percent-encoded.
    pub(crate) fn url(&self, segments: &[&str]) -> Url {
        let mut url = self.inner.base.clone();
        // `new` rejected bases that cannot carry a path
        if let Ok(mut path) = url.path_segments_mut() {
            path.pop_if_empty().push("rpc").extend(segments);
        }
        url
    }

    pub(crate) fn get(&self, url: Url) -> RequestBuilder {
        self.inner.http.get(url)
    }

    pub(crate) fn post(&self, url: Url) -> RequestBuilder {
        self.inner.http.post(url)
    }

    /// Authenticate, send, and map a failure status to an [`Error`].
    pub(crate) async fn send(&self, request: RequestBuilder) -> Result<Response> {
        // bearer_auth marks the header sensitive, so it stays out of debug output
        let response = request.bearer_auth(self.inner.key.expose()).send().await?;
        http::check(response).await
    }

    /// `POST /rpc/sessions`: create a session, or attach to the active one of the same
    /// `(org_id, source, source_id)`.
    ///
    /// Fails closed. The credentials are returned only when the response says `success`, has a
    /// valid `proxy_url` and `proxy_url_socks5`, and its `upstream_overrides` equal the
    /// request's. Otherwise the call fails and, when the server did create or attach a session,
    /// releases it (best effort) so no orphan holds the source.
    ///
    /// A 409 ([`Error::Conflict`]) means the requested `upstream_overrides` differ from the
    /// active session's.
    pub async fn create_session(&self, request: &CreateSessionRequest) -> Result<CreatedSession> {
        request.validate()?;
        let response = self
            .send(self.post(self.url(&["sessions"])).json(request))
            .await?;
        let wire: WireCreateResponse = http::json(response).await?;
        if let Some(refusal) = wire.refusal(request) {
            if wire.success {
                // best effort: the create bumped the holder count and the caller never sees the id
                if let Err(err) = self.delete_session(wire.session_id).await {
                    tracing::warn!(error = %err, "could not release a refused session; it expires on its own");
                }
            }
            return Err(refusal);
        }
        Ok(CreatedSession {
            session_id: wire.session_id,
            ca_cert_pem: wire.ca_cert_pem,
            expires_at_ms: wire.expires_at_ms,
            proxy_url: Secret::new(wire.proxy_url),
            proxy_url_socks5: Secret::new(wire.proxy_url_socks5),
            attached: wire.attached,
            warning: wire.warning,
            upstream_overrides: wire.upstream_overrides,
        })
    }

    /// Create a session and start keeping it alive, with [`SessionOptions::default`].
    pub async fn open_session(&self, request: CreateSessionRequest) -> Result<Session> {
        self.open_session_with(request, SessionOptions::default())
            .await
    }

    /// Create a session and start the keepalive configured in `options`.
    pub async fn open_session_with(
        &self,
        request: CreateSessionRequest,
        options: SessionOptions,
    ) -> Result<Session> {
        let created = self.create_session(&request).await?;
        Ok(Session::start(
            self.clone(),
            created,
            request.org_id,
            request.source_id,
            options,
        ))
    }

    /// `GET /rpc/sessions/{id}`.
    pub async fn get_session(&self, session_id: Uuid) -> Result<SessionConfig> {
        let id = session_id.to_string();
        http::json(self.send(self.get(self.url(&["sessions", &id]))).await?).await
    }

    /// `DELETE /rpc/sessions/{id}`: release one hold on the session. The last release starts
    /// teardown and capture draining. `false` when the session does not exist (404).
    pub async fn delete_session(&self, session_id: Uuid) -> Result<bool> {
        let id = session_id.to_string();
        match self
            .send(self.inner.http.delete(self.url(&["sessions", &id])))
            .await
        {
            Ok(_) => Ok(true),
            Err(Error::NotFound { .. }) => Ok(false),
            Err(err) => Err(err),
        }
    }

    /// `PATCH /rpc/sessions/{id}`: change the lifetime. Returns the new expiry in Unix
    /// milliseconds. [`Error::Conflict`] means the session is unknown, expired or closing.
    pub async fn extend_session(&self, session_id: Uuid, extend: Extend) -> Result<i64> {
        let id = session_id.to_string();
        let request = self
            .inner
            .http
            .patch(self.url(&["sessions", &id]))
            .json(&extend);
        let body: ExtendResponse = http::json(self.send(request).await?).await?;
        Ok(body.expires_at_ms)
    }

    /// `GET /rpc/sessions/{id}/status`.
    pub async fn session_status(&self, session_id: Uuid) -> Result<SessionStatus> {
        let id = session_id.to_string();
        http::json(
            self.send(self.get(self.url(&["sessions", &id, "status"])))
                .await?,
        )
        .await
    }

    /// `GET /rpc/processed`: true once a session of this source is closed, which is when its
    /// captures are drained. It does not know about other sessions of the same source that are
    /// still open. `org_id` defaults to the key's org.
    pub async fn all_processed(&self, source_id: &str, org_id: Option<&str>) -> Result<bool> {
        let mut request = self
            .get(self.url(&["processed"]))
            .query(&[("source_id", source_id)]);
        if let Some(org_id) = org_id {
            request = request.query(&[("org_id", org_id)]);
        }
        let body: ProcessedResponse = http::json(self.send(request).await?).await?;
        Ok(body.all_processed)
    }

    /// Poll [`SessionsClient::all_processed`] every `poll_interval` until it is true. The
    /// first check is immediate. Retryable errors (5xx, transport) are tolerated until
    /// `timeout`; any other error ends the wait. [`Error::Timeout`] when time runs out.
    ///
    /// The defaults of the predecessor SDK were 120 s and 0.5 s.
    pub async fn wait_all_processed(
        &self,
        source_id: &str,
        org_id: Option<&str>,
        timeout: Duration,
        poll_interval: Duration,
    ) -> Result<()> {
        let start = Instant::now();
        loop {
            match self.all_processed(source_id, org_id).await {
                Ok(true) => return Ok(()),
                Ok(false) => {}
                Err(err) if err.is_retryable() => {}
                Err(err) => return Err(err),
            }
            let elapsed = start.elapsed();
            if elapsed >= timeout {
                return Err(Error::Timeout {
                    what: "captures to be processed",
                    waited: elapsed,
                });
            }
            tokio::time::sleep(poll_interval.min(timeout - elapsed)).await;
        }
    }

    /// `GET /rpc/certificate`: the CA PEM of the deployment.
    pub async fn certificate(&self) -> Result<String> {
        Ok(self
            .send(self.get(self.url(&["certificate"])))
            .await?
            .text()
            .await?)
    }

    /// `GET /rpc/sequence`: the capture watermark and count of a source. `org_id` defaults to
    /// the key's org.
    pub async fn sequence(&self, source_id: &str, org_id: Option<&str>) -> Result<Sequence> {
        let mut request = self
            .get(self.url(&["sequence"]))
            .query(&[("source_id", source_id)]);
        if let Some(org_id) = org_id {
            request = request.query(&[("org_id", org_id)]);
        }
        http::json(self.send(request).await?).await
    }
}

// --- session handle -------------------------------------------------------------------------

/// Keepalive tuning. The defaults are the predecessor SDK's.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct KeepaliveConfig {
    /// Lifetime requested on every renewal. Default [`DEFAULT_TTL_SECS`].
    pub ttl_secs: u32,
    /// Renew when this fraction of the lifetime is left: the loop sleeps `(1 - threshold)` of
    /// the remaining time. Default `0.2`.
    pub threshold: f64,
    /// Stop after this many consecutive failed renewals. Default `3`.
    pub max_failures: u32,
    /// Shortest sleep between renewals. Default one second.
    pub min_sleep: Duration,
}

impl Default for KeepaliveConfig {
    fn default() -> Self {
        Self {
            ttl_secs: DEFAULT_TTL_SECS,
            threshold: 0.2,
            max_failures: 3,
            min_sleep: Duration::from_secs(1),
        }
    }
}

/// Options for [`SessionsClient::open_session_with`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SessionOptions {
    /// Keepalive settings, or `None` to let the session expire after its create TTL.
    pub keepalive: Option<KeepaliveConfig>,
}

impl Default for SessionOptions {
    fn default() -> Self {
        Self {
            keepalive: Some(KeepaliveConfig::default()),
        }
    }
}

/// What the keepalive loop is doing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeepaliveState {
    /// Renewing the session.
    Running,
    /// Not started: [`SessionOptions::keepalive`] was `None`.
    Disabled,
    /// Stopped by [`Session::end`] or by dropping the handle.
    Cancelled,
    /// Stopped: the server no longer knows the session (404) or refuses to extend it (409).
    SessionGone,
    /// Stopped after [`KeepaliveConfig::max_failures`] consecutive failures. The session
    /// expires at [`Session::expires_at_ms`] unless extended by hand.
    TooManyFailures,
}

/// A live session: the credentials, a keepalive task, and release on [`Session::end`].
///
/// Dropping the handle stops the keepalive but does not release the session (a drop cannot do
/// network I/O); the session then expires when its lifetime runs out. Call
/// [`Session::end`] to release it.
pub struct Session {
    client: SessionsClient,
    created: CreatedSession,
    org_id: String,
    source_id: String,
    expires_at_ms: Arc<AtomicI64>,
    cancel: CancellationToken,
    state: watch::Receiver<KeepaliveState>,
    ended: Mutex<bool>,
    ca_bundle: OnceCell<TempCaBundle>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("created", &self.created)
            .field("org_id", &self.org_id)
            .field("source_id", &self.source_id)
            .field("expires_at_ms", &self.expires_at_ms())
            .field("keepalive", &self.keepalive_state())
            .finish_non_exhaustive()
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

impl Session {
    fn start(
        client: SessionsClient,
        created: CreatedSession,
        org_id: String,
        source_id: String,
        options: SessionOptions,
    ) -> Self {
        let expires_at_ms = Arc::new(AtomicI64::new(created.expires_at_ms));
        let cancel = CancellationToken::new();
        let (tx, state) = watch::channel(if options.keepalive.is_some() {
            KeepaliveState::Running
        } else {
            KeepaliveState::Disabled
        });
        if let Some(config) = options.keepalive {
            tokio::spawn(keepalive_loop(
                client.clone(),
                created.session_id,
                Arc::clone(&expires_at_ms),
                config,
                cancel.clone(),
                tx,
            ));
        }
        Self {
            client,
            created,
            org_id,
            source_id,
            expires_at_ms,
            cancel,
            state,
            ended: Mutex::new(false),
            ca_bundle: OnceCell::new(),
        }
    }

    /// Session id.
    pub fn id(&self) -> Uuid {
        self.created.session_id
    }

    /// The validated create response.
    pub fn created(&self) -> &CreatedSession {
        &self.created
    }

    /// HTTP proxy URL. Contains the credential.
    pub fn proxy_url(&self) -> &str {
        self.created.proxy_url()
    }

    /// SOCKS5 proxy URL. Contains the credential.
    pub fn proxy_url_socks5(&self) -> &str {
        self.created.proxy_url_socks5()
    }

    /// CA PEM of the intercepting proxy.
    pub fn ca_cert_pem(&self) -> &str {
        self.created.ca_cert_pem()
    }

    /// Latest known expiry, Unix milliseconds.
    pub fn expires_at_ms(&self) -> i64 {
        self.expires_at_ms.load(Ordering::Acquire)
    }

    /// State of the keepalive loop.
    pub fn keepalive_state(&self) -> KeepaliveState {
        *self.state.borrow()
    }

    /// A receiver that wakes when the keepalive state changes, for supervising the loop.
    pub fn watch_keepalive(&self) -> watch::Receiver<KeepaliveState> {
        self.state.clone()
    }

    /// Extend the session by hand. Returns and records the new expiry.
    pub async fn extend(&self, extend: Extend) -> Result<i64> {
        let expires = self
            .client
            .extend_session(self.created.session_id, extend)
            .await?;
        self.expires_at_ms.store(expires, Ordering::Release);
        Ok(expires)
    }

    /// Wait until the source's captures are drained: [`SessionsClient::wait_all_processed`]
    /// for this session's org and source. Call after [`Session::end`].
    pub async fn wait_all_processed(
        &self,
        timeout: Duration,
        poll_interval: Duration,
    ) -> Result<()> {
        self.client
            .wait_all_processed(&self.source_id, Some(&self.org_id), timeout, poll_interval)
            .await
    }

    /// Stop the keepalive and release this hold on the session.
    ///
    /// Idempotent: after a release succeeded (or the session was already gone) later calls do
    /// nothing and return `false`. `true` means this call released it. A failed call can be
    /// repeated. The last holder's release starts capture draining, see
    /// [`Session::wait_all_processed`].
    pub async fn end(&self) -> Result<bool> {
        self.cancel.cancel();
        let mut ended = self.ended.lock().await;
        if *ended {
            return Ok(false);
        }
        let existed = self.client.delete_session(self.created.session_id).await?;
        *ended = true;
        Ok(existed)
    }

    /// Path of a PEM bundle with the session CA and the system roots, written to a private
    /// temp file on first use and deleted when the session is dropped.
    pub async fn ca_bundle(&self) -> Result<&std::path::Path> {
        let bundle = self
            .ca_bundle
            .get_or_try_init(|| async {
                let pem = self.created.ca_cert_pem.clone();
                tokio::task::spawn_blocking(move || TempCaBundle::create(&pem))
                    .await
                    .map_err(|err| Error::CaBundle(format!("bundle task failed: {err}")))?
            })
            .await?;
        Ok(bundle.path())
    }

    /// Environment that routes a child process through the session and trusts its CA.
    /// Uses [`Session::ca_bundle`].
    pub async fn proxy_env(&self) -> Result<ProxyEnv> {
        let bundle = self.ca_bundle().await?;
        Ok(ProxyEnv::new(self.proxy_url(), bundle))
    }

    /// Like [`Session::proxy_env`] with the bundle written to `path`, which the caller owns.
    pub async fn proxy_env_at(&self, path: &std::path::Path) -> Result<ProxyEnv> {
        let pem = self.created.ca_cert_pem.clone();
        let target = path.to_path_buf();
        tokio::task::spawn_blocking(move || env::write_ca_bundle(&pem, &target))
            .await
            .map_err(|err| Error::CaBundle(format!("bundle task failed: {err}")))??;
        Ok(ProxyEnv::new(self.proxy_url(), path))
    }

    /// Chromium arguments: `--proxy-server=<proxy url>`. See [`env::browser_args`].
    pub fn browser_args(&self) -> Vec<String> {
        env::browser_args(self.proxy_url())
    }

    /// A `reqwest::Client` that uses the session proxy and trusts the session CA next to its
    /// built-in roots.
    pub fn http_client(&self) -> Result<reqwest::Client> {
        let ca = reqwest::Certificate::from_pem(self.ca_cert_pem().as_bytes()).map_err(|err| {
            Error::CaBundle(format!("the session CA is not a PEM certificate: {err}"))
        })?;
        Ok(reqwest::Client::builder()
            .proxy(reqwest::Proxy::all(self.proxy_url())?)
            .add_root_certificate(ca)
            .build()?)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

async fn keepalive_loop(
    client: SessionsClient,
    session_id: Uuid,
    expires_at_ms: Arc<AtomicI64>,
    config: KeepaliveConfig,
    cancel: CancellationToken,
    state: watch::Sender<KeepaliveState>,
) {
    let mut failures = 0u32;
    let outcome = loop {
        let remaining_secs =
            (expires_at_ms.load(Ordering::Acquire) - now_ms()).max(0) as f64 / 1000.0;
        let sleep = Duration::try_from_secs_f64(remaining_secs * (1.0 - config.threshold))
            .unwrap_or_default()
            .max(config.min_sleep);
        tokio::select! {
            () = cancel.cancelled() => break KeepaliveState::Cancelled,
            () = tokio::time::sleep(sleep) => {}
        }
        match client
            .extend_session(session_id, Extend::NewTtlSecs(config.ttl_secs))
            .await
        {
            Ok(expires) => {
                expires_at_ms.store(expires, Ordering::Release);
                failures = 0;
            }
            Err(Error::NotFound { .. } | Error::Conflict { .. }) => {
                break KeepaliveState::SessionGone;
            }
            Err(err) => {
                failures += 1;
                tracing::warn!(error = %err, failures, "session keepalive failed");
                if failures >= config.max_failures {
                    break KeepaliveState::TooManyFailures;
                }
            }
        }
    };
    let _ = state.send(outcome);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_serializes_to_the_server_shape() {
        let request = CreateSessionRequest::new("acme", "crawl", "c1")
            .captured_hosts(["*.example.com"])
            .inject_header("X-Crawl-Id", "abc")
            .upstream_override("api.internal:80", "http://10.0.0.5:8080")
            .agent("UA");
        let value = serde_json::to_value(&request).expect("json");
        assert_eq!(
            value["captured_hosts"],
            serde_json::json!(["*.example.com"])
        );
        assert_eq!(value["excluded_hosts"], serde_json::json!([]));
        assert_eq!(
            value["inject_headers"],
            serde_json::json!([["X-Crawl-Id", "abc"]])
        );
        assert_eq!(
            value["upstream_overrides"]["api.internal:80"],
            "http://10.0.0.5:8080"
        );
        assert_eq!(value["serialize"], false);
        assert_eq!(value["ttl_secs"], 1800);
        assert_eq!(value["agent"], "UA");
    }

    #[test]
    fn extend_serializes_one_key() {
        assert_eq!(
            serde_json::to_string(&Extend::NewTtlSecs(1800)).expect("json"),
            r#"{"new_ttl_secs":1800}"#
        );
        assert_eq!(
            serde_json::to_string(&Extend::AdditionalSecs(300)).expect("json"),
            r#"{"additional_secs":300}"#
        );
    }

    #[test]
    fn request_debug_hides_header_values() {
        let request = CreateSessionRequest::new("a", "s", "i")
            .inject_header("Authorization", "Bearer topsecret");
        let text = format!("{request:?}");
        assert!(text.contains("Authorization"));
        assert!(!text.contains("topsecret"));
    }

    #[test]
    fn empty_ids_are_refused_before_sending() {
        assert!(CreateSessionRequest::new("", "s", "i").validate().is_err());
        assert!(
            CreateSessionRequest::new("o", "s", "  ")
                .validate()
                .is_err()
        );
        assert!(CreateSessionRequest::new("o", "s", "i").validate().is_ok());
    }

    #[test]
    fn proxy_error_causes_parse() {
        for code in [
            "session_not_found",
            "session_backend_unavailable",
            "upstream_refused",
            "upstream_dns",
            "upstream_error",
            "upstream_timeout",
        ] {
            assert_eq!(
                ProxyErrorCause::from_code(code).map(ProxyErrorCause::code),
                Some(code)
            );
        }
        assert_eq!(ProxyErrorCause::from_code("nope"), None);
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "x-proxyx-error",
            HeaderValue::from_static("upstream_timeout"),
        );
        let cause = ProxyErrorCause::from_headers(&headers).expect("cause");
        assert_eq!(cause, ProxyErrorCause::UpstreamTimeout);
        assert!(cause.is_retryable());
        assert!(!ProxyErrorCause::SessionNotFound.is_retryable());
    }

    #[test]
    fn urls_encode_segments_and_keep_a_base_path() {
        let client = SessionsClient::new("https://h.example/api/", "k").expect("client");
        assert_eq!(
            client.url(&["sessions", "a b"]).as_str(),
            "https://h.example/api/rpc/sessions/a%20b"
        );
        assert!(SessionsClient::new("ftp://h", "k").is_err());
        assert!(SessionsClient::new("https://h", "").is_err());
        assert!(SessionsClient::new("https://h", "bad\nkey").is_err());
    }
}
