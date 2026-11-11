//! HTTP access to the ProxyX control surfaces: the pool gateway's control API (admin bearer),
//! the session control plane (`pxk_` service key) and the unauthenticated ops ports.
//!
//! Every call has a timeout and a response size cap, never follows a redirect (a redirect
//! would send the bearer token to another host) and never puts a credential in an error.

use std::time::{Duration, Instant};

use proxyx_client::Secret;
use reqwest::{Method, Url};
use serde_json::{Value, json};

use crate::config::{
    Config, ControlEndpoint, PoolEndpoint, RoleEndpoint, RoleKind, RolePaths, read_secret,
};
use crate::redact::redact_text;

/// Largest backend response body read.
pub const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// How a backend call failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// Could not connect, timed out, or the body was unreadable.
    Transport,
    /// `401` or `403`: the configured credential was rejected.
    Auth,
    NotFound,
    Conflict,
    /// `4xx` other than the above: the request was refused.
    Rejected,
    /// `5xx`.
    Unavailable,
    TooLarge,
}

/// A failed backend call. The message is safe to show: it is redacted and bounded.
#[derive(Debug, Clone)]
pub struct ApiError {
    pub kind: ErrorKind,
    pub status: Option<u16>,
    pub message: String,
    /// The error body when it was a JSON object (redacted): `422` answers carry a `reason`.
    pub body: Option<Value>,
}

impl ApiError {
    fn transport(message: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::Transport,
            status: None,
            message: message.into(),
            body: None,
        }
    }

    /// The error as a tool-result object.
    pub fn to_value(&self) -> Value {
        json!({
            "kind": match self.kind {
                ErrorKind::Transport => "transport",
                ErrorKind::Auth => "auth",
                ErrorKind::NotFound => "not_found",
                ErrorKind::Conflict => "conflict",
                ErrorKind::Rejected => "rejected",
                ErrorKind::Unavailable => "unavailable",
                ErrorKind::TooLarge => "too_large",
            },
            "status": self.status,
            "message": self.message,
            "body": self.body,
        })
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.status {
            Some(status) => write!(f, "backend answered {status}: {}", self.message),
            None => write!(f, "{}", self.message),
        }
    }
}

impl std::error::Error for ApiError {}

/// A successful (2xx) answer.
#[derive(Debug, Clone)]
pub struct Reply {
    pub status: u16,
    pub body: Value,
}

/// A raw answer of any status, for health checks.
#[derive(Debug, Clone)]
pub struct RawReply {
    pub status: u16,
    pub text: String,
    pub elapsed: Duration,
}

/// One backend base URL with its credential.
#[derive(Clone)]
pub struct Api {
    http: reqwest::Client,
    base: Url,
    bearer: Option<Secret>,
    operator: Option<String>,
}

impl std::fmt::Debug for Api {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Api")
            .field("host", &self.base.host_str())
            .field("bearer", &self.bearer.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

impl Api {
    /// # Errors
    /// When the URL is not an http(s) URL or the client cannot be built.
    pub fn new(
        url: &str,
        bearer: Option<Secret>,
        operator: Option<String>,
        timeout: Duration,
    ) -> anyhow::Result<Self> {
        let base = Url::parse(url).map_err(|error| anyhow::anyhow!("not a URL: {error}"))?;
        anyhow::ensure!(
            matches!(base.scheme(), "http" | "https") && !base.cannot_be_a_base(),
            "not an http or https URL"
        );
        let http = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("proxyx-mcp/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self {
            http,
            base,
            bearer,
            operator,
        })
    }

    fn url(&self, segments: &[&str], query: &[(&str, String)]) -> Url {
        let mut url = self.base.clone();
        if let Ok(mut path) = url.path_segments_mut() {
            path.pop_if_empty().extend(segments);
        }
        if !query.is_empty() {
            url.query_pairs_mut()
                .extend_pairs(query.iter().map(|(k, v)| (*k, v.as_str())));
        }
        url
    }

    fn request(
        &self,
        method: Method,
        segments: &[&str],
        query: &[(&str, String)],
    ) -> reqwest::RequestBuilder {
        let mut request = self.http.request(method, self.url(segments, query));
        if let Some(token) = &self.bearer {
            request = request.bearer_auth(token.expose());
        }
        if let Some(operator) = &self.operator {
            request = request.header("X-Operator", operator.as_str());
        }
        request
    }

    /// Send a JSON request and decode the JSON answer.
    ///
    /// # Errors
    /// [`ApiError`] for a transport failure, an oversized body or a non-2xx status.
    pub async fn send(
        &self,
        method: Method,
        segments: &[&str],
        query: &[(&str, String)],
        body: Option<&Value>,
    ) -> Result<Reply, ApiError> {
        let mut request = self.request(method, segments, query);
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request.send().await.map_err(describe_transport)?;
        let status = response.status().as_u16();
        let text = read_capped(response, MAX_RESPONSE_BYTES).await?;
        if !(200..300).contains(&status) {
            return Err(status_error(status, &text));
        }
        let body = if text.trim().is_empty() {
            Value::Null
        } else {
            serde_json::from_str(&text).unwrap_or_else(|_| Value::String(redact_text(&text)))
        };
        Ok(Reply { status, body })
    }

    pub async fn get(
        &self,
        segments: &[&str],
        query: &[(&str, String)],
    ) -> Result<Value, ApiError> {
        self.send(Method::GET, segments, query, None)
            .await
            .map(|reply| reply.body)
    }

    pub async fn post(&self, segments: &[&str], body: &Value) -> Result<Value, ApiError> {
        self.send(Method::POST, segments, &[], Some(body))
            .await
            .map(|reply| reply.body)
    }

    pub async fn put(&self, segments: &[&str], body: &Value) -> Result<Value, ApiError> {
        self.send(Method::PUT, segments, &[], Some(body))
            .await
            .map(|reply| reply.body)
    }

    pub async fn patch(&self, segments: &[&str], body: &Value) -> Result<Value, ApiError> {
        self.send(Method::PATCH, segments, &[], Some(body))
            .await
            .map(|reply| reply.body)
    }

    pub async fn delete(&self, segments: &[&str]) -> Result<Value, ApiError> {
        self.send(Method::DELETE, segments, &[], None)
            .await
            .map(|reply| reply.body)
    }

    /// GET a path and return the status and text whatever the status is. For health checks
    /// and Prometheus scrapes.
    ///
    /// # Errors
    /// [`ApiError`] when the connection fails or the body exceeds `max` bytes.
    pub async fn get_raw(&self, path: &str, max: usize) -> Result<RawReply, ApiError> {
        let started = Instant::now();
        let segments: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
        let response = self
            .request(Method::GET, &segments, &[])
            .send()
            .await
            .map_err(describe_transport)?;
        let status = response.status().as_u16();
        let text = read_capped(response, max).await?;
        Ok(RawReply {
            status,
            text,
            elapsed: started.elapsed(),
        })
    }
}

fn describe_transport(error: reqwest::Error) -> ApiError {
    let reason = if error.is_timeout() {
        "request timed out"
    } else if error.is_connect() {
        "could not connect"
    } else if error.is_redirect() {
        "refused to follow a redirect"
    } else {
        "request failed"
    };
    ApiError::transport(reason)
}

async fn read_capped(mut response: reqwest::Response, max: usize) -> Result<String, ApiError> {
    let mut bytes: Vec<u8> = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                if bytes.len() + chunk.len() > max {
                    return Err(ApiError {
                        kind: ErrorKind::TooLarge,
                        status: Some(response.status().as_u16()),
                        message: format!("the response is larger than {max} bytes"),
                        body: None,
                    });
                }
                bytes.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(_) => return Err(ApiError::transport("the response body could not be read")),
        }
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn status_error(status: u16, body: &str) -> ApiError {
    let parsed = serde_json::from_str::<Value>(body).ok();
    let message = parsed
        .as_ref()
        .and_then(|value| {
            value
                .get("error")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_else(|| body.chars().take(300).collect());
    let body = parsed
        .filter(|value| value.is_object())
        .map(|value| crate::redact::redacted(&value));
    let message = redact_text(&message);
    let kind = match status {
        401 | 403 => ErrorKind::Auth,
        404 => ErrorKind::NotFound,
        409 => ErrorKind::Conflict,
        500..=599 => ErrorKind::Unavailable,
        _ => ErrorKind::Rejected,
    };
    ApiError {
        kind,
        status: Some(status),
        message: if message.is_empty() {
            format!("HTTP {status}")
        } else {
            message
        },
        body,
    }
}

/// The pool gateway control API (`/v1`), authenticated as admin.
#[derive(Debug, Clone)]
pub struct PoolApi {
    pub api: Api,
    pub base_url: String,
    /// The org key for the block-signal route, when configured.
    pub org_key: Option<Secret>,
}

/// The session control plane (`/rpc`), authenticated with a service key.
#[derive(Debug, Clone)]
pub struct ControlApi {
    pub api: Api,
    /// The org the key is bound to.
    pub org: String,
}

/// A running role to probe and scrape.
#[derive(Debug, Clone)]
pub struct Role {
    pub name: String,
    pub kind: RoleKind,
    pub paths: RolePaths,
    pub api: Api,
}

/// Every backend the server can reach, as configured.
#[derive(Debug, Clone, Default)]
pub struct Backends {
    pub pool: Option<PoolApi>,
    pub control: Option<ControlApi>,
    pub roles: Vec<Role>,
}

impl Backends {
    /// Build the clients and read their credential files.
    ///
    /// # Errors
    /// When a credential file cannot be read or a client cannot be built.
    pub fn connect(config: &Config) -> anyhow::Result<Self> {
        let timeout = config.limits.request_timeout();
        let pool = config
            .endpoints
            .pool
            .as_ref()
            .map(|endpoint| Self::pool(endpoint, timeout))
            .transpose()?;
        let control = config
            .endpoints
            .control
            .as_ref()
            .map(|endpoint| Self::control(endpoint, timeout))
            .transpose()?;
        let roles = config
            .endpoints
            .roles
            .iter()
            .map(|role| Self::role(role, timeout))
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(Self {
            pool,
            control,
            roles,
        })
    }

    fn pool(endpoint: &PoolEndpoint, timeout: Duration) -> anyhow::Result<PoolApi> {
        let token = read_secret(&endpoint.admin_token_file)?;
        let org_key = endpoint
            .org_key_file
            .as_deref()
            .map(read_secret)
            .transpose()?;
        Ok(PoolApi {
            api: Api::new(
                &endpoint.url,
                Some(token),
                Some(endpoint.operator.clone()),
                timeout,
            )?,
            base_url: endpoint.url.clone(),
            org_key,
        })
    }

    fn control(endpoint: &ControlEndpoint, timeout: Duration) -> anyhow::Result<ControlApi> {
        let key = read_secret(&endpoint.key_file)?;
        Ok(ControlApi {
            api: Api::new(&endpoint.url, Some(key), None, timeout)?,
            org: endpoint.org.clone(),
        })
    }

    fn role(endpoint: &RoleEndpoint, timeout: Duration) -> anyhow::Result<Role> {
        Ok(Role {
            name: endpoint.name.clone(),
            kind: endpoint.kind,
            paths: endpoint.kind.defaults(),
            api: Api::new(&endpoint.url, None, None, timeout)?,
        })
    }

    /// The configured role named `name`.
    pub fn role_named(&self, name: &str) -> Option<&Role> {
        self.roles.iter().find(|role| role.name == name)
    }
}
