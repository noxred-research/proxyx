//! Minimal REST client for OpenSearch and Elasticsearch.
//!
//! One `reqwest` client (rustls) with the configured credentials and CA.
//! Calls return the HTTP status and the JSON body; callers decide what a
//! status means, because the same status means different things to a bulk
//! item, a search and a template read.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue};
use serde_json::Value;

use super::OpenSearchConfig;

/// Status and parsed body of one response.
pub(crate) struct OsResponse {
    pub status: u16,
    /// Parsed JSON; the raw text as a string when the body is not JSON.
    pub body: Value,
}

impl OsResponse {
    pub(crate) fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// The server is overloaded or unavailable: worth retrying.
    pub(crate) fn is_transient(&self) -> bool {
        self.status == 429 || (500..600).contains(&self.status)
    }

    /// `error.type: error.reason` of an error body, else the status.
    pub(crate) fn error_summary(&self) -> String {
        let error = &self.body["error"];
        match (error["type"].as_str(), error["reason"].as_str()) {
            (Some(kind), Some(reason)) => format!("HTTP {}: {kind}: {reason}", self.status),
            _ => match error.as_str() {
                Some(text) => format!("HTTP {}: {text}", self.status),
                None => format!("HTTP {}: {}", self.status, truncate(&self.body.to_string())),
            },
        }
    }

    pub(crate) fn ensure_success(&self, what: &str) -> Result<()> {
        if self.is_success() {
            Ok(())
        } else {
            bail!("{what} failed: {}", self.error_summary())
        }
    }
}

fn truncate(text: &str) -> String {
    const MAX: usize = 512;
    if text.len() <= MAX {
        return text.to_string();
    }
    let mut end = MAX;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &text[..end])
}

#[derive(Clone)]
pub(crate) struct OsClient {
    http: reqwest::Client,
    base: String,
    auth: Option<HeaderValue>,
    bulk_timeout: Duration,
}

impl OsClient {
    pub(crate) fn new(config: &OpenSearchConfig) -> Result<Self> {
        config.validate()?;
        let mut builder = reqwest::Client::builder()
            .use_rustls_tls()
            .timeout(Duration::from_secs(config.request_timeout_secs))
            .connect_timeout(Duration::from_secs(config.connect_timeout_secs))
            .pool_idle_timeout(
                (config.pool_idle_timeout_secs > 0)
                    .then(|| Duration::from_secs(config.pool_idle_timeout_secs)),
            )
            .pool_max_idle_per_host(config.pool_max_idle_per_host)
            .tcp_keepalive(
                (config.tcp_keepalive_secs > 0)
                    .then(|| Duration::from_secs(config.tcp_keepalive_secs)),
            );
        if let Some(path) = &config.ca_cert {
            let pem = std::fs::read(path)
                .with_context(|| format!("reading capture_store.opensearch.ca_cert {path:?}"))?;
            let cert = reqwest::Certificate::from_pem(&pem)
                .context("capture_store.opensearch.ca_cert is not a PEM certificate")?;
            builder = builder.add_root_certificate(cert);
        }

        let auth = match (&config.api_key, &config.username, &config.password) {
            (Some(key), _, _) => Some(format!("ApiKey {key}")),
            (None, Some(user), password) => {
                let token = base64::engine::general_purpose::STANDARD.encode(format!(
                    "{user}:{}",
                    password.as_deref().unwrap_or_default()
                ));
                Some(format!("Basic {token}"))
            }
            _ => None,
        }
        .map(|value| {
            HeaderValue::from_str(&value)
                .context("OpenSearch credentials are not valid header text")
        })
        .transpose()?
        .map(|mut value| {
            value.set_sensitive(true);
            value
        });

        Ok(Self {
            http: builder
                .build()
                .context("building the OpenSearch HTTP client")?,
            base: config.url.trim_end_matches('/').to_string(),
            auth,
            bulk_timeout: Duration::from_secs(config.bulk_timeout_secs),
        })
    }

    async fn send(
        &self,
        method: reqwest::Method,
        path: &str,
        content: Option<(&'static str, Vec<u8>)>,
        timeout: Option<Duration>,
    ) -> Result<OsResponse> {
        let mut request = self
            .http
            .request(method.clone(), format!("{}{path}", self.base));
        if let Some(auth) = &self.auth {
            request = request.header(AUTHORIZATION, auth.clone());
        }
        if let Some((content_type, body)) = content {
            request = request.header(CONTENT_TYPE, content_type).body(body);
        }
        if let Some(timeout) = timeout {
            request = request.timeout(timeout);
        }
        let response = request
            .send()
            .await
            .with_context(|| format!("{method} {}{}", self.base, path_without_query(path)))?;
        let status = response.status().as_u16();
        let bytes = response
            .bytes()
            .await
            .with_context(|| format!("reading the response of {method} {path}"))?;
        let body = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        Ok(OsResponse { status, body })
    }

    pub(crate) async fn get(&self, path: &str) -> Result<OsResponse> {
        self.send(reqwest::Method::GET, path, None, None).await
    }

    pub(crate) async fn put_json(&self, path: &str, body: &Value) -> Result<OsResponse> {
        let body = serde_json::to_vec(body)?;
        self.send(
            reqwest::Method::PUT,
            path,
            Some(("application/json", body)),
            None,
        )
        .await
    }

    pub(crate) async fn post_json(&self, path: &str, body: &Value) -> Result<OsResponse> {
        let body = serde_json::to_vec(body)?;
        self.send(
            reqwest::Method::POST,
            path,
            Some(("application/json", body)),
            None,
        )
        .await
    }

    /// `_bulk` body of newline-delimited JSON.
    pub(crate) async fn post_ndjson(&self, path: &str, body: Vec<u8>) -> Result<OsResponse> {
        self.send(
            reqwest::Method::POST,
            path,
            Some(("application/x-ndjson", body)),
            Some(self.bulk_timeout),
        )
        .await
    }

    pub(crate) async fn post_empty(&self, path: &str) -> Result<OsResponse> {
        self.send(reqwest::Method::POST, path, None, None).await
    }

    /// Reachability and credentials: `GET /` must succeed.
    pub(crate) async fn ping(&self) -> Result<()> {
        let response = self.get("/").await?;
        response.ensure_success("GET /")
    }
}

fn path_without_query(path: &str) -> &str {
    path.split('?').next().unwrap_or(path)
}
