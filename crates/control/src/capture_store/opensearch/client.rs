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

use super::{OpenSearchConfig, SearchKind};

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

    /// Which engine and version answers, and whether ProxyX supports it.
    /// Uses only `GET /`, which both engines answer the same way.
    pub(crate) async fn detect(&self, expected: Option<SearchKind>) -> Result<Engine> {
        let response = self.get("/").await?;
        response.ensure_success("GET /")?;
        let engine = Engine::from_info(&response.body)?;
        if let Some(expected) = expected
            && expected != engine.kind
        {
            bail!(
                "capture_store.opensearch.kind is {} but the server at the URL is {} {}",
                expected.as_str(),
                engine.kind.as_str(),
                engine.version
            );
        }
        Ok(engine)
    }

    /// Reachability and credentials: `GET /` must succeed.
    pub(crate) async fn ping(&self) -> Result<()> {
        let response = self.get("/").await?;
        response.ensure_success("GET /")
    }
}

/// The engine behind the URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Engine {
    pub kind: SearchKind,
    /// `2.19.1`, `8.15.3`.
    pub version: String,
}

impl Engine {
    /// Read the body of `GET /`: OpenSearch names itself in
    /// `version.distribution`, Elasticsearch does not. Supported are
    /// OpenSearch 2 and later and Elasticsearch 8 and later.
    pub(crate) fn from_info(info: &Value) -> Result<Self> {
        let version = info["version"]["number"].as_str().context(
            "GET / answered without a version.number: this is not OpenSearch or Elasticsearch",
        )?;
        let major: u32 = version
            .split('.')
            .next()
            .and_then(|major| major.parse().ok())
            .with_context(|| format!("unreadable server version {version:?}"))?;
        let kind = match info["version"]["distribution"].as_str() {
            Some("opensearch") => SearchKind::OpenSearch,
            None if info["tagline"]
                .as_str()
                .is_some_and(|t| t.contains("for Search")) =>
            {
                SearchKind::Elasticsearch
            }
            other => bail!("unrecognized search engine (distribution {other:?})"),
        };
        let supported = match kind {
            SearchKind::OpenSearch => major >= 2,
            SearchKind::Elasticsearch => major >= 8,
        };
        if !supported {
            bail!(
                "{} {version} is not supported: use OpenSearch 2 or later, or Elasticsearch 8 or later",
                kind.as_str()
            );
        }
        Ok(Self {
            kind,
            version: version.to_owned(),
        })
    }
}

fn path_without_query(path: &str) -> &str {
    path.split('?').next().unwrap_or(path)
}

#[cfg(test)]
mod engine_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_engine_and_its_version_are_read_from_the_root_document() {
        let opensearch = json!({"version": {"distribution": "opensearch", "number": "2.19.1"}, "tagline": "The OpenSearch Project: https://opensearch.org/"});
        let elastic = json!({"version": {"number": "8.15.3"}, "tagline": "You Know, for Search"});
        assert_eq!(
            Engine::from_info(&opensearch).unwrap(),
            Engine {
                kind: SearchKind::OpenSearch,
                version: "2.19.1".into()
            }
        );
        assert_eq!(
            Engine::from_info(&elastic).unwrap().kind,
            SearchKind::Elasticsearch
        );
        for bad in [
            json!({"version": {"distribution": "opensearch", "number": "1.3.0"}}),
            json!({"version": {"number": "7.17.0"}, "tagline": "You Know, for Search"}),
            json!({"version": {"number": "8.0.0"}}),
            json!({"hello": "world"}),
            json!({"version": {"distribution": "other", "number": "9.0.0"}}),
        ] {
            assert!(Engine::from_info(&bad).is_err(), "{bad}");
        }
    }
}
