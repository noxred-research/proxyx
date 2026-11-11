//! OpenSearch / Elasticsearch capture store.
//!
//! Works against OpenSearch 2.x and Elasticsearch 8 through their shared REST
//! API: `_bulk`, composable index templates, `_search` with `search_after`,
//! `_count` and aggregations.
//!
//! - **Writes** ([`OpenSearchSink`]): `_bulk` `create` operations whose `_id`
//!   is the capture's event UUID, so a redelivered or republished capture
//!   hits a version conflict that counts as success. Unlike ClickHouse, a
//!   duplicate is never stored twice.
//! - **Reads** ([`OpenSearchStore`]): the query DSL lowers in [`lower`];
//!   what cannot be lowered exactly is rejected with a 400.
//! - **Schema** ([`schema`]): `proxyx migrate control --target opensearch`
//!   installs the index templates.

pub(crate) mod client;
mod lower;
mod read;
mod regex;
pub(crate) mod schema;
mod sink;

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

pub use sink::OpenSearchSink;

use client::OsClient;

/// How often a new index starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Rollover {
    /// One index per UTC day: `<prefix>-http-2026.11.10`.
    #[default]
    Daily,
    /// One index per ISO week: `<prefix>-http-2026.w46`.
    Weekly,
}

fn default_index_prefix() -> String {
    "proxyx".to_string()
}
fn default_shards() -> u32 {
    1
}
fn default_replicas() -> u32 {
    1
}
fn default_refresh_interval() -> String {
    "5s".to_string()
}
fn default_request_timeout_secs() -> u64 {
    30
}
fn default_bulk_timeout_secs() -> u64 {
    120
}
fn default_connect_timeout_secs() -> u64 {
    10
}
fn default_pool_idle_timeout_secs() -> u64 {
    90
}
fn default_pool_max_idle_per_host() -> usize {
    32
}
fn default_tcp_keepalive_secs() -> u64 {
    60
}
fn default_max_retries() -> u32 {
    3
}
fn default_retry_initial_backoff_ms() -> u64 {
    200
}
fn default_retry_max_backoff_ms() -> u64 {
    5_000
}
fn default_max_bulk_bytes() -> usize {
    10 * 1024 * 1024
}
fn default_bulk_size() -> usize {
    500
}
fn default_flush_interval() -> u64 {
    5
}
fn default_max_buffer_bytes() -> u64 {
    256 * 1024 * 1024
}
fn default_circuit_threshold() -> u32 {
    5
}
fn default_circuit_reset() -> u64 {
    60
}

/// `[capture_store.opensearch]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenSearchConfig {
    /// Base URL of the cluster or a coordinating node, e.g.
    /// `https://opensearch:9200`.
    pub url: String,
    /// Basic authentication.
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    /// Elasticsearch API key (the base64 `encoded` value), sent as
    /// `Authorization: ApiKey ...`. Exclusive with `username`.
    #[serde(default)]
    pub api_key: Option<String>,
    /// PEM file with the CA that signed the server certificate, in addition
    /// to the public roots.
    #[serde(default)]
    pub ca_cert: Option<PathBuf>,
    /// Prefix of index and template names; lowercase letters, digits, `.`,
    /// `_` and `-`.
    #[serde(default = "default_index_prefix")]
    pub index_prefix: String,
    #[serde(default)]
    pub rollover: Rollover,
    /// Template setting `index.number_of_shards`.
    #[serde(default = "default_shards")]
    pub number_of_shards: u32,
    /// Template setting `index.number_of_replicas`.
    #[serde(default = "default_replicas")]
    pub number_of_replicas: u32,
    /// Template setting `index.refresh_interval`: how long a write takes to
    /// become searchable.
    #[serde(default = "default_refresh_interval")]
    pub refresh_interval: String,
    /// Extra template settings by full name, e.g. `index.lifecycle.name`
    /// (Elasticsearch ILM) or `index.plugins.index_state_management.policy_id`
    /// (OpenSearch ISM). Applied by `migrate`; existing indices keep theirs.
    #[serde(default)]
    pub index_settings: BTreeMap<String, serde_json::Value>,
    /// Timeout of search, count and admin requests.
    #[serde(default = "default_request_timeout_secs")]
    pub request_timeout_secs: u64,
    /// Timeout of one `_bulk` request.
    #[serde(default = "default_bulk_timeout_secs")]
    pub bulk_timeout_secs: u64,
    /// Timeout of establishing a connection (TCP and TLS).
    #[serde(default = "default_connect_timeout_secs")]
    pub connect_timeout_secs: u64,
    /// An idle pooled connection is closed after this long; `0` keeps idle
    /// connections until the server closes them. Keep it below the idle
    /// timeout of a load balancer in front of the cluster.
    #[serde(default = "default_pool_idle_timeout_secs")]
    pub pool_idle_timeout_secs: u64,
    /// Idle connections kept per host.
    #[serde(default = "default_pool_max_idle_per_host")]
    pub pool_max_idle_per_host: usize,
    /// TCP keepalive probe interval; `0` disables keepalive probes.
    #[serde(default = "default_tcp_keepalive_secs")]
    pub tcp_keepalive_secs: u64,
    /// In-place retries of a `_bulk` request after a transient failure
    /// (transport error, timeout, `429`, `5xx`), on top of the first attempt;
    /// `0` hands every failure straight to the flush loop and its circuit
    /// breaker.
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
    /// Backoff before the first retry; it doubles per retry (with jitter) up
    /// to `retry_max_backoff_ms`.
    #[serde(default = "default_retry_initial_backoff_ms")]
    pub retry_initial_backoff_ms: u64,
    #[serde(default = "default_retry_max_backoff_ms")]
    pub retry_max_backoff_ms: u64,
    /// A flush is cut into `_bulk` requests of at most this many bytes (a
    /// single larger document is sent alone).
    #[serde(default = "default_max_bulk_bytes")]
    pub max_bulk_bytes: usize,
    /// Flush when the buffer holds this many documents; the intake channel
    /// holds twice as many.
    #[serde(default = "default_bulk_size")]
    pub bulk_size: usize,
    #[serde(default = "default_flush_interval")]
    pub flush_interval_secs: u64,
    /// Soft cap on buffered payload bytes; see the ClickHouse setting of the
    /// same name.
    #[serde(default = "default_max_buffer_bytes")]
    pub max_buffer_bytes: u64,
    #[serde(default = "default_circuit_threshold")]
    pub circuit_breaker_threshold: u32,
    #[serde(default = "default_circuit_reset")]
    pub circuit_breaker_reset_secs: u64,
}

impl OpenSearchConfig {
    /// A configuration for `url` with every other setting at its default.
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            username: None,
            password: None,
            api_key: None,
            ca_cert: None,
            index_prefix: default_index_prefix(),
            rollover: Rollover::default(),
            number_of_shards: default_shards(),
            number_of_replicas: default_replicas(),
            refresh_interval: default_refresh_interval(),
            index_settings: BTreeMap::new(),
            request_timeout_secs: default_request_timeout_secs(),
            bulk_timeout_secs: default_bulk_timeout_secs(),
            connect_timeout_secs: default_connect_timeout_secs(),
            pool_idle_timeout_secs: default_pool_idle_timeout_secs(),
            pool_max_idle_per_host: default_pool_max_idle_per_host(),
            tcp_keepalive_secs: default_tcp_keepalive_secs(),
            max_retries: default_max_retries(),
            retry_initial_backoff_ms: default_retry_initial_backoff_ms(),
            retry_max_backoff_ms: default_retry_max_backoff_ms(),
            max_bulk_bytes: default_max_bulk_bytes(),
            bulk_size: default_bulk_size(),
            flush_interval_secs: default_flush_interval(),
            max_buffer_bytes: default_max_buffer_bytes(),
            circuit_breaker_threshold: default_circuit_threshold(),
            circuit_breaker_reset_secs: default_circuit_reset(),
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if !(self.url.starts_with("http://") || self.url.starts_with("https://")) {
            bail!("capture_store.opensearch.url must start with http:// or https://");
        }
        let prefix = &self.index_prefix;
        let valid = !prefix.is_empty()
            && !prefix.starts_with(['-', '_', '+', '.'])
            && prefix.chars().all(|c| {
                c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-')
            });
        if !valid {
            bail!(
                "capture_store.opensearch.index_prefix {prefix:?} must be lowercase letters, \
                 digits, '.', '_' or '-', and not start with '-', '_', '+' or '.'"
            );
        }
        if self.api_key.is_some() && self.username.is_some() {
            bail!("capture_store.opensearch: set either api_key or username, not both");
        }
        if self.request_timeout_secs == 0
            || self.bulk_timeout_secs == 0
            || self.connect_timeout_secs == 0
        {
            bail!(
                "capture_store.opensearch: request_timeout_secs, bulk_timeout_secs and \
                 connect_timeout_secs must be positive"
            );
        }
        if self.retry_initial_backoff_ms > self.retry_max_backoff_ms {
            bail!(
                "capture_store.opensearch: retry_initial_backoff_ms must not exceed \
                 retry_max_backoff_ms"
            );
        }
        if self.bulk_size == 0 || self.max_bulk_bytes == 0 {
            bail!("capture_store.opensearch: bulk_size and max_bulk_bytes must be positive");
        }
        Ok(())
    }

    pub(crate) fn batch(&self) -> crate::pipeline::BatchConfig {
        crate::pipeline::BatchConfig {
            bulk_size: self.bulk_size,
            flush_interval_secs: self.flush_interval_secs,
            max_buffer_bytes: self.max_buffer_bytes,
            circuit_breaker_threshold: self.circuit_breaker_threshold,
            circuit_breaker_reset_secs: self.circuit_breaker_reset_secs,
        }
    }
}

/// Create or replace the index templates (`proxyx migrate control`).
/// Existing indices keep the mapping they were created with.
pub async fn install_templates(config: &OpenSearchConfig) -> Result<()> {
    schema::install_templates(&OsClient::new(config)?, config).await
}

/// Fail unless the index templates are installed at this build's schema
/// version (`proxyx migrate control --check`, ingester start).
pub async fn verify_templates(config: &OpenSearchConfig) -> Result<()> {
    schema::verify_templates(&OsClient::new(config)?, config).await
}

/// Read side of the OpenSearch capture store.
pub struct OpenSearchStore {
    client: OsClient,
    config: OpenSearchConfig,
}

impl OpenSearchStore {
    pub fn new(config: &OpenSearchConfig) -> Result<Self> {
        Ok(Self {
            client: OsClient::new(config)?,
            config: config.clone(),
        })
    }

    /// Make every write so far searchable. Writes become visible on their
    /// own every `refresh_interval`; tests and tools that read back
    /// immediately call this.
    pub async fn refresh(&self) -> Result<()> {
        let patterns = format!(
            "{},{}",
            schema::read_pattern(&self.config, schema::Kind::Http),
            schema::read_pattern(&self.config, schema::Kind::Ws)
        );
        self.client
            .post_empty(&format!(
                "/{patterns}/_refresh?ignore_unavailable=true&allow_no_indices=true"
            ))
            .await?
            .ensure_success("refreshing the capture indices")
    }
}
