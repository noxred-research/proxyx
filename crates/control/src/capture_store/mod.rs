//! Capture store abstraction: where captured HTTP exchanges and WebSocket
//! messages are written to and queried from.
//!
//! Two backends implement it:
//!
//! - **ClickHouse** (default): the historical store. The query DSL lowers to
//!   SQL in [`crate::query`]; this module only adapts those functions.
//! - **OpenSearch** (also Elasticsearch 8): [`opensearch`]. The same DSL
//!   lowers to the search query DSL; writes are idempotent `_bulk` creates
//!   keyed by the capture's event id.
//!
//! The write side is a [`CaptureSink`](crate::pipeline::CaptureSink) built by
//! [`build_sink`]; the read side is a [`CaptureStore`] built by
//! [`build_store`]. REST (`/rpc`), GraphQL and the traffic view exports go
//! through the trait, never to a backend client directly.

pub(crate) mod clickhouse;
pub mod opensearch;

use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use proxyx_control_graphql::{
    RequestRatePointDto, ScanTrafficSummaryDto, TrafficTimeSeriesPointDto,
    WsConversationSearchResponse,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::config::ControlConfig;
use crate::models::{HttpCapture, SearchResponse, WsCapture, WsSearchResponse};
use crate::pipeline::CaptureSink;
use crate::query::TrafficQuery;
use crate::query::ws::WsTrafficQuery;
use crate::views::ViewExporter;

pub use clickhouse::ClickHouseStore;
pub use opensearch::{OpenSearchConfig, OpenSearchStore, Rollover, SearchKind};

/// Which backend stores captures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum CaptureBackend {
    /// ClickHouse, configured by the `[clickhouse]` section (default).
    #[default]
    #[serde(rename = "clickhouse")]
    ClickHouse,
    /// OpenSearch or Elasticsearch 8, configured by
    /// `[capture_store.opensearch]`.
    #[serde(rename = "opensearch")]
    OpenSearch,
}

impl CaptureBackend {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClickHouse => "clickhouse",
            Self::OpenSearch => "opensearch",
        }
    }
}

/// `[capture_store]`: backend selection and the settings of the non-default
/// backends. ClickHouse keeps its own top-level `[clickhouse]` section.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CaptureStoreConfig {
    /// `clickhouse` (default) or `opensearch`.
    /// Env: `PROXYX_CONTROL_CAPTURE_STORE__BACKEND`.
    #[serde(default)]
    pub backend: CaptureBackend,
    /// Required when `backend = "opensearch"`.
    #[serde(default)]
    pub opensearch: Option<OpenSearchConfig>,
}

/// A query the active backend cannot answer, or an operation it does not
/// offer. Carried inside `anyhow::Error`; the REST layer maps it to a status.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The query cannot be lowered exactly to the backend. HTTP 400.
    #[error("{0}")]
    Rejected(String),
    /// The backend does not offer the operation. HTTP 501.
    #[error("{0}")]
    Unsupported(String),
}

/// Latest-row watermark of a `(org, source)` slice.
#[derive(Debug, Clone)]
pub struct Sequence {
    /// Cursor of the newest capture; `None` while the slice is empty.
    pub cursor: Option<String>,
    /// Number of distinct captures.
    pub count: u64,
}

/// Filters of the WebSocket conversation discovery query.
#[derive(Debug, Clone)]
pub struct ConversationQuery<'a> {
    pub org_id: &'a str,
    pub source_ids: Option<&'a [String]>,
    pub source: Option<&'a str>,
    pub host: Option<&'a str>,
    pub limit: u32,
    pub descending: bool,
}

/// Window and filters of the request count aggregations. `end` is exclusive.
#[derive(Debug, Clone)]
pub struct TimeSeriesQuery<'a> {
    /// `None` aggregates across orgs.
    pub org_id: Option<&'a str>,
    pub source_ids: Option<&'a [String]>,
    pub start: OffsetDateTime,
    pub end: OffsetDateTime,
    pub bucket_seconds: u32,
}

/// Read side of a capture store. Every method scopes by org like the SQL it
/// replaces; callers resolve the principal's org first.
#[async_trait]
pub trait CaptureStore: Send + Sync + 'static {
    fn backend(&self) -> CaptureBackend;

    /// Cheap reachability and credentials check, for `GET /health/store`.
    /// The caller bounds it with a timeout.
    async fn ping(&self) -> Result<()>;

    /// Reject an HTTP query the backend cannot answer exactly (a
    /// [`StoreError::Rejected`], mapped to 400). Called before any search.
    fn check_http_query(&self, _query: &TrafficQuery) -> Result<(), StoreError> {
        Ok(())
    }

    /// WebSocket counterpart of [`Self::check_http_query`].
    fn check_ws_query(&self, _query: &WsTrafficQuery) -> Result<(), StoreError> {
        Ok(())
    }

    async fn search_requests(&self, query: &TrafficQuery) -> Result<SearchResponse>;
    async fn count_requests(&self, query: &TrafficQuery) -> Result<u64>;
    async fn get_request(&self, org_id: &str, id: Uuid) -> Result<Option<HttpCapture>>;

    async fn search_ws(&self, query: &WsTrafficQuery) -> Result<WsSearchResponse>;
    async fn count_ws(&self, query: &WsTrafficQuery) -> Result<u64>;
    async fn get_ws_message(&self, org_id: &str, id: Uuid) -> Result<Option<WsCapture>>;

    /// One row per WebSocket conversation, ordered by last activity.
    async fn ws_conversations(
        &self,
        query: &ConversationQuery<'_>,
    ) -> Result<WsConversationSearchResponse>;

    /// Requests per minute of an org over `[start, end)`; only minutes with
    /// traffic.
    async fn request_rate_series(
        &self,
        org_id: &str,
        start: OffsetDateTime,
        end: OffsetDateTime,
    ) -> Result<Vec<RequestRatePointDto>>;

    /// Request counts per `(bucket, source_id)`.
    async fn http_traffic_time_series(
        &self,
        query: &TimeSeriesQuery<'_>,
    ) -> Result<Vec<TrafficTimeSeriesPointDto>>;

    /// Request counts of the given sources, per bucket and per source.
    /// `query.source_ids` is required and non-empty.
    async fn scan_traffic_summary(
        &self,
        query: &TimeSeriesQuery<'_>,
    ) -> Result<ScanTrafficSummaryDto>;

    /// Newest capture and capture count of one `(org, source_id)` slice.
    async fn sequence(&self, org_id: &str, source_id: &str) -> Result<Sequence>;

    /// Parquet export engine, for backends that can write to object storage.
    fn view_exporter(&self) -> Option<&dyn ViewExporter>;
}

impl dyn CaptureStore {
    /// The exporter, or a 501 naming the backend.
    pub fn require_view_exporter(&self) -> Result<&dyn ViewExporter, StoreError> {
        self.view_exporter().ok_or_else(|| {
            StoreError::Unsupported(format!(
                "traffic view exports are not supported by the {} capture store",
                self.backend().as_str()
            ))
        })
    }
}

/// Build the read side for `config.capture_store.backend`.
pub async fn build_store(config: &ControlConfig) -> Result<Arc<dyn CaptureStore>> {
    match config.capture_store.backend {
        CaptureBackend::ClickHouse => {
            let ch = config.clickhouse_config()?;
            tracing::info!(clickhouse_url = %ch.url, "ClickHouse capture store ready");
            Ok(Arc::new(ClickHouseStore::new(
                crate::runtime::clickhouse_client(ch),
            )))
        }
        CaptureBackend::OpenSearch => {
            let os = config.opensearch_config()?;
            let store = OpenSearchStore::new(os)?;
            tracing::info!(url = %os.url, "OpenSearch capture store ready");
            Ok(Arc::new(store))
        }
    }
}

/// Build the write side for `config.capture_store.backend`. The OpenSearch
/// sink checks that the index templates are installed.
pub async fn build_sink(config: &ControlConfig) -> Result<Arc<dyn CaptureSink>> {
    match config.capture_store.backend {
        CaptureBackend::ClickHouse => Ok(Arc::new(crate::pipeline::ClickHouseSink::new(
            config.clickhouse_config()?.clone(),
            config.correlation_id_header.clone(),
            config.parent_correlation_id_header.clone(),
            config.account_id_header.clone(),
            config.tool_call_id_header.clone(),
        )?)),
        CaptureBackend::OpenSearch => {
            let os = config.opensearch_config()?;
            opensearch::verify_templates(os)
                .await
                .context("OpenSearch index templates (run `proxyx migrate control` first)")?;
            Ok(Arc::new(opensearch::OpenSearchSink::connect(
                os,
                config.correlation_id_header.clone(),
                config.parent_correlation_id_header.clone(),
                config.account_id_header.clone(),
                config.tool_call_id_header.clone(),
            )?))
        }
    }
}

/// Create the OpenSearch index templates; `check` only verifies them.
pub async fn migrate_opensearch(config: &ControlConfig, check: bool) -> Result<()> {
    let os = config.opensearch_config()?;
    if check {
        opensearch::verify_templates(os).await
    } else {
        opensearch::install_templates(os).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn clickhouse_is_the_default_backend() {
        let config: CaptureStoreConfig = serde_json::from_value(json!({})).unwrap();
        assert_eq!(config.backend, CaptureBackend::ClickHouse);
        assert!(config.opensearch.is_none());
        assert_eq!(config.backend.as_str(), "clickhouse");
    }

    #[test]
    fn opensearch_backend_parses_with_defaults() {
        let config: CaptureStoreConfig = serde_json::from_value(json!({
            "backend": "opensearch",
            "opensearch": {
                "url": "https://os:9200",
                "rollover": "weekly",
                "index_settings": { "index.lifecycle.name": "keep-90d" },
            },
        }))
        .unwrap();
        assert_eq!(config.backend, CaptureBackend::OpenSearch);
        let os = config.opensearch.unwrap();
        assert_eq!(os.rollover, Rollover::Weekly);
        assert_eq!(os.index_prefix, "proxyx");
        assert_eq!(os.number_of_replicas, 1);
        assert_eq!(os.index_settings["index.lifecycle.name"], "keep-90d");
        os.validate().unwrap();
    }

    #[test]
    fn unknown_backend_is_refused() {
        assert!(
            serde_json::from_value::<CaptureStoreConfig>(json!({ "backend": "sqlite" })).is_err()
        );
    }

    #[test]
    fn opensearch_settings_are_validated() {
        let ok = OpenSearchConfig::new("http://localhost:9200");
        assert!(ok.validate().is_ok());

        let mut bad_url = ok.clone();
        bad_url.url = "localhost:9200".into();
        assert!(bad_url.validate().is_err());

        for prefix in ["", "Proxyx", "-proxyx", "pro xyx", "pro/xyx", "_x"] {
            let mut config = ok.clone();
            config.index_prefix = prefix.into();
            assert!(config.validate().is_err(), "{prefix:?} must be refused");
        }

        let mut both = ok.clone();
        both.username = Some("u".into());
        both.api_key = Some("k".into());
        assert!(both.validate().is_err());

        let mut empty_bulk = ok;
        empty_bulk.bulk_size = 0;
        assert!(empty_bulk.validate().is_err());
    }
}
