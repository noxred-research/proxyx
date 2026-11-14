//! ClickHouse handler for storing captured HTTP request events.
//!
//! Thin wrapper over [`super::batch_handler::BatchHandler`]; only the
//! domain shape (doc type, row construction, byte estimate) lives here.
//! See `batch_handler.rs` for the buffering, byte-cap, and circuit-breaker
//! behavior.

use std::time::Duration;

use anyhow::Result;

use common::wire;

use super::batch_handler::{BatchConfig, BatchHandler, FlushTarget};
use super::ch_writer::{ChTarget, ClickHouseWriter};
use super::normalize::NormalizedCapturedRequest;

/// Rows per ClickHouse insert. ClickHouse 26.3 has `async_insert` and
/// `wait_for_async_insert` on by default, so each flusher has one insert in
/// flight and a server flush merges at most one insert per flusher: bigger
/// batches are what make parts bigger and fewer. At 100, the L10 load test
/// made ~4 parts/s in `http_captures` and each of its 4 MVs.
fn default_bulk_size() -> usize {
    500
}

fn default_flush_interval() -> u64 {
    5
}

fn default_max_buffer_bytes() -> u64 {
    256 * 1024 * 1024 // 256 MiB
}

fn default_circuit_threshold() -> u32 {
    5
}

fn default_circuit_reset() -> u64 {
    60
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ClickHouseConfig {
    pub url: String,
    #[serde(default)]
    pub database: Option<String>,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub table: Option<String>,
    #[serde(default = "default_bulk_size")]
    pub bulk_size: usize,
    #[serde(default = "default_flush_interval")]
    pub flush_interval_secs: u64,
    /// Soft cap on accumulated payload bytes before the flusher refuses new
    /// inserts. Backpressure propagates to the channel sender; older docs
    /// are never dropped.
    #[serde(default = "default_max_buffer_bytes")]
    pub max_buffer_bytes: u64,
    #[serde(default = "default_circuit_threshold")]
    pub circuit_breaker_threshold: u32,
    #[serde(default = "default_circuit_reset")]
    pub circuit_breaker_reset_secs: u64,
}

impl common::config::PartialSection for ClickHouseConfig {
    const STANDALONE: &'static [&'static str] = &["user", "password", "local_single_node"];
}

impl ClickHouseConfig {
    pub(crate) fn batch(&self) -> BatchConfig {
        BatchConfig {
            bulk_size: self.bulk_size,
            flush_interval_secs: self.flush_interval_secs,
            max_buffer_bytes: self.max_buffer_bytes,
            circuit_breaker_threshold: self.circuit_breaker_threshold,
            circuit_breaker_reset_secs: self.circuit_breaker_reset_secs,
        }
    }
}

#[derive(clickhouse::Row, serde::Serialize)]
pub(crate) struct ClickHouseRow {
    /// Idempotency key — UUIDv7 minted at the proxy.
    #[serde(with = "clickhouse::serde::uuid")]
    id: uuid::Uuid,
    org_id: String,
    #[serde(with = "clickhouse::serde::time::datetime64::millis")]
    timestamp: time::OffsetDateTime,
    session_offset: u64,
    method: String,
    path: String,
    host: String,
    scheme: String,
    session_id: String,
    proxy_id: String,
    request_headers: Vec<(String, String)>,
    request_body: String,
    request_size: u32,
    status_code: u16,
    response_headers: Vec<(String, String)>,
    response_body: String,
    response_size: u32,
    duration_ms: u32,
    ratelimit_wait_ms: u32,
    source: String,
    source_id: String,
    correlation_id: Option<String>,
    parent_correlation_id: Option<String>,
    account_id: Option<String>,
    tool_call_id: Option<String>,
    /// Engine version key for `ReplicatedReplacingMergeTree`. Wall-clock
    /// nanoseconds at insert time. When proxy retries replay the same
    /// logical capture and collide on the sort-key tuple, the latest
    /// write wins at merge time.
    #[serde(with = "clickhouse::serde::time::datetime64::nanos")]
    inserted_at: time::OffsetDateTime,
}

/// Document prepared for ClickHouse insertion from a captured request.
pub(crate) struct HttpRequestDocument {
    event_id: uuid::Uuid,
    org_id: String,
    timestamp: time::OffsetDateTime,
    session_offset: u64,

    method: String,
    path: String,
    host: String,
    scheme: String,
    request_headers: Vec<(String, String)>,
    request_body: String,
    request_size: u64,
    status_code: u32,
    response_headers: Vec<(String, String)>,
    response_body: String,
    response_size: u64,
    duration_ms: u64,
    ratelimit_wait_ms: u64,
    source: String,
    source_id: String,
    correlation_id: Option<String>,
    parent_correlation_id: Option<String>,
    account_id: Option<String>,
    tool_call_id: Option<String>,
    session_id: uuid::Uuid,
    proxy_id: String,
}

impl HttpRequestDocument {
    fn from_captured(
        req: &wire::CapturedRequest,
        session_offset: u64,
        correlation_id_header: Option<&str>,
        parent_correlation_id_header: Option<&str>,
        account_id_header: Option<&str>,
        tool_call_id_header: Option<&str>,
    ) -> Self {
        let normalized = NormalizedCapturedRequest::from_captured(
            req,
            session_offset,
            correlation_id_header,
            parent_correlation_id_header,
            account_id_header,
            tool_call_id_header,
        );
        Self {
            event_id: normalized.event_id,
            org_id: normalized.org_id,
            timestamp: normalized.timestamp,
            session_offset: normalized.session_offset,

            method: normalized.method,
            path: normalized.path,
            host: normalized.host,
            scheme: normalized.scheme,
            request_headers: normalized.request_headers,
            request_body: normalized.request_body,
            request_size: normalized.request_size,
            status_code: normalized.status_code,
            response_headers: normalized.response_headers,
            response_body: normalized.response_body,
            response_size: normalized.response_size,
            duration_ms: normalized.duration_ms,
            ratelimit_wait_ms: normalized.ratelimit_wait_ms,
            source: normalized.source,
            correlation_id: normalized.correlation_id,
            parent_correlation_id: normalized.parent_correlation_id,
            account_id: normalized.account_id,
            tool_call_id: normalized.tool_call_id,
            source_id: normalized.source_id,
            session_id: normalized.session_id,
            proxy_id: normalized.proxy_id,
        }
    }
}

/// `FlushTarget` binding for HTTP captures. Pairs `HttpRequestDocument`
/// (the buffered doc) with `ClickHouseRow` (the CH wire row, see
/// [`ChTarget`]) and declares the `http_captures` table identifier used in
/// logs.
pub(crate) struct HttpTarget;

impl FlushTarget for HttpTarget {
    type Doc = HttpRequestDocument;
    const NAME: &'static str = "http_captures";

    fn estimate_bytes(doc: &Self::Doc) -> u64 {
        let req = doc.request_body.len() as u64;
        let resp = doc.response_body.len() as u64;
        let headers: u64 = doc
            .request_headers
            .iter()
            .chain(doc.response_headers.iter())
            .map(|(k, v)| (k.len() + v.len()) as u64)
            .sum();
        // 512B fudge for path/host/method/etc.
        req + resp + headers + 512
    }

    fn completed_at(doc: &Self::Doc) -> time::OffsetDateTime {
        let duration = time::Duration::milliseconds(doc.duration_ms.min(i64::MAX as u64) as i64);
        doc.timestamp.checked_add(duration).unwrap_or(doc.timestamp)
    }
}

impl ChTarget for HttpTarget {
    type Row = ClickHouseRow;

    fn to_row(doc: &Self::Doc) -> Self::Row {
        ClickHouseRow {
            id: doc.event_id,
            org_id: doc.org_id.clone(),
            timestamp: doc.timestamp,
            session_offset: doc.session_offset,
            method: doc.method.clone(),
            path: doc.path.clone(),
            host: doc.host.clone(),
            scheme: doc.scheme.clone(),
            session_id: doc.session_id.to_string(),
            proxy_id: doc.proxy_id.clone(),
            request_headers: doc.request_headers.clone(),
            request_body: doc.request_body.clone(),
            request_size: doc.request_size.min(u32::MAX as u64) as u32,
            status_code: doc.status_code.min(u16::MAX as u32) as u16,
            response_headers: doc.response_headers.clone(),
            response_body: doc.response_body.clone(),
            response_size: doc.response_size.min(u32::MAX as u64) as u32,
            duration_ms: doc.duration_ms.min(u32::MAX as u64) as u32,
            ratelimit_wait_ms: doc.ratelimit_wait_ms.min(u32::MAX as u64) as u32,
            source: doc.source.clone(),
            source_id: doc.source_id.clone(),
            correlation_id: doc.correlation_id.clone(),
            parent_correlation_id: doc.parent_correlation_id.clone(),
            account_id: doc.account_id.clone(),
            tool_call_id: doc.tool_call_id.clone(),
            inserted_at: time::OffsetDateTime::now_utc(),
        }
    }
}

/// ClickHouse handler that batches and flushes captured HTTP requests.
pub struct ClickHouseHandler {
    inner: BatchHandler<HttpTarget>,
    correlation_id_header: Option<String>,
    parent_correlation_id_header: Option<String>,
    account_id_header: Option<String>,
    tool_call_id_header: Option<String>,
}

impl ClickHouseHandler {
    /// Create a new ClickHouse handler. Spawns a background flusher task.
    pub fn new(
        config: ClickHouseConfig,
        correlation_id_header: Option<String>,
        parent_correlation_id_header: Option<String>,
        account_id_header: Option<String>,
        tool_call_id_header: Option<String>,
    ) -> Result<Self> {
        let mut client = clickhouse::Client::default().with_url(&config.url);
        if let Some(ref db) = config.database {
            client = client.with_database(db);
        }
        if let Some(ref user) = config.user {
            client = client.with_user(user);
        }
        if let Some(ref password) = config.password {
            client = client.with_password(password);
        }

        tracing::info!(
            url = %config.url,
            "ClickHouse client created",
        );

        let table = config
            .table
            .clone()
            .unwrap_or_else(|| "http_captures".to_string());

        let inner = BatchHandler::<HttpTarget>::new(
            Box::new(ClickHouseWriter::<HttpTarget>::new(client, table)),
            config.batch(),
        );

        Ok(Self {
            inner,
            correlation_id_header,
            parent_correlation_id_header,
            account_id_header,
            tool_call_id_header,
        })
    }

    /// Send a captured request to the handler. Applies backpressure via channel.
    /// `ack` is acknowledged once the doc's batch is flushed to ClickHouse.
    pub async fn send(
        &self,
        captured: &wire::CapturedRequest,
        session_offset: u64,
        ack: Option<common::log::AckHandle>,
    ) -> Result<()> {
        let doc = HttpRequestDocument::from_captured(
            captured,
            session_offset,
            self.correlation_id_header.as_deref(),
            self.parent_correlation_id_header.as_deref(),
            self.account_id_header.as_deref(),
            self.tool_call_id_header.as_deref(),
        );
        self.inner.send_doc(doc, ack).await
    }

    /// Close the channel and wait for the flusher to drain, up to `timeout`.
    /// Idempotent.
    pub async fn flush_and_close(&self, timeout: Duration) {
        self.inner.flush_and_close(timeout).await
    }

    /// Whether this handler's circuit breaker is open.
    pub fn circuit_open(&self) -> bool {
        self.inner.circuit_open()
    }
}
