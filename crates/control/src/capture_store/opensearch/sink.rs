//! Write side: captures to `_bulk`.
//!
//! Each capture becomes a `create` of the document with `_id` = the event
//! UUID in the index of its timestamp. A second `create` of the same id
//! answers 409, which counts as written: redelivery (broker or proxy retry)
//! therefore never duplicates a capture. Batching, backpressure, the circuit
//! breaker and the post-flush broker ack are the shared
//! [`BatchHandler`](crate::pipeline::BatchHandler).

use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use common::log::AckHandle;
use common::wire;
use serde_json::{Value, json};
use time::OffsetDateTime;
use uuid::Uuid;

use super::OpenSearchConfig;
use super::client::OsClient;
use super::schema::{self, Kind};
use crate::pipeline::{
    BatchHandler, BatchWriter, CaptureSink, FlushTarget, NormalizedCapturedRequest,
    NormalizedWsMessage, WriteOutcome,
};

/// One capture staged for `_bulk`.
pub(crate) struct BulkDoc {
    index: String,
    id: String,
    /// The JSON document, serialized when the capture is staged.
    source: Vec<u8>,
    completed_at: OffsetDateTime,
    event_id: Uuid,
    parent_event_id: Option<Uuid>,
}

impl BulkDoc {
    /// Bytes this document adds to a `_bulk` body.
    fn wire_len(&self) -> usize {
        self.source.len() + self.index.len() + self.id.len() + 64
    }

    fn append_to(&self, body: &mut Vec<u8>) {
        let action = json!({ "create": { "_index": self.index, "_id": self.id } });
        // Serializing a `Value` cannot fail.
        body.extend_from_slice(action.to_string().as_bytes());
        body.push(b'\n');
        body.extend_from_slice(&self.source);
        body.push(b'\n');
    }
}

pub(crate) struct HttpBulkTarget;

impl FlushTarget for HttpBulkTarget {
    type Doc = BulkDoc;
    const NAME: &'static str = "http_captures";

    fn estimate_bytes(doc: &BulkDoc) -> u64 {
        doc.wire_len() as u64
    }

    fn completed_at(doc: &BulkDoc) -> OffsetDateTime {
        doc.completed_at
    }

    fn record_row_write_error(doc: &BulkDoc, err: &dyn std::fmt::Display) {
        tracing::error!(
            target_table = Self::NAME,
            error = %err,
            event_id = %doc.event_id,
            "failed to index capture",
        );
    }
}

pub(crate) struct WsBulkTarget;

impl FlushTarget for WsBulkTarget {
    type Doc = BulkDoc;
    const NAME: &'static str = "ws_messages";

    fn estimate_bytes(doc: &BulkDoc) -> u64 {
        doc.wire_len() as u64
    }

    fn completed_at(doc: &BulkDoc) -> OffsetDateTime {
        doc.completed_at
    }

    fn record_row_write_error(doc: &BulkDoc, err: &dyn std::fmt::Display) {
        tracing::error!(
            target_table = Self::NAME,
            error = %err,
            event_id = %doc.event_id,
            parent_event_id = ?doc.parent_event_id,
            "failed to index WebSocket message",
        );
    }
}

/// Sends batches as `_bulk` requests.
struct BulkWriter {
    client: OsClient,
    table: &'static str,
    max_bulk_bytes: usize,
    retry: RetryPolicy,
}

/// In-place retry budget of one `_bulk` request.
#[derive(Clone, Copy)]
struct RetryPolicy {
    max_retries: u32,
    initial_backoff: Duration,
    max_backoff: Duration,
}

impl RetryPolicy {
    fn new(config: &OpenSearchConfig) -> Self {
        Self {
            max_retries: config.max_retries,
            initial_backoff: Duration::from_millis(config.retry_initial_backoff_ms),
            max_backoff: Duration::from_millis(config.retry_max_backoff_ms),
        }
    }

    /// Wait before retry number `retry` (1-based): exponential from the
    /// initial backoff, capped, plus up to 25 % jitter.
    fn backoff(&self, retry: u32) -> Duration {
        let exponent = retry.saturating_sub(1).min(20);
        let base = self
            .initial_backoff
            .saturating_mul(1u32 << exponent)
            .min(self.max_backoff);
        base + base.mul_f64(rand::random::<f64>() * 0.25)
    }
}

/// What one `_bulk` item answered.
enum ItemFate {
    Written,
    Retry,
    Poison(String),
}

/// Why a whole `_bulk` request failed.
struct RequestFailure {
    /// A retry may succeed: transport error, timeout, `429` or `5xx`.
    transient: bool,
    error: anyhow::Error,
}

fn item_fate(item: &Value) -> ItemFate {
    // `{"create": {"status": 201, "error": {...}}}`
    let op = item.as_object().and_then(|o| o.values().next());
    let status = op.and_then(|o| o["status"].as_u64()).unwrap_or_default();
    match status {
        200..=299 | 409 => ItemFate::Written,
        429 | 500..=599 => ItemFate::Retry,
        _ => {
            let error = op.map(|o| &o["error"]).unwrap_or(&Value::Null);
            ItemFate::Poison(format!(
                "HTTP {status}: {}: {}",
                error["type"].as_str().unwrap_or("unknown"),
                error["reason"].as_str().unwrap_or("no reason given"),
            ))
        }
    }
}

impl BulkWriter {
    /// One `_bulk` request: the fate of each document, or why the request as
    /// a whole failed.
    async fn send_chunk(&self, chunk: &[&BulkDoc]) -> Result<Vec<ItemFate>, RequestFailure> {
        let mut body = Vec::with_capacity(chunk.iter().map(|d| d.wire_len()).sum());
        for doc in chunk {
            doc.append_to(&mut body);
        }
        // A transport error or timeout never reached an answer.
        let response = self
            .client
            .post_ndjson(
                "/_bulk?filter_path=errors,items.*.status,items.*.error.type,items.*.error.reason",
                body,
            )
            .await
            .map_err(|error| RequestFailure {
                transient: true,
                error,
            })?;

        // A request too large for the server can never succeed alone.
        if response.status == 413 && chunk.len() == 1 {
            return Ok(vec![ItemFate::Poison(response.error_summary())]);
        }
        if let Err(error) = response.ensure_success("_bulk") {
            return Err(RequestFailure {
                transient: response.is_transient(),
                error,
            });
        }

        if response.body["errors"].as_bool() == Some(false) {
            return Ok(chunk.iter().map(|_| ItemFate::Written).collect());
        }
        let items = response.body["items"]
            .as_array()
            .filter(|items| items.len() == chunk.len())
            .ok_or_else(|| RequestFailure {
                transient: false,
                error: anyhow::anyhow!("_bulk answered with an unexpected item list"),
            })?;
        Ok(items.iter().map(item_fate).collect())
    }

    /// Write the documents `indices` of `docs` with the bounded in-place
    /// retry: the whole request again after a transient failure, only the
    /// `429`/`5xx` items after a partial one, each time after an exponential
    /// backoff. Settled documents get their fate in `fates`. Returns the
    /// failure that exhausted the budget (or was not worth retrying); the
    /// documents without a fate are then the caller's to requeue.
    async fn write_chunk(
        &self,
        docs: &[BulkDoc],
        indices: Vec<usize>,
        fates: &mut [Option<ItemFate>],
    ) -> Option<RequestFailure> {
        let mut pending = indices;
        let mut retries = 0;
        loop {
            let chunk: Vec<&BulkDoc> = pending.iter().map(|&i| &docs[i]).collect();
            let failure = match self.send_chunk(&chunk).await {
                Ok(results) => {
                    let mut again = Vec::new();
                    for (&i, fate) in pending.iter().zip(results) {
                        match fate {
                            ItemFate::Retry => again.push(i),
                            settled => fates[i] = Some(settled),
                        }
                    }
                    if again.is_empty() {
                        return None;
                    }
                    pending = again;
                    RequestFailure {
                        transient: true,
                        error: anyhow::anyhow!(
                            "{} documents were answered HTTP 429 or 5xx",
                            pending.len()
                        ),
                    }
                }
                Err(failure) => failure,
            };
            if !failure.transient || retries >= self.retry.max_retries {
                return Some(failure);
            }
            retries += 1;
            common::metrics::INGESTER_STORE_RETRIES_TOTAL
                .with_label_values(&[self.table])
                .inc();
            tracing::warn!(
                target_table = self.table,
                retry = retries,
                max_retries = self.retry.max_retries,
                error = %failure.error,
                "_bulk failed transiently, retrying",
            );
            tokio::time::sleep(self.retry.backoff(retries)).await;
        }
    }
}

#[async_trait]
impl<T> BatchWriter<T> for BulkWriter
where
    T: FlushTarget<Doc = BulkDoc>,
{
    fn flush_span(&self, rows: usize, bytes: u64) -> tracing::Span {
        tracing::info_span!(
            "opensearch.flush",
            db.system = "opensearch",
            db.collection.name = self.table,
            rows = rows,
            bytes = bytes,
            trace_id = tracing::field::Empty,
        )
    }

    async fn write(&self, docs: &[BulkDoc]) -> WriteOutcome {
        let mut fates: Vec<Option<ItemFate>> = (0..docs.len()).map(|_| None).collect();
        let mut error: Option<anyhow::Error> = None;
        let mut start = 0;
        while start < docs.len() {
            let mut end = start;
            let mut bytes = 0;
            while end < docs.len()
                && (end == start || bytes + docs[end].wire_len() <= self.max_bulk_bytes)
            {
                bytes += docs[end].wire_len();
                end += 1;
            }
            if let Some(failure) = self
                .write_chunk(docs, (start..end).collect(), &mut fates)
                .await
            {
                // The cluster is unreachable, refusing or shedding load past
                // the retry budget: leave this and every later document for
                // the flush loop instead of probing with each chunk.
                error = Some(failure.error);
                break;
            }
            start = end;
        }

        let mut outcome = WriteOutcome::default();
        for (i, fate) in fates.into_iter().enumerate() {
            match fate {
                Some(ItemFate::Written) => {}
                Some(ItemFate::Poison(reason)) => outcome.poison.push((i, reason)),
                Some(ItemFate::Retry) | None => outcome.retry.push(i),
            }
        }
        if !outcome.retry.is_empty() {
            outcome.error = Some(error.unwrap_or_else(|| anyhow::anyhow!("documents not written")));
        }
        outcome
    }
}

/// Capture sink writing to OpenSearch.
pub struct OpenSearchSink {
    config: OpenSearchConfig,
    http: BatchHandler<HttpBulkTarget>,
    ws: BatchHandler<WsBulkTarget>,
    correlation_id_header: Option<String>,
    parent_correlation_id_header: Option<String>,
    account_id_header: Option<String>,
    tool_call_id_header: Option<String>,
}

impl OpenSearchSink {
    /// Spawns one batching flusher per document kind. `client` comes from the
    /// same config, already validated.
    fn new(
        config: &OpenSearchConfig,
        client: OsClient,
        correlation_id_header: Option<String>,
        parent_correlation_id_header: Option<String>,
        account_id_header: Option<String>,
        tool_call_id_header: Option<String>,
    ) -> Self {
        let writer = |table: &'static str| BulkWriter {
            client: client.clone(),
            table,
            max_bulk_bytes: config.max_bulk_bytes,
            retry: RetryPolicy::new(config),
        };
        Self {
            http: BatchHandler::new(Box::new(writer(HttpBulkTarget::NAME)), config.batch()),
            ws: BatchHandler::new(Box::new(writer(WsBulkTarget::NAME)), config.batch()),
            config: config.clone(),
            correlation_id_header,
            parent_correlation_id_header,
            account_id_header,
            tool_call_id_header,
        }
    }

    /// Connect with `config` and build the sink; for callers outside the
    /// ingester that have no template check to run.
    pub fn connect(
        config: &OpenSearchConfig,
        correlation_id_header: Option<String>,
        parent_correlation_id_header: Option<String>,
        account_id_header: Option<String>,
        tool_call_id_header: Option<String>,
    ) -> Result<Self> {
        Ok(Self::new(
            config,
            OsClient::new(config)?,
            correlation_id_header,
            parent_correlation_id_header,
            account_id_header,
            tool_call_id_header,
        ))
    }
}

#[async_trait]
impl CaptureSink for OpenSearchSink {
    async fn send_http(
        &self,
        captured: &wire::CapturedRequest,
        session_offset: u64,
        ack: Option<AckHandle>,
    ) -> Result<()> {
        let n = NormalizedCapturedRequest::from_captured(
            captured,
            session_offset,
            self.correlation_id_header.as_deref(),
            self.parent_correlation_id_header.as_deref(),
            self.account_id_header.as_deref(),
            self.tool_call_id_header.as_deref(),
        );
        let duration = time::Duration::milliseconds(n.duration_ms.min(i64::MAX as u64) as i64);
        let doc = BulkDoc {
            index: schema::index_name(&self.config, Kind::Http, n.timestamp),
            id: n.event_id.to_string(),
            source: serde_json::to_vec(&schema::http_document(&n))?,
            completed_at: n.timestamp.checked_add(duration).unwrap_or(n.timestamp),
            event_id: n.event_id,
            parent_event_id: None,
        };
        self.http.send_doc(doc, ack).await
    }

    async fn send_ws(
        &self,
        message: &wire::CapturedWsMessage,
        session_offset: u64,
        ack: Option<AckHandle>,
    ) -> Result<()> {
        let n = NormalizedWsMessage::from_wire(message, session_offset);
        let doc = BulkDoc {
            index: schema::index_name(&self.config, Kind::Ws, n.timestamp),
            id: n.event_id.to_string(),
            source: serde_json::to_vec(&schema::ws_document(&n))?,
            completed_at: n.timestamp,
            event_id: n.event_id,
            parent_event_id: Some(n.parent_event_id),
        };
        self.ws.send_doc(doc, ack).await
    }

    async fn flush_and_close(&self, timeout: Duration) {
        self.http.flush_and_close(timeout).await;
        self.ws.flush_and_close(timeout).await;
    }

    fn circuit_open(&self) -> bool {
        self.http.circuit_open() || self.ws.circuit_open()
    }
}
