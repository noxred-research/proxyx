//! Request log writer — pushes captured HTTP exchanges to the captures log.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use prost::Message;
use tokio::sync::mpsc;
use uuid::Uuid;

use common::log::CaptureLogProducer;
use common::wire::{self, request_log_message};

/// Max publish attempts before a capture is counted as dropped.
const MAX_PUBLISH_ATTEMPTS: u32 = 5;

/// Configuration for the request log writer.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RequestLogConfig {
    /// Redis stream name (default: `proxyx:request_log`).
    #[serde(default = "default_stream_name")]
    pub stream_name: String,
    /// Channel capacity for backpressure (default: 256). Also the largest
    /// number of captures the drain hands to the producer in one batch.
    #[serde(default = "default_channel_capacity")]
    pub channel_capacity: usize,
    /// Approximate cap on the Redis stream length (`XADD ... MAXLEN ~ N`).
    /// 0 disables trimming. Default: 1_000_000.
    #[serde(default = "default_max_stream_len")]
    pub max_stream_len: u64,
}

fn default_stream_name() -> String {
    "proxyx:request_log".to_string()
}
fn default_channel_capacity() -> usize {
    256
}
fn default_max_stream_len() -> u64 {
    1_000_000
}

impl Default for RequestLogConfig {
    fn default() -> Self {
        Self {
            stream_name: default_stream_name(),
            channel_capacity: default_channel_capacity(),
            max_stream_len: default_max_stream_len(),
        }
    }
}

/// In-flight captured exchange before conversion to `CapturedRequest`.
/// Produced by the MITM module.
#[derive(Debug, Clone)]
pub struct PipelineEvent {
    /// UUIDv7, minted at MITM body finalization.
    pub event_id: Uuid,
    pub session_id: common::types::SessionId,
    pub proxy_id: String,
    pub timestamp: time::OffsetDateTime,
    pub method: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub request_headers: Vec<(String, String)>,
    pub request_body: Bytes,
    pub request_body_size: u64,
    pub request_body_truncated: bool,
    pub response_status: u32,
    pub response_status_text: String,
    pub response_headers: Vec<(String, String)>,
    pub response_body: Bytes,
    pub response_body_size: u64,
    pub response_body_truncated: bool,
    pub timing: TimingInfo,
    pub metadata: SessionMetadata,
}

#[derive(Debug, Clone, Default)]
pub struct TimingInfo {
    pub client_tls_ms: u64,
    pub upstream_tls_ms: u64,
    pub ttfb_ms: u64,
    pub total_ms: u64,
    pub ratelimit_wait_ms: u64,
}

#[derive(Debug, Clone)]
pub struct SessionMetadata {
    pub org_id: String,
    pub source: String,
    pub source_id: String,
}

/// WebSocket message direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WsDirection {
    /// client -> server
    C2s,
    /// server -> client
    S2c,
}

impl WsDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::C2s => "c2s",
            Self::S2c => "s2c",
        }
    }
}

/// WebSocket logical opcode (data or close). Control frames PING/PONG are
/// represented when `capture_ws_control_frames=true`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WsOpcode {
    Text,
    Binary,
    Close,
    Ping,
    Pong,
}

/// In-flight captured WebSocket message before conversion to
/// `wire::CapturedWsMessage`. Produced by `mitm::websocket::proxy_websocket`.
///
/// One per logical (reassembled, decompressed) protocol message. The
/// `parent_event_id` links back to the `101 Switching Protocols` row in
/// `http_captures`.
#[derive(Debug, Clone)]
pub struct WsPipelineEvent {
    /// UUIDv7, minted when the message reassembles (FIN frame).
    pub event_id: Uuid,
    /// `event_id` of the 101 row in `http_captures`.
    pub parent_event_id: Uuid,
    pub session_id: common::types::SessionId,
    pub proxy_id: String,
    pub timestamp: time::OffsetDateTime,
    pub direction: WsDirection,
    pub opcode: WsOpcode,
    /// Reassembled, decompressed payload, capped at `max_ws_payload_capture`.
    pub payload: Bytes,
    /// Pre-truncation, post-decompression size. `payload.len() ==
    /// min(payload_size, max_ws_payload_capture)`.
    pub payload_size: u64,
    pub payload_truncated: bool,
    /// RSV1 was set on the leading wire frame (permessage-deflate).
    pub was_compressed: bool,
    /// Set only when `opcode == Close`. RFC 6455 section 5.5.1.
    pub close_code: Option<u16>,
    pub close_reason: Option<String>,
    /// Hoisted from the parent 101 row's `host`.
    pub host: String,
    pub metadata: SessionMetadata,
}

/// Captures-log request writer. Owns a background drain task that pulls
/// items off an mpsc, encodes them as protobuf envelopes, and hands them
/// to the configured `CaptureLogProducer`.
///
/// Both HTTP captures (`PipelineEvent`) and WebSocket messages
/// (`WsPipelineEvent`) ride a single FIFO so per-source emit order is
/// preserved end-to-end.
pub struct RequestLogWriter {
    sender: parking_lot::Mutex<Option<mpsc::Sender<DrainItem>>>,
    drain: parking_lot::Mutex<Option<tokio::task::JoinHandle<Box<dyn CaptureLogProducer>>>>,
    capacity: usize,
    progress: Arc<Progress>,
}

/// What the drain task reports about itself, for the readiness check.
struct Progress {
    /// Time zero of `last_ms`.
    origin: tokio::time::Instant,
    /// Milliseconds after `origin` of the last sign of life: a batch was
    /// published, or work arrived after the writer sat idle.
    last_ms: AtomicU64,
    /// A batch is being published right now.
    publishing: AtomicBool,
}

impl Progress {
    fn new() -> Self {
        Self {
            origin: tokio::time::Instant::now(),
            last_ms: AtomicU64::new(0),
            publishing: AtomicBool::new(false),
        }
    }

    fn touch(&self) {
        self.last_ms
            .store(self.origin.elapsed().as_millis() as u64, Ordering::Release);
    }

    fn since_last(&self) -> Duration {
        let last = Duration::from_millis(self.last_ms.load(Ordering::Acquire));
        self.origin.elapsed().saturating_sub(last)
    }
}

/// Items multiplexed onto the writer's single FIFO. Boxed so the enum slot
/// stays small while individual events are large.
enum DrainItem {
    Http(Box<PipelineEvent>),
    Ws(Box<WsPipelineEvent>),
}

impl RequestLogWriter {
    /// Create writer and spawn background drain task. The drain task owns
    /// the producer for the lifetime of the writer; it is returned via
    /// the join handle so `flush_and_close` can finalize it.
    pub fn new(config: RequestLogConfig, producer: Box<dyn CaptureLogProducer>) -> Self {
        let (sender, receiver) = mpsc::channel(config.channel_capacity);
        let progress = Arc::new(Progress::new());
        let drain = tokio::spawn(drain_task(
            receiver,
            producer,
            config.stream_name,
            config.channel_capacity,
            progress.clone(),
        ));
        Self {
            sender: parking_lot::Mutex::new(Some(sender)),
            drain: parking_lot::Mutex::new(Some(drain)),
            capacity: config.channel_capacity,
            progress,
        }
    }

    /// Captures queued in the writer channel, not counting the batch being
    /// published. 0 once the writer is closed.
    pub fn queued(&self) -> usize {
        self.sender
            .lock()
            .as_ref()
            .map_or(0, |s| s.max_capacity() - s.capacity())
    }

    /// Size of the writer channel (`request_log.channel_capacity`).
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Work is queued or a batch is being published.
    pub fn has_work(&self) -> bool {
        self.queued() > 0 || self.progress.publishing.load(Ordering::Acquire)
    }

    /// Time since the writer last made progress: published a batch, or got
    /// work after sitting idle. Grows without bound while idle, so read it
    /// together with [`RequestLogWriter::has_work`].
    pub fn since_progress(&self) -> Duration {
        self.progress.since_last()
    }

    /// Send an HTTP exchange. Blocks if channel is full (backpressure).
    pub async fn send(&self, event: PipelineEvent) {
        let sender = self.sender.lock().clone();
        let Some(sender) = sender else {
            tracing::debug!("request log writer closed, http event dropped");
            return;
        };
        if sender.send(DrainItem::Http(Box::new(event))).await.is_err() {
            tracing::warn!("request log channel closed, http event dropped");
            return;
        }
        record_buffer_depth(&sender);
    }

    /// Send a WebSocket message. Blocks if channel is full (backpressure).
    pub async fn send_ws(&self, event: WsPipelineEvent) {
        let sender = self.sender.lock().clone();
        let Some(sender) = sender else {
            tracing::debug!("request log writer closed, ws event dropped");
            return;
        };
        if sender.send(DrainItem::Ws(Box::new(event))).await.is_err() {
            tracing::warn!("request log channel closed, ws event dropped");
            return;
        }
        record_buffer_depth(&sender);
    }

    /// Close the channel, wait for the drain task to finish, then flush
    /// the producer. The total wall-clock budget is bounded by `timeout`.
    /// Idempotent.
    pub async fn flush_and_close(&self, timeout: std::time::Duration) {
        let _ = self.sender.lock().take();
        let task = self.drain.lock().take();
        let Some(task) = task else { return };
        let started = std::time::Instant::now();
        let half = timeout / 2;
        let producer = match tokio::time::timeout(half, task).await {
            Ok(Ok(producer)) => Some(producer),
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "request log writer drain task panicked");
                None
            }
            Err(_) => {
                tracing::warn!(
                    timeout_secs = timeout.as_secs(),
                    "request log writer drain timed out before producer flush",
                );
                None
            }
        };
        if let Some(producer) = producer {
            let remaining = timeout.saturating_sub(started.elapsed());
            producer.flush_and_close(remaining).await;
            tracing::info!("request log writer drained");
        }
    }
}

/// Captures queued in the writer channel (sent, not yet received).
fn record_buffer_depth(sender: &mpsc::Sender<DrainItem>) {
    let queued = sender.max_capacity() - sender.capacity();
    common::metrics::PROXY_CAPTURE_BUFFER_DEPTH.set(queued as i64);
}

/// Drains events, encodes them as protobuf envelopes, and forwards them
/// to the producer. Each round takes everything queued (up to
/// `batch_capacity`) and publishes it as one batch, so the producer can send
/// one request per partition instead of one per capture. The next round
/// starts only after this batch is published, which keeps per-key order.
/// The producer is returned to `flush_and_close` so it can run a final
/// broker-side flush.
async fn drain_task(
    mut receiver: mpsc::Receiver<DrainItem>,
    producer: Box<dyn CaptureLogProducer>,
    stream_name: String,
    batch_capacity: usize,
    progress: Arc<Progress>,
) -> Box<dyn CaptureLogProducer> {
    tracing::info!(%stream_name, "request log writer started");

    let mut items = Vec::with_capacity(batch_capacity);
    loop {
        let was_idle = receiver.is_empty();
        if receiver.recv_many(&mut items, batch_capacity).await == 0 {
            break;
        }
        if was_idle {
            // The idle time before this work is not a stall.
            progress.touch();
        }
        common::metrics::PROXY_CAPTURE_BUFFER_DEPTH.set(receiver.len() as i64);
        let records = items.drain(..).filter_map(encode_item).collect();
        progress.publishing.store(true, Ordering::Release);
        publish_with_retry(producer.as_ref(), records).await;
        progress.publishing.store(false, Ordering::Release);
        progress.touch();
    }

    tracing::info!("request log writer stopped");
    producer
}

/// Encodes a queued item as a `(key, payload)` record keyed by `source_id`.
/// Returns `None` for a WebSocket message that cannot be converted.
fn encode_item(item: DrainItem) -> Option<(Bytes, Bytes)> {
    match item {
        DrainItem::Http(event) => {
            let envelope = wire::RequestLogMessage {
                kind: Some(request_log_message::Kind::Request(convert_event(&event))),
            };
            Some((
                Bytes::from(event.metadata.source_id.clone()),
                Bytes::from(envelope.encode_to_vec()),
            ))
        }
        DrainItem::Ws(event) => {
            let captured = match convert_ws_event(&event) {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        event_id = %event.event_id,
                        parent_event_id = %event.parent_event_id,
                        "failed to convert WsPipelineEvent to wire form, dropping"
                    );
                    return None;
                }
            };
            let envelope = wire::RequestLogMessage {
                kind: Some(request_log_message::Kind::WsMessage(captured)),
            };
            Some((
                Bytes::from(event.metadata.source_id.clone()),
                Bytes::from(envelope.encode_to_vec()),
            ))
        }
    }
}

/// Publish a batch of captures, retrying the failed ones (in order) with
/// exponential backoff. Captures are the proxy's product, not best-effort
/// telemetry, so we block-and-retry rather than drop on the first failure.
/// Unsent records stay pending without consuming their own retry attempts.
/// Only captures that fail every attempt are counted as dropped and surfaced
/// at `error!`. `Bytes::clone` is a cheap refcount bump, so retrying does not
/// re-copy payloads.
async fn publish_with_retry(producer: &dyn CaptureLogProducer, mut records: Vec<(Bytes, Bytes)>) {
    let mut attempts = vec![0; records.len()];
    let mut backoff = Duration::from_millis(50);
    while !records.is_empty() {
        let outcomes = {
            let publish = producer.publish_batch(&records);
            tokio::pin!(publish);
            tokio::select! {
                biased;
                outcomes = &mut publish => outcomes,
                _ = tokio::time::sleep(Duration::from_secs(5)) => {
                    let source_ids = records.iter()
                        .map(|(key, _)| String::from_utf8_lossy(key))
                        .collect::<std::collections::BTreeSet<_>>();
                    tracing::warn!(
                        max_record_attempt = attempts.iter().max().copied().unwrap_or(0) + 1,
                        records = records.len(),
                        source_ids = ?source_ids,
                        capture_buffer_depth = common::metrics::PROXY_CAPTURE_BUFFER_DEPTH.get(),
                        "capture batch publish stalled"
                    );
                    publish.await
                }
            }
        };
        let mut outcomes = outcomes.into_iter();
        let mut record_attempts = attempts.iter_mut();
        let mut last_error = None;
        records.retain(|_| {
            let attempt = record_attempts
                .next()
                .expect("one attempt count per record");
            match outcomes.next().expect("one publish outcome per record") {
                common::log::PublishOutcome::Published => {
                    common::metrics::PROXY_CAPTURES_PUBLISHED_TOTAL.inc();
                    // Use the exhausted count to remove both entries below.
                    *attempt = MAX_PUBLISH_ATTEMPTS;
                    false
                }
                common::log::PublishOutcome::NotSent => true,
                common::log::PublishOutcome::Failed(error) => {
                    *attempt += 1;
                    if *attempt == MAX_PUBLISH_ATTEMPTS {
                        common::metrics::PROXY_CAPTURES_DROPPED_TOTAL.inc();
                        tracing::error!(
                            error = %error,
                            attempts = *attempt,
                            "capture-log publish failed permanently, capture dropped"
                        );
                        false
                    } else {
                        last_error = Some((error, *attempt));
                        true
                    }
                }
            }
        });
        // Retain the matching counters without copying or reallocating records.
        attempts.retain(|attempt| *attempt < MAX_PUBLISH_ATTEMPTS);
        if let Some((error, attempt)) = last_error {
            tracing::warn!(
                error = %error,
                attempt,
                pending = records.len(),
                "capture-log publish failed, retrying"
            );
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_secs(5));
        } else {
            // A dropped blocker leaves unsent records with a fresh retry budget.
            backoff = Duration::from_millis(50);
        }
    }
}

/// Convert `PipelineEvent` to the wire contract expected by the API.
///
/// `event_id` is minted at the proxy and propagated end-to-end so the
/// API's ClickHouse insert is idempotent.
pub fn convert_event(event: &PipelineEvent) -> wire::CapturedRequest {
    let timestamp_nanos = event.timestamp.unix_timestamp_nanos() as i64;
    wire::CapturedRequest {
        event_id: Bytes::copy_from_slice(event.event_id.as_bytes()),
        session_id: Bytes::copy_from_slice(event.session_id.as_bytes()),
        proxy_id: event.proxy_id.clone(),
        org_id: event.metadata.org_id.clone(),
        source: event.metadata.source.clone(),
        source_id: event.metadata.source_id.clone(),
        timestamp_nanos,

        method: event.method.clone(),
        scheme: event.scheme.clone(),
        host: event.host.clone(),
        port: event.port as u32,
        path: event.path.clone(),
        request_headers: event
            .request_headers
            .iter()
            .map(|(name, value)| wire::Header {
                name: name.clone(),
                value: value.clone(),
            })
            .collect(),
        request_body: event.request_body.clone(),
        request_body_size: event.request_body_size,
        request_body_truncated: event.request_body_truncated,
        response_status: event.response_status,
        response_headers: event
            .response_headers
            .iter()
            .map(|(name, value)| wire::Header {
                name: name.clone(),
                value: value.clone(),
            })
            .collect(),
        response_body: event.response_body.clone(),
        response_body_size: event.response_body_size,
        response_body_truncated: event.response_body_truncated,
        duration_ms: event.timing.total_ms,
        ratelimit_wait_ms: event.timing.ratelimit_wait_ms,
    }
}

/// Convert a `WsPipelineEvent` into the wire `CapturedWsMessage`.
/// Returns an error if the event timestamp cannot be represented as nanoseconds.
pub fn convert_ws_event(event: &WsPipelineEvent) -> anyhow::Result<wire::CapturedWsMessage> {
    let timestamp_nanos: i64 = event
        .timestamp
        .unix_timestamp_nanos()
        .try_into()
        .map_err(|_| anyhow::anyhow!("ws timestamp out of i64 range"))?;
    let direction = match event.direction {
        WsDirection::C2s => wire::WsDirection::C2s as i32,
        WsDirection::S2c => wire::WsDirection::S2c as i32,
    };
    let opcode = match event.opcode {
        WsOpcode::Text => wire::WsOpcode::Text as i32,
        WsOpcode::Binary => wire::WsOpcode::Binary as i32,
        WsOpcode::Close => wire::WsOpcode::Close as i32,
        WsOpcode::Ping => wire::WsOpcode::Ping as i32,
        WsOpcode::Pong => wire::WsOpcode::Pong as i32,
    };
    Ok(wire::CapturedWsMessage {
        event_id: Bytes::copy_from_slice(event.event_id.as_bytes()),
        parent_event_id: Bytes::copy_from_slice(event.parent_event_id.as_bytes()),
        session_id: Bytes::copy_from_slice(event.session_id.as_bytes()),
        proxy_id: event.proxy_id.clone(),
        org_id: event.metadata.org_id.clone(),
        source: event.metadata.source.clone(),
        source_id: event.metadata.source_id.clone(),
        timestamp_nanos,
        direction,
        opcode,
        payload: event.payload.clone(),
        payload_size: event.payload_size,
        payload_truncated: event.payload_truncated,
        was_compressed: event.was_compressed,
        close_code: event.close_code.map(|c| c as u32).unwrap_or(0),
        close_reason: event.close_reason.clone().unwrap_or_default(),
        host: event.host.clone(),
    })
}

/// A small HTTP capture for tests of the writer's behavior.
#[cfg(test)]
pub(crate) fn test_event(source_id: &str) -> PipelineEvent {
    PipelineEvent {
        event_id: Uuid::now_v7(),
        session_id: Uuid::new_v4(),
        proxy_id: "test-proxy".into(),
        timestamp: time::OffsetDateTime::now_utc(),
        method: "GET".into(),
        scheme: "https".into(),
        host: "example.test".into(),
        port: 443,
        path: "/".into(),
        request_headers: Vec::new(),
        request_body: Bytes::new(),
        request_body_size: 0,
        request_body_truncated: false,
        response_status: 200,
        response_status_text: "OK".into(),
        response_headers: Vec::new(),
        response_body: Bytes::new(),
        response_body_size: 0,
        response_body_truncated: false,
        timing: TimingInfo::default(),
        metadata: SessionMetadata {
            org_id: "test-org".into(),
            source: "test".into(),
            source_id: source_id.into(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::log::PublishOutcome;
    use std::io::{self, Write};
    use std::pin::Pin;
    use std::sync::Arc;
    use tokio::sync::Notify;

    #[derive(Clone)]
    struct LogWriter(Arc<parking_lot::Mutex<Vec<u8>>>);

    impl Write for LogWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct HeldProducer {
        started: Notify,
        release: Notify,
        delivered: parking_lot::Mutex<Vec<Bytes>>,
    }

    impl CaptureLogProducer for HeldProducer {
        fn publish<'a, 'b, 'f>(
            &'a self,
            _key: &'b [u8],
            _payload: Bytes,
        ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + 'f>>
        where
            'a: 'f,
            'b: 'f,
            Self: 'f,
        {
            Box::pin(async { unreachable!("the drain publishes in batches") })
        }

        fn publish_batch<'a, 'b, 'f>(
            &'a self,
            records: &'b [(Bytes, Bytes)],
        ) -> Pin<Box<dyn Future<Output = Vec<PublishOutcome>> + Send + 'f>>
        where
            'a: 'f,
            'b: 'f,
            Self: 'f,
        {
            Box::pin(async move {
                self.started.notify_one();
                self.release.notified().await;
                self.delivered
                    .lock()
                    .extend(records.iter().map(|(_, payload)| payload.clone()));
                records.iter().map(|_| PublishOutcome::Published).collect()
            })
        }

        fn flush_and_close<'a, 'f>(
            &'a self,
            _timeout: Duration,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + 'f>>
        where
            'a: 'f,
            Self: 'f,
        {
            Box::pin(async {})
        }
    }

    // All retry tests share the production dropped-capture counter.
    static RETRY_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    fn dropped_captures_count() -> u64 {
        common::metrics::PROXY_CAPTURES_DROPPED_TOTAL.get() as u64
    }

    /// Producer that records the payloads of each `publish_batch` call and
    /// fails the payloads in `failing` during the first `failing_calls` calls.
    struct FlakyProducer {
        calls: parking_lot::Mutex<Vec<Vec<Bytes>>>,
        failing: Vec<Bytes>,
        failing_calls: usize,
    }

    impl FlakyProducer {
        fn new(failing: &[&'static str], failing_calls: usize) -> Self {
            Self {
                calls: parking_lot::Mutex::new(Vec::new()),
                failing: failing.iter().map(|p| Bytes::from(*p)).collect(),
                failing_calls,
            }
        }
    }

    impl CaptureLogProducer for FlakyProducer {
        fn publish<'life0, 'life1, 'async_trait>(
            &'life0 self,
            _key: &'life1 [u8],
            _payload: Bytes,
        ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + 'async_trait>>
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(async { unreachable!("the drain publishes in batches") })
        }

        fn publish_batch<'life0, 'life1, 'async_trait>(
            &'life0 self,
            records: &'life1 [(Bytes, Bytes)],
        ) -> Pin<Box<dyn Future<Output = Vec<PublishOutcome>> + Send + 'async_trait>>
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait,
        {
            let results = {
                let mut calls = self.calls.lock();
                let failing = calls.len() < self.failing_calls;
                calls.push(records.iter().map(|(_, payload)| payload.clone()).collect());
                records
                    .iter()
                    .map(|(_, payload)| {
                        if failing && self.failing.contains(payload) {
                            PublishOutcome::Failed(anyhow::anyhow!("broker unavailable"))
                        } else {
                            PublishOutcome::Published
                        }
                    })
                    .collect()
            };
            Box::pin(async move { results })
        }

        fn flush_and_close<'life0, 'async_trait>(
            &'life0 self,
            _timeout: Duration,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + 'async_trait>>
        where
            'life0: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(async {})
        }
    }

    /// Exercises the default sequential batch implementation, recording real writes.
    struct SequentialProducer {
        attempts: parking_lot::Mutex<Vec<Bytes>>,
        delivered: parking_lot::Mutex<Vec<Bytes>>,
        failures: Vec<(Bytes, usize)>,
    }

    impl SequentialProducer {
        fn new(failures: &[(&'static str, usize)]) -> Self {
            Self {
                attempts: parking_lot::Mutex::new(Vec::new()),
                delivered: parking_lot::Mutex::new(Vec::new()),
                failures: failures
                    .iter()
                    .map(|(payload, count)| (Bytes::from(*payload), *count))
                    .collect(),
            }
        }
    }

    impl CaptureLogProducer for SequentialProducer {
        fn publish<'life0, 'life1, 'async_trait>(
            &'life0 self,
            _key: &'life1 [u8],
            payload: Bytes,
        ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + 'async_trait>>
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(async move {
                let mut attempts = self.attempts.lock();
                let attempt = attempts.iter().filter(|p| **p == payload).count() + 1;
                attempts.push(payload.clone());
                if self
                    .failures
                    .iter()
                    .any(|(p, failures)| *p == payload && attempt <= *failures)
                {
                    return Err(anyhow::anyhow!("broker unavailable"));
                }
                self.delivered.lock().push(payload);
                Ok(())
            })
        }

        fn flush_and_close<'life0, 'async_trait>(
            &'life0 self,
            _timeout: Duration,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + 'async_trait>>
        where
            'life0: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(async {})
        }
    }

    /// One record per payload, each with its own key.
    fn records(payloads: &[&'static str]) -> Vec<(Bytes, Bytes)> {
        payloads
            .iter()
            .map(|p| (Bytes::from(format!("source-{p}")), Bytes::from(*p)))
            .collect()
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_batch_reports_sources_before_publish_returns_and_keeps_delivery() {
        let output = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_writer({
                let output = output.clone();
                move || LogWriter(output.clone())
            })
            .finish();
        let _subscriber = tracing::subscriber::set_default(subscriber);
        let producer = Arc::new(HeldProducer {
            started: Notify::new(),
            release: Notify::new(),
            delivered: parking_lot::Mutex::new(Vec::new()),
        });
        let task_producer = producer.clone();
        let publish = tokio::spawn(async move {
            publish_with_retry(
                task_producer.as_ref(),
                vec![
                    (Bytes::from_static(b"crawl-1"), Bytes::from_static(b"a")),
                    (Bytes::from_static(b"crawl-1"), Bytes::from_static(b"b")),
                    (Bytes::from_static(b"scan-2"), Bytes::from_static(b"c")),
                ],
            )
            .await;
        });

        producer.started.notified().await;
        tokio::time::advance(Duration::from_secs(4)).await;
        assert!(output.lock().is_empty(), "no early stall warning");
        tokio::time::advance(Duration::from_secs(2)).await;
        tokio::task::yield_now().await;
        assert!(
            !publish.is_finished(),
            "diagnostic must not stop publishing"
        );
        let log: serde_json::Value = serde_json::from_slice(&output.lock()).unwrap();
        assert_eq!(log["level"], "WARN");
        assert_eq!(log["fields"]["message"], "capture batch publish stalled");
        assert_eq!(log["fields"]["records"], 3);
        assert_eq!(log["fields"]["max_record_attempt"], 1);
        let sources = log["fields"]["source_ids"].as_str().unwrap();
        assert_eq!(sources.matches("crawl-1").count(), 1);
        assert_eq!(sources.matches("scan-2").count(), 1);

        producer.release.notify_one();
        publish.await.unwrap();
        assert_eq!(*producer.delivered.lock(), ["a", "b", "c"].map(Bytes::from));

        output.lock().clear();
        let quick = FlakyProducer::new(&[], 0);
        publish_with_retry(&quick, records(&["fast"])).await;
        tokio::time::advance(Duration::from_secs(6)).await;
        assert!(output.lock().is_empty(), "no warning after a fast publish");
    }

    #[tokio::test(start_paused = true)]
    async fn retry_resends_only_failed_records_in_order() {
        let _guard = RETRY_TEST_LOCK.lock().await;
        let producer = FlakyProducer::new(&["b", "d"], 1);

        publish_with_retry(&producer, records(&["a", "b", "c", "d"])).await;

        let calls = producer.calls.lock();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0], ["a", "b", "c", "d"].map(Bytes::from));
        assert_eq!(calls[1], ["b", "d"].map(Bytes::from));
    }

    #[tokio::test(start_paused = true)]
    async fn records_failing_every_attempt_are_counted_as_dropped() {
        let _guard = RETRY_TEST_LOCK.lock().await;
        let producer = FlakyProducer::new(&["b", "c"], usize::MAX);
        let dropped_before = dropped_captures_count();

        publish_with_retry(&producer, records(&["a", "b", "c"])).await;

        assert_eq!(producer.calls.lock().len(), MAX_PUBLISH_ATTEMPTS as usize);
        assert_eq!(dropped_captures_count() - dropped_before, 2);
    }

    #[tokio::test(start_paused = true)]
    async fn exhausted_first_record_does_not_drop_unsent_records() {
        let _guard = RETRY_TEST_LOCK.lock().await;
        let producer = SequentialProducer::new(&[("a", 5)]);
        let dropped_before = dropped_captures_count();

        publish_with_retry(&producer, records(&["a", "b", "c"])).await;

        assert_eq!(
            *producer.attempts.lock(),
            ["a", "a", "a", "a", "a", "b", "c"].map(Bytes::from)
        );
        assert_eq!(*producer.delivered.lock(), ["b", "c"].map(Bytes::from));
        assert_eq!(dropped_captures_count() - dropped_before, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn blocked_record_retains_all_five_actual_publish_attempts() {
        let _guard = RETRY_TEST_LOCK.lock().await;
        let producer = SequentialProducer::new(&[("a", 5), ("b", 4)]);
        let dropped_before = dropped_captures_count();

        publish_with_retry(&producer, records(&["a", "b", "c"])).await;

        assert_eq!(
            *producer.attempts.lock(),
            ["a", "a", "a", "a", "a", "b", "b", "b", "b", "b", "c"].map(Bytes::from)
        );
        assert_eq!(*producer.delivered.lock(), ["b", "c"].map(Bytes::from));
        assert_eq!(dropped_captures_count() - dropped_before, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn sequential_recovery_preserves_order_without_resending_successes() {
        let _guard = RETRY_TEST_LOCK.lock().await;
        let producer = SequentialProducer::new(&[("a", 2), ("b", 1)]);
        let dropped_before = dropped_captures_count();

        publish_with_retry(&producer, records(&["a", "b", "c"])).await;

        assert_eq!(
            *producer.attempts.lock(),
            ["a", "a", "a", "b", "b", "c"].map(Bytes::from)
        );
        assert_eq!(*producer.delivered.lock(), ["a", "b", "c"].map(Bytes::from));
        assert_eq!(dropped_captures_count(), dropped_before);
    }
}
