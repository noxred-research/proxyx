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
    drain: parking_lot::Mutex<Option<tokio::task::JoinHandle<()>>>,
    producer: Arc<dyn CaptureLogProducer>,
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
    failure: parking_lot::Mutex<FailureState>,
}

#[derive(Default)]
struct FailureState {
    /// Since when captures are dropped, and the latest error.
    active: Option<(tokio::time::Instant, String)>,
    /// Counts failures, so a probe can tell whether one arrived while it ran.
    generation: u64,
}

/// The writer is dropping captures: a capture failed all its attempts and
/// no batch has published cleanly since, and the broker does not answer a
/// probe either.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishFailure {
    /// Error of the latest dropped capture, or of the probe.
    pub error: String,
    /// How long publishing has been failing.
    pub since: Duration,
}

impl Progress {
    fn new() -> Self {
        Self {
            origin: tokio::time::Instant::now(),
            last_ms: AtomicU64::new(0),
            publishing: AtomicBool::new(false),
            failure: parking_lot::Mutex::new(FailureState::default()),
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

    /// A capture failed its last attempt.
    fn fail(&self, error: String) {
        let mut state = self.failure.lock();
        state.generation += 1;
        let since = state
            .active
            .take()
            .map_or_else(tokio::time::Instant::now, |(since, _)| since);
        state.active = Some((since, error));
    }

    /// A batch published cleanly.
    fn recover(&self) {
        self.failure.lock().active = None;
    }

    /// The broker answered a probe started when the generation was
    /// `generation`; a failure that came in since keeps the state.
    fn recover_if(&self, generation: u64) {
        let mut state = self.failure.lock();
        if state.generation == generation {
            state.active = None;
        }
    }

    fn failure(&self) -> Option<(PublishFailure, u64)> {
        let state = self.failure.lock();
        state.active.as_ref().map(|(since, error)| {
            (
                PublishFailure {
                    error: error.clone(),
                    since: since.elapsed(),
                },
                state.generation,
            )
        })
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
        let producer: Arc<dyn CaptureLogProducer> = Arc::from(producer);
        let drain = tokio::spawn(drain_task(
            receiver,
            producer.clone(),
            config.stream_name,
            config.channel_capacity,
            progress.clone(),
        ));
        Self {
            sender: parking_lot::Mutex::new(Some(sender)),
            drain: parking_lot::Mutex::new(Some(drain)),
            producer,
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

    /// Whether captures are being dropped because the broker does not take
    /// them. While they are, the producer is probed (at most for `timeout`):
    /// a broker that answers clears the failure at once, so readiness
    /// recovers although no capture arrives to prove it. A clean batch
    /// clears it too. `None` when publishing works.
    pub async fn publish_failure(&self, timeout: Duration) -> Option<PublishFailure> {
        let (failure, generation) = self.progress.failure()?;
        let probed = match tokio::time::timeout(timeout, self.producer.probe()).await {
            Ok(Ok(())) => {
                self.progress.recover_if(generation);
                return self.progress.failure().map(|(failure, _)| failure);
            }
            Ok(Err(error)) => format!("{error:#}"),
            Err(_) => format!("no answer within {timeout:?}"),
        };
        Some(PublishFailure {
            error: format!("{} (broker probe: {probed})", failure.error),
            since: failure.since,
        })
    }

    /// Send an HTTP exchange. Blocks if channel is full (backpressure).
    pub async fn send(&self, event: PipelineEvent) {
        let sender = self.sender.lock().clone();
        let Some(sender) = sender else {
            tracing::warn!("request log writer closed, http event dropped");
            common::metrics::PROXY_CAPTURES_DROPPED_TOTAL.inc();
            return;
        };
        if sender.send(DrainItem::Http(Box::new(event))).await.is_err() {
            tracing::warn!("request log channel closed, http event dropped");
            common::metrics::PROXY_CAPTURES_DROPPED_TOTAL.inc();
            return;
        }
        record_buffer_depth(&sender);
    }

    /// Send a WebSocket message. Blocks if channel is full (backpressure).
    pub async fn send_ws(&self, event: WsPipelineEvent) {
        let sender = self.sender.lock().clone();
        let Some(sender) = sender else {
            tracing::warn!("request log writer closed, ws event dropped");
            common::metrics::PROXY_CAPTURES_DROPPED_TOTAL.inc();
            return;
        };
        if sender.send(DrainItem::Ws(Box::new(event))).await.is_err() {
            tracing::warn!("request log channel closed, ws event dropped");
            common::metrics::PROXY_CAPTURES_DROPPED_TOTAL.inc();
            return;
        }
        record_buffer_depth(&sender);
    }

    /// Close the channel, wait for the drain task to finish, then flush
    /// the producer. The total wall-clock budget is bounded by `timeout`.
    /// Idempotent.
    pub async fn flush_and_close(&self, timeout: std::time::Duration) {
        let queued = self.queued();
        let _ = self.sender.lock().take();
        let task = self.drain.lock().take();
        let Some(task) = task else { return };
        let started = std::time::Instant::now();
        let half = timeout / 2;
        let drained = match tokio::time::timeout(half, task).await {
            Ok(Ok(())) => true,
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "request log writer drain task panicked");
                false
            }
            Err(_) => {
                tracing::error!(
                    timeout_secs = timeout.as_secs(),
                    queued_at_shutdown = queued,
                    "request log writer drain timed out before producer flush; captures \
                     still queued or in flight are lost",
                );
                false
            }
        };
        if drained {
            let remaining = timeout.saturating_sub(started.elapsed());
            self.producer.flush_and_close(remaining).await;
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
async fn drain_task(
    mut receiver: mpsc::Receiver<DrainItem>,
    producer: Arc<dyn CaptureLogProducer>,
    stream_name: String,
    batch_capacity: usize,
    progress: Arc<Progress>,
) {
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
        let mut records = Vec::with_capacity(items.len());
        for item in items.drain(..) {
            match encode_item(item) {
                Some(record) => records.push(record),
                // `encode_item` logged why; the capture is lost all the same.
                None => common::metrics::PROXY_CAPTURES_DROPPED_TOTAL.inc(),
            }
        }
        if !records.is_empty() {
            progress.publishing.store(true, Ordering::Release);
            publish_with_retry(producer.as_ref(), records, &progress).await;
            progress.publishing.store(false, Ordering::Release);
        }
        progress.touch();
        // Senders race with the gauge writes above; this one follows the
        // slowest step, so an idle writer settles at its real depth.
        common::metrics::PROXY_CAPTURE_BUFFER_DEPTH.set(receiver.len() as i64);
    }

    tracing::info!("request log writer stopped");
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
async fn publish_with_retry(
    producer: &dyn CaptureLogProducer,
    mut records: Vec<(Bytes, Bytes)>,
    progress: &Progress,
) {
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
        let mut dropped_error = None;
        let mut clean = true;
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
                common::log::PublishOutcome::NotSent => {
                    clean = false;
                    true
                }
                common::log::PublishOutcome::Failed(error) => {
                    clean = false;
                    *attempt += 1;
                    if *attempt == MAX_PUBLISH_ATTEMPTS {
                        common::metrics::PROXY_CAPTURES_DROPPED_TOTAL.inc();
                        tracing::error!(
                            error = %error,
                            attempts = *attempt,
                            "capture-log publish failed permanently, capture dropped"
                        );
                        dropped_error = Some(format!("{error:#}"));
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
        // Readiness follows what the broker does with captures: dropping one
        // means it refused it five times; a batch it took whole means it works.
        if let Some(error) = dropped_error {
            progress.fail(error);
        } else if clean {
            progress.recover();
        }
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
                &Progress::new(),
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
        publish_with_retry(&quick, records(&["fast"]), &Progress::new()).await;
        tokio::time::advance(Duration::from_secs(6)).await;
        assert!(output.lock().is_empty(), "no warning after a fast publish");
    }

    #[tokio::test(start_paused = true)]
    async fn retry_resends_only_failed_records_in_order() {
        let _guard = RETRY_TEST_LOCK.lock().await;
        let producer = FlakyProducer::new(&["b", "d"], 1);

        publish_with_retry(&producer, records(&["a", "b", "c", "d"]), &Progress::new()).await;

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

        publish_with_retry(&producer, records(&["a", "b", "c"]), &Progress::new()).await;

        assert_eq!(producer.calls.lock().len(), MAX_PUBLISH_ATTEMPTS as usize);
        assert_eq!(dropped_captures_count() - dropped_before, 2);
    }

    #[tokio::test(start_paused = true)]
    async fn exhausted_first_record_does_not_drop_unsent_records() {
        let _guard = RETRY_TEST_LOCK.lock().await;
        let producer = SequentialProducer::new(&[("a", 5)]);
        let dropped_before = dropped_captures_count();

        publish_with_retry(&producer, records(&["a", "b", "c"]), &Progress::new()).await;

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

        publish_with_retry(&producer, records(&["a", "b", "c"]), &Progress::new()).await;

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

        publish_with_retry(&producer, records(&["a", "b", "c"]), &Progress::new()).await;

        assert_eq!(
            *producer.attempts.lock(),
            ["a", "a", "a", "b", "b", "c"].map(Bytes::from)
        );
        assert_eq!(*producer.delivered.lock(), ["a", "b", "c"].map(Bytes::from));
        assert_eq!(dropped_captures_count(), dropped_before);
    }

    /// A broker whose publishes and probes are switched from the test.
    struct ToggleState {
        publish_works: std::sync::atomic::AtomicBool,
        probe_works: std::sync::atomic::AtomicBool,
        probes: std::sync::atomic::AtomicU64,
        delivered: parking_lot::Mutex<Vec<Bytes>>,
    }

    impl ToggleState {
        fn new(publish_works: bool, probe_works: bool) -> Arc<Self> {
            Arc::new(Self {
                publish_works: publish_works.into(),
                probe_works: probe_works.into(),
                probes: 0.into(),
                delivered: parking_lot::Mutex::new(Vec::new()),
            })
        }

        fn set_publish(&self, works: bool) {
            self.publish_works.store(works, Ordering::SeqCst);
        }

        fn delivered(&self) -> usize {
            self.delivered.lock().len()
        }
    }

    struct ToggleProducer(Arc<ToggleState>);

    impl CaptureLogProducer for ToggleProducer {
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
            let results = if self.0.publish_works.load(Ordering::SeqCst) {
                self.0
                    .delivered
                    .lock()
                    .extend(records.iter().map(|(key, _)| key.clone()));
                records.iter().map(|_| PublishOutcome::Published).collect()
            } else {
                records
                    .iter()
                    .map(|_| PublishOutcome::Failed(anyhow::anyhow!("connection refused")))
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

        fn probe<'life0, 'async_trait>(
            &'life0 self,
        ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + 'async_trait>>
        where
            'life0: 'async_trait,
            Self: 'async_trait,
        {
            self.0.probes.fetch_add(1, Ordering::SeqCst);
            let works = self.0.probe_works.load(Ordering::SeqCst);
            Box::pin(async move {
                if works {
                    Ok(())
                } else {
                    Err(anyhow::anyhow!("broker unreachable"))
                }
            })
        }
    }

    fn fast_health() -> crate::config::HealthConfig {
        crate::config::HealthConfig {
            check_interval_ms: 50,
            redis_timeout_ms: 300,
            redis_failure_threshold: 2,
            capture_stall_fraction: 0.9,
            capture_stall_window_ms: 30_000,
            capture_publish_stale_ms: 60_000,
            drain_notice_ms: 0,
        }
    }

    struct Rig {
        writer: Arc<RequestLogWriter>,
        state: Arc<ToggleState>,
        readiness: Arc<crate::health::Readiness>,
        cancel: tokio_util::sync::CancellationToken,
        monitor: tokio::task::JoinHandle<()>,
    }

    impl Rig {
        async fn start(publish_works: bool, probe_works: bool) -> Self {
            let state = ToggleState::new(publish_works, probe_works);
            let writer = Arc::new(RequestLogWriter::new(
                RequestLogConfig {
                    channel_capacity: 16,
                    ..RequestLogConfig::default()
                },
                Box::new(ToggleProducer(state.clone())),
            ));
            let redis = redis::aio::ConnectionManager::new(
                redis::Client::open(crate::health::testkit::fake_redis().await).unwrap(),
            )
            .await
            .unwrap();
            let readiness = Arc::new(crate::health::Readiness::new());
            readiness
                .register_listener("test")
                .store(true, Ordering::Release);
            let cancel = tokio_util::sync::CancellationToken::new();
            let monitor = crate::health::spawn_monitor(
                readiness.clone(),
                redis,
                writer.clone(),
                fast_health(),
                cancel.clone(),
            );
            let rig = Self {
                writer,
                state,
                readiness,
                cancel,
                monitor,
            };
            rig.wait_ready(true).await;
            rig
        }

        /// Wait for readiness to become `want`; returns the pipeline detail.
        async fn wait_ready(&self, want: bool) -> Option<String> {
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            loop {
                let report = self.readiness.report();
                if report.ready == want {
                    return report.checks[crate::health::CHECK_CAPTURE_PIPELINE]
                        .detail
                        .clone();
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "readiness stayed {}, wanted {want}: {report:?}",
                    report.ready
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }

        async fn send(&self, id: &str) {
            self.writer.send(test_event(id)).await;
        }

        /// Wait until nothing is queued or in flight.
        async fn settle(&self) {
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            while self.writer.has_work() {
                assert!(std::time::Instant::now() < deadline, "writer never settled");
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }

        async fn stop(self) {
            self.cancel.cancel();
            self.monitor.await.unwrap();
        }
    }

    #[tokio::test]
    async fn fast_publish_failures_fail_readiness_and_the_probe_recovers_it_without_traffic() {
        let _guard = RETRY_TEST_LOCK.lock().await;
        let rig = Rig::start(false, false).await;
        let dropped_before = dropped_captures_count();

        for i in 0..3 {
            rig.send(&format!("down-{i}")).await;
        }
        // Every attempt fails at once: the writer never stalls, yet readiness
        // must report the dropped captures.
        let detail = rig
            .wait_ready(false)
            .await
            .expect("a failing check has a detail");
        assert!(detail.contains("captures are being dropped"), "{detail}");
        assert!(detail.contains("connection refused"), "{detail}");
        assert!(
            detail.contains("broker probe: broker unreachable"),
            "{detail}"
        );
        rig.settle().await;
        assert_eq!(rig.state.delivered(), 0);
        assert_eq!(dropped_captures_count() - dropped_before, 3);
        assert_eq!(rig.writer.queued(), 0);
        // Still failing while the broker is down and nothing arrives.
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(!rig.readiness.report().ready, "no stale recovery");

        // The broker is back; no capture arrives, the probe alone recovers.
        rig.state.probe_works.store(true, Ordering::SeqCst);
        rig.state.set_publish(true);
        rig.wait_ready(true).await;

        // And the next capture goes through.
        rig.send("up-0").await;
        rig.settle().await;
        assert_eq!(rig.state.delivered(), 1);
        assert_eq!(dropped_captures_count() - dropped_before, 3);
        assert!(rig.readiness.report().ready);
        rig.stop().await;
    }

    #[tokio::test]
    async fn a_clean_batch_recovers_readiness_when_the_probe_cannot() {
        let _guard = RETRY_TEST_LOCK.lock().await;
        let rig = Rig::start(false, false).await;
        rig.send("down-0").await;
        rig.wait_ready(false).await;

        // Publishing works again but the probe still fails (a broker that
        // accepts captures yet refuses metadata): the next batch decides.
        rig.state.set_publish(true);
        rig.send("up-0").await;
        rig.settle().await;
        rig.wait_ready(true).await;
        assert_eq!(rig.state.delivered(), 1);
        rig.stop().await;
    }

    #[tokio::test]
    async fn a_healthy_writer_is_never_probed() {
        let _guard = RETRY_TEST_LOCK.lock().await;
        let rig = Rig::start(true, false).await;
        for i in 0..5 {
            rig.send(&format!("ok-{i}")).await;
        }
        rig.settle().await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(rig.readiness.report().ready);
        assert_eq!(rig.state.probes.load(Ordering::SeqCst), 0);
        rig.stop().await;
    }

    #[tokio::test]
    async fn every_accepted_capture_is_published_or_counted_dropped_across_flaps_and_shutdown() {
        let _guard = RETRY_TEST_LOCK.lock().await;
        let rig = Rig::start(true, true).await;
        let dropped_before = dropped_captures_count();
        let senders = 4;
        let per_sender = 40;

        // The broker flaps while four tunnels send, so retries, drops and
        // concurrent senders interleave.
        let flapper = {
            let state = rig.state.clone();
            tokio::spawn(async move {
                let mut works = false;
                loop {
                    works = !works;
                    state.set_publish(works);
                    tokio::time::sleep(Duration::from_millis(40)).await;
                }
            })
        };
        let mut tasks = Vec::new();
        for s in 0..senders {
            let writer = rig.writer.clone();
            tasks.push(tokio::spawn(async move {
                for i in 0..per_sender {
                    writer.send(test_event(&format!("flap-{s}-{i}"))).await;
                    tokio::time::sleep(Duration::from_millis(3)).await;
                }
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
        flapper.abort();
        // The broker is back for the final drain at shutdown.
        rig.state.set_publish(true);
        rig.writer.flush_and_close(Duration::from_secs(10)).await;

        // A capture accepted after shutdown is counted, not lost silently.
        rig.writer.send(test_event("late")).await;

        let accepted = (senders * per_sender) as usize;
        let delivered = rig.state.delivered();
        let dropped = (dropped_captures_count() - dropped_before) as usize;
        assert_eq!(
            delivered + dropped,
            accepted + 1,
            "published {delivered} + dropped {dropped}"
        );
        let delivered_keys = rig.state.delivered.lock().clone();
        let unique: std::collections::BTreeSet<_> = delivered_keys.iter().collect();
        assert_eq!(unique.len(), delivered, "no capture published twice");
        assert!(!unique.contains(&Bytes::from("late")));
        assert_eq!(rig.writer.queued(), 0);
        assert!(!rig.writer.has_work());
        rig.stop().await;
    }
}
