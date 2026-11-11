//! Generic batch handler for capture stores.
//!
//! Owns the public lifecycle (`new`, `send_doc`, `flush_and_close`) and
//! the internal byte-cap select loop + circuit breaker. Domain specifics
//! (doc type, byte estimation, per-row failure logging) are encapsulated by
//! the `FlushTarget` trait; how a batch reaches the store is encapsulated by
//! `BatchWriter` (ClickHouse `INSERT`, OpenSearch `_bulk`).
//!
//! Both the HTTP and WS handlers wrap a `BatchHandler<T: FlushTarget>`;
//! their public APIs differ only in the shape of `send(...)` (the doc
//! the caller hands in) and the initial table/config plumbing.
//!
//! Behavior — circuit breaker, byte-cap backpressure, requeue on flush
//! failure — is identical across handlers and stores. Logs use structured
//! `target_table = T::NAME` fields so a single prefix grep covers both
//! pipelines.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::Result;
use parking_lot::Mutex;
use tokio::sync::mpsc;
use tokio::time::interval;
use tracing::Instrument as _;

use common::log::AckHandle;

/// Buffering and circuit-breaker settings shared by every capture store.
#[derive(Debug, Clone)]
pub(crate) struct BatchConfig {
    pub bulk_size: usize,
    pub flush_interval_secs: u64,
    pub max_buffer_bytes: u64,
    pub circuit_breaker_threshold: u32,
    pub circuit_breaker_reset_secs: u64,
}

/// Domain plug-in for `BatchHandler`. Each target binds a doc type, the
/// target identifier (used in logs and metrics), and the hooks that read
/// from the doc.
pub(crate) trait FlushTarget: Send + Sync + 'static {
    /// Buffered document type — domain shape staged before the write.
    type Doc: Send + Sync + 'static;

    /// Identifier for tracing spans + log messages
    /// (e.g. `"http_captures"`, `"ws_messages"`).
    const NAME: &'static str;

    /// Cheap upper bound on the doc's serialized footprint, used by the
    /// byte-cap accounting.
    fn estimate_bytes(doc: &Self::Doc) -> u64;

    /// When the capture completed at the proxy. Commit lag is measured
    /// from here to the store write succeeding.
    fn completed_at(doc: &Self::Doc) -> time::OffsetDateTime;

    /// Hook for per-row failure logs. Default behavior logs only the
    /// `target_table` and `error` fields. Targets override to attach
    /// domain-specific fields such as `event_id`, `parent_event_id`.
    fn record_row_write_error(_doc: &Self::Doc, err: &dyn std::fmt::Display) {
        tracing::error!(
            target_table = Self::NAME,
            error = %err,
            "failed to write row to the capture store",
        );
    }
}

/// What a [`BatchWriter`] did with one batch. Indices refer to the slice
/// passed to [`BatchWriter::write`]; an index in neither list was written.
#[derive(Default)]
pub(crate) struct WriteOutcome {
    /// Rows the store can never accept (serialization or mapping errors),
    /// with the reason. They are dropped, counted and acked: retrying would
    /// wedge the pipeline.
    pub poison: Vec<(usize, String)>,
    /// Rows to write again at the next flush. Their acks do not fire.
    pub retry: Vec<usize>,
    /// Why `retry` is not empty, when the whole write failed.
    pub error: Option<anyhow::Error>,
}

impl WriteOutcome {
    /// The whole write failed: retry every row but the `poison` ones.
    pub fn failed(total: usize, poison: Vec<(usize, String)>, error: anyhow::Error) -> Self {
        let retry = (0..total)
            .filter(|i| !poison.iter().any(|(p, _)| p == i))
            .collect();
        Self {
            poison,
            retry,
            error: Some(error),
        }
    }
}

/// How a batch reaches the store.
#[async_trait::async_trait]
pub(crate) trait BatchWriter<T: FlushTarget>: Send + Sync + 'static {
    /// Root span of one flush of `rows` rows and `bytes` estimated bytes.
    fn flush_span(&self, rows: usize, bytes: u64) -> tracing::Span;

    /// Write `docs`. Must not partially report: every index is written,
    /// poison or retry.
    async fn write(&self, docs: &[T::Doc]) -> WriteOutcome;
}

/// Public batch-write handler. Spawns a background flusher task on
/// `new`, accepts docs via `send_doc`, drains on `flush_and_close`.
pub(crate) struct BatchHandler<T: FlushTarget> {
    sender: parking_lot::Mutex<Option<mpsc::Sender<BufferedDoc<T>>>>,
    drain: parking_lot::Mutex<Option<tokio::task::JoinHandle<()>>>,
    consecutive_failures: Arc<AtomicU32>,
    circuit_breaker_threshold: u32,
}

impl<T: FlushTarget> BatchHandler<T> {
    /// Build a handler around the given writer. Spawns the background
    /// flusher task.
    pub fn new(writer: Box<dyn BatchWriter<T>>, config: BatchConfig) -> Self {
        let (sender, receiver) = mpsc::channel(config.bulk_size * 2);
        let consecutive_failures = Arc::new(AtomicU32::new(0));
        let circuit_breaker_threshold = config.circuit_breaker_threshold;

        let flusher: Flusher<T> = Flusher {
            writer,
            buffer: Arc::new(Mutex::new(Vec::with_capacity(config.bulk_size))),
            buffer_bytes: Arc::new(AtomicU64::new(0)),
            receiver,
            consecutive_failures: consecutive_failures.clone(),
            circuit_open_until: Arc::new(AtomicU64::new(0)),
            config,
        };
        common::metrics::INGESTER_CIRCUIT_OPEN
            .with_label_values(&[T::NAME])
            .set(0);
        let drain = tokio::spawn(flusher.run());

        Self {
            sender: parking_lot::Mutex::new(Some(sender)),
            drain: parking_lot::Mutex::new(Some(drain)),
            consecutive_failures,
            circuit_breaker_threshold,
        }
    }

    /// Whether the circuit breaker is open: enough consecutive flushes failed
    /// and none has succeeded since. Like the `proxyx_ingester_circuit_open`
    /// gauge, it stays true through the half-open retry after the reset
    /// window and clears on the next successful flush.
    pub fn circuit_open(&self) -> bool {
        self.consecutive_failures.load(Ordering::Relaxed) >= self.circuit_breaker_threshold
    }

    /// Send a doc plus its broker ack. Applies backpressure via the bounded
    /// mpsc. The ack fires only after the doc's batch is flushed to the
    /// store. If the channel is closed (shutdown) the ack is dropped and the
    /// doc is read again after restart.
    pub async fn send_doc(&self, doc: T::Doc, ack: Option<AckHandle>) -> Result<()> {
        let sender = self.sender.lock().clone();
        let Some(sender) = sender else {
            return Err(anyhow::anyhow!("{} handler closed", T::NAME));
        };
        sender
            .send((doc, ack))
            .await
            .map_err(|_| anyhow::anyhow!("{} flusher dropped, channel closed", T::NAME))?;
        Ok(())
    }

    /// Close the channel and wait for the flusher to drain, up to
    /// `timeout`. Idempotent.
    pub async fn flush_and_close(&self, timeout: Duration) {
        let _ = self.sender.lock().take();
        let task = self.drain.lock().take();
        if let Some(task) = task {
            match tokio::time::timeout(timeout, task).await {
                Ok(Ok(())) => tracing::info!(target_table = T::NAME, "handler drained"),
                Ok(Err(e)) => tracing::warn!(
                    target_table = T::NAME,
                    error = %e,
                    "flusher panicked",
                ),
                Err(_) => tracing::warn!(
                    target_table = T::NAME,
                    timeout_secs = timeout.as_secs(),
                    "flusher drain timed out",
                ),
            }
        }
    }
}

/// A buffered doc paired with the broker ack to fire once it is durably
/// flushed to the store.
type BufferedDoc<T> = (<T as FlushTarget>::Doc, Option<AckHandle>);

/// Background task that batches and flushes events to the store.
struct Flusher<T: FlushTarget> {
    writer: Box<dyn BatchWriter<T>>,
    config: BatchConfig,
    /// Buffered docs paired with the broker ack to fire once the doc's
    /// batch is durably flushed.
    buffer: Arc<Mutex<Vec<BufferedDoc<T>>>>,
    /// Approximate accumulated payload size in bytes. Tracked
    /// separately from `buffer` to avoid recomputing under the lock.
    buffer_bytes: Arc<AtomicU64>,
    receiver: mpsc::Receiver<BufferedDoc<T>>,
    consecutive_failures: Arc<AtomicU32>,
    circuit_open_until: Arc<AtomicU64>,
}

impl<T: FlushTarget> Flusher<T> {
    async fn run(mut self) {
        let mut flush_interval = interval(Duration::from_secs(self.config.flush_interval_secs));

        loop {
            // If the buffer is at the byte cap, do not pull new docs off
            // the channel — senders block on `send()` and propagate
            // backpressure. We still service the periodic flush tick.
            let bytes_now = self.buffer_bytes.load(Ordering::Relaxed);
            if bytes_now >= self.config.max_buffer_bytes {
                tracing::debug!(
                    target_table = T::NAME,
                    bytes_now,
                    max_buffer_bytes = self.config.max_buffer_bytes,
                    "buffer at byte cap, flushing before accepting more",
                );
                // F2.11: If the flush fails (e.g. circuit breaker open), sleep
                // before retrying so we don't busy-spin and peg a core.
                if self.try_flush().await.is_err() {
                    let backoff = Duration::from_millis(
                        (self.config.circuit_breaker_reset_secs * 1000).clamp(100, 1000),
                    );
                    tokio::time::sleep(backoff).await;
                }
                continue;
            }
            tokio::select! {
                result = self.receiver.recv() => match result {
                    Some((doc, ack)) => {
                        let doc_bytes = T::estimate_bytes(&doc);
                        let should_flush = {
                            let mut buffer = self.buffer.lock();
                            buffer.push((doc, ack));
                            self.buffer_bytes.fetch_add(doc_bytes, Ordering::Relaxed);
                            buffer.len() >= self.config.bulk_size
                        };
                        if should_flush {
                            let _ = self.try_flush().await;
                        }
                    }
                    None => {
                        tracing::info!(
                            target_table = T::NAME,
                            "handler channel closed, flushing remaining",
                        );
                        let _ = self.try_flush().await;
                        break;
                    }
                },
                _ = flush_interval.tick() => {
                    let _ = self.try_flush().await;
                }
            }
        }
    }

    fn is_circuit_open(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now < self.circuit_open_until.load(Ordering::Relaxed)
    }

    fn open_circuit(&self) {
        let reset_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + self.config.circuit_breaker_reset_secs;

        self.circuit_open_until.store(reset_at, Ordering::Relaxed);
        common::metrics::INGESTER_CIRCUIT_OPEN
            .with_label_values(&[T::NAME])
            .set(1);
        tracing::error!(
            target_table = T::NAME,
            reset_secs = self.config.circuit_breaker_reset_secs,
            "circuit breaker opened",
        );
    }

    fn record_success(&self) {
        let prev = self.consecutive_failures.swap(0, Ordering::Relaxed);
        common::metrics::INGESTER_CIRCUIT_OPEN
            .with_label_values(&[T::NAME])
            .set(0);
        if prev > 0 {
            tracing::info!(
                target_table = T::NAME,
                prev_failures = prev,
                "connection recovered",
            );
        }
    }

    fn record_failure(&self) {
        let failures = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
        if failures >= self.config.circuit_breaker_threshold {
            self.open_circuit();
        }
    }

    /// Flush the in-memory buffer to the store.
    ///
    /// Returns `Ok(())` if the buffer was empty or the write
    /// succeeded. Returns `Err` if the circuit breaker is open or the
    /// write failed, in which case the good docs are re-queued for the
    /// next attempt. Individual poison rows (rows the store rejects for
    /// good) are dropped, counted and acked (F2.10).
    async fn try_flush(&self) -> Result<()> {
        if self.is_circuit_open() {
            tracing::debug!(
                target_table = T::NAME,
                "circuit breaker open, skipping flush",
            );
            return Err(anyhow::anyhow!("circuit breaker open"));
        }
        let flush_start = Instant::now();

        let batch: Vec<BufferedDoc<T>> = {
            let mut buffer = self.buffer.lock();
            if buffer.is_empty() {
                return Ok(());
            }
            std::mem::take(&mut *buffer)
        };

        // Reserve the byte accounting for this batch — if the flush
        // fails we re-add the bytes when re-buffering.
        let batch_bytes: u64 = batch.iter().map(|(doc, _)| T::estimate_bytes(doc)).sum();
        self.buffer_bytes.fetch_sub(
            batch_bytes.min(self.buffer_bytes.load(Ordering::Relaxed)),
            Ordering::Relaxed,
        );

        // One root span per non-empty batch; empty ticks return above so
        // they make no spans.
        let span = self.writer.flush_span(batch.len(), batch_bytes);
        common::telemetry::start_trace(&span, None);
        self.flush_batch(batch, flush_start).instrument(span).await
    }

    /// Write one batch taken by [`Self::try_flush`].
    async fn flush_batch(&self, batch: Vec<BufferedDoc<T>>, flush_start: Instant) -> Result<()> {
        // The writer borrows the docs across its awaits, so they are split
        // from the acks: `AckHandle` is `Send`-only and a shared borrow of
        // it would make the flusher future non-`Send`.
        let (docs, mut acks): (Vec<T::Doc>, Vec<Option<AckHandle>>) = batch.into_iter().unzip();
        let outcome = self.writer.write(&docs).await;

        #[derive(Clone, Copy, PartialEq, Eq)]
        enum Fate {
            Written,
            Poison,
            Retry,
        }
        let mut fate = vec![Fate::Written; docs.len()];
        for (i, reason) in &outcome.poison {
            T::record_row_write_error(&docs[*i], reason);
            common::metrics::INGESTER_ROWS_DROPPED_TOTAL
                .with_label_values(&[T::NAME])
                .inc();
            fate[*i] = Fate::Poison;
        }
        for &i in &outcome.retry {
            if fate[i] == Fate::Written {
                fate[i] = Fate::Retry;
            }
        }

        let mut written: Vec<BufferedDoc<T>> = Vec::new();
        let mut poison: Vec<BufferedDoc<T>> = Vec::new();
        let mut retry: Vec<BufferedDoc<T>> = Vec::new();
        for (i, doc) in docs.into_iter().enumerate() {
            let item = (doc, acks[i].take());
            match fate[i] {
                Fate::Written => written.push(item),
                Fate::Poison => poison.push(item),
                Fate::Retry => retry.push(item),
            }
        }

        // Ack the poison docs: they are dropped, not retried. Kafka would
        // not redeliver an un-acked offset to this consumer, so a dropped
        // ack would hold the partition's commit at that offset.
        ack_batch(poison).await;

        let failed = !retry.is_empty();
        if failed {
            let error = outcome
                .error
                .map_or_else(|| "rows rejected for retry".to_string(), |e| e.to_string());
            tracing::error!(
                target_table = T::NAME,
                error = %error,
                count = retry.len(),
                "bulk write failed",
            );
            self.record_failure();
            let retry_bytes: u64 = retry.iter().map(|(doc, _)| T::estimate_bytes(doc)).sum();
            self.requeue(retry, retry_bytes);
        } else {
            tracing::debug!(
                target_table = T::NAME,
                count = written.len(),
                "flushed batch to the capture store"
            );
            self.record_success();
        }
        if !written.is_empty() {
            let now = time::OffsetDateTime::now_utc();
            let lag = common::metrics::CAPTURE_COMMIT_LAG_SECONDS.with_label_values(&[T::NAME]);
            for (doc, _) in &written {
                lag.observe(commit_lag_seconds(now, T::completed_at(doc)));
            }
            // Durable now — acknowledge the broker for every written doc.
            ack_batch(written).await;
        }
        observe_flush::<T>(flush_start, if failed { "error" } else { "ok" });
        if failed {
            Err(anyhow::anyhow!("batch write failed"))
        } else {
            Ok(())
        }
    }

    fn requeue(&self, batch: Vec<BufferedDoc<T>>, batch_bytes: u64) {
        let mut buffer = self.buffer.lock();
        buffer.extend(batch);
        self.buffer_bytes.fetch_add(batch_bytes, Ordering::Relaxed);
    }
}

fn observe_flush<T: FlushTarget>(start: Instant, outcome: &str) {
    common::metrics::INGESTER_FLUSH_DURATION_SECONDS
        .with_label_values(&[T::NAME, outcome])
        .observe(start.elapsed().as_secs_f64());
}

/// Seconds from `completed_at` to `now`, clamped at 0 so clock skew or a
/// future timestamp never produces a negative lag.
fn commit_lag_seconds(now: time::OffsetDateTime, completed_at: time::OffsetDateTime) -> f64 {
    (now - completed_at).as_seconds_f64().max(0.0)
}

/// Acknowledge the broker for every doc in a durably-flushed batch.
/// Acks run concurrently (pipelined through the shared broker connection)
/// and are all awaited so they cannot accumulate as detached tasks. A
/// failed ack is logged and left to redelivery; the store's dedup makes the
/// replay harmless. Docs are dropped — only the acks are needed here.
async fn ack_batch<D>(batch: Vec<(D, Option<AckHandle>)>) {
    let mut set = tokio::task::JoinSet::new();
    for (_doc, ack) in batch {
        if let Some(ack) = ack {
            set.spawn(async move { ack.ack().await });
        }
    }
    while let Some(res) = set.join_next().await {
        match res {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "broker ack after flush failed; broker will redeliver")
            }
            Err(e) => tracing::warn!(error = %e, "ack task panicked"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::ch_writer::{ChTarget, ClickHouseWriter};

    #[derive(clickhouse::Row, serde::Serialize)]
    struct TestRow {
        value: u64,
    }

    struct TestTarget;

    impl FlushTarget for TestTarget {
        type Doc = u64;
        const NAME: &'static str = "test";

        fn estimate_bytes(_: &Self::Doc) -> u64 {
            8
        }

        fn completed_at(_: &Self::Doc) -> time::OffsetDateTime {
            time::OffsetDateTime::UNIX_EPOCH
        }
    }

    impl ChTarget for TestTarget {
        type Row = TestRow;

        fn to_row(value: &Self::Doc) -> Self::Row {
            TestRow { value: *value }
        }
    }

    fn test_config() -> BatchConfig {
        BatchConfig {
            bulk_size: 100,
            flush_interval_secs: 3_600,
            max_buffer_bytes: 1_024,
            circuit_breaker_threshold: 5,
            circuit_breaker_reset_secs: 60,
        }
    }

    fn flusher_with(
        writer: Box<dyn BatchWriter<TestTarget>>,
        receiver: mpsc::Receiver<BufferedDoc<TestTarget>>,
    ) -> Flusher<TestTarget> {
        Flusher::<TestTarget> {
            writer,
            config: test_config(),
            buffer: Arc::new(Mutex::new(Vec::new())),
            buffer_bytes: Arc::new(AtomicU64::new(0)),
            receiver,
            consecutive_failures: Arc::new(AtomicU32::new(0)),
            circuit_open_until: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Flusher whose ClickHouse URL refuses connections, so every insert fails.
    fn test_flusher(receiver: mpsc::Receiver<BufferedDoc<TestTarget>>) -> Flusher<TestTarget> {
        flusher_with(
            Box::new(ClickHouseWriter::<TestTarget>::new(
                clickhouse::Client::default().with_url("http://127.0.0.1:1"),
                "test".to_string(),
            )),
            receiver,
        )
    }

    /// Writer that reports a fixed outcome for the first doc batch.
    struct ScriptedWriter {
        poison: Vec<usize>,
        retry: Vec<usize>,
    }

    #[async_trait::async_trait]
    impl BatchWriter<TestTarget> for ScriptedWriter {
        fn flush_span(&self, _rows: usize, _bytes: u64) -> tracing::Span {
            tracing::info_span!("scripted.flush")
        }

        async fn write(&self, _docs: &[u64]) -> WriteOutcome {
            WriteOutcome {
                poison: self
                    .poison
                    .iter()
                    .map(|i| (*i, "bad row".to_string()))
                    .collect(),
                retry: self.retry.clone(),
                error: (!self.retry.is_empty()).then(|| anyhow::anyhow!("store down")),
            }
        }
    }

    struct CountingAck(Arc<AtomicU32>);

    #[async_trait::async_trait]
    impl common::log::AckInner for CountingAck {
        async fn ack_boxed(self: Box<Self>) -> Result<()> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    #[tokio::test]
    async fn flush_makes_one_span_per_non_empty_batch() {
        let (spans, _guard) = crate::test_trace::capture();
        let (_sender, receiver) = mpsc::channel(1);
        let flusher = test_flusher(receiver);

        assert!(flusher.try_flush().await.is_ok(), "empty buffer is a no-op");
        flusher.buffer.lock().push((7, None));
        assert!(
            flusher.try_flush().await.is_err(),
            "ClickHouse is unreachable"
        );

        // The ClickHouse client adds its own spans below the flush span.
        let spans = spans.take();
        let roots: Vec<_> = spans
            .iter()
            .filter(|span| span.parent_span_id == opentelemetry::trace::SpanId::INVALID)
            .collect();
        assert_eq!(roots.len(), 1, "one root span per non-empty batch");
        let span = roots[0];
        assert_eq!(span.name, "clickhouse.flush");
        assert_eq!(
            crate::test_trace::attr(span, "db.collection.name").as_deref(),
            Some("test")
        );
        assert_eq!(crate::test_trace::attr(span, "rows").as_deref(), Some("1"));
        assert!(matches!(
            span.status,
            opentelemetry::trace::Status::Error { .. }
        ));
    }

    #[tokio::test]
    async fn partial_outcome_acks_written_and_poison_and_requeues_the_rest() {
        let (_sender, receiver) = mpsc::channel(1);
        let flusher = flusher_with(
            Box::new(ScriptedWriter {
                poison: vec![1],
                retry: vec![2],
            }),
            receiver,
        );
        let acked = Arc::new(AtomicU32::new(0));
        {
            let mut buffer = flusher.buffer.lock();
            for doc in 0..4u64 {
                let ack = common::log::AckHandle::new(CountingAck(acked.clone()));
                buffer.push((doc, Some(ack)));
            }
        }
        flusher.buffer_bytes.store(32, Ordering::Relaxed);

        assert!(flusher.try_flush().await.is_err(), "one row must retry");

        // Docs 0 and 3 were written and doc 1 was poison: three acks. Doc 2
        // is back in the buffer with its ack unfired.
        assert_eq!(acked.load(Ordering::Relaxed), 3);
        let buffer = flusher.buffer.lock();
        assert_eq!(buffer.len(), 1);
        assert_eq!(buffer[0].0, 2);
        assert_eq!(flusher.buffer_bytes.load(Ordering::Relaxed), 8);
        assert_eq!(flusher.consecutive_failures.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn commit_lag_is_elapsed_seconds_clamped_at_zero() {
        let now = time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(100);
        let past = now - time::Duration::milliseconds(2_500);
        assert_eq!(commit_lag_seconds(now, past), 2.5);
        let future = now + time::Duration::seconds(30);
        assert_eq!(commit_lag_seconds(now, future), 0.0);
    }
}
