//! Request log pipeline for dispatching captures (HTTP + WebSocket) to the
//! capture store (ClickHouse or OpenSearch, see [`crate::capture_store`]).

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::sync::mpsc;

use common::log::AckHandle;
use common::wire;

use crate::pipeline::clickhouse::ClickHouseConfig;

mod batch_handler;
mod ch_writer;
pub mod clickhouse;
mod normalize;
pub mod ws_clickhouse;

pub(crate) use batch_handler::{BatchConfig, BatchHandler, BatchWriter, FlushTarget, WriteOutcome};
pub(crate) use normalize::{NormalizedCapturedRequest, NormalizedWsMessage};

/// Messages on the dispatch mpsc. HTTP and WS captures share one FIFO.
pub enum PipelineMessage {
    /// Captured HTTP request to insert. Boxed to keep the enum slot small.
    /// `ack` is acknowledged to the broker only after the doc's batch is
    /// durably flushed to the capture store (at-least-once delivery).
    Capture {
        captured: Box<wire::CapturedRequest>,
        session_offset: u64,
        ack: AckHandle,
    },
    /// Captured WebSocket message to insert. Boxed for the same reason.
    WsMessage {
        message: Box<wire::CapturedWsMessage>,
        session_offset: u64,
        ack: AckHandle,
    },
}

/// Write side of a capture store: takes normalized captures and acks them
/// once a batch is durable.
#[async_trait::async_trait]
pub trait CaptureSink: Send + Sync + 'static {
    /// Stage one HTTP capture. Applies backpressure when the buffer is full.
    /// `ack` fires after the capture's batch was written to the store.
    async fn send_http(
        &self,
        captured: &wire::CapturedRequest,
        session_offset: u64,
        ack: Option<AckHandle>,
    ) -> Result<()>;

    /// Stage one WebSocket message; same contract as [`Self::send_http`].
    async fn send_ws(
        &self,
        message: &wire::CapturedWsMessage,
        session_offset: u64,
        ack: Option<AckHandle>,
    ) -> Result<()>;

    /// Flush what is buffered and stop, within `timeout` per handler.
    async fn flush_and_close(&self, timeout: Duration);

    /// Whether the store's circuit breaker is open for either table: the
    /// ingester is then not writing and reports itself unhealthy.
    fn circuit_open(&self) -> bool;
}

/// ClickHouse sink: one batching handler per table.
pub struct ClickHouseSink {
    http: clickhouse::ClickHouseHandler,
    ws: ws_clickhouse::WsClickHouseHandler,
}

impl ClickHouseSink {
    /// Build both handlers; spawns their flusher tasks.
    pub fn new(
        config: ClickHouseConfig,
        correlation_id_header: Option<String>,
        parent_correlation_id_header: Option<String>,
        account_id_header: Option<String>,
        tool_call_id_header: Option<String>,
    ) -> Result<Self> {
        let http = clickhouse::ClickHouseHandler::new(
            config.clone(),
            correlation_id_header,
            parent_correlation_id_header,
            account_id_header,
            tool_call_id_header,
        )?;
        let ws = ws_clickhouse::WsClickHouseHandler::new(config)?;
        Ok(Self { http, ws })
    }
}

#[async_trait::async_trait]
impl CaptureSink for ClickHouseSink {
    async fn send_http(
        &self,
        captured: &wire::CapturedRequest,
        session_offset: u64,
        ack: Option<AckHandle>,
    ) -> Result<()> {
        self.http.send(captured, session_offset, ack).await
    }

    async fn send_ws(
        &self,
        message: &wire::CapturedWsMessage,
        session_offset: u64,
        ack: Option<AckHandle>,
    ) -> Result<()> {
        self.ws.send(message, session_offset, ack).await
    }

    async fn flush_and_close(&self, timeout: Duration) {
        self.http.flush_and_close(timeout).await;
        self.ws.flush_and_close(timeout).await;
    }

    fn circuit_open(&self) -> bool {
        self.http.circuit_open() || self.ws.circuit_open()
    }
}

/// In-process event pipeline for captured requests.
///
/// Receives `PipelineMessage` events from the consumer and forwards them to
/// the capture sink.
pub struct RequestPipeline {
    sender: parking_lot::Mutex<Option<mpsc::Sender<PipelineMessage>>>,
    drain: parking_lot::Mutex<Option<tokio::task::JoinHandle<()>>>,
    sink: Arc<dyn CaptureSink>,
}

impl RequestPipeline {
    /// Create a new pipeline that feeds `sink`.
    ///
    /// Spawns a background drain task. Returns the pipeline handle.
    pub fn new(sink: Arc<dyn CaptureSink>, channel_capacity: usize) -> Self {
        let (sender, receiver) = mpsc::channel(channel_capacity);
        let drain = tokio::spawn(drain_task(receiver, sink.clone()));
        Self {
            sender: parking_lot::Mutex::new(Some(sender)),
            drain: parking_lot::Mutex::new(Some(drain)),
            sink,
        }
    }

    /// The sink this pipeline feeds.
    pub fn sink(&self) -> Arc<dyn CaptureSink> {
        self.sink.clone()
    }

    /// Get a clone of the sender for the consumer to use.
    pub fn sender(&self) -> mpsc::Sender<PipelineMessage> {
        self.sender
            .lock()
            .as_ref()
            .expect("pipeline sender already closed")
            .clone()
    }

    /// Close the dispatch channel and drain remaining events; flush the
    /// handlers within the supplied `timeout`.
    pub async fn flush_and_close(&self, timeout: Duration) {
        let _ = self.sender.lock().take();
        let task = self.drain.lock().take();
        let Some(task) = task else { return };
        let half = timeout / 2;
        match tokio::time::timeout(half, task).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "pipeline drain task panicked");
                return;
            }
            Err(_) => {
                tracing::warn!("pipeline drain task timed out before handler flush");
                return;
            }
        }

        self.sink.flush_and_close(half).await;
    }
}

/// Background task that drains the dispatch mpsc and forwards each message
/// to the sink.
async fn drain_task(mut receiver: mpsc::Receiver<PipelineMessage>, sink: Arc<dyn CaptureSink>) {
    while let Some(msg) = receiver.recv().await {
        match msg {
            PipelineMessage::Capture {
                captured,
                session_offset,
                ack,
            } => {
                if let Err(e) = sink.send_http(&captured, session_offset, Some(ack)).await {
                    // Only happens at shutdown, when the handler is closed.
                    // The ack was dropped, so the capture is read again
                    // after restart. Dedup makes the replay safe.
                    tracing::error!(
                        error = %e,
                        event_id = ?captured.event_id,
                        session_offset,
                        "capture store http handler failed"
                    );
                }
            }
            PipelineMessage::WsMessage {
                message,
                session_offset,
                ack,
            } => {
                if let Err(e) = sink.send_ws(&message, session_offset, Some(ack)).await {
                    tracing::error!(
                        error = %e,
                        event_id = ?message.event_id,
                        parent_event_id = ?message.parent_event_id,
                        session_offset,
                        "capture store ws handler failed"
                    );
                }
            }
        }
    }

    tracing::info!("pipeline: drain task stopped (channel closed)");
}
