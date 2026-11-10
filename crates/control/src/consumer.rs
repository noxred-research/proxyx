//! Consumes the captures log and dispatches to the pipeline.
//!
//! The broker is hidden behind `common::log::CaptureLogConsumer`. This
//! file owns only the API-side semantics: protobuf envelope decoding,
//! capture-vs-SessionEnd dispatch, and the order in which sessions close.
//!
//! A capture is acked only after its ClickHouse insert succeeds. Every
//! polled message gets a sequence number, and a session's row flips to
//! `closed` in PG once its SessionEnd and every message read before it are
//! acked. At that point every capture of the session read by this consumer
//! is in ClickHouse. With `session_lifecycle_writes` off, the session is
//! released the same way but the PG row is left for the serving ingester.
//! The SessionEnd itself is acked as soon as it is dispatched, so a
//! ClickHouse outage never leaves a broker offset un-acked.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::db::Db;
use anyhow::Result;
use async_trait::async_trait;
use parking_lot::Mutex;
use prost::Message;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::Instrument as _;
use uuid::Uuid;

use common::log::{AckHandle, AckInner, CaptureLogConsumer};
use common::wire::{self, request_log_message};

use crate::pipeline::PipelineMessage;

/// Maximum messages pulled in one `poll`.
const BATCH_SIZE: usize = 10;

enum DispatchOutcome {
    /// Continue with the next message.
    Continue,
    /// Pipeline channel closed; stop the consumer.
    Stop,
}

/// A session ready to close, with the span started when its SessionEnd
/// arrived.
struct SessionClose {
    session_id: Uuid,
    span: tracing::Span,
}

/// Tracks which polled messages are acked and releases each SessionEnd
/// once every message read before it is acked.
///
/// Every message must be acked. A message that is never acked holds back
/// every later session close in this process.
#[derive(Default)]
struct CloseOrder {
    /// Every sequence number below this is acked.
    acked_below: u64,
    /// Acked sequence numbers at or above `acked_below`.
    acked: BTreeSet<u64>,
    /// Sequence number of a SessionEnd → the session it closes.
    pending: BTreeMap<u64, SessionClose>,
}

impl CloseOrder {
    /// Mark `seq` acked. Returns the sessions whose SessionEnd and every
    /// earlier message are now acked.
    fn ack(&mut self, seq: u64) -> Vec<SessionClose> {
        self.acked.insert(seq);
        while self.acked.remove(&self.acked_below) {
            self.acked_below += 1;
        }
        let still_pending = self.pending.split_off(&self.acked_below);
        std::mem::replace(&mut self.pending, still_pending)
            .into_values()
            .collect()
    }
}

/// Broker ack that also advances the [`CloseOrder`].
struct OrderedAck {
    inner: AckHandle,
    seq: u64,
    order: Arc<Mutex<CloseOrder>>,
    closes: mpsc::UnboundedSender<SessionClose>,
}

#[async_trait]
impl AckInner for OrderedAck {
    async fn ack_boxed(self: Box<Self>) -> Result<()> {
        self.finish(false).await
    }

    async fn reject_boxed(self: Box<Self>) -> Result<()> {
        self.finish(true).await
    }
}

impl OrderedAck {
    /// Ack or reject the broker message, then advance the close order.
    async fn finish(self, reject: bool) -> Result<()> {
        let OrderedAck {
            inner,
            seq,
            order,
            closes,
        } = self;
        let result = if reject {
            inner.reject().await
        } else {
            inner.ack().await
        };
        // The message is handled even when the broker ack fails (the
        // capture is already in ClickHouse), so it still counts here.
        let ready = order.lock().ack(seq);
        for close in ready {
            // Fails only when the closer stopped at shutdown; the row stays
            // `consuming` and the reaper re-sends its SessionEnd.
            let _ = closes.send(close);
        }
        result
    }
}

/// Pulls envelopes off the captures log and dispatches them to the
/// in-process pipeline.
pub struct RequestLogConsumer {
    consumer: Box<dyn CaptureLogConsumer>,
    sender: mpsc::Sender<PipelineMessage>,
    next_seq: u64,
    order: Arc<Mutex<CloseOrder>>,
    closes: mpsc::UnboundedSender<SessionClose>,
}

impl RequestLogConsumer {
    /// Build the consumer and spawn the task that marks sessions closed.
    /// `db` is `None` when `session_lifecycle_writes` is off.
    pub fn new(
        consumer: Box<dyn CaptureLogConsumer>,
        db: Option<Db>,
        sender: mpsc::Sender<PipelineMessage>,
    ) -> Self {
        let (closes, closes_rx) = mpsc::unbounded_channel();
        tokio::spawn(close_sessions(db, closes_rx));
        Self {
            consumer,
            sender,
            next_seq: 0,
            order: Arc::new(Mutex::new(CloseOrder::default())),
            closes,
        }
    }

    /// Run the consumer loop until shutdown is signalled.
    pub async fn run(mut self, shutdown: CancellationToken) {
        tracing::info!("request log consumer started");

        loop {
            if shutdown.is_cancelled() {
                tracing::info!("request log consumer shutting down");
                break;
            }

            let batch = match self.consumer.poll(BATCH_SIZE).await {
                Ok(batch) => batch,
                Err(e) => {
                    tracing::warn!(error = %e, "captures log poll failed");
                    tokio::select! {
                        _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {},
                        _ = shutdown.cancelled() => break,
                    }
                    continue;
                }
            };

            for msg in batch {
                let seq = self.next_seq;
                self.next_seq += 1;
                let ack = AckHandle::new(OrderedAck {
                    inner: msg.ack,
                    seq,
                    order: Arc::clone(&self.order),
                    closes: self.closes.clone(),
                });
                match self
                    .dispatch(&msg.payload, msg.session_offset, seq, ack)
                    .await
                {
                    DispatchOutcome::Continue => {}
                    DispatchOutcome::Stop => return,
                }
            }
        }
    }

    async fn dispatch(
        &mut self,
        payload: &[u8],
        session_offset: u64,
        seq: u64,
        ack: AckHandle,
    ) -> DispatchOutcome {
        let envelope = match wire::RequestLogMessage::decode(payload) {
            Ok(env) => env,
            Err(e) => {
                common::metrics::INGESTER_MESSAGES_TOTAL
                    .with_label_values(&["error"])
                    .inc();
                tracing::warn!(error = %e, "failed to decode protobuf envelope; rejecting");
                // RabbitMQ dead-letters it; the other brokers ack it.
                if let Err(e) = ack.reject().await {
                    tracing::warn!(error = %e, "reject of malformed envelope failed");
                }
                return DispatchOutcome::Continue;
            }
        };

        common::metrics::INGESTER_MESSAGES_TOTAL
            .with_label_values(&["ok"])
            .inc();
        match envelope.kind {
            Some(request_log_message::Kind::Request(captured)) => {
                self.dispatch_capture(captured, session_offset, ack).await
            }
            Some(request_log_message::Kind::SessionEnd(event)) => {
                self.dispatch_session_end(event, seq, ack).await;
                DispatchOutcome::Continue
            }
            Some(request_log_message::Kind::WsMessage(message)) => {
                self.dispatch_ws_message(message, session_offset, ack).await
            }
            None => {
                tracing::warn!("envelope with no kind; acking and skipping");
                if let Err(e) = ack.ack().await {
                    tracing::warn!(error = %e, "ack of empty envelope failed");
                }
                DispatchOutcome::Continue
            }
        }
    }

    async fn dispatch_capture(
        &mut self,
        captured: wire::CapturedRequest,
        session_offset: u64,
        ack: AckHandle,
    ) -> DispatchOutcome {
        // The ack rides with the capture and fires only after the batch is
        // durably flushed to ClickHouse. The channel closes only at
        // shutdown; the capture is then read again after restart.
        if self
            .sender
            .send(PipelineMessage::Capture {
                captured: Box::new(captured),
                session_offset,
                ack,
            })
            .await
            .is_err()
        {
            tracing::warn!("pipeline channel closed, stopping consumer");
            return DispatchOutcome::Stop;
        }
        DispatchOutcome::Continue
    }

    async fn dispatch_ws_message(
        &mut self,
        message: wire::CapturedWsMessage,
        session_offset: u64,
        ack: AckHandle,
    ) -> DispatchOutcome {
        // Ack fires post-flush; see `dispatch_capture`.
        if self
            .sender
            .send(PipelineMessage::WsMessage {
                message: Box::new(message),
                session_offset,
                ack,
            })
            .await
            .is_err()
        {
            tracing::warn!("pipeline channel closed, stopping consumer (ws)");
            return DispatchOutcome::Stop;
        }
        DispatchOutcome::Continue
    }

    /// Register the session to close once every earlier message is acked,
    /// then ack the SessionEnd. The row stays `consuming` until then.
    ///
    /// If the consumer stops before the close, Kafka has not committed past
    /// the unacked captures before the SessionEnd, so the next owner of the
    /// partition reads it again. Otherwise (Redis Streams, or a failed PG
    /// update) the reaper re-sends the SessionEnd for the `consuming` row.
    async fn dispatch_session_end(
        &mut self,
        event: wire::SessionEndEvent,
        seq: u64,
        ack: AckHandle,
    ) {
        let session_id = Uuid::from_slice(&event.session_id).unwrap_or_else(|_| Uuid::nil());
        tracing::info!(
            %session_id,
            org_id = %event.org_id,
            "session ended, waiting for earlier captures to be stored",
        );
        // Root span from SessionEnd receipt until the row is closed.
        // Search Tempo by `session_id`.
        let span = tracing::info_span!(
            "proxyx.session.end",
            %session_id,
            org_id = %event.org_id,
            source = %event.source,
            source_id = %event.source_id,
            trace_id = tracing::field::Empty,
        );
        common::telemetry::start_trace(&span, None);

        self.order
            .lock()
            .pending
            .insert(seq, SessionClose { session_id, span });
        if let Err(e) = ack.ack().await {
            tracing::warn!(%session_id, error = %e, "ack of SessionEnd failed");
        }
    }
}

/// Mark each released session `closed` in PG, or only log it when
/// `db` is `None`. Runs until every sender is dropped.
async fn close_sessions(db: Option<Db>, mut closes: mpsc::UnboundedReceiver<SessionClose>) {
    while let Some(SessionClose { session_id, span }) = closes.recv().await {
        let Some(db) = &db else {
            tracing::debug!(
                parent: &span,
                %session_id,
                "session flushed; session_lifecycle writes disabled",
            );
            continue;
        };
        async {
            let result = db.close_session(session_id).await;
            match result {
                Ok(_) => tracing::info!(%session_id, "session closed"),
                Err(e) => tracing::warn!(
                    %session_id,
                    error = %e,
                    "failed to mark session_lifecycle closed; the reaper will re-send SessionEnd",
                ),
            }
        }
        .instrument(span)
        .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn order_with_session_end_at(seq: u64) -> CloseOrder {
        let mut order = CloseOrder::default();
        order.pending.insert(
            seq,
            SessionClose {
                session_id: Uuid::from_u128(seq as u128),
                span: tracing::Span::none(),
            },
        );
        order
    }

    fn closed(sessions: Vec<SessionClose>) -> Vec<Uuid> {
        sessions.into_iter().map(|close| close.session_id).collect()
    }

    #[test]
    fn session_closes_only_after_every_earlier_message_is_acked() {
        let mut order = order_with_session_end_at(2);
        assert!(order.ack(2).is_empty(), "captures 0 and 1 are not stored");
        assert!(order.ack(0).is_empty(), "capture 1 is not stored");
        assert_eq!(closed(order.ack(1)), [Uuid::from_u128(2)]);
    }

    #[test]
    fn later_messages_do_not_hold_back_a_session_end() {
        let mut order = order_with_session_end_at(1);
        assert_eq!(closed(order.ack(1)), Vec::<Uuid>::new());
        assert_eq!(closed(order.ack(0)), [Uuid::from_u128(1)]);
        assert!(order.pending.is_empty());
        assert!(order.ack(3).is_empty(), "seq 2 is still in flight");
    }

    #[test]
    fn one_ack_can_release_several_sessions_in_order() {
        let mut order = order_with_session_end_at(1);
        order.pending.insert(
            3,
            SessionClose {
                session_id: Uuid::from_u128(3),
                span: tracing::Span::none(),
            },
        );
        assert!(order.ack(1).is_empty());
        assert!(order.ack(2).is_empty());
        assert!(order.ack(3).is_empty());
        assert_eq!(
            closed(order.ack(0)),
            [Uuid::from_u128(1), Uuid::from_u128(3)]
        );
    }

    struct FailingAck;

    #[async_trait]
    impl AckInner for FailingAck {
        async fn ack_boxed(self: Box<Self>) -> Result<()> {
            Err(anyhow::anyhow!("broker unavailable"))
        }
    }

    #[tokio::test]
    async fn failed_broker_ack_still_releases_the_session() {
        let order = Arc::new(Mutex::new(order_with_session_end_at(0)));
        let (closes, mut closes_rx) = mpsc::unbounded_channel();
        let ack = AckHandle::new(OrderedAck {
            inner: AckHandle::new(FailingAck),
            seq: 0,
            order,
            closes,
        });

        assert!(ack.ack().await.is_err(), "the broker error is returned");
        let close = closes_rx.try_recv().expect("session released");
        assert_eq!(close.session_id, Uuid::from_u128(0));
    }

    struct RecordingAck(Arc<std::sync::atomic::AtomicBool>);

    #[async_trait]
    impl AckInner for RecordingAck {
        async fn ack_boxed(self: Box<Self>) -> Result<()> {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
    }

    /// With `session_lifecycle_writes` off the closer has no pool, so a
    /// released session cannot reach Postgres.
    #[tokio::test]
    async fn disabled_lifecycle_writes_release_the_session_without_postgres() {
        let order = Arc::new(Mutex::new(order_with_session_end_at(0)));
        let (closes, closes_rx) = mpsc::unbounded_channel();
        let closer = tokio::spawn(close_sessions(None, closes_rx));
        let broker_acked = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ack = AckHandle::new(OrderedAck {
            inner: AckHandle::new(RecordingAck(Arc::clone(&broker_acked))),
            seq: 0,
            order: Arc::clone(&order),
            closes,
        });

        ack.ack().await.expect("broker ack succeeds");
        assert!(broker_acked.load(std::sync::atomic::Ordering::SeqCst));
        assert!(order.lock().pending.is_empty(), "session released");
        tokio::time::timeout(std::time::Duration::from_secs(1), closer)
            .await
            .expect("closer drains the release without Postgres")
            .expect("closer does not panic");
    }
}
