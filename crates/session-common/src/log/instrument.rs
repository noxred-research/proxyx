//! Broker-neutral metrics: wrappers that count what a producer publishes and
//! what a consumer receives and acks, and the connection state that Kafka and
//! RabbitMQ report.
//!
//! The wrappers sit between the process and any [`CaptureLogProducer`] or
//! [`CaptureLogConsumer`], so the three brokers report the same families,
//! labelled by `broker`.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;

use super::{
    AckHandle, AckInner, CaptureLogConsumer, CaptureLogProducer, LogMessage, PublishOutcome,
};
use crate::metrics;

/// Connection state of one producer or consumer: the
/// `proxyx_broker_connected` gauge, the reconnect counter and an atomic for
/// health checks.
pub struct ConnState {
    broker: &'static str,
    role: &'static str,
    up: AtomicBool,
    was_down: AtomicBool,
}

impl ConnState {
    /// A state that starts down; the first [`set(true)`](Self::set) is the
    /// initial connect and does not count as a reconnect.
    pub fn new(broker: &'static str, role: &'static str) -> Arc<Self> {
        metrics::BROKER_CONNECTED
            .with_label_values(&[broker, role])
            .set(0);
        Arc::new(Self {
            broker,
            role,
            up: AtomicBool::new(false),
            was_down: AtomicBool::new(false),
        })
    }

    /// Record that the connection is up or down. Going up again after a loss
    /// counts one reconnect.
    pub fn set(&self, up: bool) {
        let previous = self.up.swap(up, Ordering::Relaxed);
        metrics::BROKER_CONNECTED
            .with_label_values(&[self.broker, self.role])
            .set(i64::from(up));
        if !up {
            // A first failed connect is a loss too: the next success is the
            // connection coming back.
            self.was_down.store(true, Ordering::Relaxed);
        } else if !previous && self.was_down.swap(false, Ordering::Relaxed) {
            metrics::BROKER_RECONNECTS_TOTAL
                .with_label_values(&[self.broker, self.role])
                .inc();
        }
    }

    pub fn is_up(&self) -> bool {
        self.up.load(Ordering::Relaxed)
    }
}

/// Wrap `inner` so its publishes are counted under `broker`.
pub fn instrument_producer(
    broker: &'static str,
    inner: Box<dyn CaptureLogProducer>,
) -> Box<dyn CaptureLogProducer> {
    Box::new(InstrumentedProducer { broker, inner })
}

/// Wrap `inner` so its messages and acks are counted under `broker`.
pub fn instrument_consumer(
    broker: &'static str,
    inner: Box<dyn CaptureLogConsumer>,
) -> Box<dyn CaptureLogConsumer> {
    Box::new(InstrumentedConsumer { broker, inner })
}

struct InstrumentedProducer {
    broker: &'static str,
    inner: Box<dyn CaptureLogProducer>,
}

impl InstrumentedProducer {
    fn count(&self, outcomes: &[PublishOutcome], started: Instant) {
        metrics::BROKER_PUBLISH_DURATION_SECONDS
            .with_label_values(&[self.broker])
            .observe(started.elapsed().as_secs_f64());
        for outcome in outcomes {
            let label = match outcome {
                PublishOutcome::Published => "published",
                PublishOutcome::Failed(_) => "failed",
                PublishOutcome::NotSent => "not_sent",
            };
            metrics::BROKER_PUBLISH_RECORDS_TOTAL
                .with_label_values(&[self.broker, label])
                .inc();
        }
    }
}

#[async_trait]
impl CaptureLogProducer for InstrumentedProducer {
    async fn publish(&self, key: &[u8], payload: Bytes) -> Result<()> {
        let started = Instant::now();
        let result = self.inner.publish(key, payload).await;
        let outcome = match &result {
            Ok(()) => PublishOutcome::Published,
            Err(error) => PublishOutcome::Failed(anyhow::anyhow!("{error}")),
        };
        self.count(&[outcome], started);
        result
    }

    async fn publish_batch(&self, records: &[(Bytes, Bytes)]) -> Vec<PublishOutcome> {
        let started = Instant::now();
        let outcomes = self.inner.publish_batch(records).await;
        self.count(&outcomes, started);
        outcomes
    }

    async fn flush_and_close(&self, timeout: Duration) {
        self.inner.flush_and_close(timeout).await;
    }

    fn healthy(&self) -> bool {
        self.inner.healthy()
    }
}

struct InstrumentedConsumer {
    broker: &'static str,
    inner: Box<dyn CaptureLogConsumer>,
}

struct CountedAck {
    broker: &'static str,
    inner: AckHandle,
}

#[async_trait]
impl AckInner for CountedAck {
    async fn ack_boxed(self: Box<Self>) -> Result<()> {
        let result = self.inner.ack().await;
        let outcome = if result.is_ok() { "ok" } else { "error" };
        metrics::BROKER_ACKS_TOTAL
            .with_label_values(&[self.broker, outcome])
            .inc();
        result
    }

    async fn reject_boxed(self: Box<Self>) -> Result<()> {
        let result = self.inner.reject().await;
        let outcome = if result.is_ok() { "rejected" } else { "error" };
        metrics::BROKER_ACKS_TOTAL
            .with_label_values(&[self.broker, outcome])
            .inc();
        result
    }
}

#[async_trait]
impl CaptureLogConsumer for InstrumentedConsumer {
    async fn poll(&mut self, max: usize) -> Result<Vec<LogMessage>> {
        let broker = self.broker;
        let mut messages = self.inner.poll(max).await?;
        metrics::BROKER_CONSUMED_TOTAL
            .with_label_values(&[broker])
            .inc_by(messages.len() as f64);
        for message in &mut messages {
            let inner = std::mem::replace(&mut message.ack, AckHandle::new(Placeholder));
            message.ack = AckHandle::new(CountedAck { broker, inner });
        }
        Ok(messages)
    }

    fn connection(&self) -> Option<Arc<ConnState>> {
        self.inner.connection()
    }
}

/// Stands in for the real ack while it is moved into [`CountedAck`].
struct Placeholder;

#[async_trait]
impl AckInner for Placeholder {
    async fn ack_boxed(self: Box<Self>) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    struct FakeProducer {
        outcomes: Mutex<Vec<PublishOutcome>>,
    }

    #[async_trait]
    impl CaptureLogProducer for FakeProducer {
        async fn publish(&self, _key: &[u8], _payload: Bytes) -> Result<()> {
            Ok(())
        }

        async fn publish_batch(&self, _records: &[(Bytes, Bytes)]) -> Vec<PublishOutcome> {
            std::mem::take(&mut *self.outcomes.lock())
        }

        async fn flush_and_close(&self, _timeout: Duration) {}
    }

    fn count(broker: &str, outcome: &str) -> f64 {
        metrics::BROKER_PUBLISH_RECORDS_TOTAL
            .with_label_values(&[broker, outcome])
            .get()
    }

    #[tokio::test]
    async fn producer_wrapper_counts_each_outcome() {
        let producer = instrument_producer(
            "test_producer",
            Box::new(FakeProducer {
                outcomes: Mutex::new(vec![
                    PublishOutcome::Published,
                    PublishOutcome::Failed(anyhow::anyhow!("boom")),
                    PublishOutcome::NotSent,
                    PublishOutcome::Published,
                ]),
            }),
        );
        let records = vec![(Bytes::from_static(b"k"), Bytes::from_static(b"v")); 4];
        let outcomes = producer.publish_batch(&records).await;
        assert_eq!(outcomes.len(), 4);
        assert_eq!(count("test_producer", "published"), 2.0);
        assert_eq!(count("test_producer", "failed"), 1.0);
        assert_eq!(count("test_producer", "not_sent"), 1.0);
    }

    struct Acker(Arc<AtomicBool>);

    #[async_trait]
    impl AckInner for Acker {
        async fn ack_boxed(self: Box<Self>) -> Result<()> {
            self.0.store(true, Ordering::Relaxed);
            Ok(())
        }
    }

    struct FakeConsumer(Vec<LogMessage>);

    #[async_trait]
    impl CaptureLogConsumer for FakeConsumer {
        async fn poll(&mut self, _max: usize) -> Result<Vec<LogMessage>> {
            Ok(std::mem::take(&mut self.0))
        }
    }

    #[tokio::test]
    async fn consumer_wrapper_counts_messages_and_acks_and_still_acks() {
        let acked = Arc::new(AtomicBool::new(false));
        let mut consumer = instrument_consumer(
            "test_consumer",
            Box::new(FakeConsumer(vec![LogMessage {
                key: Bytes::new(),
                payload: Bytes::new(),
                session_offset: 1,
                ack: AckHandle::new(Acker(acked.clone())),
            }])),
        );
        let mut messages = consumer.poll(10).await.unwrap();
        assert_eq!(
            metrics::BROKER_CONSUMED_TOTAL
                .with_label_values(&["test_consumer"])
                .get(),
            1.0
        );
        messages.pop().unwrap().ack.ack().await.unwrap();
        assert!(acked.load(Ordering::Relaxed));
        assert_eq!(
            metrics::BROKER_ACKS_TOTAL
                .with_label_values(&["test_consumer", "ok"])
                .get(),
            1.0
        );
    }

    #[test]
    fn conn_state_counts_a_reconnect_only_after_a_loss() {
        let state = ConnState::new("test_conn", "consumer");
        let reconnects = || {
            metrics::BROKER_RECONNECTS_TOTAL
                .with_label_values(&["test_conn", "consumer"])
                .get()
        };
        state.set(true);
        assert!(state.is_up());
        assert_eq!(reconnects(), 0.0, "the first connect is not a reconnect");
        state.set(false);
        assert!(!state.is_up());
        state.set(false);
        state.set(true);
        assert_eq!(reconnects(), 1.0);
        state.set(true);
        assert_eq!(reconnects(), 1.0);
    }
}
