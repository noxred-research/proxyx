//! Captures-bus abstraction: producer + consumer traits over the broker.
//!
//! The transport-specific implementation lives in submodules (e.g.
//! `redis_stream`). Callers depend only on these traits; swapping brokers
//! (Redis Streams → Redpanda → ...) is a matter of choosing a different
//! impl at startup (`broker_kind`: `redis_stream`, `kafka` or `rabbitmq`).
//!
//! Contract:
//! - `publish` returns iff the message survives broker restart (durable).
//! - Messages with the same `key` are delivered in publish order.
//! - Delivery is at-least-once. Dedup downstream via `event_id`.
//! - `session_offset` is monotonic within a key's partition and serves as
//!   the sub-millisecond tiebreaker on the consumer side. Redis Streams and
//!   Kafka take it from the broker (stream id, partition offset); RabbitMQ
//!   has no offsets, so the producer stamps it (see [`rabbitmq`]).

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Deserializer, Serialize};

pub mod instrument;
pub mod kafka;
pub mod rabbitmq;
pub mod redis_stream;

pub use instrument::{ConnState, instrument_consumer, instrument_producer};

/// Which broker carries the captures log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokerKind {
    /// Redis Streams (default).
    #[default]
    RedisStream,
    /// Apache Kafka or a Kafka-compatible broker such as Redpanda. Needs the
    /// `[kafka]` section.
    Kafka,
    /// RabbitMQ (quorum queues). Needs the `[rabbitmq]` section.
    Rabbitmq,
}

impl BrokerKind {
    /// Stable name, used as the `broker` metric label and in messages.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RedisStream => "redis_stream",
            Self::Kafka => "kafka",
            Self::Rabbitmq => "rabbitmq",
        }
    }
}

/// Set when a configuration used a deprecated `redpanda` name.
static LEGACY_NAME_USED: AtomicBool = AtomicBool::new(false);

impl<'de> Deserialize<'de> for BrokerKind {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let name = String::deserialize(d)?;
        match name.as_str() {
            "redis_stream" => Ok(Self::RedisStream),
            "kafka" => Ok(Self::Kafka),
            "rabbitmq" => Ok(Self::Rabbitmq),
            // Deprecated alias, accepted for one release.
            "redpanda" => {
                LEGACY_NAME_USED.store(true, Ordering::Relaxed);
                Ok(Self::Kafka)
            }
            other => Err(serde::de::Error::custom(format!(
                "unknown broker_kind {other:?}: expected \"redis_stream\", \"kafka\" or \"rabbitmq\""
            ))),
        }
    }
}

/// Pick the `[kafka]` section, falling back to the deprecated `[redpanda]`
/// one. Both present is an error. Using the old name is logged by
/// [`warn_deprecated_broker_names`].
pub fn resolve_kafka_section<'a>(
    kafka: Option<&'a kafka::KafkaConfig>,
    legacy: Option<&'a kafka::KafkaConfig>,
) -> Result<Option<&'a kafka::KafkaConfig>> {
    match (kafka, legacy) {
        (Some(_), Some(_)) => anyhow::bail!(
            "both [kafka] and the deprecated [redpanda] section are set; remove [redpanda]"
        ),
        (None, Some(legacy)) => {
            LEGACY_NAME_USED.store(true, Ordering::Relaxed);
            Ok(Some(legacy))
        }
        (kafka, None) => Ok(kafka),
    }
}

/// Log a deprecation warning when the configuration used `redpanda` as the
/// broker kind or section name. Call once after logging is initialised.
pub fn warn_deprecated_broker_names() {
    if LEGACY_NAME_USED.load(Ordering::Relaxed) {
        tracing::warn!(
            "the `redpanda` broker_kind and [redpanda] section are deprecated and will be \
             removed in the next release: use broker_kind = \"kafka\" and [kafka] \
             (PROXYX_*_KAFKA__* environment variables)"
        );
    }
}

/// Outcome for one record in a batch. Only `Failed` consumes a retry attempt.
#[derive(Debug)]
pub enum PublishOutcome {
    Published,
    Failed(anyhow::Error),
    NotSent,
}

/// Sink for captured-log messages. Ownership is shared (`Send + Sync`)
/// because every proxy worker pushes through the same producer.
#[async_trait]
pub trait CaptureLogProducer: Send + Sync {
    /// Publish `payload` keyed by `key`. The key controls partitioning
    /// (and therefore per-key ordering) on brokers that partition by it;
    /// on single-partition brokers it is recorded but ignored for routing.
    async fn publish(&self, key: &[u8], payload: Bytes) -> Result<()>;

    /// Publish `records` as `(key, payload)` pairs and return one outcome per
    /// record, in input order. Records with the same key are published in
    /// input order, and no record is published after a failed record with
    /// the same key. Blocked records return `NotSent`, which must not consume
    /// their retry attempts. Exception: a record that can never be published
    /// (too large) fails alone.
    ///
    /// The default publishes one record at a time and stops at the first
    /// failure. Brokers that can send many records per request override it.
    async fn publish_batch(&self, records: &[(Bytes, Bytes)]) -> Vec<PublishOutcome> {
        let mut results = Vec::with_capacity(records.len());
        for (key, payload) in records {
            let result = self.publish(key, payload.clone()).await;
            let failed = result.is_err();
            results.push(match result {
                Ok(()) => PublishOutcome::Published,
                Err(error) => PublishOutcome::Failed(error),
            });
            if failed {
                break;
            }
        }
        results.resize_with(records.len(), || PublishOutcome::NotSent);
        results
    }

    /// Flush in-flight messages and release resources, bounded by
    /// `timeout`. Idempotent.
    async fn flush_and_close(&self, timeout: Duration);

    /// Whether the producer currently has a working broker connection: false
    /// after a failed connect or publish until the next success. Brokers that
    /// cannot tell (Redis) report true.
    fn healthy(&self) -> bool {
        true
    }

    /// Check that the broker answers, reconnecting first when the connection
    /// is gone, without publishing anything. The proxy runs it while publishes
    /// are failing, so that readiness recovers when the broker is back even if
    /// no capture arrives to prove it. Brokers that cannot tell succeed.
    async fn probe(&self) -> Result<()> {
        Ok(())
    }
}

/// One message read off the captures log.
pub struct LogMessage {
    /// Producer-supplied partition key. Empty bytes when unset.
    pub key: Bytes,
    /// Opaque message body — typically a protobuf-encoded envelope.
    pub payload: Bytes,
    /// Broker-assigned monotonic position within the message's partition.
    /// Used as the sub-millisecond tiebreaker in ClickHouse sort keys.
    pub session_offset: u64,
    /// Per-message ack handle. Every message must be acked once it is
    /// handled. A dropped ack is not a retry: Redis Streams redelivers it
    /// after the idle timeout, but Kafka redelivers it only after the
    /// partition moves to another consumer, and until then the partition's
    /// commit cannot pass it.
    pub ack: AckHandle,
}

/// Per-message ack handle. Consumes itself on `ack` so a message can be
/// acknowledged exactly once at the call site.
pub struct AckHandle(Box<dyn AckInner>);

impl AckHandle {
    pub fn new<T: AckInner + 'static>(inner: T) -> Self {
        Self(Box::new(inner))
    }

    /// Acknowledge the message. After return, the broker will not
    /// redeliver it on the next poll.
    pub async fn ack(self) -> Result<()> {
        self.0.ack_boxed().await
    }

    /// Give up on the message for good: it will never be handled (a
    /// malformed envelope). RabbitMQ dead-letters it; the other brokers have
    /// no such channel, so it is acked like any handled message.
    pub async fn reject(self) -> Result<()> {
        self.0.reject_boxed().await
    }
}

#[async_trait]
pub trait AckInner: Send {
    async fn ack_boxed(self: Box<Self>) -> Result<()>;

    /// See [`AckHandle::reject`]. Defaults to an ack.
    async fn reject_boxed(self: Box<Self>) -> Result<()> {
        self.ack_boxed().await
    }
}

/// Source of captured-log messages. `&mut self` because consumer state
/// (cursor, blocking connection) is single-owned.
#[async_trait]
pub trait CaptureLogConsumer: Send {
    /// Poll up to `max` messages. May block for an implementation-defined
    /// interval waiting for new messages; returns empty `Vec` on timeout.
    /// Malformed broker entries are logged and acked inside the impl.
    async fn poll(&mut self, max: usize) -> Result<Vec<LogMessage>>;

    /// Connection state of this consumer for health checks, for brokers that
    /// track one (Kafka, RabbitMQ).
    fn connection(&self) -> Option<std::sync::Arc<ConnState>> {
        None
    }
}
