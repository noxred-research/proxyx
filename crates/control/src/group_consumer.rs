use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result};
use async_trait::async_trait;
use bytes::Bytes;
use common::log::kafka::KafkaConfig;
use common::log::{AckHandle, AckInner, CaptureLogConsumer, ConnState, LogMessage};
use parking_lot::Mutex;
use rdkafka::ClientContext;
use rdkafka::Message as _;
use rdkafka::config::{ClientConfig, FromClientConfigAndContext};
use rdkafka::consumer::{BaseConsumer, Consumer, ConsumerContext, Rebalance, StreamConsumer};

struct GroupContext {
    tracker: Mutex<AckTracker>,
    /// Starts down. Up after a message was received or a metadata request
    /// succeeded, down again when librdkafka reports that every broker is
    /// unreachable.
    state: Arc<ConnState>,
}

impl ClientContext for GroupContext {
    fn error(&self, error: rdkafka::error::KafkaError, reason: &str) {
        use rdkafka::error::{KafkaError, RDKafkaErrorCode};
        if matches!(error, KafkaError::Global(RDKafkaErrorCode::AllBrokersDown)) {
            self.state.set(false);
        }
        tracing::warn!(%error, reason, "Kafka client error");
    }
}

impl ConsumerContext for GroupContext {
    fn pre_rebalance(&self, _: &BaseConsumer<Self>, rebalance: &Rebalance<'_>) {
        // Only revoked partitions lose their ack state. A cooperative
        // rebalance that keeps a partition must not drop its acks or let
        // its watermark skip an offset that is not stored yet.
        if let Rebalance::Revoke(partitions) = rebalance {
            let mut tracker = self.tracker.lock();
            for element in partitions.elements() {
                tracker.revoke(element.partition());
            }
        }
        tracing::info!(?rebalance, "consumer group rebalance started");
    }

    fn post_rebalance(&self, _: &BaseConsumer<Self>, rebalance: &Rebalance<'_>) {
        tracing::info!(?rebalance, "consumer group rebalance completed");
    }
}

struct PartitionState {
    acked: BTreeSet<i64>,
    watermark: i64,
}

/// Per-partition contiguous ack watermark. Kafka does not redeliver an
/// un-acked offset to the consumer that owns its partition, so every
/// message must be acked: one missing ack holds the partition's commit at
/// that offset until the partition moves to another consumer.
#[derive(Default)]
struct AckTracker {
    partitions: HashMap<i32, PartitionState>,
}

impl AckTracker {
    /// Start tracking `partition` at `offset` unless it is already tracked.
    fn observe(&mut self, partition: i32, offset: i64) {
        self.partitions
            .entry(partition)
            .or_insert_with(|| PartitionState {
                acked: BTreeSet::new(),
                watermark: offset - 1,
            });
    }

    /// Forget a revoked partition. Acks for it are ignored until it is
    /// assigned again and observed from its committed offset.
    fn revoke(&mut self, partition: i32) {
        self.partitions.remove(&partition);
    }

    /// Record an ack. Returns the new watermark when it advanced.
    fn ack(&mut self, partition: i32, offset: i64) -> Option<i64> {
        let state = self.partitions.get_mut(&partition)?;
        if offset <= state.watermark {
            return None;
        }
        state.acked.insert(offset);
        let previous = state.watermark;
        while state.acked.remove(&(state.watermark + 1)) {
            state.watermark += 1;
        }
        (state.watermark != previous).then_some(state.watermark)
    }
}

/// librdkafka settings shared by the group consumer and the admin client:
/// brokers, client id, TLS and SASL.
pub(crate) fn client_config(config: &KafkaConfig, client_id: &str) -> ClientConfig {
    let mut client_config = ClientConfig::new();
    client_config
        .set("bootstrap.servers", &config.brokers)
        .set("client.id", client_id);

    // The protocol follows what the producer does: TLS when `[kafka.tls]`
    // is set, SASL when `[kafka.sasl]` is.
    match (&config.tls, &config.sasl) {
        (Some(_), Some(_)) => client_config.set("security.protocol", "sasl_ssl"),
        (None, Some(_)) => client_config.set("security.protocol", "sasl_plaintext"),
        (Some(_), None) => client_config.set("security.protocol", "ssl"),
        (None, None) => &mut client_config,
    };
    if let Some(sasl) = &config.sasl {
        client_config
            .set("sasl.mechanism", &sasl.mechanism)
            .set("sasl.username", &sasl.username)
            .set("sasl.password", &sasl.password);
    }
    if let Some(tls) = &config.tls {
        if let Some(ca) = &tls.ca_cert {
            client_config.set("ssl.ca.location", ca);
        }
        if let Some(cert) = &tls.client_cert {
            client_config.set("ssl.certificate.location", cert);
        }
        if let Some(key) = &tls.client_key {
            client_config.set("ssl.key.location", key);
        }
    }
    client_config
}

type KafkaConsumer = StreamConsumer<GroupContext>;

pub struct KafkaGroupConsumer {
    consumer: Arc<KafkaConsumer>,
    topic: String,
    state: Arc<ConnState>,
}

impl KafkaGroupConsumer {
    pub fn new(config: &KafkaConfig, group_id: &str, consumer_id: &str) -> Result<Self> {
        config.validate()?;
        let mut client_config = client_config(config, consumer_id);
        client_config
            .set("group.id", group_id)
            .set("enable.auto.commit", "true")
            .set("auto.commit.interval.ms", "5000")
            .set("enable.auto.offset.store", "false")
            .set("auto.offset.reset", "earliest")
            .set("partition.assignment.strategy", "cooperative-sticky");

        // Starts down: the first message or a successful metadata request
        // (which needs a working TLS and SASL handshake) marks it up, and
        // `poll` retries the request while it is down.
        let state = ConnState::new("kafka", "consumer");
        let context = GroupContext {
            tracker: Mutex::new(AckTracker::default()),
            state: Arc::clone(&state),
        };
        let consumer = Arc::new(
            KafkaConsumer::from_config_and_context(&client_config, context)
                .context("creating Kafka group consumer")?,
        );
        consumer
            .subscribe(&[&config.topic])
            .context("subscribing Kafka group consumer")?;

        Ok(Self {
            consumer,
            topic: config.topic.clone(),
            state,
        })
    }
}

#[async_trait]
impl CaptureLogConsumer for KafkaGroupConsumer {
    async fn poll(&mut self, max: usize) -> Result<Vec<LogMessage>> {
        let mut messages = Vec::with_capacity(max);
        while messages.len() < max {
            let wait = if messages.is_empty() {
                Duration::from_secs(1)
            } else {
                Duration::from_millis(1)
            };
            let message = match tokio::time::timeout(wait, self.consumer.recv()).await {
                Ok(Ok(message)) => message,
                Ok(Err(error)) => return Err(error).context("polling Kafka group consumer"),
                Err(_) => break,
            };

            self.state.set(true);
            let partition = message.partition();
            let offset = message.offset();
            self.consumer
                .context()
                .tracker
                .lock()
                .observe(partition, offset);

            messages.push(LogMessage {
                key: Bytes::copy_from_slice(message.key().unwrap_or_default()),
                payload: Bytes::copy_from_slice(message.payload().unwrap_or_default()),
                session_offset: offset as u64,
                ack: AckHandle::new(KafkaAck {
                    consumer: Arc::clone(&self.consumer),
                    topic: self.topic.clone(),
                    partition,
                    offset,
                }),
            });
        }
        if messages.is_empty() && !self.state.is_up() {
            // Down and idle: a metadata request tells whether the brokers are
            // back, since no message would.
            let consumer = Arc::clone(&self.consumer);
            let reachable = tokio::task::spawn_blocking(move || {
                consumer
                    .fetch_metadata(None, Duration::from_secs(2))
                    .is_ok()
            })
            .await
            .unwrap_or(false);
            if reachable {
                self.state.set(true);
            }
        }
        Ok(messages)
    }

    fn connection(&self) -> Option<Arc<ConnState>> {
        Some(Arc::clone(&self.state))
    }
}

struct KafkaAck {
    consumer: Arc<KafkaConsumer>,
    topic: String,
    partition: i32,
    offset: i64,
}

#[async_trait]
impl AckInner for KafkaAck {
    async fn ack_boxed(self: Box<Self>) -> Result<()> {
        let watermark = self
            .consumer
            .context()
            .tracker
            .lock()
            .ack(self.partition, self.offset);
        if let Some(watermark) = watermark {
            self.consumer
                .store_offset(&self.topic, self.partition, watermark)
                .context("storing contiguous Kafka offset")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::AckTracker;

    #[test]
    fn advances_only_through_contiguous_acks() {
        let mut tracker = AckTracker::default();
        tracker.observe(3, 10);
        assert_eq!(tracker.ack(3, 11), None);
        assert_eq!(tracker.ack(3, 10), Some(11));
        assert_eq!(tracker.ack(3, 12), Some(12));
    }

    #[test]
    fn revoking_one_partition_keeps_the_gap_on_another() {
        let mut tracker = AckTracker::default();
        tracker.observe(3, 10);
        tracker.observe(4, 50);
        assert_eq!(tracker.ack(3, 11), None);

        tracker.revoke(4);
        tracker.observe(3, 12);

        assert_eq!(tracker.ack(3, 12), None, "offset 10 is still not acked");
        assert_eq!(tracker.ack(3, 10), Some(12));
    }

    #[test]
    fn revoked_partition_restarts_from_its_next_observed_offset() {
        let mut tracker = AckTracker::default();
        tracker.observe(3, 10);
        tracker.revoke(3);
        assert_eq!(tracker.ack(3, 10), None, "ack after revoke is ignored");

        tracker.observe(3, 10);
        assert_eq!(tracker.ack(3, 10), Some(10));
        assert_eq!(tracker.ack(3, 9), None, "offset below the watermark");
    }
}
