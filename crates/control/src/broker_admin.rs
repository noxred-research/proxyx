//! Broker administration for the `migrate` command: the Kafka topic or the
//! RabbitMQ exchanges and queues of the captures log.
//!
//! This module has no runtime role: it runs during `proxyx migrate` to make
//! sure the captures log exists with the right shape before the proxy and the
//! ingester start.

use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use common::log::kafka::KafkaConfig;
use rdkafka::admin::{AdminClient, AdminOptions, NewTopic, ResourceSpecifier, TopicReplication};
use rdkafka::client::DefaultClientContext;
use rdkafka::consumer::{BaseConsumer, Consumer};
use rdkafka::error::RDKafkaErrorCode;

use crate::config::{BrokerKind, ControlConfig};

const ADMIN_TIMEOUT: Duration = Duration::from_secs(15);

/// Create what the configured broker needs (idempotent). Redis Streams needs
/// nothing: the consumer group is created on first start.
pub async fn ensure_broker(config: &ControlConfig) -> Result<()> {
    match config.broker_kind {
        BrokerKind::RedisStream => Ok(()),
        BrokerKind::Kafka => {
            let kafka = config
                .kafka_config()?
                .context("[kafka] config section required for topic creation")?;
            ensure_kafka_topic(kafka).await
        }
        BrokerKind::Rabbitmq => {
            let rabbitmq = config
                .rabbitmq
                .as_ref()
                .context("[rabbitmq] config section required to declare the queues")?;
            common::log::rabbitmq::declare_topology(rabbitmq).await
        }
    }
}

/// Fail unless what the configured broker needs exists (`migrate --check`).
pub async fn verify_broker(config: &ControlConfig) -> Result<()> {
    match config.broker_kind {
        BrokerKind::RedisStream => Ok(()),
        BrokerKind::Kafka => {
            let kafka = config
                .kafka_config()?
                .context("[kafka] config section required")?;
            verify_kafka_topic(kafka).await
        }
        BrokerKind::Rabbitmq => {
            let rabbitmq = config
                .rabbitmq
                .as_ref()
                .context("[rabbitmq] config section required")?;
            common::log::rabbitmq::verify_topology(rabbitmq).await
        }
    }
}

/// Ensure the captures topic exists with the configured partition count.
///
/// - absent: created with `partitions`, `replication_factor` and
///   `retention.ms`;
/// - present with the same partition count: left alone (a different
///   `retention.ms` is reported, not changed);
/// - present with another partition count: an error, because the count is
///   permanent.
pub async fn ensure_kafka_topic(config: &KafkaConfig) -> Result<()> {
    config.validate()?;
    let config = config.clone();
    tokio::task::spawn_blocking(move || ensure_kafka_topic_blocking(&config))
        .await
        .context("Kafka admin task panicked")?
}

/// Fail unless the topic exists with the configured partition count.
pub async fn verify_kafka_topic(config: &KafkaConfig) -> Result<()> {
    config.validate()?;
    let config = config.clone();
    tokio::task::spawn_blocking(move || {
        let consumer: BaseConsumer =
            crate::group_consumer::client_config(&config, "proxyx-migrate")
                .create()
                .context("creating the Kafka client")?;
        let partitions = partition_count(&consumer, &config.topic)?;
        match partitions {
            Some(n) if n == config.partitions as usize => Ok(()),
            Some(n) => bail!(
                "Kafka topic '{}' has {n} partition(s) but the configuration requires {}",
                config.topic,
                config.partitions
            ),
            None => bail!(
                "Kafka topic '{}' does not exist (run `proxyx migrate control`)",
                config.topic
            ),
        }
    })
    .await
    .context("Kafka admin task panicked")?
}

fn partition_count(consumer: &BaseConsumer, topic: &str) -> Result<Option<usize>> {
    let metadata = consumer
        .fetch_metadata(Some(topic), ADMIN_TIMEOUT)
        .context("fetching Kafka metadata")?;
    Ok(metadata
        .topics()
        .iter()
        .find(|t| t.name() == topic && t.error().is_none())
        .map(|t| t.partitions().len()))
}

fn ensure_kafka_topic_blocking(config: &KafkaConfig) -> Result<()> {
    let client_config = crate::group_consumer::client_config(config, "proxyx-migrate");
    let admin: AdminClient<DefaultClientContext> = client_config
        .create()
        .context("creating the Kafka admin client")?;
    let consumer: BaseConsumer = client_config
        .create()
        .context("creating the Kafka metadata client")?;

    let retention = config.retention_ms.to_string();
    let topic = NewTopic::new(
        &config.topic,
        config.partitions,
        TopicReplication::Fixed(config.replication_factor),
    )
    .set("retention.ms", &retention);
    let options = AdminOptions::new().request_timeout(Some(ADMIN_TIMEOUT));
    let runtime = tokio::runtime::Handle::current();
    let results = runtime
        .block_on(admin.create_topics([&topic], &options))
        .context("creating the Kafka topic")?;

    match results.into_iter().next() {
        Some(Ok(_)) => {
            tracing::info!(
                topic = %config.topic,
                partitions = config.partitions,
                replication_factor = config.replication_factor,
                retention_ms = config.retention_ms,
                "Kafka topic created"
            );
            Ok(())
        }
        Some(Err((_, RDKafkaErrorCode::TopicAlreadyExists))) => {
            match partition_count(&consumer, &config.topic)? {
                Some(n) if n == config.partitions as usize => {
                    tracing::info!(topic = %config.topic, partitions = n, "Kafka topic exists with the right partition count");
                    report_retention(&admin, &runtime, config, &options);
                    Ok(())
                }
                Some(n) => bail!(
                    "Kafka topic '{}' exists with {n} partition(s) but the configuration requires \
                     {}; the partition count is permanent and cannot be changed",
                    config.topic,
                    config.partitions
                ),
                None => bail!(
                    "Kafka topic '{}' reported as existing but has no metadata",
                    config.topic
                ),
            }
        }
        Some(Err((name, code))) => bail!("creating Kafka topic {name} failed: {code}"),
        None => bail!("the broker answered the topic creation with no result"),
    }
}

/// Warn when the existing topic's `retention.ms` differs from the config.
fn report_retention(
    admin: &AdminClient<DefaultClientContext>,
    runtime: &tokio::runtime::Handle,
    config: &KafkaConfig,
    options: &AdminOptions,
) {
    let described = runtime
        .block_on(admin.describe_configs([&ResourceSpecifier::Topic(&config.topic)], options));
    let Ok(results) = described else { return };
    let Some(Ok(resource)) = results.into_iter().next() else {
        return;
    };
    let current = resource
        .entries
        .iter()
        .find(|e| e.name == "retention.ms")
        .and_then(|e| e.value.clone());
    if current.as_deref() != Some(&config.retention_ms.to_string()) {
        tracing::warn!(
            topic = %config.topic,
            current = ?current,
            configured = config.retention_ms,
            "the topic's retention.ms differs from kafka.retention_ms; change it with \
             kafka-configs.sh or rpk, migrate does not alter an existing topic"
        );
    }
}
