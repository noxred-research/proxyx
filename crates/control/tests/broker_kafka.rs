//! The Kafka backend against a real broker (Apache Kafka, or Redpanda: the
//! protocol is the same). Skipped with a message unless
//! `PROXYX_TEST_KAFKA_BROKERS` is set, e.g.
//!
//! ```text
//! docker run -d --name proxyx-kafka -p 45596:9092 -e KAFKA_NODE_ID=1 \
//!   -e KAFKA_PROCESS_ROLES=broker,controller \
//!   -e KAFKA_LISTENERS=PLAINTEXT://:9092,CONTROLLER://:9093 \
//!   -e KAFKA_ADVERTISED_LISTENERS=PLAINTEXT://127.0.0.1:45596 \
//!   -e KAFKA_CONTROLLER_LISTENER_NAMES=CONTROLLER \
//!   -e KAFKA_LISTENER_SECURITY_PROTOCOL_MAP=CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT \
//!   -e KAFKA_CONTROLLER_QUORUM_VOTERS=1@localhost:9093 \
//!   -e KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR=1 \
//!   -e KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR=1 \
//!   -e KAFKA_TRANSACTION_STATE_LOG_MIN_ISR=1 apache/kafka:4.3.1
//! export PROXYX_TEST_KAFKA_BROKERS=127.0.0.1:45596
//! ```
//!
//! The Postgres-backed barrier test also needs `PROXYX_TEST_DATABASE_URL`.
//! SASL is covered when `PROXYX_TEST_KAFKA_SASL_BROKERS` points at a listener
//! with user `px` / password `pxpass` (PLAIN, SCRAM-SHA-256 or SCRAM-SHA-512,
//! chosen by `PROXYX_TEST_KAFKA_SASL_MECHANISM`).

use std::time::Duration;

use async_trait::async_trait;
use common::log::kafka::{KafkaCompression, KafkaConfig, KafkaProducer, SaslConfig};
use common::log::{CaptureLogConsumer, CaptureLogProducer};
use proxyx_control::broker_admin;
use proxyx_control::group_consumer::KafkaGroupConsumer;
use uuid::Uuid;

mod support;
use support::broker::*;

struct Kafka {
    config: KafkaConfig,
    group: String,
}

fn config(brokers: String, partitions: i32) -> KafkaConfig {
    let id = &Uuid::new_v4().simple().to_string()[..10];
    serde_json::from_value(serde_json::json!({
        "brokers": brokers,
        "topic": format!("pxt.{id}"),
        "partitions": partitions,
        "replication_factor": 1,
        "retention_ms": 3_600_000,
    }))
    .unwrap()
}

impl Kafka {
    async fn start(partitions: i32) -> Option<Self> {
        let Ok(brokers) = std::env::var("PROXYX_TEST_KAFKA_BROKERS") else {
            eprintln!("SKIP: PROXYX_TEST_KAFKA_BROKERS is not set");
            return None;
        };
        Some(Self::with(config(brokers, partitions)).await)
    }

    async fn with(config: KafkaConfig) -> Self {
        broker_admin::ensure_kafka_topic(&config).await.unwrap();
        // The topic is visible to the pure-Rust client a moment after the
        // admin client created it.
        for _ in 0..100 {
            if KafkaProducer::new(&config, "probe").await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        Self {
            group: format!("pxt-{}", Uuid::new_v4().simple()),
            config,
        }
    }
}

#[async_trait]
impl Backend for Kafka {
    fn name(&self) -> &'static str {
        "kafka"
    }

    async fn producer(&self) -> Box<dyn CaptureLogProducer> {
        Box::new(KafkaProducer::new(&self.config, "test").await.unwrap())
    }

    async fn consumer(&self) -> Box<dyn CaptureLogConsumer> {
        Box::new(
            KafkaGroupConsumer::new(
                &self.config,
                &self.group,
                &format!("test-{}", Uuid::new_v4().simple()),
            )
            .unwrap(),
        )
    }
}

#[tokio::test]
async fn per_key_order_and_session_end_last() {
    let Some(kafka) = Kafka::start(4).await else {
        return;
    };
    ordering_per_key(&kafka).await;
}

#[tokio::test]
async fn unacked_messages_are_redelivered_acked_ones_are_not() {
    let Some(kafka) = Kafka::start(3).await else {
        return;
    };
    // Dropping the consumer commits what was acked and releases its partitions.
    redelivery_of_unacked(&kafka, async |consumer, unacked| {
        drop(unacked);
        drop(consumer);
        tokio::time::sleep(Duration::from_secs(1)).await;
    })
    .await;
}

#[tokio::test]
async fn session_closes_only_after_every_earlier_message_is_acked() {
    let Some(kafka) = Kafka::start(4).await else {
        return;
    };
    let Ok(database) = std::env::var("PROXYX_TEST_DATABASE_URL") else {
        eprintln!("SKIP: PROXYX_TEST_DATABASE_URL is not set");
        return;
    };
    session_end_barrier(&kafka, &database).await;
}

#[tokio::test]
async fn every_compression_codec_round_trips() {
    let Some(base) = Kafka::start(2).await else {
        return;
    };
    for codec in ["gzip", "lz4", "snappy", "zstd"] {
        let mut config = base.config.clone();
        config.topic = format!("pxt.{}.{codec}", &Uuid::new_v4().simple().to_string()[..8]);
        config.compression = serde_json::from_value(serde_json::json!(codec)).unwrap();
        let kafka = Kafka::with(config).await;
        let producer = kafka.producer().await;
        let records: Vec<_> = (0..20).map(|n| capture_record("src-0", n)).collect();
        publish_all(producer.as_ref(), &records).await;
        let mut consumer = kafka.consumer().await;
        let got = collect(consumer.as_mut(), 20, Duration::from_secs(60)).await;
        let order: Vec<u64> = got.iter().map(|m| identify(m).1).collect();
        assert_eq!(order, (0..20).collect::<Vec<_>>(), "{codec}");
        assert_ne!(base.config.compression, KafkaCompression::Zstd);
    }
}

#[tokio::test]
async fn linger_coalesces_concurrent_publishers() {
    let Some(base) = Kafka::start(2).await else {
        return;
    };
    let mut config = base.config.clone();
    config.linger_ms = 50;
    let kafka = Kafka::with(config).await;
    let producer = std::sync::Arc::new(kafka.producer().await);
    let mut tasks = Vec::new();
    for n in 0..30u64 {
        let producer = producer.clone();
        tasks.push(tokio::spawn(async move {
            producer.publish_batch(&[capture_record("src-0", n)]).await
        }));
    }
    for task in tasks {
        let outcomes = task.await.unwrap();
        assert!(matches!(
            outcomes[0],
            common::log::PublishOutcome::Published
        ));
    }
    let mut consumer = kafka.consumer().await;
    let got = collect(consumer.as_mut(), 30, Duration::from_secs(60)).await;
    assert_eq!(got.len(), 30);
}

#[tokio::test]
async fn migrate_creates_the_topic_with_retention_and_guards_the_partition_count() {
    let Some(kafka) = Kafka::start(3).await else {
        return;
    };
    // Idempotent.
    broker_admin::ensure_kafka_topic(&kafka.config)
        .await
        .unwrap();
    broker_admin::verify_kafka_topic(&kafka.config)
        .await
        .unwrap();
    // A different partition count is refused, in both commands.
    let mut changed = kafka.config.clone();
    changed.partitions = 5;
    let error = broker_admin::ensure_kafka_topic(&changed)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("permanent"), "{error:#}");
    assert!(broker_admin::verify_kafka_topic(&changed).await.is_err());
    // A topic that was never created fails the check.
    let mut missing = kafka.config.clone();
    missing.topic = format!("pxt.missing.{}", Uuid::new_v4().simple());
    assert!(broker_admin::verify_kafka_topic(&missing).await.is_err());
    // And the producer refuses to start without a topic.
    assert!(KafkaProducer::new(&missing, "test").await.is_err());
}

#[tokio::test]
async fn sasl_listener_accepts_the_configured_mechanism() {
    let Ok(brokers) = std::env::var("PROXYX_TEST_KAFKA_SASL_BROKERS") else {
        eprintln!("SKIP: PROXYX_TEST_KAFKA_SASL_BROKERS is not set");
        return;
    };
    let mechanism =
        std::env::var("PROXYX_TEST_KAFKA_SASL_MECHANISM").unwrap_or_else(|_| "PLAIN".into());
    let mut config = config(brokers, 2);
    config.sasl = Some(SaslConfig {
        mechanism: mechanism.clone(),
        username: "px".into(),
        password: "pxpass".into(),
    });
    let kafka = Kafka::with(config).await;
    let producer = kafka.producer().await;
    let records: Vec<_> = (0..10).map(|n| capture_record("src-0", n)).collect();
    publish_all(producer.as_ref(), &records).await;
    let mut consumer = kafka.consumer().await;
    let got = collect(consumer.as_mut(), 10, Duration::from_secs(60)).await;
    assert_eq!(got.len(), 10, "{mechanism}");

    // Wrong credentials are refused.
    let mut wrong = kafka.config.clone();
    wrong.sasl.as_mut().unwrap().password = "nope".into();
    assert!(KafkaProducer::new(&wrong, "test").await.is_err());
}
