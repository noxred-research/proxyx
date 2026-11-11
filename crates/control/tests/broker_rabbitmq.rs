//! The RabbitMQ backend against a real broker. Skipped with a message unless
//! `PROXYX_TEST_RABBITMQ_URL` is set, e.g.
//!
//! ```text
//! docker run -d --name proxyx-rabbit -p 45597:5672 -p 45599:15672 \
//!   -e RABBITMQ_DEFAULT_USER=px -e RABBITMQ_DEFAULT_PASS=pxpass rabbitmq:4-management
//! export PROXYX_TEST_RABBITMQ_URL=amqp://px:pxpass@127.0.0.1:45597/%2f
//! export PROXYX_TEST_RABBITMQ_MGMT=http://px:pxpass@127.0.0.1:45599   # connection-loss tests
//! ```
//!
//! The Postgres-backed barrier test also needs `PROXYX_TEST_DATABASE_URL`.
//! Each test declares its own exchange and queues and deletes them at the end.

use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use common::log::rabbitmq::{
    RabbitMqConfig, RabbitMqConsumer, RabbitMqProducer, declare_topology, verify_topology,
};
use common::log::{CaptureLogConsumer, CaptureLogProducer, PublishOutcome};
use proxyx_control::consumer::RequestLogConsumer;
use proxyx_control::pipeline::PipelineMessage;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

mod support;
use support::broker::*;

struct Rabbit {
    config: RabbitMqConfig,
    mgmt: Option<String>,
    http: reqwest::Client,
}

impl Rabbit {
    async fn start() -> Option<Self> {
        let Ok(url) = std::env::var("PROXYX_TEST_RABBITMQ_URL") else {
            eprintln!("SKIP: PROXYX_TEST_RABBITMQ_URL is not set");
            return None;
        };
        let id = Uuid::new_v4().simple().to_string()[..10].to_string();
        let mut config = RabbitMqConfig::new(url);
        config.exchange = format!("pxt.{id}");
        config.client_name_prefix = format!("pxt{id}");
        config.partitions = 4;
        config.quorum_group_size = 1;
        config.prefetch = 100;
        config.reconnect_initial_backoff_ms = 200;
        config.reconnect_max_backoff_ms = 1_000;
        declare_topology(&config).await.unwrap();
        Some(Self {
            config,
            mgmt: std::env::var("PROXYX_TEST_RABBITMQ_MGMT").ok(),
            http: reqwest::Client::new(),
        })
    }

    fn mgmt_url(&self, path: &str) -> Option<(String, String, String)> {
        let base = self.mgmt.as_ref()?;
        let rest = base.strip_prefix("http://")?;
        let (auth, host) = rest.split_once('@')?;
        let (user, password) = auth.split_once(':')?;
        Some((format!("http://{host}{path}"), user.into(), password.into()))
    }

    /// Close every connection whose name ends with `-<component>`. The
    /// management listing is refreshed every few seconds, so wait for it.
    async fn kill_connections(&self, component: &str) -> usize {
        let wanted = format!("{}-{component}", self.config.client_name_prefix);
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let (url, user, password) = self.mgmt_url("/api/connections").expect("management url");
            let list: Vec<serde_json::Value> = self
                .http
                .get(url)
                .basic_auth(&user, Some(&password))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            let names: Vec<String> = list
                .iter()
                .filter(|c| c["user_provided_name"].as_str() == Some(wanted.as_str()))
                .filter_map(|c| c["name"].as_str().map(str::to_owned))
                .collect();
            if !names.is_empty() {
                for name in &names {
                    let path = format!("/api/connections/{}", name.replace(' ', "%20"));
                    let (url, user, password) = self.mgmt_url(&path).unwrap();
                    self.http
                        .delete(url)
                        .basic_auth(&user, Some(&password))
                        .send()
                        .await
                        .unwrap();
                }
                return names.len();
            }
            assert!(
                Instant::now() < deadline,
                "connection {wanted} never listed"
            );
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    async fn dead_letter_count(&self) -> u64 {
        let path = format!("/api/queues/%2f/{}", self.config.dead_queue_name());
        let (url, user, password) = self.mgmt_url(&path).expect("management url");
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let queue: serde_json::Value = self
                .http
                .get(&url)
                .basic_auth(&user, Some(&password))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            let messages = queue["messages"].as_u64().unwrap_or(0);
            if messages > 0 || Instant::now() > deadline {
                return messages;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    async fn finish(self) {
        // Delete the exchanges and queues through the management API when it
        // is configured; otherwise they stay (the names are unique).
        let mut paths = vec![
            format!("/api/exchanges/%2f/{}", self.config.exchange),
            format!("/api/exchanges/%2f/{}.dlx", self.config.exchange),
            format!("/api/queues/%2f/{}", self.config.dead_queue_name()),
        ];
        paths.extend(
            (0..self.config.partitions)
                .map(|p| format!("/api/queues/%2f/{}", self.config.queue_name(p))),
        );
        for path in paths {
            if let Some((url, user, password)) = self.mgmt_url(&path) {
                let _ = self
                    .http
                    .delete(url)
                    .basic_auth(user, Some(password))
                    .send()
                    .await;
            }
        }
    }
}

#[async_trait]
impl Backend for Rabbit {
    fn name(&self) -> &'static str {
        "rabbitmq"
    }

    async fn producer(&self) -> Box<dyn CaptureLogProducer> {
        Box::new(RabbitMqProducer::new(&self.config, "test").await.unwrap())
    }

    async fn consumer(&self) -> Box<dyn CaptureLogConsumer> {
        Box::new(
            RabbitMqConsumer::new(&self.config, "ingester")
                .await
                .unwrap(),
        )
    }
}

#[tokio::test]
async fn per_key_order_and_session_end_last() {
    let Some(rabbit) = Rabbit::start().await else {
        return;
    };
    ordering_per_key(&rabbit).await;
    rabbit.finish().await;
}

#[tokio::test]
async fn unacked_messages_are_redelivered_when_the_connection_is_lost() {
    let Some(rabbit) = Rabbit::start().await else {
        return;
    };
    let killable = rabbit.mgmt.is_some();
    let rabbit_ref = &rabbit;
    redelivery_of_unacked(&rabbit, async move |consumer, unacked| {
        if killable {
            assert!(rabbit_ref.kill_connections("ingester").await >= 1);
            // Once the client has noticed the loss, the old handles cannot ack
            // on the dead channel. (An ack sent before it notices may look
            // successful and is lost; the broker redelivers either way.)
            tokio::time::sleep(Duration::from_secs(3)).await;
            for message in unacked {
                assert!(message.ack.ack().await.is_err());
            }
        }
        drop(consumer);
        tokio::time::sleep(Duration::from_secs(1)).await;
    })
    .await;
    rabbit.finish().await;
}

#[tokio::test]
async fn consumer_reconnects_with_backoff_and_gets_the_unacked_back() {
    let Some(rabbit) = Rabbit::start().await else {
        return;
    };
    if rabbit.mgmt.is_none() {
        eprintln!("SKIP: PROXYX_TEST_RABBITMQ_MGMT is not set");
        return;
    }
    let producer = rabbit.producer().await;
    let records: Vec<_> = (0..20)
        .map(|n| capture_record(&format!("src-{}", n % 2), n))
        .collect();
    publish_all(producer.as_ref(), &records).await;

    let reconnects = || {
        common::metrics::BROKER_RECONNECTS_TOTAL
            .with_label_values(&["rabbitmq", "consumer"])
            .get()
    };
    let before = reconnects();
    let mut consumer = rabbit.consumer().await;
    let state = consumer
        .connection()
        .expect("rabbitmq reports its connection");
    assert!(state.is_up());
    let mut messages = collect(consumer.as_mut(), 20, Duration::from_secs(60)).await;
    let unacked = messages.split_off(10);
    let unacked_ids: std::collections::HashSet<_> = unacked.iter().map(identify).collect();
    for message in messages {
        message.ack.ack().await.unwrap();
    }

    assert!(rabbit.kill_connections("ingester").await >= 1);
    // The same consumer object recovers on its own: polls come back empty while
    // it is down or backing off, then the unacked messages are redelivered.
    let again = collect(consumer.as_mut(), 10, Duration::from_secs(60)).await;
    let again_ids: std::collections::HashSet<_> = again.iter().map(identify).collect();
    assert_eq!(again_ids, unacked_ids);
    assert!(state.is_up());
    assert!(reconnects() > before, "the reconnect is counted");
    for message in unacked {
        assert!(message.ack.ack().await.is_err(), "stale handles cannot ack");
    }
    for message in again {
        message.ack.ack().await.unwrap();
    }
    rabbit.finish().await;
}

#[tokio::test]
async fn producer_reconnects_after_the_connection_is_lost() {
    let Some(rabbit) = Rabbit::start().await else {
        return;
    };
    if rabbit.mgmt.is_none() {
        eprintln!("SKIP: PROXYX_TEST_RABBITMQ_MGMT is not set");
        return;
    }
    let producer = rabbit.producer().await;
    assert!(producer.healthy());
    publish_all(producer.as_ref(), &[capture_record("src-0", 0)]).await;

    assert!(rabbit.kill_connections("test").await >= 1);

    // The writer retries failed records, so do the same: the producer must
    // publish again within the budget without being rebuilt.
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut published = 0;
    while published < 4 {
        assert!(Instant::now() < deadline, "the producer never recovered");
        match producer
            .publish_batch(&[capture_record("src-0", 1 + published)])
            .await
            .pop()
        {
            Some(PublishOutcome::Published) => published += 1,
            _ => tokio::time::sleep(Duration::from_millis(300)).await,
        }
    }
    assert!(producer.healthy());

    let mut consumer = rabbit.consumer().await;
    let got = collect(consumer.as_mut(), 5, Duration::from_secs(60)).await;
    let seqs: Vec<u64> = got.iter().map(|m| identify(m).1).collect();
    assert_eq!(seqs, vec![0, 1, 2, 3, 4]);
    rabbit.finish().await;
}

#[tokio::test]
async fn malformed_envelopes_are_dead_lettered_and_the_stream_goes_on() {
    let Some(rabbit) = Rabbit::start().await else {
        return;
    };
    if rabbit.mgmt.is_none() {
        eprintln!("SKIP: PROXYX_TEST_RABBITMQ_MGMT is not set");
        return;
    }
    let producer = rabbit.producer().await;
    publish_all(
        producer.as_ref(),
        &[
            (
                Bytes::from_static(b"src-0"),
                Bytes::from_static(b"this is not protobuf \xff\xff"),
            ),
            capture_record("src-0", 7),
        ],
    )
    .await;

    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    let consumer = RequestLogConsumer::new(rabbit.consumer().await, None, tx);
    let shutdown = CancellationToken::new();
    let run = tokio::spawn(consumer.run(shutdown.clone()));

    let message = tokio::time::timeout(Duration::from_secs(60), rx.recv())
        .await
        .expect("the good capture arrives after the bad one")
        .unwrap();
    let PipelineMessage::Capture { ack, .. } = message else {
        panic!("expected a capture");
    };
    ack.ack().await.unwrap();
    assert_eq!(rabbit.dead_letter_count().await, 1);
    shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(10), run).await;
    rabbit.finish().await;
}

#[tokio::test]
async fn session_closes_only_after_every_earlier_message_is_acked() {
    let Some(rabbit) = Rabbit::start().await else {
        return;
    };
    let Ok(database) = std::env::var("PROXYX_TEST_DATABASE_URL") else {
        eprintln!("SKIP: PROXYX_TEST_DATABASE_URL is not set");
        return;
    };
    session_end_barrier(&rabbit, &database).await;
    rabbit.finish().await;
}

#[tokio::test]
async fn topology_is_declared_idempotently_and_verified() {
    let Some(rabbit) = Rabbit::start().await else {
        return;
    };
    declare_topology(&rabbit.config).await.unwrap();
    verify_topology(&rabbit.config).await.unwrap();

    // A queue redeclared with other arguments is refused with a hint.
    let mut changed = rabbit.config.clone();
    changed.delivery_limit = 7;
    let error = declare_topology(&changed).await.unwrap_err();
    assert!(
        format!("{error:#}").contains("different arguments"),
        "{error:#}"
    );

    // Another exchange has no queues yet.
    let mut elsewhere = rabbit.config.clone();
    elsewhere.exchange = format!("{}.other", rabbit.config.exchange);
    assert!(verify_topology(&elsewhere).await.is_err());

    // Publishing to an exchange that does not exist fails the record, not the
    // process, and the producer reports it unhealthy until a publish works.
    let producer = RabbitMqProducer::new(&elsewhere, "test").await.unwrap();
    let outcome = producer
        .publish_batch(&[capture_record("src-0", 1)])
        .await
        .pop()
        .unwrap();
    assert!(matches!(outcome, PublishOutcome::Failed(_)), "{outcome:?}");
    rabbit.finish().await;
}

#[tokio::test]
async fn bad_credentials_fail_fast() {
    let Some(rabbit) = Rabbit::start().await else {
        return;
    };
    let mut wrong = rabbit.config.clone();
    wrong.password = Some("not-the-password".into());
    wrong.username = Some("px".into());
    assert!(RabbitMqProducer::new(&wrong, "test").await.is_err());
    assert!(RabbitMqConsumer::new(&wrong, "test").await.is_err());
    rabbit.finish().await;
}

#[tokio::test]
async fn probe_checks_the_queues_and_keeps_the_publish_channel() {
    let Some(rabbit) = Rabbit::start().await else {
        return;
    };
    let producer = rabbit.producer().await;
    producer.probe().await.unwrap();
    publish_all(producer.as_ref(), &[capture_record("src-0", 0)]).await;

    // A producer configured for more partitions than were declared finds the
    // missing queue, without closing the channel the publishes use.
    let mut wider = rabbit.config.clone();
    wider.partitions += 1;
    let wide = RabbitMqProducer::new(&wider, "test").await.unwrap();
    let error = format!("{:#}", wide.probe().await.unwrap_err());
    assert!(error.contains("is missing"), "{error}");
    for _ in 0..3 {
        assert!(wide.probe().await.is_err());
    }
    producer.probe().await.unwrap();
    publish_all(producer.as_ref(), &[capture_record("src-0", 1)]).await;
    rabbit.finish().await;
}
