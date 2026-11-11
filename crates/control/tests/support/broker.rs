//! Scenarios shared by the broker integration tests (Kafka, RabbitMQ): the
//! same behaviour, checked against each real broker through the
//! `CaptureLogProducer` / `CaptureLogConsumer` traits.

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use common::log::{CaptureLogConsumer, CaptureLogProducer, LogMessage, PublishOutcome};
use common::wire::{self, request_log_message};
use prost::Message as _;
use proxyx_control::consumer::RequestLogConsumer;
use proxyx_control::pipeline::PipelineMessage;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// A broker under test.
#[async_trait]
pub trait Backend: Send + Sync {
    fn name(&self) -> &'static str;
    /// A producer on this test's captures log.
    async fn producer(&self) -> Box<dyn CaptureLogProducer>;
    /// A new consumer of the same consumer group / queues.
    async fn consumer(&self) -> Box<dyn CaptureLogConsumer>;
}

/// Event id of message number `n`.
pub fn event_id(n: u64) -> Uuid {
    Uuid::from_u128((0x018f_0000_0000_7000_8000_u128 << 64) | u128::from(n))
}

/// A capture of `source_id` carrying sequence number `n` as its event id.
pub fn capture_record(source_id: &str, n: u64) -> (Bytes, Bytes) {
    let message = wire::RequestLogMessage {
        kind: Some(request_log_message::Kind::Request(wire::CapturedRequest {
            event_id: Bytes::copy_from_slice(event_id(n).as_bytes()),
            session_id: Bytes::copy_from_slice(event_id(9_999).as_bytes()),
            org_id: "org-1".into(),
            source: "crawler".into(),
            source_id: source_id.into(),
            timestamp_nanos: 1_700_000_000_000_000_000 + n as i64,
            method: "GET".into(),
            scheme: "https".into(),
            host: "example.com".into(),
            port: 443,
            path: format!("/{n}"),
            response_status: 200,
            ..Default::default()
        })),
    };
    (
        Bytes::copy_from_slice(source_id.as_bytes()),
        Bytes::from(message.encode_to_vec()),
    )
}

pub fn session_end_record(source_id: &str, session_id: Uuid) -> (Bytes, Bytes) {
    let message = wire::RequestLogMessage {
        kind: Some(request_log_message::Kind::SessionEnd(
            wire::SessionEndEvent {
                session_id: Bytes::copy_from_slice(session_id.as_bytes()),
                org_id: "org-1".into(),
                source: "crawler".into(),
                source_id: source_id.into(),
                timestamp_nanos: 1_700_000_000_000_000_000,
            },
        )),
    };
    (
        Bytes::copy_from_slice(source_id.as_bytes()),
        Bytes::from(message.encode_to_vec()),
    )
}

/// `(key, sequence)` of a polled message: the capture's event id number, or
/// `u64::MAX` for a SessionEnd.
pub fn identify(message: &LogMessage) -> (String, u64) {
    let envelope =
        wire::RequestLogMessage::decode(&message.payload[..]).expect("a ProxyX envelope");
    let key = String::from_utf8(message.key.to_vec()).expect("utf-8 key");
    let n = match envelope.kind {
        Some(request_log_message::Kind::Request(r)) => {
            let id = Uuid::from_slice(&r.event_id).unwrap();
            (id.as_u128() & 0xffff_ffff) as u64
        }
        Some(request_log_message::Kind::SessionEnd(_)) => u64::MAX,
        other => panic!("unexpected envelope {other:?}"),
    };
    (key, n)
}

pub async fn publish_all(producer: &dyn CaptureLogProducer, records: &[(Bytes, Bytes)]) {
    for outcome in producer.publish_batch(records).await {
        assert!(
            matches!(outcome, PublishOutcome::Published),
            "publish failed: {outcome:?}"
        );
    }
}

/// Poll until `want` messages arrived, acking nothing.
pub async fn collect(
    consumer: &mut dyn CaptureLogConsumer,
    want: usize,
    within: Duration,
) -> Vec<LogMessage> {
    let deadline = Instant::now() + within;
    let mut out = Vec::new();
    while out.len() < want {
        assert!(
            Instant::now() < deadline,
            "received {} of {want} messages in {within:?}",
            out.len()
        );
        out.extend(consumer.poll(50).await.expect("poll"));
    }
    out
}

/// Poll for `window` and return what arrived.
pub async fn drain(consumer: &mut dyn CaptureLogConsumer, window: Duration) -> Vec<LogMessage> {
    let deadline = Instant::now() + window;
    let mut out = Vec::new();
    while Instant::now() < deadline {
        out.extend(consumer.poll(50).await.expect("poll"));
    }
    out
}

/// Every message of one source reaches the consumer in publish order, with a
/// strictly increasing `session_offset`, and the SessionEnd published after the
/// captures arrives after them: the order the close barrier relies on.
pub async fn ordering_per_key(backend: &dyn Backend) {
    const SOURCES: u64 = 6;
    const PER_SOURCE: u64 = 40;
    let producer = backend.producer().await;

    // Interleave the sources in batches of 25 records, so a batch holds
    // several keys and every key spans several batches.
    let mut all: Vec<(Bytes, Bytes)> = Vec::new();
    for n in 0..PER_SOURCE {
        for source in 0..SOURCES {
            all.push(capture_record(&format!("src-{source}"), source * 1_000 + n));
        }
    }
    for source in 0..SOURCES {
        all.push(session_end_record(
            &format!("src-{source}"),
            event_id(source),
        ));
    }
    for batch in all.chunks(25) {
        publish_all(producer.as_ref(), batch).await;
    }

    let mut consumer = backend.consumer().await;
    let want = all.len();
    let messages = collect(consumer.as_mut(), want, Duration::from_secs(90)).await;
    assert_eq!(messages.len(), want, "no duplicates on a clean run");

    let mut per_key: BTreeMap<String, Vec<(u64, u64)>> = BTreeMap::new();
    for message in &messages {
        let (key, n) = identify(message);
        per_key
            .entry(key)
            .or_default()
            .push((n, message.session_offset));
    }
    assert_eq!(per_key.len(), SOURCES as usize);
    for (key, seen) in per_key {
        let source: u64 = key.trim_start_matches("src-").parse().unwrap();
        let mut expected: Vec<u64> = (0..PER_SOURCE).map(|n| source * 1_000 + n).collect();
        expected.push(u64::MAX);
        let order: Vec<u64> = seen.iter().map(|(n, _)| *n).collect();
        assert_eq!(
            order,
            expected,
            "{}: {key} arrived out of order",
            backend.name()
        );
        assert!(
            seen.windows(2).all(|w| w[0].1 < w[1].1),
            "{}: session_offset is not strictly increasing for {key}: {seen:?}",
            backend.name()
        );
    }
    for message in messages {
        message.ack.ack().await.expect("ack");
    }
}

/// Acked messages are not delivered again; unacked ones are, after the
/// consumer that held them goes away.
pub async fn redelivery_of_unacked(
    backend: &dyn Backend,
    lose: impl AsyncFnOnce(Box<dyn CaptureLogConsumer>, Vec<LogMessage>),
) {
    const TOTAL: u64 = 60;
    let producer = backend.producer().await;
    let records: Vec<(Bytes, Bytes)> = (0..TOTAL)
        .map(|n| capture_record(&format!("src-{}", n % 3), n))
        .collect();
    publish_all(producer.as_ref(), &records).await;

    let mut first = backend.consumer().await;
    let mut messages = collect(first.as_mut(), TOTAL as usize, Duration::from_secs(90)).await;
    assert_eq!(messages.len(), TOTAL as usize);

    // Ack the first half in arrival order (a prefix of every partition).
    let unacked = messages.split_off(TOTAL as usize / 2);
    let acked_ids: HashSet<(String, u64)> = messages.iter().map(identify).collect();
    for message in messages {
        message.ack.ack().await.expect("ack");
    }
    let unacked_ids: HashSet<(String, u64)> = unacked.iter().map(identify).collect();
    assert_eq!(unacked_ids.len(), TOTAL as usize / 2);

    lose(first, unacked).await;

    let mut second = backend.consumer().await;
    let again = collect(second.as_mut(), unacked_ids.len(), Duration::from_secs(90)).await;
    let again_ids: HashSet<(String, u64)> = again.iter().map(identify).collect();
    assert_eq!(
        again_ids, unacked_ids,
        "exactly the unacked messages come back"
    );
    assert!(again_ids.is_disjoint(&acked_ids));
    for message in again {
        message.ack.ack().await.expect("ack");
    }
    let rest = drain(second.as_mut(), Duration::from_secs(3)).await;
    assert!(
        rest.is_empty(),
        "everything is acked, nothing is delivered again"
    );
}

/// With the real `RequestLogConsumer` and Postgres: a session's row turns
/// `closed` only after its SessionEnd and every message read before it are
/// acked, however the broker interleaves other sources.
pub async fn session_end_barrier(backend: &dyn Backend, database_url: &str) {
    let admin = sqlx::PgPool::connect(database_url).await.expect("postgres");
    let database = format!("pxt_{}", &Uuid::new_v4().simple().to_string()[..12]);
    // The identifier contains only a fixed prefix and UUID hexadecimal digits.
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {database}")))
        .execute(&admin)
        .await
        .unwrap();
    let (base, _) = database_url
        .rsplit_once('/')
        .expect("database url has a database");
    let url = format!("{base}/{database}");
    let pool = sqlx::PgPool::connect(&url).await.unwrap();
    let db = proxyx_control::db::Db::connect(&url, 4).await.unwrap();
    proxyx_control::migrations::run_database(&db).await.unwrap();

    let session = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO session_lifecycle (session_id, org_id, source, source_id, state, expires_at) \
         VALUES ($1, 'org-1', 'crawler', 'src-0', 'consuming', now() + interval '1 hour')",
    )
    .bind(session)
    .execute(&pool)
    .await
    .unwrap();
    let state = || async {
        sqlx::query_scalar::<_, String>("SELECT state FROM session_lifecycle WHERE session_id = $1")
            .bind(session)
            .fetch_one(&pool)
            .await
            .unwrap()
    };

    let producer = backend.producer().await;
    let mut records: Vec<(Bytes, Bytes)> = (0..5).map(|n| capture_record("src-0", n)).collect();
    records.push(session_end_record("src-0", session));
    publish_all(producer.as_ref(), &records).await;

    let (tx, mut rx) = tokio::sync::mpsc::channel(64);
    let consumer = RequestLogConsumer::new(backend.consumer().await, Some(db.clone()), tx);
    let shutdown = CancellationToken::new();
    let run = tokio::spawn(consumer.run(shutdown.clone()));

    let mut captures = Vec::new();
    for _ in 0..5 {
        let message = tokio::time::timeout(Duration::from_secs(90), rx.recv())
            .await
            .expect("capture reaches the pipeline")
            .expect("channel open");
        let PipelineMessage::Capture { ack, .. } = message else {
            panic!("expected a capture");
        };
        captures.push(ack);
    }
    // The SessionEnd was read (and acked on its own) but its captures are not
    // flushed: the session must stay `consuming`.
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(state().await, "consuming");
    let last = captures.pop().unwrap();
    for ack in captures {
        ack.ack().await.unwrap();
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(
        state().await,
        "consuming",
        "one capture is still not durable"
    );
    last.ack().await.unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    while state().await != "closed" {
        assert!(Instant::now() < deadline, "the session never closed");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(10), run).await;
    pool.close().await;
    // Reuse the identifier generated from the UUID above.
    let _ = sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP DATABASE {database} WITH (FORCE)"
    )))
    .execute(&admin)
    .await;
}

pub fn arc<T: Backend + 'static>(backend: T) -> Arc<dyn Backend> {
    Arc::new(backend)
}
