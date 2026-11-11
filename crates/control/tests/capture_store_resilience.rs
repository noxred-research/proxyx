//! Write-path resilience of the OpenSearch capture store against a scripted
//! fake cluster: bounded in-place retry with backoff, authorization recovery,
//! per-item retry and poison isolation, and the circuit breaker the ingester
//! health check reads. No real OpenSearch is needed.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use common::log::AckHandle;
use parking_lot::Mutex;
use proxyx_control::capture_store::CaptureStore;
use proxyx_control::capture_store::opensearch::{
    OpenSearchConfig, OpenSearchSink, OpenSearchStore,
};
use proxyx_control::pipeline::CaptureSink;

mod support;
use support::*;

/// The metrics are process-global and labelled by table only, so the tests
/// that read them must not overlap.
static ONE_AT_A_TIME: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// How the fake answers one `_bulk` request.
#[derive(Clone)]
enum Reply {
    /// Every document created.
    Ok,
    /// A bare HTTP status with an error body.
    Status(u16),
    /// `errors: true` with one status per document.
    Items(Vec<u16>),
}

struct Fake {
    /// Number of documents in each `_bulk` request received.
    bulks: Mutex<Vec<usize>>,
    bulk_ids: Mutex<Vec<Vec<String>>>,
    script: Mutex<VecDeque<Reply>>,
    default: Mutex<Reply>,
    root_status: Mutex<u16>,
}

impl Fake {
    fn new(default: Reply) -> Arc<Self> {
        Arc::new(Self {
            bulks: Mutex::new(Vec::new()),
            bulk_ids: Mutex::new(Vec::new()),
            script: Mutex::new(VecDeque::new()),
            default: Mutex::new(default),
            root_status: Mutex::new(200),
        })
    }

    fn then(self: &Arc<Self>, replies: impl IntoIterator<Item = Reply>) -> Arc<Self> {
        self.script.lock().extend(replies);
        self.clone()
    }

    fn requests(&self) -> usize {
        self.bulks.lock().len()
    }
}

async fn root(State(fake): State<Arc<Fake>>) -> (StatusCode, &'static str) {
    let status = *fake.root_status.lock();
    (
        StatusCode::from_u16(status).unwrap(),
        r#"{"version":{"number":"2.19.7"}}"#,
    )
}

async fn bulk(State(fake): State<Arc<Fake>>, body: Bytes) -> (StatusCode, String) {
    let docs = body.iter().filter(|b| **b == b'\n').count() / 2;
    fake.bulks.lock().push(docs);
    let ids = body
        .split(|b| *b == b'\n')
        .step_by(2)
        .take(docs)
        .map(|action| {
            serde_json::from_slice::<serde_json::Value>(action).unwrap()["create"]["_id"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    fake.bulk_ids.lock().push(ids);
    let reply = fake
        .script
        .lock()
        .pop_front()
        .unwrap_or_else(|| fake.default.lock().clone());
    match reply {
        Reply::Ok => {
            let items: Vec<String> = (0..docs)
                .map(|_| r#"{"create":{"status":201}}"#.to_string())
                .collect();
            (
                StatusCode::OK,
                format!(r#"{{"errors":false,"items":[{}]}}"#, items.join(",")),
            )
        }
        Reply::Status(code) => (
            StatusCode::from_u16(code).unwrap(),
            r#"{"error":{"type":"fake_exception","reason":"scripted"},"status":0}"#.to_string(),
        ),
        Reply::Items(statuses) => {
            assert_eq!(statuses.len(), docs, "script has one status per document");
            let items: Vec<String> = statuses
                .iter()
                .map(|s| {
                    if *s < 300 {
                        format!(r#"{{"create":{{"status":{s}}}}}"#)
                    } else if matches!(*s, 401 | 403) {
                        format!(
                            r#"{{"create":{{"status":{s},"error":{{"type":"security_exception","reason":"access denied"}}}}}}"#
                        )
                    } else {
                        format!(
                            r#"{{"create":{{"status":{s},"error":{{"type":"fake","reason":"no"}}}}}}"#
                        )
                    }
                })
                .collect();
            (
                StatusCode::OK,
                format!(r#"{{"errors":true,"items":[{}]}}"#, items.join(",")),
            )
        }
    }
}

async fn serve(fake: &Arc<Fake>) -> String {
    let app = Router::new()
        .route("/", get(root))
        .route("/_bulk", post(bulk))
        .with_state(fake.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await });
    url
}

fn config(url: String) -> OpenSearchConfig {
    let mut config = OpenSearchConfig::new(url);
    config.max_retries = 3;
    config.retry_initial_backoff_ms = 10;
    config.retry_max_backoff_ms = 40;
    config.flush_interval_secs = 1;
    config.circuit_breaker_threshold = 2;
    config.circuit_breaker_reset_secs = 1;
    config
}

fn sink(config: &OpenSearchConfig) -> OpenSearchSink {
    OpenSearchSink::connect(config, None, None, None, None).unwrap()
}

fn retries(table: &str) -> u64 {
    common::metrics::INGESTER_STORE_RETRIES_TOTAL
        .with_label_values(&[table])
        .get() as u64
}

struct CountAck(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl common::log::AckInner for CountAck {
    async fn ack_boxed(self: Box<Self>) -> anyhow::Result<()> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

async fn send_one(sink: &OpenSearchSink, n: u64, acks: &Arc<AtomicUsize>) {
    let ack = AckHandle::new(CountAck(acks.clone()));
    let Message::Http(captured) = Message::Http(capture(n)) else {
        unreachable!()
    };
    sink.send_http(&captured, 1000 + n, Some(ack))
        .await
        .unwrap();
}

#[tokio::test]
async fn transient_failures_are_retried_in_place_within_the_budget() {
    let _turn = ONE_AT_A_TIME.lock().await;
    let fake = Fake::new(Reply::Ok).then([Reply::Status(503), Reply::Status(429)]);
    let url = serve(&fake).await;
    let before = retries("http_captures");

    let sent = deliver_via(
        Arc::new(sink(&config(url))),
        vec![Message::Http(capture(1))],
    )
    .await;

    assert_eq!(sent, 1, "acked after the third attempt wrote it");
    assert_eq!(fake.requests(), 3, "two failures, then success");
    assert_eq!(retries("http_captures") - before, 2);
}

#[tokio::test]
async fn only_throttled_items_are_sent_again() {
    let _turn = ONE_AT_A_TIME.lock().await;
    // Two documents: the first is created, the second throttled once.
    let fake = Fake::new(Reply::Ok).then([Reply::Items(vec![201, 429])]);
    let url = serve(&fake).await;

    let messages = vec![Message::Http(capture(1)), Message::Http(capture(2))];
    assert_eq!(deliver_via(Arc::new(sink(&config(url))), messages).await, 2);

    assert_eq!(
        *fake.bulks.lock(),
        vec![2, 1],
        "the retry carries one document"
    );
}

#[tokio::test]
async fn authorization_errors_requeue_without_drops_until_permissions_recover() {
    let _turn = ONE_AT_A_TIME.lock().await;
    for reply in [
        Reply::Status(401),
        Reply::Status(403),
        Reply::Items(vec![401]),
        Reply::Items(vec![403]),
    ] {
        let fake = Fake::new(reply);
        let url = serve(&fake).await;
        let config = config(url);
        let store = OpenSearchStore::new(&config).unwrap();
        let sink = sink(&config);
        let acks = Arc::new(AtomicUsize::new(0));
        let before = retries("http_captures");
        let dropped =
            common::metrics::INGESTER_ROWS_DROPPED_TOTAL.with_label_values(&["http_captures"]);
        let dropped_before = dropped.get();

        send_one(&sink, 1, &acks).await;
        let deadline = Instant::now() + Duration::from_secs(20);
        while !sink.circuit_open() {
            assert!(
                Instant::now() < deadline,
                "authorization failure never opened the circuit"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        assert_eq!(fake.requests(), config.circuit_breaker_threshold as usize);
        assert_eq!(retries("http_captures"), before);
        assert_eq!(acks.load(Ordering::Relaxed), 0);
        assert_eq!(dropped.get(), dropped_before);
        store.ping().await.unwrap();

        *fake.default.lock() = Reply::Ok;
        let deadline = Instant::now() + Duration::from_secs(20);
        while sink.circuit_open() || acks.load(Ordering::Relaxed) == 0 {
            assert!(
                Instant::now() < deadline,
                "authorization recovery never acked the capture"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(acks.load(Ordering::Relaxed), 1);
        assert_eq!(dropped.get(), dropped_before);
        assert_eq!(retries("http_captures"), before);
        sink.flush_and_close(Duration::from_secs(5)).await;
    }
}

#[tokio::test]
async fn authorization_items_preserve_sibling_fates_and_retry_indices() {
    let _turn = ONE_AT_A_TIME.lock().await;
    let fake = Fake::new(Reply::Ok).then([Reply::Items(vec![201, 403, 400, 401, 409, 429])]);
    let url = serve(&fake).await;
    let before = retries("http_captures");
    let dropped =
        common::metrics::INGESTER_ROWS_DROPPED_TOTAL.with_label_values(&["http_captures"]);
    let dropped_before = dropped.get();
    let sink = sink(&config(url));
    let acks = Arc::new(AtomicUsize::new(0));

    for n in 1..=6 {
        send_one(&sink, n, &acks).await;
    }
    // The written, rejected-for-good and duplicate items are settled at once;
    // the authorization and throttled ones stay unacked, are not retried in
    // place (the flush fails toward the breaker) and are written by a later
    // flush once the store answers.
    let deadline = Instant::now() + Duration::from_secs(20);
    while acks.load(Ordering::Relaxed) < 6 {
        assert!(Instant::now() < deadline, "retained documents never acked");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    sink.flush_and_close(Duration::from_secs(5)).await;
    assert_eq!(acks.load(Ordering::Relaxed), 6);

    assert_eq!(*fake.bulks.lock(), vec![6, 3]);
    let ids = fake.bulk_ids.lock();
    assert_eq!(
        ids[1],
        vec![
            uuid_n(2).to_string(),
            uuid_n(4).to_string(),
            uuid_n(6).to_string()
        ]
    );
    assert_eq!(retries("http_captures"), before);
    assert_eq!(dropped.get() - dropped_before, 1.0);
}

#[tokio::test]
async fn an_item_rejected_for_good_is_acked_and_dropped() {
    let _turn = ONE_AT_A_TIME.lock().await;
    let fake = Fake::new(Reply::Items(vec![400]));
    let url = serve(&fake).await;
    let sink = sink(&config(url));
    let acks = Arc::new(AtomicUsize::new(0));
    let dropped =
        common::metrics::INGESTER_ROWS_DROPPED_TOTAL.with_label_values(&["http_captures"]);
    let before = dropped.get();

    send_one(&sink, 1, &acks).await;
    sink.flush_and_close(Duration::from_secs(10)).await;

    assert_eq!(fake.requests(), 1);
    assert_eq!(acks.load(Ordering::Relaxed), 1);
    assert_eq!(dropped.get() - before, 1.0);
    assert!(!sink.circuit_open());
}

#[tokio::test]
async fn the_circuit_opens_after_repeated_failures_and_closes_on_recovery() {
    let _turn = ONE_AT_A_TIME.lock().await;
    let fake = Fake::new(Reply::Status(503));
    let url = serve(&fake).await;
    let mut config = config(url);
    config.max_retries = 1;
    let sink = sink(&config);
    let acks = Arc::new(AtomicUsize::new(0));

    assert!(!sink.circuit_open());
    send_one(&sink, 1, &acks).await;

    let deadline = Instant::now() + Duration::from_secs(20);
    while !sink.circuit_open() {
        assert!(Instant::now() < deadline, "the circuit never opened");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(acks.load(Ordering::Relaxed), 0, "nothing acked while down");

    // The cluster recovers: the next attempt after the reset window writes
    // the requeued capture, acks it and closes the circuit.
    *fake.default.lock() = Reply::Ok;
    let deadline = Instant::now() + Duration::from_secs(20);
    while sink.circuit_open() || acks.load(Ordering::Relaxed) == 0 {
        assert!(Instant::now() < deadline, "the circuit never closed");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(acks.load(Ordering::Relaxed), 1);
    sink.flush_and_close(Duration::from_secs(5)).await;
}

#[tokio::test]
async fn ping_follows_the_cluster() {
    let _turn = ONE_AT_A_TIME.lock().await;
    let fake = Fake::new(Reply::Ok);
    let url = serve(&fake).await;
    let store = OpenSearchStore::new(&config(url)).unwrap();

    store.ping().await.unwrap();
    *fake.root_status.lock() = 503;
    assert!(store.ping().await.is_err());
    *fake.root_status.lock() = 401;
    assert!(store.ping().await.is_err());
}
