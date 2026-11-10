//! Helpers shared by the capture store integration tests.

#![allow(dead_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use common::log::{AckHandle, AckInner};
use common::wire;
use proxyx_control::capture_store::CaptureStore;
use proxyx_control::pipeline::{CaptureSink, PipelineMessage, RequestPipeline};
use proxyx_control::query::TrafficQuery;
use proxyx_control::query::ws::WsTrafficQuery;
use serde_json::{Value, json};
use time::OffsetDateTime;
use uuid::Uuid;

static BASE: AtomicI64 = AtomicI64::new(1_700_000_000_000_000_000); // 2023-11-14T22:13:20Z

/// Capture time of event 0, nanoseconds since the epoch. A store with a
/// retention TTL needs recent data: tests of it move the base with
/// [`set_base_nanos`] before building captures.
pub fn base_nanos() -> i64 {
    BASE.load(Ordering::Relaxed)
}

pub fn set_base_nanos(nanos: i64) {
    BASE.store(nanos, Ordering::Relaxed);
}
pub const ORG: &str = "org-1";

/// Run `messages` through a pipeline into `sink` and flush it. Returns how
/// many broker acks fired; every message must have been acked once its batch
/// was written.
pub async fn deliver_via(sink: Arc<dyn CaptureSink>, messages: Vec<Message>) -> usize {
    let pipeline = RequestPipeline::new(sink, 256);
    let sender = pipeline.sender();
    let acked = Arc::new(AtomicUsize::new(0));
    let sent = messages.len();
    for (i, message) in messages.into_iter().enumerate() {
        let ack = AckHandle::new(CountingAck(acked.clone()));
        let offset = 1000 + i as u64;
        let pipeline_message = match message {
            Message::Http(captured) => PipelineMessage::Capture {
                captured: Box::new(captured),
                session_offset: offset,
                ack,
            },
            Message::Ws(message) => PipelineMessage::WsMessage {
                message: Box::new(message),
                session_offset: offset,
                ack,
            },
        };
        sender.send(pipeline_message).await.unwrap();
    }
    drop(sender);
    pipeline.flush_and_close(Duration::from_secs(240)).await;
    assert_eq!(
        acked.load(Ordering::Relaxed),
        sent,
        "every message is acked once its batch is written"
    );
    acked.load(Ordering::Relaxed)
}

pub enum Message {
    Http(wire::CapturedRequest),
    Ws(wire::CapturedWsMessage),
}

pub struct CountingAck(Arc<AtomicUsize>);

#[async_trait]
impl AckInner for CountingAck {
    async fn ack_boxed(self: Box<Self>) -> anyhow::Result<()> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

pub fn header(name: &str, value: &str) -> wire::Header {
    wire::Header {
        name: name.to_string(),
        value: value.to_string(),
    }
}

/// UUIDv7-like id: sortable by `n`.
pub fn uuid_n(n: u64) -> Uuid {
    Uuid::from_u128((0x018f_0000_0000_7000_8000_u128 << 64) | u128::from(n))
}

pub fn capture(n: u64) -> wire::CapturedRequest {
    wire::CapturedRequest {
        event_id: uuid_n(n).as_bytes().to_vec().into(),
        session_id: uuid_n(9_000).as_bytes().to_vec().into(),
        proxy_id: "proxy-1".into(),
        org_id: ORG.into(),
        source: "crawler".into(),
        source_id: "run-1".into(),
        timestamp_nanos: base_nanos() + (n as i64) * 1_000_000_000,
        method: "GET".into(),
        scheme: "https".into(),
        host: "api.example.com".into(),
        port: 443,
        path: format!("/items/{n}"),
        response_status: 200,
        duration_ms: 12,
        ..Default::default()
    }
}

/// A query as a REST caller sends it: `extra` is merged over an org-scoped
/// query with one empty branch.
pub fn tq(extra: Value) -> TrafficQuery {
    let mut query = json!({ "org_id": ORG, "branches": [{}] });
    for (key, value) in extra.as_object().unwrap() {
        query[key] = value.clone();
    }
    serde_json::from_value(query).unwrap()
}

pub fn branch(branch: Value) -> TrafficQuery {
    tq(json!({ "branches": [branch] }))
}

pub fn wq(extra: Value) -> WsTrafficQuery {
    let mut query = json!({ "org_id": ORG, "branches": [{}] });
    for (key, value) in extra.as_object().unwrap() {
        query[key] = value.clone();
    }
    serde_json::from_value(query).unwrap()
}

pub async fn ids(store: &dyn CaptureStore, query: &TrafficQuery) -> Vec<Uuid> {
    store
        .search_requests(query)
        .await
        .unwrap()
        .items
        .into_iter()
        .map(|i| i.id)
        .collect()
}

pub fn contains(value: &str) -> Value {
    json!({ "op": "contains", "value": value })
}

pub fn exact(value: &str) -> Value {
    json!({ "op": "exact", "value": value })
}

pub fn not(filter: Value) -> Value {
    json!({ "op": "not", "filter": filter })
}

pub fn ts_of(n: u64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp_nanos(
        i128::from(base_nanos()) + i128::from(n) * 1_000_000_000,
    )
    .unwrap()
}

/// Captures `1..=n` one second apart, status `200 + n % 5`.
pub fn series(n: u64) -> Vec<Message> {
    (1..=n)
        .map(|i| {
            let mut c = capture(i);
            c.response_status = 200 + (i % 5) as u32;
            Message::Http(c)
        })
        .collect()
}

pub mod broker;
