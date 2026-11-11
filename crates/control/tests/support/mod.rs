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

/// Five captures for the boundary-value tests of every store: a 100
/// character body, a body that contains it, a newline in a request body,
/// statuses at the edges of a 32-bit field, empty and non-ASCII bodies.
pub fn boundary_messages() -> Vec<Message> {
    let body = |n: u64, status: u32, request: &[u8], response: &str| {
        let mut c = capture(n);
        c.response_status = status;
        c.request_body = request.to_vec().into();
        c.request_body_size = request.len() as u64;
        c.response_body = response.as_bytes().to_vec().into();
        c.response_body_size = response.len() as u64;
        Message::Http(c)
    };
    let x100 = "x".repeat(100);
    vec![
        body(1, 200, b"", &x100),
        body(2, 599, b"x", &format!("y{x100}y")),
        body(3, 404, b"line1\nline2", "ünï body"),
        body(4, 100, b"line1Xline2", "ÜNÏ BODY"),
        body(5, 200, b"", ""),
        // Only the Unicode case variants of `k` and `s`.
        body(6, 200, b"k", "\u{212a}"),
        body(7, 200, b"s", "\u{17f}"),
    ]
}

/// Filters on [`boundary_messages`] and the rows every store returns for
/// them. `contains` with non-ASCII letters is left out: its case folding
/// differs between the stores.
pub fn boundary_cases() -> Vec<(&'static str, Value, Vec<Uuid>)> {
    let (a, b, c, d, e) = (uuid_n(1), uuid_n(2), uuid_n(3), uuid_n(4), uuid_n(5));
    let (f, g) = (uuid_n(6), uuid_n(7));
    let rx = |value: &str| json!({ "op": "regex_match", "value": value });
    let status = |op: &str, value: i64| json!({ "op": op, "value": value });
    let big = 1_i64 << 40;
    vec![
        (
            "regex pins one 100 character string",
            json!({ "response_body": rx("^x{100}$") }),
            vec![a],
        ),
        (
            "the same unanchored",
            json!({ "response_body": rx("x{100}") }),
            vec![a, b],
        ),
        (
            "anchored empty regex",
            json!({ "response_body": rx("^$") }),
            vec![e],
        ),
        (
            "anchored empty repetition",
            json!({ "response_body": rx("^.{0}$") }),
            vec![e],
        ),
        (
            "empty regex on a request body",
            json!({ "request_body": rx("^$") }),
            vec![a, e],
        ),
        (
            "negated whole-string regex",
            json!({ "response_body": not(rx("^x{100}$")) }),
            vec![b, c, d, e, f, g],
        ),
        (
            "negated empty regex",
            json!({ "response_body": not(rx("^$")) }),
            vec![a, b, c, d, f, g],
        ),
        (
            "whole-string alternative with an empty one",
            json!({ "response_body": rx("^x{100}$|^$") }),
            vec![a, e],
        ),
        (
            "contains a part of a token",
            json!({ "response_body": contains("xxx") }),
            vec![a, b],
        ),
        (
            "contains a part of a token, in a request body",
            json!({ "request_body": contains("LINE") }),
            vec![c, d],
        ),
        (
            "dot does not match a newline",
            json!({ "request_body": rx("line1.line2") }),
            vec![d],
        ),
        (
            "negated dot rule",
            json!({ "request_body": not(rx("line1.line2")) }),
            vec![a, b, c, e, f, g],
        ),
        (
            "dot does not match a newline, anchored",
            json!({ "request_body": rx("^line1.line2$") }),
            vec![d],
        ),
        (
            "an escaped newline does",
            json!({ "request_body": rx(r"^line1\nline2$") }),
            vec![c],
        ),
        (
            "status above the 32-bit range, exact",
            json!({ "status_code": status("exact", big) }),
            vec![],
        ),
        (
            "status above the 32-bit range, gt",
            json!({ "status_code": status("gt", i64::MAX - 1) }),
            vec![],
        ),
        (
            "status above the 32-bit range, lte",
            json!({ "status_code": status("lte", i64::MAX) }),
            vec![a, b, c, d, e, f, g],
        ),
        (
            "status below the 32-bit range, gt",
            json!({ "status_code": status("gt", -big) }),
            vec![a, b, c, d, e, f, g],
        ),
        (
            "status below the 32-bit range, lte",
            json!({ "status_code": status("lte", -big) }),
            vec![],
        ),
        (
            "negated status above the range",
            json!({ "status_code": not(status("gt", big)) }),
            vec![a, b, c, d, e, f, g],
        ),
        (
            "status range up to the 32-bit edge",
            json!({ "status_code": { "op": "all", "filters": [
                status("gte", 400),
                status("lte", i64::from(i32::MAX) + 1),
            ] } }),
            vec![b, c],
        ),
        (
            "status in the type or beyond it",
            json!({ "status_code": { "op": "any", "filters": [
                status("exact", 599),
                status("exact", big),
            ] } }),
            vec![b],
        ),
        (
            "(?i) folds a non-ASCII letter",
            json!({ "response_body": rx("(?i)^ünï body$") }),
            vec![c, d],
        ),
    ]
}

/// Two WebSocket close messages for the `close_code` boundary tests, and
/// two text messages holding only the Unicode case variants of `k` and `s`.
pub fn boundary_close_messages() -> Vec<Message> {
    let text = |event: u64, payload: &str| {
        Message::Ws(wire::CapturedWsMessage {
            event_id: uuid_n(event).as_bytes().to_vec().into(),
            parent_event_id: uuid_n(500).as_bytes().to_vec().into(),
            session_id: uuid_n(9_000).as_bytes().to_vec().into(),
            proxy_id: "proxy-1".into(),
            org_id: ORG.into(),
            source: "crawler".into(),
            source_id: "run-1".into(),
            timestamp_nanos: base_nanos() + event as i64 * 1_000_000_000,
            direction: wire::WsDirection::C2s as i32,
            opcode: wire::WsOpcode::Text as i32,
            payload: payload.as_bytes().to_vec().into(),
            payload_size: payload.len() as u64,
            host: "ws.example.com".into(),
            ..Default::default()
        })
    };
    let closes = [(601, 1000), (602, 4999)].into_iter().map(|(event, code)| {
        Message::Ws(wire::CapturedWsMessage {
            event_id: uuid_n(event).as_bytes().to_vec().into(),
            parent_event_id: uuid_n(500).as_bytes().to_vec().into(),
            session_id: uuid_n(9_000).as_bytes().to_vec().into(),
            proxy_id: "proxy-1".into(),
            org_id: ORG.into(),
            source: "crawler".into(),
            source_id: "run-1".into(),
            timestamp_nanos: base_nanos() + event as i64 * 1_000_000_000,
            direction: wire::WsDirection::C2s as i32,
            opcode: wire::WsOpcode::Close as i32,
            close_code: code,
            host: "ws.example.com".into(),
            ..Default::default()
        })
    });
    closes
        .chain([text(603, "\u{212a}"), text(604, "\u{17f}")])
        .collect()
}

/// Filters on [`boundary_close_messages`] and the rows every store returns.
pub fn boundary_ws_cases() -> Vec<(&'static str, Value, Vec<Uuid>)> {
    let (low, high) = (uuid_n(601), uuid_n(602));
    let code = |op: &str, value: i64| json!({ "close_code": { "op": op, "value": value } });
    let big = 1_i64 << 40;
    vec![
        (
            "close code above the 32-bit range, exact",
            code("exact", big),
            vec![],
        ),
        (
            "close code above the 32-bit range, gte",
            code("gte", i64::from(i32::MAX) + 1),
            vec![],
        ),
        (
            "close code below the 32-bit range, lt",
            code("lt", -big),
            vec![],
        ),
        (
            "close code below a huge bound",
            code("lt", big),
            vec![low, high, uuid_n(603), uuid_n(604)],
        ),
        ("close code inside the type", code("gt", 1000), vec![high]),
        ("close code, exact", code("exact", 1000), vec![low]),
    ]
}

pub mod broker;
