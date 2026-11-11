//! ClickHouse handler for storing captured WebSocket messages.
//!
//! Sibling of `clickhouse.rs` (HTTP captures). Same engine semantics
//! (ReplicatedReplacingMergeTree on `inserted_at`), same circuit-breaker
//! discipline, same byte-cap backpressure. Different row type, different
//! target table (`ws_messages`).
//!
//! Kept as a separate handler so a CH stall on WS insert (which can be
//! denser than HTTP for chatty subscriptions) doesn't backpressure the HTTP
//! capture path or vice versa. The buffering and circuit-breaker plumbing
//! live in `super::batch_handler`; this file only declares the domain
//! shape.

use std::time::Duration;

use anyhow::Result;

use common::wire;

use super::batch_handler::{BatchHandler, FlushTarget};
use super::ch_writer::{ChTarget, ClickHouseWriter};
use super::clickhouse::ClickHouseConfig;
use super::normalize::NormalizedWsMessage;

#[derive(clickhouse::Row, serde::Serialize)]
pub(crate) struct WsClickHouseRow {
    /// Idempotency key — UUIDv7 minted at the proxy.
    #[serde(with = "clickhouse::serde::uuid")]
    id: uuid::Uuid,
    #[serde(with = "clickhouse::serde::uuid")]
    parent_event_id: uuid::Uuid,
    org_id: String,
    #[serde(with = "clickhouse::serde::time::datetime64::millis")]
    timestamp: time::OffsetDateTime,
    session_offset: u64,
    /// CH `Enum8('c2s'=1, 's2c'=2)`. The clickhouse-rs RowBinary serializer
    /// encodes Enum8 columns as their numeric discriminant, not the string
    /// label, so we feed the discriminant directly.
    direction: i8,
    /// CH `Enum8('text'=1, 'binary'=2, 'close'=8, 'ping'=9, 'pong'=10)`.
    opcode: i8,
    session_id: String,
    proxy_id: String,
    source: String,
    source_id: String,
    host: String,
    #[serde(with = "serde_bytes")]
    payload: Vec<u8>,
    payload_size: u32,
    /// CH `UInt8` boolean.
    payload_truncated: u8,
    payload_is_text: u8,
    was_compressed: u8,
    close_code: u16,
    close_reason: String,
    /// Engine version key. Wall-clock nanoseconds at insert time.
    #[serde(with = "clickhouse::serde::time::datetime64::nanos")]
    inserted_at: time::OffsetDateTime,
}

/// In-memory document staged for the next flush.
pub(crate) struct WsMessageDocument {
    normalized: NormalizedWsMessage,
}

impl WsMessageDocument {
    fn from_wire(msg: &wire::CapturedWsMessage, session_offset: u64) -> Self {
        Self {
            normalized: NormalizedWsMessage::from_wire(msg, session_offset),
        }
    }

    fn to_row(&self) -> WsClickHouseRow {
        let n = &self.normalized;
        WsClickHouseRow {
            id: n.event_id,
            parent_event_id: n.parent_event_id,
            org_id: n.org_id.clone(),
            timestamp: n.timestamp,
            session_offset: n.session_offset,
            direction: n.direction.discriminant(),
            opcode: n.opcode.discriminant(),
            session_id: n.session_id.to_string(),
            proxy_id: n.proxy_id.clone(),
            source: n.source.clone(),
            source_id: n.source_id.clone(),
            host: n.host.clone(),
            payload: n.payload.clone(),
            payload_size: n.payload_size.min(u32::MAX as u64) as u32,
            payload_truncated: u8::from(n.payload_truncated),
            payload_is_text: u8::from(n.payload_is_text),
            was_compressed: u8::from(n.was_compressed),
            close_code: n.close_code,
            close_reason: n.close_reason.clone(),
            inserted_at: time::OffsetDateTime::now_utc(),
        }
    }
}

/// `FlushTarget` binding for WS messages. Overrides
/// `record_row_write_error` so per-row failures still carry
/// `event_id`/`parent_event_id` for incident triage.
pub(crate) struct WsTarget;

impl FlushTarget for WsTarget {
    type Doc = WsMessageDocument;
    const NAME: &'static str = "ws_messages";

    fn estimate_bytes(doc: &Self::Doc) -> u64 {
        // 256B fudge for scalar columns + close_reason + host etc.
        doc.normalized.payload.len() as u64 + 256
    }

    fn completed_at(doc: &Self::Doc) -> time::OffsetDateTime {
        doc.normalized.timestamp
    }

    fn record_row_write_error(doc: &Self::Doc, err: &dyn std::fmt::Display) {
        tracing::error!(
            target_table = Self::NAME,
            error = %err,
            event_id = %doc.normalized.event_id,
            parent_event_id = %doc.normalized.parent_event_id,
            "failed to write row to ClickHouse insert",
        );
    }
}

impl ChTarget for WsTarget {
    type Row = WsClickHouseRow;

    fn to_row(doc: &Self::Doc) -> Self::Row {
        doc.to_row()
    }
}

pub struct WsClickHouseHandler {
    inner: BatchHandler<WsTarget>,
}

impl WsClickHouseHandler {
    /// Build a handler reusing the existing `ClickHouseConfig`. The CH
    /// connection settings (URL, DB, auth) are shared with the HTTP handler;
    /// only the target table differs.
    pub fn new(config: ClickHouseConfig) -> Result<Self> {
        let mut client = clickhouse::Client::default().with_url(&config.url);
        if let Some(ref db) = config.database {
            client = client.with_database(db);
        }
        if let Some(ref user) = config.user {
            client = client.with_user(user);
        }
        if let Some(ref password) = config.password {
            client = client.with_password(password);
        }

        tracing::info!(
            url = %config.url,
            "WsClickHouse client created",
        );

        // Hard-coded table — the HTTP handler's `table` config field doesn't
        // apply here. WS rows always go to `ws_messages`.
        let table = "ws_messages".to_string();

        let inner = BatchHandler::<WsTarget>::new(
            Box::new(ClickHouseWriter::<WsTarget>::new(client, table)),
            config.batch(),
        );

        Ok(Self { inner })
    }

    pub async fn send(
        &self,
        message: &wire::CapturedWsMessage,
        session_offset: u64,
        ack: Option<common::log::AckHandle>,
    ) -> Result<()> {
        let doc = WsMessageDocument::from_wire(message, session_offset);
        self.inner.send_doc(doc, ack).await
    }

    pub async fn flush_and_close(&self, timeout: Duration) {
        self.inner.flush_and_close(timeout).await
    }

    /// Whether this handler's circuit breaker is open.
    pub fn circuit_open(&self) -> bool {
        self.inner.circuit_open()
    }
}
