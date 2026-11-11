//! Read-side facade over `ws_messages` and its materialized views.
//!
//! Sibling of `crate::traffic` for HTTP. Filter/cursor/routing logic
//! lives in [`crate::query::ws`]. This module owns the ClickHouse row
//! shapes (one full row, two summary variants) plus the single-row
//! `get_ws_by_id` lookup.
//!
//! ## Enum8 columns
//!
//! `direction` and `opcode` are CH `Enum8`. The Rust clickhouse crate's
//! RowBinary deserializer surfaces them as raw `i8` tags rather than
//! the schema's string labels. Every SELECT in this module casts both
//! to `LowCardinality(String)` via `CAST(... AS String) AS ...` so the
//! row structs can use `String` fields and the API surface returns the
//! human-readable label.

use anyhow::{Context, Result};
use serde::Deserialize;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::models::{BodyFetch, WsCapture, WsCaptureSummary};

/// Explicit projection list shared by every full-row read. Replaces
/// `?fields` because two Enum8 columns need to be cast to String for
/// RowBinary deserialization.
const FULL_ROW_PROJECTION: &str = "id, parent_event_id, org_id, timestamp, session_offset, \
     CAST(direction AS String) AS direction, CAST(opcode AS String) AS opcode, \
     session_id, proxy_id, source, source_id, host, payload, payload_size, \
     payload_truncated, payload_is_text, was_compressed, close_code, close_reason";

/// Internal row matching the full ws_messages schema (used by `get_ws_by_id`).
#[derive(clickhouse::Row, Deserialize)]
pub(crate) struct ClickHouseWsCapture {
    #[serde(with = "clickhouse::serde::uuid")]
    id: Uuid,
    #[serde(with = "clickhouse::serde::uuid")]
    parent_event_id: Uuid,
    org_id: String,
    #[serde(with = "clickhouse::serde::time::datetime64::millis")]
    timestamp: OffsetDateTime,
    session_offset: u64,
    direction: String,
    opcode: String,
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
}

impl From<ClickHouseWsCapture> for WsCapture {
    fn from(c: ClickHouseWsCapture) -> Self {
        Self {
            id: c.id,
            parent_event_id: c.parent_event_id,
            org_id: c.org_id,
            timestamp: c.timestamp,
            session_offset: c.session_offset,
            direction: c.direction,
            opcode: c.opcode,
            session_id: c.session_id,
            proxy_id: c.proxy_id,
            source: c.source,
            source_id: c.source_id,
            host: c.host,
            payload: String::from_utf8_lossy(&c.payload).into_owned(),
            payload_size: c.payload_size,
            payload_truncated: c.payload_truncated != 0,
            payload_is_text: c.payload_is_text != 0,
            was_compressed: c.was_compressed != 0,
            close_code: c.close_code,
            close_reason: c.close_reason,
        }
    }
}

/// Summary row — metadata only (no payload). Read by
/// `crate::query::ws::search` from `ws_messages` or
/// `ws_messages_by_parent`.
#[derive(clickhouse::Row, Deserialize)]
pub(crate) struct ClickHouseWsSummary {
    #[serde(with = "clickhouse::serde::uuid")]
    pub(crate) id: Uuid,
    #[serde(with = "clickhouse::serde::uuid")]
    parent_event_id: Uuid,
    org_id: String,
    #[serde(with = "clickhouse::serde::time::datetime64::millis")]
    pub(crate) timestamp: OffsetDateTime,
    pub(crate) session_offset: u64,
    direction: String,
    opcode: String,
    session_id: String,
    proxy_id: String,
    source: String,
    source_id: String,
    host: String,
    payload_size: u32,
    payload_truncated: u8,
    payload_is_text: u8,
    was_compressed: u8,
    close_code: u16,
    close_reason: String,
}

impl From<ClickHouseWsSummary> for WsCaptureSummary {
    fn from(c: ClickHouseWsSummary) -> Self {
        Self {
            id: c.id,
            parent_event_id: c.parent_event_id,
            org_id: c.org_id,
            timestamp: c.timestamp,
            session_offset: c.session_offset,
            direction: c.direction,
            opcode: c.opcode,
            session_id: c.session_id,
            proxy_id: c.proxy_id,
            source: c.source,
            source_id: c.source_id,
            host: c.host,
            payload_size: c.payload_size,
            payload_truncated: c.payload_truncated != 0,
            payload_is_text: c.payload_is_text != 0,
            was_compressed: c.was_compressed != 0,
            close_code: c.close_code,
            close_reason: c.close_reason,
            payload: None,
        }
    }
}

fn map_payload(raw: Vec<u8>, size: u32, max: Option<u32>) -> Option<BodyFetch> {
    let max = max?;
    if size > max {
        Some(BodyFetch::TooLarge { size })
    } else {
        Some(BodyFetch::Body {
            value: String::from_utf8_lossy(&raw).into_owned(),
        })
    }
}

/// Locator row — just enough to find the full row in the base table
/// via its sort key `(org_id, source_id, timestamp, session_offset, id)`.
#[derive(clickhouse::Row, Deserialize)]
struct WsByIdLocator {
    #[serde(with = "clickhouse::serde::uuid")]
    id: Uuid,
    source_id: String,
    #[serde(with = "clickhouse::serde::time::datetime64::millis")]
    timestamp: OffsetDateTime,
    session_offset: u64,
}

/// Fetch a single WS message by its UUID, scoped to an org.
///
/// Uses a two-step approach to avoid reading large payload columns from
/// unmerged parts of the `ws_messages_by_id` MV:
///
/// 1. Look up `(source_id, timestamp, session_offset)` from
///    `ws_messages_by_id` using only lightweight locator columns.
/// 2. Fetch the full row from the base `ws_messages` table whose sort
///    key `(org_id, source_id, timestamp, session_offset, id)` gives a
///    precise single-granule seek.
#[tracing::instrument(name = "clickhouse.get_ws_message", skip_all, fields(db.system = "clickhouse", org_id = %org_id, id = %id))]
pub async fn get_ws_by_id(
    client: &clickhouse::Client,
    org_id: &str,
    id: Uuid,
) -> Result<Option<WsCapture>> {
    // Step 1: lightweight locator lookup on the by_id MV.
    let locators = client
        .query("SELECT ?fields FROM ws_messages_by_id WHERE id = ? AND org_id = ? LIMIT 1")
        .bind(id)
        .bind(org_id)
        .fetch_all::<WsByIdLocator>()
        .await
        .context("ws_traffic get_ws_by_id locator query failed")?;

    let loc = match locators.into_iter().next() {
        Some(l) => l,
        None => return Ok(None),
    };

    // Step 2: full row from base table using its sort key.
    // Bind the timestamp as a formatted string — `OffsetDateTime`'s
    // RowBinary bind produces a tuple that ClickHouse rejects.
    let ts_str = crate::query::cursor::ts_literal(loc.timestamp);
    let sql = format!(
        "SELECT {FULL_ROW_PROJECTION} FROM ws_messages \
         WHERE org_id = ? AND source_id = ? AND timestamp = ? \
         AND session_offset = ? AND id = ? LIMIT 1"
    );
    let rows = client
        .query(&sql)
        .bind(org_id)
        .bind(&loc.source_id)
        .bind(ts_str.as_str())
        .bind(loc.session_offset)
        .bind(loc.id)
        .fetch_all::<ClickHouseWsCapture>()
        .await
        .context("ws_traffic get_ws_by_id full-row query failed")?;

    Ok(rows.into_iter().next().map(WsCapture::from))
}

/// Public projection helpers used by `crate::query::ws::search` to
/// build SELECT lists with or without the payload column.
pub(crate) mod projection {
    /// Metadata-only projection (no payload column).
    pub(crate) const SUMMARY: &str = "id, parent_event_id, org_id, timestamp, session_offset, \
        CAST(direction AS String) AS direction, CAST(opcode AS String) AS opcode, \
        session_id, proxy_id, source, source_id, host, \
        payload_size, payload_truncated, payload_is_text, was_compressed, \
        close_code, close_reason";
}

/// Sort-key tuple identifying one WS message; stage 1 of
/// [`crate::query::ws::search`] returns these, stage 2 fetches payloads.
pub(crate) struct WsBodyKey {
    pub id: Uuid,
    pub org_id: String,
    pub source_id: String,
    pub timestamp: OffsetDateTime,
    pub session_offset: u64,
}

/// Stage-2 row: a message's id plus its (size-masked) payload.
#[derive(clickhouse::Row, Deserialize)]
struct PayloadRow {
    #[serde(with = "clickhouse::serde::uuid")]
    id: Uuid,
    #[serde(with = "serde_bytes")]
    payload: Vec<u8>,
    payload_size: u32,
}

/// Fetch payloads for a page of WS messages, keyed on the full sort-key
/// tuple `(org_id, source_id, timestamp, session_offset, id)` of the
/// base `ws_messages` table (where the payload lives, even when stage 1
/// read an MV). The tuple is the table's full sort key, so ClickHouse
/// seeks each row to its granule instead of scanning the partition (the
/// HTTP analog measured ~15 ms/page vs ~10 M rows for a JOIN). Mirrors
/// [`crate::traffic::fetch_page_bodies`].
pub(crate) async fn fetch_page_payloads(
    client: &clickhouse::Client,
    keys: &[WsBodyKey],
    payload_max: Option<u32>,
) -> Result<std::collections::HashMap<Uuid, Option<BodyFetch>>> {
    if keys.is_empty() {
        return Ok(std::collections::HashMap::new());
    }

    // Values come from a page just read from ClickHouse (UUIDs, typed
    // timestamp, u64), not user input, so direct formatting is safe.
    let tuples: String = keys
        .iter()
        .map(|k| {
            format!(
                "('{}','{}','{}',{},'{}')",
                k.org_id,
                k.source_id,
                crate::query::cursor::ts_literal(k.timestamp),
                k.session_offset,
                k.id,
            )
        })
        .collect::<Vec<_>>()
        .join(",");

    let payload_proj = match payload_max {
        Some(n) => format!("if(payload_size <= {n}, payload, '') AS payload"),
        None => "'' AS payload".to_string(),
    };
    let sql = format!(
        "SELECT id, {payload_proj}, payload_size \
         FROM ws_messages \
         WHERE (org_id, source_id, timestamp, session_offset, id) IN ({tuples}) \
         LIMIT 1 BY id"
    );

    let rows = client
        .query(&sql)
        .fetch_all::<PayloadRow>()
        .await
        .context("ws payload-fetch query failed")?;

    Ok(rows
        .into_iter()
        .map(|r| (r.id, map_payload(r.payload, r.payload_size, payload_max)))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::map_payload;
    use crate::models::BodyFetch;

    #[test]
    fn text_payload_roundtrips_within_cap() {
        match map_payload(b"hello".to_vec(), 5, Some(2048)) {
            Some(BodyFetch::Body { value }) => assert_eq!(value, "hello"),
            _ => panic!("expected Body"),
        }
    }

    #[test]
    fn binary_payload_decodes_lossily_without_panic() {
        // Lone 0xFF/0xFE are invalid UTF-8. Reading the column into a Rust
        // `String` crashed the whole WS search here; lossy decode must not.
        match map_payload(vec![0xff, 0xfe], 2, Some(2048)) {
            Some(BodyFetch::Body { value }) => assert!(value.contains('\u{fffd}')),
            _ => panic!("expected Body"),
        }
    }

    #[test]
    fn payload_over_cap_is_too_large() {
        assert!(matches!(
            map_payload(vec![1, 2, 3], 9000, Some(2048)),
            Some(BodyFetch::TooLarge { size: 9000 })
        ));
    }

    #[test]
    fn no_cap_yields_none() {
        assert!(map_payload(b"x".to_vec(), 1, None).is_none());
    }
}
