//! Domain models for the API database layer.

use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;

mod headers_as_map {
    use serde::ser::{SerializeMap, Serializer};

    /// Serialize `Vec<(String, String)>` as a JSON object, preserving all
    /// entries. When duplicate keys exist the last value wins (same behavior
    /// as the old `serde_json::Value` JSONB column).
    pub fn serialize<S: Serializer>(headers: &[(String, String)], s: S) -> Result<S::Ok, S::Error> {
        let mut map = s.serialize_map(Some(headers.len()))?;
        for (k, v) in headers {
            map.serialize_entry(k, v)?;
        }
        map.end()
    }
}

/// Row in the `http_captures` table.
///
/// Single source of truth for the ClickHouse schema. Used for both reads
/// and as the reference for batch inserts.
#[derive(Debug, Clone, Serialize)]
pub struct HttpCapture {
    pub id: Uuid,
    pub org_id: String,
    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,
    pub method: String,
    pub path: String,
    pub host: String,
    pub scheme: String,
    pub session_id: String,
    pub proxy_id: String,
    #[serde(with = "headers_as_map")]
    pub request_headers: Vec<(String, String)>,
    pub request_body: String,
    pub request_size: u32,
    pub status_code: u16,
    #[serde(with = "headers_as_map")]
    pub response_headers: Vec<(String, String)>,
    pub response_body: String,
    pub response_size: u32,
    pub duration_ms: u32,
    pub ratelimit_wait_ms: u32,
    pub source: String,
    pub source_id: String,
    pub correlation_id: Option<String>,
    pub parent_correlation_id: Option<String>,
    pub account_id: Option<String>,
    pub tool_call_id: Option<String>,
}

/// Summary row returned by search queries (header fields present, bodies optional).
#[derive(Debug, Clone, Serialize)]
pub struct HttpCaptureSummary {
    pub id: Uuid,
    pub org_id: String,
    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,
    pub session_offset: u64,
    pub method: String,
    pub path: String,
    pub host: String,
    pub scheme: String,
    pub session_id: String,
    pub proxy_id: String,
    pub request_size: u32,
    pub status_code: u16,
    pub response_size: u32,
    pub duration_ms: u32,
    pub ratelimit_wait_ms: u32,
    pub source: String,
    pub source_id: String,
    pub correlation_id: Option<String>,
    pub parent_correlation_id: Option<String>,
    pub account_id: Option<String>,
    pub tool_call_id: Option<String>,
    pub request_headers: Vec<(String, String)>,
    pub response_headers: Vec<(String, String)>,
    /// Request body, when the search query asked for it via
    /// `request_body_max_fetch_size`. `None` when not requested;
    /// `Some(BodyFetch::TooLarge { size })` when the body's size
    /// exceeded the cap; `Some(BodyFetch::Body { value })` otherwise.
    pub request_body: Option<BodyFetch>,
    /// Response body counterpart — see `request_body`.
    pub response_body: Option<BodyFetch>,
}

/// Body returned in a [`HttpCaptureSummary`] when the search query
/// requested it via `request_body_max_fetch_size` /
/// `response_body_max_fetch_size`. The `size` carried by `TooLarge`
/// is the actual body size in bytes — callers can use it to decide
/// whether to fetch the full row through `GET /orgs/{}/requests/{}`.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum BodyFetch {
    Body { value: String },
    TooLarge { size: u32 },
}

/// Paginated search response with cursor.
#[derive(Debug, Clone, Serialize)]
pub struct SearchResponse {
    pub items: Vec<HttpCaptureSummary>,
    /// Opaque cursor for the next page. `None` when there are no more results.
    pub next_cursor: Option<String>,
    /// Total number of rows matching the filter (ignoring cursor/limit).
    pub total_count: Option<u64>,
}

/// Row in the `ws_messages` table.
///
/// Single source of truth for the WS ClickHouse schema. Used for full-row
/// reads (per-id lookup); the search path projects only the metadata
/// columns plus an optional capped payload via [`WsCaptureSummary`].
#[derive(Debug, Clone, Serialize)]
pub struct WsCapture {
    pub id: Uuid,
    pub parent_event_id: Uuid,
    pub org_id: String,
    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,
    pub session_offset: u64,
    /// CH `Enum8('c2s'=1, 's2c'=2)` — read out as a string.
    pub direction: String,
    /// CH `Enum8('text'=1, 'binary'=2, 'close'=8, 'ping'=9, 'pong'=10)`.
    pub opcode: String,
    pub session_id: String,
    pub proxy_id: String,
    pub source: String,
    pub source_id: String,
    pub host: String,
    pub payload: String,
    pub payload_size: u32,
    pub payload_truncated: bool,
    pub payload_is_text: bool,
    pub was_compressed: bool,
    pub close_code: u16,
    pub close_reason: String,
}

/// Summary row returned by WS search queries. Mirrors `HttpCaptureSummary`:
/// metadata columns are always present, the payload column is gated on the
/// caller-supplied `payload_max_fetch_size`.
#[derive(Debug, Clone, Serialize)]
pub struct WsCaptureSummary {
    pub id: Uuid,
    pub parent_event_id: Uuid,
    pub org_id: String,
    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,
    pub session_offset: u64,
    pub direction: String,
    pub opcode: String,
    pub session_id: String,
    pub proxy_id: String,
    pub source: String,
    pub source_id: String,
    pub host: String,
    pub payload_size: u32,
    pub payload_truncated: bool,
    pub payload_is_text: bool,
    pub was_compressed: bool,
    pub close_code: u16,
    pub close_reason: String,
    /// Payload, when the search query asked for it via
    /// `payload_max_fetch_size`. `None` when not requested;
    /// `Some(BodyFetch::TooLarge { size })` when the payload's size
    /// exceeded the cap; `Some(BodyFetch::Body { value })` otherwise.
    pub payload: Option<BodyFetch>,
}

/// Paginated WS search response with cursor.
#[derive(Debug, Clone, Serialize)]
pub struct WsSearchResponse {
    pub items: Vec<WsCaptureSummary>,
    /// Opaque cursor for the next page. `None` when there are no more results.
    pub next_cursor: Option<String>,
    /// Total rows matching the filter (ignoring pagination). `None` when the
    /// caller did not request a count (e.g. the internal RPC search path).
    pub total_count: Option<u64>,
}
