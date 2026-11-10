//! Read-side facade over `http_captures` and its materialized views.
//!
//! Filter/cursor/routing logic lives in [`crate::query`]. This module
//! owns the ClickHouse row shapes (one full row, one summary) and the
//! `From` impls into the public model types, plus the single-row
//! `get_by_id` lookup.

use anyhow::{Context, Result};
use serde::Deserialize;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::models::{BodyFetch, HttpCapture, HttpCaptureSummary};

/// Internal struct matching the full ClickHouse row (used by `get_by_id`).
#[derive(clickhouse::Row, Deserialize)]
pub(crate) struct ClickHouseCapture {
    #[serde(with = "clickhouse::serde::uuid")]
    id: Uuid,
    org_id: String,
    #[serde(with = "clickhouse::serde::time::datetime64::millis")]
    timestamp: OffsetDateTime,
    method: String,
    path: String,
    host: String,
    scheme: String,
    session_id: String,
    proxy_id: String,
    request_headers: Vec<(String, String)>,
    request_body: String,
    request_size: u32,
    status_code: u16,
    response_headers: Vec<(String, String)>,
    response_body: String,
    response_size: u32,
    duration_ms: u32,
    ratelimit_wait_ms: u32,
    source: String,
    source_id: String,
    correlation_id: Option<String>,
    parent_correlation_id: Option<String>,
    account_id: Option<String>,
    tool_call_id: Option<String>,
}

impl From<ClickHouseCapture> for HttpCapture {
    fn from(c: ClickHouseCapture) -> Self {
        Self {
            id: c.id,
            org_id: c.org_id,
            timestamp: c.timestamp,
            method: c.method,
            path: c.path,
            host: c.host,
            scheme: c.scheme,
            session_id: c.session_id,
            proxy_id: c.proxy_id,
            request_headers: c.request_headers,
            request_body: c.request_body,
            request_size: c.request_size,
            status_code: c.status_code,
            response_headers: c.response_headers,
            response_body: c.response_body,
            response_size: c.response_size,
            duration_ms: c.duration_ms,
            ratelimit_wait_ms: c.ratelimit_wait_ms,
            source: c.source,
            source_id: c.source_id,
            correlation_id: c.correlation_id,
            parent_correlation_id: c.parent_correlation_id,
            account_id: c.account_id,
            tool_call_id: c.tool_call_id,
        }
    }
}

/// Summary row — metadata plus headers (no bodies). Read by
/// `crate::query::search` from `http_captures` or `http_captures_timeline`.
#[derive(clickhouse::Row, Deserialize)]
pub(crate) struct ClickHouseSummary {
    #[serde(with = "clickhouse::serde::uuid")]
    pub(crate) id: Uuid,
    org_id: String,
    #[serde(with = "clickhouse::serde::time::datetime64::millis")]
    pub(crate) timestamp: OffsetDateTime,
    #[serde(default)]
    pub(crate) session_offset: u64,
    method: String,
    path: String,
    host: String,
    scheme: String,
    session_id: String,
    proxy_id: String,
    request_headers: Vec<(String, String)>,
    request_size: u32,
    status_code: u16,
    response_headers: Vec<(String, String)>,
    response_size: u32,
    duration_ms: u32,
    ratelimit_wait_ms: u32,
    source: String,
    source_id: String,
    correlation_id: Option<String>,
    parent_correlation_id: Option<String>,
    account_id: Option<String>,
    tool_call_id: Option<String>,
    /// `toString` of the search's sort expression (`''` for timestamp
    /// order); feeds the next-page cursor.
    pub(crate) sort_key: String,
}

impl From<ClickHouseSummary> for HttpCaptureSummary {
    fn from(c: ClickHouseSummary) -> Self {
        Self {
            id: c.id,
            org_id: c.org_id,
            timestamp: c.timestamp,
            session_offset: c.session_offset,
            method: c.method,
            path: c.path,
            host: c.host,
            scheme: c.scheme,
            session_id: c.session_id,
            proxy_id: c.proxy_id,
            request_size: c.request_size,
            status_code: c.status_code,
            response_size: c.response_size,
            duration_ms: c.duration_ms,
            ratelimit_wait_ms: c.ratelimit_wait_ms,
            source: c.source,
            source_id: c.source_id,
            correlation_id: c.correlation_id,
            parent_correlation_id: c.parent_correlation_id,
            account_id: c.account_id,
            tool_call_id: c.tool_call_id,
            request_headers: c.request_headers,
            response_headers: c.response_headers,
            request_body: None,
            response_body: None,
        }
    }
}

fn map_body(raw: String, size: u32, max: Option<u32>) -> Option<BodyFetch> {
    let max = max?;
    if size > max {
        Some(BodyFetch::TooLarge { size })
    } else {
        Some(BodyFetch::Body { value: raw })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_preserves_headers_without_bodies() {
        let summary = HttpCaptureSummary::from(ClickHouseSummary {
            id: Uuid::nil(),
            org_id: "org".to_string(),
            timestamp: OffsetDateTime::UNIX_EPOCH,
            session_offset: 0,
            method: "GET".to_string(),
            path: "/".to_string(),
            host: "example.com".to_string(),
            scheme: "https".to_string(),
            session_id: "session".to_string(),
            proxy_id: "proxy".to_string(),
            request_headers: vec![("accept".to_string(), "application/json".to_string())],
            request_size: 0,
            status_code: 200,
            response_headers: vec![("content-type".to_string(), "application/json".to_string())],
            response_size: 0,
            duration_ms: 10,
            ratelimit_wait_ms: 0,
            source: "crawler".to_string(),
            source_id: "source".to_string(),
            correlation_id: None,
            parent_correlation_id: None,
            account_id: None,
            tool_call_id: None,
            sort_key: String::new(),
        });

        assert_eq!(
            summary.request_headers,
            vec![("accept".to_string(), "application/json".to_string())]
        );
        assert_eq!(
            summary.response_headers,
            vec![("content-type".to_string(), "application/json".to_string())]
        );
        assert!(summary.request_body.is_none());
        assert!(summary.response_body.is_none());
    }

    #[test]
    fn map_body_applies_size_cap() {
        // No cap requested → body never materialized.
        assert!(map_body("x".to_string(), 1, None).is_none());
        // Within cap → returned verbatim.
        match map_body("{}".to_string(), 2, Some(10)) {
            Some(BodyFetch::Body { value }) => assert_eq!(value, "{}"),
            other => panic!("expected fetched body, got {other:?}"),
        }
        // Over cap → TooLarge carries the true size, not the masked body.
        match map_body(String::new(), 5000, Some(1024)) {
            Some(BodyFetch::TooLarge { size }) => assert_eq!(size, 5000),
            other => panic!("expected too-large, got {other:?}"),
        }
    }
}

/// Locator row — just enough to find the full row in the base table via its
/// complete sort key `(org_id, source_id, timestamp, session_offset, id)`.
#[derive(clickhouse::Row, Deserialize)]
struct ByIdLocator {
    #[serde(with = "clickhouse::serde::uuid")]
    id: Uuid,
    source_id: String,
    #[serde(with = "clickhouse::serde::time::datetime64::millis")]
    timestamp: OffsetDateTime,
    session_offset: u64,
}

/// Fetch a single capture by its UUID, scoped to an org.
///
/// Uses a two-step approach to avoid reading large body columns from
/// all 43+ unmerged parts of the `http_captures_by_id` MV:
///
/// 1. Look up `(source_id, timestamp)` from `http_captures_by_id`
///    using only lightweight columns (the primary key narrows to one
///    granule per part, but each granule is small without bodies).
/// 2. Fetch the full row from the base `http_captures` table whose
///    sort key `(org_id, source_id, timestamp, id)` gives a precise
///    single-granule seek.
#[tracing::instrument(name = "clickhouse.get_request", skip_all, fields(db.system = "clickhouse", org_id = %org_id, id = %id))]
pub async fn get_by_id(
    client: &clickhouse::Client,
    org_id: &str,
    id: Uuid,
) -> Result<Option<HttpCapture>> {
    // Step 1: lightweight locator lookup on the by_id MV.
    let locators = client
        .query("SELECT ?fields FROM http_captures_by_id WHERE id = ? AND org_id = ? LIMIT 1")
        .bind(id)
        .bind(org_id)
        .fetch_all::<ByIdLocator>()
        .await
        .context("traffic get_by_id locator query failed")?;

    let loc = match locators.into_iter().next() {
        Some(l) => l,
        None => return Ok(None),
    };

    // Step 2: full row from base table using its sort key.
    // Bind the timestamp as a formatted string — `OffsetDateTime`'s
    // RowBinary bind produces a tuple that ClickHouse rejects.
    let ts_str = crate::query::cursor::ts_literal(loc.timestamp);
    let rows = client
        .query(
            "SELECT ?fields FROM http_captures \
             WHERE org_id = ? AND source_id = ? AND timestamp = ? \
             AND session_offset = ? AND id = ? \
             LIMIT 1",
        )
        .bind(org_id)
        .bind(&loc.source_id)
        .bind(ts_str.as_str())
        .bind(loc.session_offset)
        .bind(loc.id)
        .fetch_all::<ClickHouseCapture>()
        .await
        .context("traffic get_by_id full-row query failed")?;

    Ok(rows.into_iter().next().map(HttpCapture::from))
}

/// Sort-key tuple identifying one capture within an org. Stage 1 of
/// [`crate::query::search`] returns these for the page; stage 2 fetches
/// the bodies for exactly these rows.
pub(crate) struct BodyKey {
    pub id: Uuid,
    pub org_id: String,
    pub source_id: String,
    pub timestamp: OffsetDateTime,
    pub session_offset: u64,
}

/// Stage-2 row: a capture's id plus its (already size-masked) bodies.
#[derive(clickhouse::Row, Deserialize)]
struct BodyRow {
    #[serde(with = "clickhouse::serde::uuid")]
    id: Uuid,
    request_body: String,
    request_size: u32,
    response_body: String,
    response_size: u32,
}

/// Fetch bodies for a page of captures, keyed on the full sort-key
/// tuple `(org_id, source_id, timestamp, session_offset, id)`.
///
/// That tuple is the table's full sort key, so ClickHouse
/// seeks each row to its exact granule (~15 ms/page) rather than
/// scanning the org/source partition — which a JOIN or an `id`-only
/// `IN` would do (~10 M rows, >30 s). Body size-masking matches the
/// single-query path: `request_body`/`response_body` are projected as
/// `if(size <= cap, body, '')`, then mapped to `Body`/`TooLarge` via
/// [`map_body`] using the row's `*_size`.
///
/// Returns id → (request_body, response_body); ids absent from the map
/// had no row (should not happen for a freshly-read page) and keep
/// `None` bodies.
pub(crate) async fn fetch_page_bodies(
    client: &clickhouse::Client,
    keys: &[BodyKey],
    request_max: Option<u32>,
    response_max: Option<u32>,
) -> Result<std::collections::HashMap<Uuid, (Option<BodyFetch>, Option<BodyFetch>)>> {
    if keys.is_empty() {
        return Ok(std::collections::HashMap::new());
    }

    // Build the tuple-IN list. Values come from a page we just read from
    // ClickHouse (UUIDs, a typed timestamp, a u64), not from user input,
    // so direct formatting is safe — there is no string to escape.
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

    let req_proj = body_projection(request_max, "request_body", "request_size");
    let resp_proj = body_projection(response_max, "response_body", "response_size");
    let sql = format!(
        "SELECT id, {req_proj}, request_size, {resp_proj}, response_size \
         FROM http_captures \
         WHERE (org_id, source_id, timestamp, session_offset, id) IN ({tuples}) \
         LIMIT 1 BY id"
    );

    // A page of exact sort-key lookups; extra threads only queue for CPU
    //.
    let rows = client
        .query(&sql)
        .with_option("max_threads", "1")
        .fetch_all::<BodyRow>()
        .await
        .context("traffic body-fetch query failed")?;

    Ok(rows
        .into_iter()
        .map(|r| {
            (
                r.id,
                (
                    map_body(r.request_body, r.request_size, request_max),
                    map_body(r.response_body, r.response_size, response_max),
                ),
            )
        })
        .collect())
}

/// Single body-column projection: `if(size <= cap, body, '') AS body`,
/// or `'' AS body` when the side was not requested (column never read).
fn body_projection(max: Option<u32>, body_col: &str, size_col: &str) -> String {
    match max {
        Some(n) => format!("if({size_col} <= {n}, {body_col}, '') AS {body_col}"),
        None => format!("'' AS {body_col}"),
    }
}
