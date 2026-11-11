//! Modular traffic query builder.
//!
//! `TrafficQuery` is an envelope of OR'd branches. Each [`QueryBranch`]
//! carries one filter tree per filterable column plus its own
//! partition-pruning identifiers (`source`, `source_id`); the envelope
//! shares `org_id`, pagination, and sort order across all branches.
//! Inter-branch composition is `OR`; intra-branch is implicit `AND`.
//!
//! `search` and `count` lower each branch's filters through
//! [`string_filter`] and [`int_filter`], join the branch fragments with
//! `OR`, AND the result against `org_id` and the cursor clause, and run
//! the query.
//!
//! See `docs/QUERY_SYSTEM.md` for the wire-format design.

pub(crate) mod cursor;
mod int_filter;
mod routing;
mod string_filter;
pub mod ws;
mod ws_routing;

use std::collections::HashMap;

use crate::db::Db;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::models::{HttpCaptureSummary, SearchResponse};

pub use int_filter::{IntFilter, NonEmpty};
pub use string_filter::StringFilter;

/// Accept either a single string or an array of strings from JSON.
/// `"abc"` → `Some(vec!["abc"])`, `["a","b"]` → `Some(vec!["a","b"])`, `null` → `None`.
fn deserialize_string_or_vec<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<Vec<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de;

    struct StringOrVec;

    impl<'de> de::Visitor<'de> for StringOrVec {
        type Value = Option<Vec<String>>;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("null, a string, or an array of strings")
        }

        fn visit_none<E: de::Error>(self) -> std::result::Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_unit<E: de::Error>(self) -> std::result::Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Self::Value, E> {
            Ok(Some(vec![v.to_owned()]))
        }

        fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<Self::Value, E> {
            Ok(Some(vec![v]))
        }

        fn visit_seq<A: de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> std::result::Result<Self::Value, A::Error> {
            let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0));
            while let Some(s) = seq.next_element::<String>()? {
                out.push(s);
            }
            if out.is_empty() {
                Ok(None)
            } else {
                Ok(Some(out))
            }
        }
    }

    deserializer.deserialize_any(StringOrVec)
}

pub(crate) const DEFAULT_LIMIT: u32 = 100;
pub(crate) const MAX_LIMIT: u32 = 5000;
/// Hard deadline for `search` / `count` queries in seconds. Caps the
/// blast radius of a pathological RE2 pattern or an unindexed scan.
const QUERY_MAX_EXECUTION_TIME_SECS: &str = "30";

/// Per-query memory ceiling in bytes (2 GiB) for `search` queries.
/// Defense-in-depth alongside the two-stage body fetch: a single
/// pathological query fails with `MEMORY_LIMIT_EXCEEDED` (caught and
/// surfaced as a 500) instead of consuming the shared server budget
/// and starving concurrent queries into server-wide OOM. The
/// two-stage body search peaks ~700 MiB, so 2 GiB leaves ample
/// headroom while still bounding the blast radius.
pub(crate) const QUERY_MAX_MEMORY_USAGE_BYTES: &str = "2147483648";

/// Exact-match filter on a single HTTP header (key + value).
/// Keys are lowered at query time to match the ingest-time normalization.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HeaderExactFilter {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SortOrder {
    #[default]
    Asc,
    Desc,
}

impl SortOrder {
    pub(crate) fn is_desc(self) -> bool {
        matches!(self, Self::Desc)
    }
    fn sql(self) -> &'static str {
        match self {
            Self::Asc => "ASC",
            Self::Desc => "DESC",
        }
    }
}

/// Column a search orders by. `Timestamp` is the on-disk sort key; every
/// other field orders by its value first and breaks ties on
/// `(timestamp, session_offset, id)`, so the keyset cursor stays total.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SortField {
    #[default]
    Timestamp,
    Method,
    Url,
    StatusCode,
    ResponseSize,
    MimeType,
    Cookies,
    DurationMs,
}

impl SortField {
    /// SQL expression ordered on ahead of the timestamp key; `None` for
    /// the timestamp key itself.
    fn expr(self) -> Option<&'static str> {
        match self {
            Self::Timestamp => None,
            Self::Method => Some("method"),
            Self::Url => Some("concat(host, path)"),
            Self::StatusCode => Some("status_code"),
            Self::ResponseSize => Some("response_size"),
            Self::MimeType => Some(string_filter::MIME_TYPE.name),
            // Number of cookie-carrying sides: request sends, response sets.
            Self::Cookies => Some(
                "(arrayExists(k -> lower(k) = 'cookie', mapKeys(request_headers)) \
                 + arrayExists(k -> lower(k) = 'set-cookie', mapKeys(response_headers)))",
            ),
            Self::DurationMs => Some("duration_ms"),
        }
    }

    /// Header maps live only on the base table.
    pub(crate) fn needs_headers(self) -> bool {
        matches!(self, Self::MimeType | Self::Cookies)
    }

    /// Byte a sorted cursor carries so it is only accepted back under the
    /// same field and direction.
    pub(crate) fn cursor_tag(self, order: SortOrder) -> u8 {
        (self as u8) << 1 | u8::from(order.is_desc())
    }
}

const REQUEST_SENDS_COOKIES: &str =
    "arrayExists(k -> lower(k) = 'cookie', mapKeys(request_headers))";
const RESPONSE_SETS_COOKIES: &str =
    "arrayExists(k -> lower(k) = 'set-cookie', mapKeys(response_headers))";

/// Top-level search request. Holds the shared org/cursor/order plus a
/// non-empty list of branches that get OR'd together.
#[derive(Debug, Clone, Deserialize)]
pub struct TrafficQuery {
    pub org_id: Option<String>,
    pub branches: NonEmpty<QueryBranch>,
    pub cursor: Option<String>,
    pub end_cursor: Option<String>,
    pub limit: Option<u32>,
    #[serde(default)]
    pub order: SortOrder,
    #[serde(default)]
    pub order_by: SortField,
    /// When `Some(N)`, the search response carries each row's
    /// `request_body` provided its size is `<= N`; otherwise carries
    /// `BodyFetch::TooLarge { size }`. `None` skips body fetching
    /// for this side entirely — the column is not read from CH.
    pub request_body_max_fetch_size: Option<u32>,
    /// Response-body counterpart — see `request_body_max_fetch_size`.
    pub response_body_max_fetch_size: Option<u32>,
}

/// One OR-branch. All fields are optional; an empty branch matches
/// every row in the org (effectively `TRUE`).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct QueryBranch {
    #[serde(default, deserialize_with = "deserialize_string_or_vec")]
    pub source_id: Option<Vec<String>>,
    pub source: Option<String>,

    pub host: Option<StringFilter>,
    pub method: Option<StringFilter>,
    pub path: Option<StringFilter>,
    pub request_body: Option<StringFilter>,
    pub response_body: Option<StringFilter>,
    pub correlation_id: Option<StringFilter>,
    pub parent_correlation_id: Option<StringFilter>,
    pub account_id: Option<StringFilter>,
    pub tool_call_id: Option<StringFilter>,
    pub status_code: Option<IntFilter>,
    pub response_size: Option<IntFilter>,
    pub duration_ms: Option<IntFilter>,
    /// Matched against the response `Content-Type` media type.
    pub mime_type: Option<StringFilter>,
    pub request_sends_cookies: Option<bool>,
    pub response_sets_cookies: Option<bool>,
    pub request_header: Option<HeaderExactFilter>,
    pub response_header: Option<HeaderExactFilter>,

    /// Capture-time window of this branch's sources, set server-side by
    /// [`bound_to_sessions`]. Never read from or written to the wire, so it
    /// does not change view ids (a hash of the serialized branches).
    #[serde(skip)]
    pub(crate) time_window: Option<TimeWindow>,
}

/// Capture-time bounds for a branch: `timestamp >= start [AND <= end]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TimeWindow {
    pub(crate) start: OffsetDateTime,
    /// `None` while a session of one of the sources is still open.
    pub(crate) end: Option<OffsetDateTime>,
}

/// Widening applied on both sides of a session window. Capture timestamps
/// come from the proxy clock, session times from the API; on staging the
/// closest capture was 45 ms inside its window. Parts span days, so an hour
/// costs nothing in pruning.
const SESSION_WINDOW_SLACK: Duration = Duration::hours(1);

/// Bound every `source_id` branch to the time its sources' sessions were
/// open, so ClickHouse prunes partitions and parts by `timestamp` instead
/// of reading a granule from every part that spans the source.
/// A branch stays unbounded if any of its sources has no session row.
pub(crate) async fn bound_to_sessions(db: &Db, query: &mut TrafficQuery) -> Result<()> {
    let mut source_ids: Vec<&str> = query
        .branches
        .0
        .iter()
        .filter_map(|b| b.source_id.as_deref())
        .flatten()
        .map(String::as_str)
        .collect();
    if source_ids.is_empty() {
        return Ok(());
    }
    source_ids.sort_unstable();
    source_ids.dedup();

    let windows: HashMap<String, TimeWindow> = db
        .source_windows(&source_ids)
        .await
        .context("failed to look up source session windows")?
        .into_iter()
        .map(|(id, window)| {
            (
                id,
                TimeWindow {
                    start: window.start,
                    end: window.end,
                },
            )
        })
        .collect();

    for branch in &mut query.branches.0 {
        branch.time_window = branch
            .source_id
            .as_deref()
            .and_then(|ids| branch_window(ids, &windows));
    }
    Ok(())
}

/// Union of the sources' windows plus slack; `None` if any source is unknown.
fn branch_window(
    source_ids: &[String],
    windows: &HashMap<String, TimeWindow>,
) -> Option<TimeWindow> {
    let mut found = source_ids.iter().map(|id| windows.get(id).copied());
    let first = found.next()??;
    let union = found.try_fold(first, |acc, w| {
        let w = w?;
        Some(TimeWindow {
            start: acc.start.min(w.start),
            end: acc.end.zip(w.end).map(|(a, b)| a.max(b)),
        })
    })?;
    Some(TimeWindow {
        start: union.start - SESSION_WINDOW_SLACK,
        end: union.end.map(|end| end + SESSION_WINDOW_SLACK),
    })
}

fn is_exact_string_filter(filter: &StringFilter) -> bool {
    matches!(filter, StringFilter::Exact { .. })
}

impl QueryBranch {
    /// True if this branch must be served from the base table rather
    /// than the timeline MV. Body/correlation columns and the
    /// `source_id` partition key are only fully indexed on the base.
    pub(crate) fn needs_full_table(&self) -> bool {
        self.source_id.is_some()
            || self.request_body.is_some()
            || self.response_body.is_some()
            || self.correlation_id.is_some()
            || self.parent_correlation_id.is_some()
            || self.account_id.is_some()
            || self.tool_call_id.is_some()
            || self.request_header.is_some()
            || self.response_header.is_some()
            || self.reads_headers()
    }

    /// True if a filter derives from the header maps, which only the base
    /// table stores.
    fn reads_headers(&self) -> bool {
        self.mime_type.is_some()
            || self.request_sends_cookies.is_some()
            || self.response_sets_cookies.is_some()
    }

    pub(crate) fn matches_agent_hierarchy_prefix(&self) -> bool {
        let has_parent = self
            .parent_correlation_id
            .as_ref()
            .is_some_and(is_exact_string_filter);
        let has_correlation = self
            .correlation_id
            .as_ref()
            .is_some_and(is_exact_string_filter);
        let has_no_correlation = self.correlation_id.is_none();
        let has_tool = self
            .tool_call_id
            .as_ref()
            .is_some_and(is_exact_string_filter);
        let has_no_tool = self.tool_call_id.is_none();
        has_parent
            && (has_correlation || has_no_correlation)
            && (has_no_tool || (has_correlation && has_tool))
            && self.request_body.is_none()
            && self.response_body.is_none()
            && self.request_header.is_none()
            && self.response_header.is_none()
            && !self.reads_headers()
    }

    /// Lower the branch's filters into a parenthesized AND of SQL
    /// fragments, pushing positional binds onto `binds`. Empty branches
    /// lower to the literal `1` so the surrounding OR composition still
    /// makes sense.
    fn lower(&self, binds: &mut Vec<String>) -> String {
        let mut conditions: Vec<String> = Vec::new();

        if let Some(ref source_ids) = self.source_id {
            match source_ids.len() {
                0 => {}
                1 => {
                    conditions.push("source_id = ?".to_string());
                    binds.push(source_ids[0].clone());
                }
                n => {
                    let placeholders = vec!["?"; n].join(", ");
                    conditions.push(format!("source_id IN ({placeholders})"));
                    binds.extend(source_ids.iter().cloned());
                }
            }
        }
        if let Some(ref source) = self.source {
            conditions.push("source = ?".to_string());
            binds.push(source.clone());
        }
        if let Some(window) = self.time_window {
            conditions.push("timestamp >= ?".to_string());
            binds.push(cursor::ts_literal(window.start));
            if let Some(end) = window.end {
                conditions.push("timestamp <= ?".to_string());
                binds.push(cursor::ts_literal(end));
            }
        }
        push_string_filter(&mut conditions, binds, &string_filter::HOST, &self.host);
        push_string_filter(&mut conditions, binds, &string_filter::METHOD, &self.method);
        push_string_filter(&mut conditions, binds, &string_filter::PATH, &self.path);
        push_string_filter(
            &mut conditions,
            binds,
            &string_filter::REQUEST_BODY,
            &self.request_body,
        );
        push_string_filter(
            &mut conditions,
            binds,
            &string_filter::RESPONSE_BODY,
            &self.response_body,
        );
        push_string_filter(
            &mut conditions,
            binds,
            &string_filter::CORRELATION_ID,
            &self.correlation_id,
        );
        push_string_filter(
            &mut conditions,
            binds,
            &string_filter::PARENT_CORRELATION_ID,
            &self.parent_correlation_id,
        );
        push_string_filter(
            &mut conditions,
            binds,
            &string_filter::ACCOUNT_ID,
            &self.account_id,
        );
        push_string_filter(
            &mut conditions,
            binds,
            &string_filter::TOOL_CALL_ID,
            &self.tool_call_id,
        );
        if let Some(ref f) = self.status_code {
            conditions.push(int_filter::lower_int("status_code", f, binds));
        }
        if let Some(f) = &self.response_size {
            conditions.push(int_filter::lower_int("response_size", f, binds));
        }
        if let Some(f) = &self.duration_ms {
            conditions.push(int_filter::lower_int("duration_ms", f, binds));
        }
        push_string_filter(
            &mut conditions,
            binds,
            &string_filter::MIME_TYPE,
            &self.mime_type,
        );
        push_bool(
            &mut conditions,
            REQUEST_SENDS_COOKIES,
            self.request_sends_cookies,
        );
        push_bool(
            &mut conditions,
            RESPONSE_SETS_COOKIES,
            self.response_sets_cookies,
        );
        if let Some(ref f) = self.request_header {
            conditions.push(
                "arrayFirst((v, k) -> lower(k) = ?, \
                 mapValues(request_headers), mapKeys(request_headers)) = ?"
                    .to_string(),
            );
            binds.push(f.key.to_lowercase());
            binds.push(f.value.clone());
        }
        if let Some(ref f) = self.response_header {
            conditions.push(
                "arrayFirst((v, k) -> lower(k) = ?, \
                 mapValues(response_headers), mapKeys(response_headers)) = ?"
                    .to_string(),
            );
            binds.push(f.key.to_lowercase());
            binds.push(f.value.clone());
        }

        match conditions.len() {
            0 => "1".to_string(),
            1 => conditions.into_iter().next().unwrap(),
            _ => format!("({})", conditions.join(" AND ")),
        }
    }
}

fn push_string_filter(
    conditions: &mut Vec<String>,
    binds: &mut Vec<String>,
    col: &string_filter::ColumnDescriptor,
    f: &Option<StringFilter>,
) {
    if let Some(f) = f {
        conditions.push(string_filter::lower_string(col, f, binds));
    }
}

fn push_bool(conditions: &mut Vec<String>, column: &str, value: Option<bool>) {
    if let Some(v) = value {
        let n = u8::from(v);
        conditions.push(format!("{column} = {n}"));
    }
}

/// Build the WHERE clause + positional bind list. Shape is always:
/// `org_id = ? AND (b1 OR b2 OR ...) [AND lower-bound] [AND upper-bound]`.
pub(crate) fn build_where(
    query: &TrafficQuery,
    cursor_boundaries: &CursorBoundaries,
) -> (String, Vec<String>) {
    let mut binds: Vec<String> = Vec::new();
    let mut top: Vec<String> = Vec::new();

    if let Some(ref org_id) = query.org_id {
        binds.push(org_id.clone());
        top.push("org_id = ?".to_string());
    }

    let branch_clauses: Vec<String> = query
        .branches
        .0
        .iter()
        .map(|b| b.lower(&mut binds))
        .collect();
    let or_clause = match branch_clauses.len() {
        1 => branch_clauses.into_iter().next().unwrap(),
        _ => format!("({})", branch_clauses.join(" OR ")),
    };
    // Skip the OR clause when it's the trivial `1` (single empty branch).
    if or_clause != "1" {
        top.push(or_clause);
    }

    if let Some((ts, session_offset, id)) = cursor_boundaries.start {
        let op = if query.order.is_desc() { "<" } else { ">" };
        match query
            .order_by
            .expr()
            .zip(cursor_boundaries.start_key.as_deref())
        {
            Some((expr, key)) => {
                top.push(format!(
                    "({expr}, timestamp, session_offset, id) {op} (?, ?, ?, ?)"
                ));
                binds.push(key.to_string());
            }
            None => top.push(format!("(timestamp, session_offset, id) {op} (?, ?, ?)")),
        }
        push_cursor_binds(&mut binds, ts, session_offset, id);
    }

    if let Some((ts, session_offset, id)) = cursor_boundaries.end {
        let predicate = if query.order.is_desc() {
            "(timestamp, session_offset, id) >= (?, ?, ?)"
        } else {
            "(timestamp, session_offset, id) <= (?, ?, ?)"
        };
        top.push(predicate.to_string());
        push_cursor_binds(&mut binds, ts, session_offset, id);
    }

    let where_clause = if top.is_empty() {
        "1".to_string()
    } else {
        top.join(" AND ")
    };
    (where_clause, binds)
}
fn push_cursor_binds(binds: &mut Vec<String>, ts: OffsetDateTime, session_offset: u64, id: Uuid) {
    binds.push(cursor::ts_literal(ts));
    binds.push(session_offset.to_string());
    binds.push(id.to_string());
}

/// Build the SELECT fragment for a Parquet bulk export via ClickHouse's
/// `s3()` table function. Returns `(sql, binds)` using `?` positional
/// placeholders — pass each bind value to `clickhouse::Query::bind` in
/// order, then call `.execute()`.
///
/// Always targets the base `http_captures` table (full row fidelity,
/// bodies included). No cursor applied — exports the full filtered set.
pub(crate) fn build_export_select(query: &TrafficQuery, table: &str) -> (String, Vec<String>) {
    let (where_clause, binds) = build_where(query, &CursorBoundaries::default());
    let sql = format!(
        "SELECT id, org_id, timestamp, session_offset, \
                method, path, host, scheme, session_id, proxy_id, \
                request_headers, request_body, request_size, \
                status_code, response_headers, response_body, response_size, \
                duration_ms, ratelimit_wait_ms, source, source_id, \
                correlation_id, parent_correlation_id, account_id, tool_call_id, inserted_at \
         FROM {table} \
         WHERE {where_clause}",
    );
    (sql, binds)
}

/// Pre-validate every `RegexMatch.value` across every branch. Returns
/// the field path of the first invalid pattern alongside the parser
/// error.
pub fn validate_regex_patterns(query: &TrafficQuery) -> Result<(), RegexValidationError> {
    for (idx, branch) in query.branches.0.iter().enumerate() {
        let fields: [(&str, &Option<StringFilter>); 10] = [
            ("host", &branch.host),
            ("method", &branch.method),
            ("path", &branch.path),
            ("request_body", &branch.request_body),
            ("response_body", &branch.response_body),
            ("correlation_id", &branch.correlation_id),
            ("parent_correlation_id", &branch.parent_correlation_id),
            ("account_id", &branch.account_id),
            ("tool_call_id", &branch.tool_call_id),
            ("mime_type", &branch.mime_type),
        ];
        for (name, f) in fields {
            if let Some(f) = f {
                let mut patterns = Vec::new();
                string_filter::collect_regex_patterns(f, &mut patterns);
                for p in patterns {
                    if let Err(err) = regex::Regex::new(p) {
                        return Err(RegexValidationError {
                            branch: idx,
                            field: name,
                            pattern: p.to_string(),
                            error: err.to_string(),
                        });
                    }
                }
            }
        }
    }
    Ok(())
}

#[derive(Debug)]
pub struct RegexValidationError {
    pub branch: usize,
    pub field: &'static str,
    pub pattern: String,
    pub error: String,
}

impl std::fmt::Display for RegexValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "regex compilation failed at branches[{}].{}: pattern={:?}: {}",
            self.branch, self.field, self.pattern, self.error
        )
    }
}

impl std::error::Error for RegexValidationError {}

type CursorBoundary = (OffsetDateTime, u64, Uuid);

#[derive(Clone, Default)]
pub(crate) struct CursorBoundaries {
    pub(crate) start: Option<CursorBoundary>,
    /// Sort value carried by the start cursor when the query orders by a
    /// non-timestamp field.
    pub(crate) start_key: Option<String>,
    pub(crate) end: Option<CursorBoundary>,
}
pub(crate) fn cursor_boundaries(query: &TrafficQuery) -> Result<CursorBoundaries> {
    let (start_key, start) = match (query.cursor.as_deref(), query.order_by.expr()) {
        (None, _) => (None, None),
        (Some(c), None) => (None, Some(cursor::decode_cursor(c)?)),
        (Some(c), Some(_)) => {
            let tag = query.order_by.cursor_tag(query.order);
            let (key, ts, session_offset, id) = cursor::decode_sorted_cursor(c, tag)?;
            (Some(key), Some((ts, session_offset, id)))
        }
    };
    let end = query
        .end_cursor
        .as_deref()
        .map(cursor::decode_cursor)
        .transpose()?;
    if end.is_some() && query.order_by != SortField::Timestamp {
        anyhow::bail!("end_cursor requires timestamp order");
    }

    if let (Some(start), Some(end)) = (start, end) {
        let reversed = if query.order.is_desc() {
            end > start
        } else {
            end < start
        };
        if reversed {
            anyhow::bail!("end_cursor is before cursor for the requested order");
        }
    }

    Ok(CursorBoundaries {
        start,
        start_key,
        end,
    })
}

/// Lower `query` to its ClickHouse WHERE clause and binds, for the lowering
/// benchmarks.
#[doc(hidden)]
pub fn lower_for_bench(query: &TrafficQuery) -> (String, Vec<String>) {
    build_where(query, &CursorBoundaries::default())
}

pub(crate) fn limit_clamped(query: &TrafficQuery) -> u32 {
    query.limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT)
}

impl TrafficQuery {
    /// True when the caller asked for body fetching on either side.
    /// Drives table routing and projection-list construction in
    /// `search`. `count` ignores bodies and treats this as `false`.
    fn want_bodies(&self) -> bool {
        self.request_body_max_fetch_size.is_some() || self.response_body_max_fetch_size.is_some()
    }

    /// `max_threads` for this query. A query whose branches are all bounded
    /// by a session window reads a handful of granules; ClickHouse's default
    /// fan-out (one thread per core) then mostly waits in the CPU run queue.
    /// Benchmarked on staging at 90 concurrent: 1 thread gave 276 q/s vs 194
    /// q/s at the default, with 11.7 vs 17.5 ms CPU per query.
    /// Body filters read the body columns (~92% of the table), so they keep
    /// the default: on a 108k-row scan a body search took 18 s on 4 threads
    /// and hit the 30 s timeout on 1. `"0"` keeps ClickHouse's default.
    fn max_threads(&self) -> &'static str {
        let point_lookup = |b: &QueryBranch| {
            b.time_window.is_some() && b.request_body.is_none() && b.response_body.is_none()
        };
        if self.branches.0.iter().all(point_lookup) {
            "1"
        } else {
            "0"
        }
    }
}

/// Build the `ORDER BY` key list for the search scan. Mirrors the
/// `(org_id,) timestamp, session_offset, id` sort key; `org_id` is
/// included only when the query is scoped to one org so ClickHouse can
/// engage read-in-order on the full key prefix. A non-timestamp sort
/// expression goes ahead of the timestamp tie-breakers.
fn order_by_keys(scoped_to_org: bool, sort_expr: Option<&str>, order: &str) -> String {
    use std::fmt::Write;
    let mut keys = String::new();
    if scoped_to_org {
        let _ = write!(keys, "org_id {order}, ");
    }
    if let Some(expr) = sort_expr {
        let _ = write!(keys, "{expr} {order}, ");
    }
    let _ = write!(
        keys,
        "timestamp {order}, session_offset {order}, id {order}"
    );
    keys
}

fn select_timeline_summary() -> &'static str {
    "id, org_id, timestamp, session_offset, method, path, host, scheme, session_id, proxy_id, \
     CAST(map(), 'Map(String, String)') AS request_headers, request_size, status_code, \
     CAST(map(), 'Map(String, String)') AS response_headers, response_size, \
     duration_ms, ratelimit_wait_ms, source, source_id, correlation_id, parent_correlation_id, account_id, tool_call_id, \
     sort_key"
}
/// Run the search query and return paginated summaries.
///
/// Always asks ClickHouse for `limit + 1` rows; emits `next_cursor`
/// only when CH actually returned the extra row, so callers get a
/// definitive end-of-page signal without a second roundtrip.
#[tracing::instrument(name = "clickhouse.search_requests", skip_all, fields(db.system = "clickhouse", org_id = ?query.org_id))]
pub async fn search(client: &clickhouse::Client, query: &TrafficQuery) -> Result<SearchResponse> {
    let boundaries = cursor_boundaries(query)?;
    search_with_boundaries(client, query, boundaries).await
}

pub(crate) async fn search_with_boundaries(
    client: &clickhouse::Client,
    query: &TrafficQuery,
    boundaries: CursorBoundaries,
) -> Result<SearchResponse> {
    let (where_clause, binds) = build_where(query, &boundaries);
    let limit = limit_clamped(query);
    let want_bodies = query.want_bodies();
    let table = routing::select_table(query, want_bodies);
    let order = query.order.sql();
    let fetch_limit = limit + 1;

    let req_max = query.request_body_max_fetch_size;
    let resp_max = query.response_body_max_fetch_size;

    // Stage 1: fetch the page's metadata + sort-key tuples only — never
    // the body columns (~92% of the table). Bodies dragged through
    // `ORDER BY ... LIMIT 1 BY id` buffer every wide matched row before
    // the LIMIT collapses it (measured ~8 GiB, OOM on broad scans).
    let sort_expr = query.order_by.expr();
    let order_by = order_by_keys(query.org_id.is_some(), sort_expr, order);
    let select_clause = if table == "http_captures" {
        "?fields".to_string()
    } else {
        select_timeline_summary().to_string()
    };
    // `sort_key` is the row's sort value as a string; the next cursor
    // carries it so the keyset predicate can resume after this page.
    let sort_key = sort_expr.map_or_else(|| "''".to_string(), |e| format!("toString({e})"));
    let sql = format!(
        "WITH {sort_key} AS sort_key SELECT {select_clause} FROM {table} WHERE {where_clause} \
         ORDER BY {order_by} LIMIT 1 BY id LIMIT {fetch_limit}"
    );

    let mut q = client
        .query(&sql)
        .with_option("max_execution_time", QUERY_MAX_EXECUTION_TIME_SECS)
        .with_option("max_memory_usage", QUERY_MAX_MEMORY_USAGE_BYTES)
        .with_option("optimize_read_in_order", "1")
        .with_option("max_threads", query.max_threads());
    for b in &binds {
        q = q.bind(b);
    }
    let mut rows = q
        .fetch_all::<crate::traffic::ClickHouseSummary>()
        .await
        .context("traffic search query failed")?;

    let next_cursor = if rows.len() as u32 > limit {
        rows.truncate(limit as usize);
        rows.last().map(|r| match sort_expr {
            Some(_) => cursor::encode_sorted_cursor(
                query.order_by.cursor_tag(query.order),
                &r.sort_key,
                r.timestamp,
                r.session_offset,
                r.id,
            ),
            None => cursor::encode_cursor(r.timestamp, r.session_offset, r.id),
        })
    } else {
        None
    };

    let mut items: Vec<HttpCaptureSummary> =
        rows.into_iter().map(HttpCaptureSummary::from).collect();

    // Stage 2: when bodies are requested, fetch them for exactly the
    // page's rows, keyed on the full sort-key tuple
    // `(source_id, timestamp, session_offset, id)`. That tuple is a
    // sort-key suffix, so ClickHouse seeks each row to its granule
    // (measured ~15 ms / page) instead of re-scanning the partition (a
    // JOIN or `id`-only `IN` reads ~10 M rows and times out).
    if want_bodies && !items.is_empty() {
        let keys: Vec<crate::traffic::BodyKey> = items
            .iter()
            .map(|i| crate::traffic::BodyKey {
                id: i.id,
                org_id: i.org_id.clone(),
                source_id: i.source_id.clone(),
                timestamp: i.timestamp,
                session_offset: i.session_offset,
            })
            .collect();
        let mut bodies =
            crate::traffic::fetch_page_bodies(client, &keys, req_max, resp_max).await?;
        for item in &mut items {
            if let Some((req, resp)) = bodies.remove(&item.id) {
                item.request_body = req;
                item.response_body = resp;
            }
        }
    }

    Ok(SearchResponse {
        items,
        next_cursor,
        total_count: None,
    })
}

/// Count rows matching the query under the same cursor / order
/// semantics as [`search`]. Ignores `limit`.
#[tracing::instrument(name = "clickhouse.count_requests", skip_all, fields(db.system = "clickhouse", org_id = ?query.org_id))]
pub async fn count(client: &clickhouse::Client, query: &TrafficQuery) -> Result<u64> {
    let boundaries = cursor_boundaries(query)?;
    count_with_boundaries(client, query, boundaries).await
}

pub(crate) async fn count_with_boundaries(
    client: &clickhouse::Client,
    query: &TrafficQuery,
    boundaries: CursorBoundaries,
) -> Result<u64> {
    let (where_clause, binds) = build_where(query, &boundaries);
    // count never reads bodies; pass want_bodies=false unconditionally.
    let table = routing::select_table(query, false);

    // uniqCombined (not uniqExact): exact-distinct builds an unbounded
    // in-memory hash set of every matching id; over 1M+ rows across many
    // source_ids that breached the per-query memory cap. uniqCombined is
    // bounded (~12 MiB) at ~0.07% error — the count is a progress/size
    // metric, never an exact-equality gate.
    let sql = format!("SELECT uniqCombined(id) FROM {table} WHERE {where_clause}");

    let mut q = client
        .query(&sql)
        .with_option("max_execution_time", QUERY_MAX_EXECUTION_TIME_SECS)
        .with_option("max_threads", query.max_threads());
    for b in &binds {
        q = q.bind(b);
    }

    let count: u64 = q.fetch_one().await.context("traffic count query failed")?;
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lower(query: &TrafficQuery) -> (String, Vec<String>) {
        build_where(query, &CursorBoundaries::default())
    }

    #[test]
    fn single_branch_renders_without_or_envelope() {
        let q = TrafficQuery {
            org_id: Some("org-1".into()),
            branches: NonEmpty(vec![QueryBranch {
                host: Some(StringFilter::Contains {
                    value: "spayco".into(),
                }),
                ..Default::default()
            }]),
            cursor: None,
            end_cursor: None,
            limit: None,
            order: SortOrder::Asc,
            order_by: SortField::Timestamp,
            request_body_max_fetch_size: None,
            response_body_max_fetch_size: None,
        };
        let (sql, binds) = lower(&q);
        assert_eq!(sql, "org_id = ? AND lower(host) LIKE lower(?)");
        assert_eq!(binds, vec!["org-1", "%spayco%"]);
    }

    #[test]
    fn multi_branch_or_composes() {
        let q = TrafficQuery {
            org_id: Some("org-1".into()),
            branches: NonEmpty(vec![
                QueryBranch {
                    host: Some(StringFilter::Contains {
                        value: "spayco".into(),
                    }),
                    status_code: Some(IntFilter::Gte { value: 500 }),
                    ..Default::default()
                },
                QueryBranch {
                    path: Some(StringFilter::Contains {
                        value: "/api".into(),
                    }),
                    status_code: Some(IntFilter::Exact { value: 429 }),
                    ..Default::default()
                },
            ]),
            cursor: None,
            end_cursor: None,
            limit: None,
            order: SortOrder::Asc,
            order_by: SortField::Timestamp,
            request_body_max_fetch_size: None,
            response_body_max_fetch_size: None,
        };
        let (sql, binds) = lower(&q);
        assert_eq!(
            sql,
            "org_id = ? AND ((lower(host) LIKE lower(?) AND status_code >= 500) \
             OR (lower(path) LIKE lower(?) AND status_code = 429))"
        );
        assert_eq!(binds, vec!["org-1", "%spayco%", "%/api%"]);
    }

    #[test]
    fn empty_branch_collapses_to_org_only() {
        let q = TrafficQuery {
            org_id: Some("org-1".into()),
            branches: NonEmpty(vec![QueryBranch::default()]),
            cursor: None,
            end_cursor: None,
            limit: None,
            order: SortOrder::Asc,
            order_by: SortField::Timestamp,
            request_body_max_fetch_size: None,
            response_body_max_fetch_size: None,
        };
        let (sql, binds) = lower(&q);
        assert_eq!(sql, "org_id = ?");
        assert_eq!(binds, vec!["org-1"]);
    }

    #[test]
    fn empty_branches_list_rejected_at_deserialize() {
        let bad = r#"{"org_id":"x","branches":[]}"#;
        let err = serde_json::from_str::<TrafficQuery>(bad).unwrap_err();
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn json_round_trip_or_query() {
        let json = r#"{
            "org_id": "org-1",
            "branches": [
                {"host": {"op":"contains","value":"a"}},
                {"path": {"op":"exact","value":"/b"}}
            ],
            "limit": 50,
            "order": "desc"
        }"#;
        let q: TrafficQuery = serde_json::from_str(json).unwrap();
        let (sql, _) = lower(&q);
        assert_eq!(
            sql,
            "org_id = ? AND (lower(host) LIKE lower(?) OR path = ?)"
        );
        assert!(q.order.is_desc());
    }

    #[test]
    fn order_by_keys_scopes_on_org() {
        assert_eq!(
            order_by_keys(true, None, "ASC"),
            "org_id ASC, timestamp ASC, session_offset ASC, id ASC"
        );
        assert_eq!(
            order_by_keys(false, None, "DESC"),
            "timestamp DESC, session_offset DESC, id DESC"
        );
    }

    #[test]
    fn timeline_summary_projects_empty_headers() {
        let s = select_timeline_summary();
        assert!(s.contains("CAST(map(), 'Map(String, String)') AS request_headers"));
        assert!(s.contains("CAST(map(), 'Map(String, String)') AS response_headers"));
        assert!(!s.contains("request_body"));
        assert!(!s.contains("response_body"));
    }

    #[test]
    fn want_bodies_routes_to_base_table() {
        let q = TrafficQuery {
            org_id: Some("org-1".into()),
            branches: NonEmpty(vec![QueryBranch::default()]),
            cursor: None,
            end_cursor: None,
            limit: None,
            order: SortOrder::Asc,
            order_by: SortField::Timestamp,
            request_body_max_fetch_size: Some(1024),
            response_body_max_fetch_size: None,
        };
        assert_eq!(routing::select_table(&q, q.want_bodies()), "http_captures");
        // count never reads bodies, even if the caller set the flag
        assert_eq!(routing::select_table(&q, false), "http_captures_timeline");
    }

    #[test]
    fn no_bodies_unaffected_by_fetch_fields() {
        let q = TrafficQuery {
            org_id: Some("org-1".into()),
            branches: NonEmpty(vec![QueryBranch::default()]),
            cursor: None,
            end_cursor: None,
            limit: None,
            order: SortOrder::Asc,
            order_by: SortField::Timestamp,
            request_body_max_fetch_size: None,
            response_body_max_fetch_size: None,
        };
        assert!(!q.want_bodies());
        assert_eq!(
            routing::select_table(&q, q.want_bodies()),
            "http_captures_timeline"
        );
    }

    #[test]
    fn agent_hierarchy_prefix_routes_to_hierarchy_mv() {
        let q = TrafficQuery {
            org_id: Some("org-1".into()),
            branches: NonEmpty(vec![QueryBranch {
                parent_correlation_id: Some(StringFilter::Exact {
                    value: "scan-1".into(),
                }),
                correlation_id: Some(StringFilter::Exact {
                    value: "agent-1".into(),
                }),
                tool_call_id: Some(StringFilter::Exact {
                    value: "tool-1".into(),
                }),
                ..Default::default()
            }]),
            cursor: None,
            end_cursor: None,
            limit: None,
            order: SortOrder::Asc,
            order_by: SortField::Timestamp,
            request_body_max_fetch_size: None,
            response_body_max_fetch_size: None,
        };
        assert_eq!(
            routing::select_table(&q, q.want_bodies()),
            "http_captures_by_agent_hierarchy"
        );
    }

    #[test]
    fn non_prefix_tool_filter_routes_to_base_table() {
        let q = TrafficQuery {
            org_id: Some("org-1".into()),
            branches: NonEmpty(vec![QueryBranch {
                parent_correlation_id: Some(StringFilter::Exact {
                    value: "scan-1".into(),
                }),
                tool_call_id: Some(StringFilter::Exact {
                    value: "tool-1".into(),
                }),
                ..Default::default()
            }]),
            cursor: None,
            end_cursor: None,
            limit: None,
            order: SortOrder::Asc,
            order_by: SortField::Timestamp,
            request_body_max_fetch_size: None,
            response_body_max_fetch_size: None,
        };
        assert_eq!(routing::select_table(&q, q.want_bodies()), "http_captures");
    }
    fn test_id(value: u128) -> Uuid {
        Uuid::from_u128(value)
    }

    fn test_cursor(timestamp: &str, session_offset: u64, id: Uuid) -> String {
        let timestamp =
            OffsetDateTime::parse(timestamp, &time::format_description::well_known::Rfc3339)
                .unwrap();
        cursor::encode_cursor(timestamp, session_offset, id)
    }

    fn traffic_query(
        order: SortOrder,
        start_cursor: Option<String>,
        end_cursor: Option<String>,
    ) -> TrafficQuery {
        TrafficQuery {
            org_id: Some("org-1".into()),
            branches: NonEmpty(vec![QueryBranch::default()]),
            cursor: start_cursor,
            end_cursor,
            limit: None,
            order,
            order_by: SortField::Timestamp,
            request_body_max_fetch_size: None,
            response_body_max_fetch_size: None,
        }
    }

    #[test]
    fn ascending_window_is_lower_exclusive_upper_inclusive() {
        let query = traffic_query(
            SortOrder::Asc,
            Some(test_cursor("2026-09-03T10:00:00Z", 10, test_id(10))),
            Some(test_cursor("2026-09-03T10:01:00Z", 20, test_id(20))),
        );
        let (sql, _) = build_where(&query, &cursor_boundaries(&query).unwrap());
        assert!(sql.contains("(timestamp, session_offset, id) > (?, ?, ?)"));
        assert!(sql.contains("(timestamp, session_offset, id) <= (?, ?, ?)"));
    }

    #[test]
    fn descending_window_is_lower_exclusive_upper_inclusive() {
        let query = traffic_query(
            SortOrder::Desc,
            Some(test_cursor("2026-09-03T10:01:00Z", 20, test_id(20))),
            Some(test_cursor("2026-09-03T10:00:00Z", 10, test_id(10))),
        );
        let (sql, _) = build_where(&query, &cursor_boundaries(&query).unwrap());
        assert!(sql.contains("(timestamp, session_offset, id) < (?, ?, ?)"));
        assert!(sql.contains("(timestamp, session_offset, id) >= (?, ?, ?)"));
    }

    #[test]
    fn count_and_search_share_identical_window_bounds() {
        let query = traffic_query(
            SortOrder::Asc,
            Some(test_cursor("2026-09-03T10:00:00Z", 10, test_id(10))),
            Some(test_cursor("2026-09-03T10:01:00Z", 20, test_id(20))),
        );
        let bounds = cursor_boundaries(&query).unwrap();
        let search_where = build_where(&query, &bounds).0;
        let count_where = build_where(&query, &bounds).0;
        assert_eq!(search_where, count_where);
        assert!(count_where.contains("(timestamp, session_offset, id) <= (?, ?, ?)"));
    }

    #[test]
    fn malformed_window_cursor_is_rejected() {
        let malformed_start = traffic_query(
            SortOrder::Asc,
            Some("not-a-cursor".into()),
            Some(test_cursor("2026-09-03T10:01:00Z", 20, test_id(20))),
        );
        assert!(cursor_boundaries(&malformed_start).is_err());

        let malformed_end = traffic_query(SortOrder::Asc, None, Some("not-a-cursor".into()));
        assert!(cursor_boundaries(&malformed_end).is_err());
    }

    #[test]
    fn reversed_window_is_rejected_for_each_order() {
        let early = test_cursor("2026-09-03T10:00:00Z", 10, test_id(10));
        let late = test_cursor("2026-09-03T10:01:00Z", 20, test_id(20));

        let ascending = traffic_query(SortOrder::Asc, Some(late.clone()), Some(early.clone()));
        let descending = traffic_query(SortOrder::Desc, Some(early), Some(late));

        assert!(cursor_boundaries(&ascending).is_err());
        assert!(cursor_boundaries(&descending).is_err());
    }

    fn sorted_query(order_by: SortField, order: SortOrder, cursor: Option<String>) -> TrafficQuery {
        TrafficQuery {
            order_by,
            ..traffic_query(order, cursor, None)
        }
    }

    fn sorted_cursor(field: SortField, order: SortOrder, sort_key: &str) -> String {
        let ts = OffsetDateTime::parse(
            "2026-09-03T10:00:00Z",
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap();
        cursor::encode_sorted_cursor(field.cursor_tag(order), sort_key, ts, 7, test_id(7))
    }

    #[test]
    fn sorted_cursor_round_trips_including_empty_value() {
        let tag = SortField::MimeType.cursor_tag(SortOrder::Asc);
        for key in ["404", "", "text/html"] {
            let (decoded, _, session_offset, id) = cursor::decode_sorted_cursor(
                &sorted_cursor(SortField::MimeType, SortOrder::Asc, key),
                tag,
            )
            .unwrap();
            assert_eq!(decoded, key);
            assert_eq!((session_offset, id), (7, test_id(7)));
        }
    }

    #[test]
    fn sort_field_resumes_after_the_sort_value_then_capture_order() {
        let desc = sorted_query(
            SortField::StatusCode,
            SortOrder::Desc,
            Some(sorted_cursor(SortField::StatusCode, SortOrder::Desc, "404")),
        );
        let (sql, binds) = build_where(&desc, &cursor_boundaries(&desc).unwrap());
        assert_eq!(
            sql,
            "org_id = ? AND (status_code, timestamp, session_offset, id) < (?, ?, ?, ?)"
        );
        assert_eq!(binds[..3], ["org-1", "404", "2026-09-03 10:00:00.000"]);

        let asc = sorted_query(
            SortField::Url,
            SortOrder::Asc,
            Some(sorted_cursor(SortField::Url, SortOrder::Asc, "a.com/x")),
        );
        let (sql, binds) = build_where(&asc, &cursor_boundaries(&asc).unwrap());
        assert!(
            sql.ends_with("(concat(host, path), timestamp, session_offset, id) > (?, ?, ?, ?)")
        );
        assert_eq!(binds[1], "a.com/x");
    }

    #[test]
    fn sort_field_orders_ahead_of_the_timestamp_tie_breakers() {
        assert_eq!(
            order_by_keys(true, SortField::ResponseSize.expr(), "DESC"),
            "org_id DESC, response_size DESC, timestamp DESC, session_offset DESC, id DESC"
        );
    }

    #[test]
    fn cursor_shape_must_match_the_sort_field() {
        // A sorted cursor is longer than 40 bytes; timestamp order rejects it.
        let timestamp = sorted_query(
            SortField::Timestamp,
            SortOrder::Asc,
            Some(sorted_cursor(SortField::Method, SortOrder::Asc, "x")),
        );
        assert!(cursor_boundaries(&timestamp).is_err());

        let truncated = sorted_query(SortField::Method, SortOrder::Asc, Some("AAAA".into()));
        assert!(cursor_boundaries(&truncated).is_err());

        let mut windowed = sorted_query(SortField::Method, SortOrder::Asc, None);
        windowed.end_cursor = Some(test_cursor("2026-09-03T10:00:00Z", 1, test_id(1)));
        assert!(cursor_boundaries(&windowed).is_err());
    }

    #[test]
    fn sorted_order_rejects_cursors_minted_for_another_order() {
        let mismatch = |order_by, order, cursor: String| {
            let err = cursor_boundaries(&sorted_query(order_by, order, Some(cursor)))
                .err()
                .expect("cursor must be rejected");
            assert_eq!(err.to_string(), "cursor does not match orderBy");
        };
        // A timestamp cursor carries no sort value; comparing '' against a
        // numeric column would fail inside ClickHouse.
        mismatch(
            SortField::StatusCode,
            SortOrder::Asc,
            test_cursor("2026-09-03T10:00:00Z", 1, test_id(1)),
        );
        // Another field's value would resume the scan at the wrong place.
        mismatch(
            SortField::Url,
            SortOrder::Asc,
            sorted_cursor(SortField::StatusCode, SortOrder::Asc, "404"),
        );
        // So would the same field in the other direction.
        mismatch(
            SortField::StatusCode,
            SortOrder::Desc,
            sorted_cursor(SortField::StatusCode, SortOrder::Asc, "404"),
        );
    }

    #[test]
    fn header_derived_sorts_route_to_base_table() {
        for field in [SortField::MimeType, SortField::Cookies] {
            let q = sorted_query(field, SortOrder::Asc, None);
            assert_eq!(routing::select_table(&q, false), "http_captures");
        }
        let q = sorted_query(SortField::DurationMs, SortOrder::Asc, None);
        assert_eq!(routing::select_table(&q, false), "http_captures_timeline");
    }

    #[test]
    fn response_filters_lower_against_columns_and_headers() {
        let q = TrafficQuery {
            branches: NonEmpty(vec![QueryBranch {
                response_size: Some(IntFilter::All {
                    filters: NonEmpty(vec![
                        IntFilter::Gte { value: 10 },
                        IntFilter::Lte { value: 20 },
                    ]),
                }),
                duration_ms: Some(IntFilter::Gte { value: 500 }),
                mime_type: Some(StringFilter::Contains {
                    value: "json".into(),
                }),
                response_sets_cookies: Some(true),
                ..Default::default()
            }]),
            ..traffic_query(SortOrder::Asc, None, None)
        };
        let (sql, binds) = lower(&q);
        assert_eq!(
            sql,
            format!(
                "org_id = ? AND ((response_size >= 10 AND response_size <= 20) \
                 AND duration_ms >= 500 AND lower({}) LIKE lower(?) AND {RESPONSE_SETS_COOKIES} = 1)",
                string_filter::MIME_TYPE.name
            )
        );
        assert_eq!(binds, vec!["org-1", "%json%"]);
        assert_eq!(routing::select_table(&q, false), "http_captures");
    }

    #[test]
    fn header_filters_match_names_case_insensitively_and_values_exactly() {
        for (request_value, response_value) in [("Agent-1", "Application/JSON"), ("", "")] {
            let q = TrafficQuery {
                branches: NonEmpty(vec![QueryBranch {
                    request_header: Some(HeaderExactFilter {
                        key: "X-ProxyX-Agent".into(),
                        value: request_value.into(),
                    }),
                    response_header: Some(HeaderExactFilter {
                        key: "CoNtEnT-TyPe".into(),
                        value: response_value.into(),
                    }),
                    ..Default::default()
                }]),
                ..traffic_query(SortOrder::Asc, None, None)
            };
            let (sql, binds) = lower(&q);
            assert_eq!(
                sql,
                "org_id = ? AND (arrayFirst((v, k) -> lower(k) = ?, \
                 mapValues(request_headers), mapKeys(request_headers)) = ? \
                 AND arrayFirst((v, k) -> lower(k) = ?, \
                 mapValues(response_headers), mapKeys(response_headers)) = ?)"
            );
            assert_eq!(
                binds,
                vec![
                    "org-1",
                    "x-proxyx-agent",
                    request_value,
                    "content-type",
                    response_value,
                ]
            );
            assert_eq!(routing::select_table(&q, false), "http_captures");
        }
    }

    #[test]
    fn request_cookie_filter_reads_headers_case_insensitively() {
        let q = TrafficQuery {
            branches: NonEmpty(vec![QueryBranch {
                request_sends_cookies: Some(false),
                ..Default::default()
            }]),
            ..traffic_query(SortOrder::Asc, None, None)
        };
        let (sql, _) = lower(&q);
        assert_eq!(
            sql,
            "org_id = ? AND arrayExists(k -> lower(k) = 'cookie', mapKeys(request_headers)) = 0"
        );
        assert_eq!(routing::select_table(&q, false), "http_captures");
    }

    fn ts(value: &str) -> OffsetDateTime {
        OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339).unwrap()
    }

    fn sessions(entries: &[(&str, &str, Option<&str>)]) -> HashMap<String, TimeWindow> {
        entries
            .iter()
            .map(|(id, start, end)| {
                (
                    (*id).to_string(),
                    TimeWindow {
                        start: ts(start),
                        end: end.map(ts),
                    },
                )
            })
            .collect()
    }

    #[test]
    fn branch_window_spans_every_source_plus_slack() {
        let windows = sessions(&[
            ("a", "2026-10-15T02:00:00Z", Some("2026-10-15T03:00:00Z")),
            ("b", "2026-10-14T10:00:00Z", Some("2026-10-15T05:00:00Z")),
        ]);
        let window = branch_window(&["a".into(), "b".into()], &windows).unwrap();
        assert_eq!(window.start, ts("2026-10-14T09:00:00Z"));
        assert_eq!(window.end, Some(ts("2026-10-15T06:00:00Z")));
    }

    #[test]
    fn branch_window_has_no_end_while_any_source_is_open() {
        let windows = sessions(&[
            ("a", "2026-10-15T02:00:00Z", Some("2026-10-15T03:00:00Z")),
            ("open", "2026-10-15T04:00:00Z", None),
        ]);
        let window = branch_window(&["a".into(), "open".into()], &windows).unwrap();
        assert_eq!(window.start, ts("2026-10-15T01:00:00Z"));
        assert_eq!(window.end, None);
    }

    #[test]
    fn branch_window_is_unbounded_when_a_source_has_no_session() {
        let windows = sessions(&[("a", "2026-10-15T02:00:00Z", Some("2026-10-15T03:00:00Z"))]);
        assert_eq!(
            branch_window(&["a".into(), "unknown".into()], &windows),
            None
        );
        assert_eq!(branch_window(&[], &windows), None);
    }

    #[test]
    fn time_window_lowers_into_the_branch_and_stays_off_the_wire() {
        let branch = QueryBranch {
            source_id: Some(vec!["src-1".into()]),
            time_window: Some(TimeWindow {
                start: ts("2026-10-15T01:21:06.536Z"),
                end: Some(ts("2026-10-15T06:15:40.334Z")),
            }),
            ..Default::default()
        };
        let q = TrafficQuery {
            branches: NonEmpty(vec![branch.clone()]),
            ..traffic_query(SortOrder::Asc, None, None)
        };
        let (sql, binds) = lower(&q);
        assert_eq!(
            sql,
            "org_id = ? AND (source_id = ? AND timestamp >= ? AND timestamp <= ?)"
        );
        assert_eq!(
            binds,
            vec![
                "org-1",
                "src-1",
                "2026-10-15 01:21:06.536",
                "2026-10-15 06:15:40.334"
            ]
        );
        // View ids hash the serialized branches; the window must not move them.
        let unbounded = QueryBranch {
            time_window: None,
            ..branch.clone()
        };
        assert_eq!(
            serde_json::to_string(&branch).unwrap(),
            serde_json::to_string(&unbounded).unwrap()
        );
    }

    #[test]
    fn only_fully_session_bounded_queries_run_single_threaded() {
        let bounded = QueryBranch {
            source_id: Some(vec!["src-1".into()]),
            time_window: Some(TimeWindow {
                start: ts("2026-10-15T01:00:00Z"),
                end: None,
            }),
            ..Default::default()
        };
        let query = |branches: Vec<QueryBranch>| TrafficQuery {
            branches: NonEmpty(branches),
            ..traffic_query(SortOrder::Asc, None, None)
        };
        assert_eq!(
            query(vec![bounded.clone(), bounded.clone()]).max_threads(),
            "1"
        );
        // One unbounded branch (unknown source, or no source at all) widens
        // the scan, so the server default applies.
        assert_eq!(
            query(vec![bounded.clone(), QueryBranch::default()]).max_threads(),
            "0"
        );
        assert_eq!(query(vec![QueryBranch::default()]).max_threads(), "0");
        // Body filters scan the body columns even inside a session window.
        let body_search = QueryBranch {
            response_body: Some(StringFilter::Contains {
                value: "password".into(),
            }),
            ..bounded
        };
        assert_eq!(query(vec![body_search]).max_threads(), "0");
    }
}
