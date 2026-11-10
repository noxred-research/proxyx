//! Lowering of the traffic query DSL to the OpenSearch / Elasticsearch search
//! DSL.
//!
//! The lowering is pure: it builds `serde_json::Value` request fragments and
//! is covered by golden files (`golden/*.json`). Equivalence with the
//! ClickHouse lowering rests on three decisions.
//!
//! ## Three-valued logic
//!
//! SQL comparisons on a `NULL` column are `NULL`, and `NOT NULL` is `NULL`, so
//! `NOT (correlation_id = 'x')` does not match a row without a correlation id.
//! A search `must_not` does match it. Every filter is therefore lowered twice,
//! on demand: `truth = true` gives the query for rows where the filter is
//! TRUE, `truth = false` for rows where it is FALSE (not NULL). `Not` swaps
//! the polarity, `All`/`Any` apply De Morgan, and a leaf is negated as
//! `exists AND NOT leaf` on nullable fields.
//!
//! ## Derived fields
//!
//! Values that ClickHouse computes at query time are computed at ingest time
//! and stored next to the column they derive from (see `schema.rs`): byte
//! lengths (`len.<column>`), the response media type (`mime_type`), cookie
//! flags, the header `key:value` terms and the URL sort key.
//!
//! ## Rejections
//!
//! A construct that cannot be lowered exactly is rejected with
//! [`StoreError::Rejected`] (HTTP 400): regular expressions outside the RE2
//! subset of [`super::regex`], and an empty header value (ClickHouse's
//! `map[key] = ''` also matches a missing header).

use serde_json::{Value, json};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::capture_store::StoreError;
use crate::query::ws::{WsQueryBranch, WsTrafficQuery};
use crate::query::{
    CursorBoundaries, HeaderExactFilter, IntFilter, QueryBranch, SortField, SortOrder,
    StringFilter, TrafficQuery,
};

use super::regex;

type Result<T> = std::result::Result<T, StoreError>;

/// Field type of a string column; decides how an empty exact match is
/// expressed (`wildcard` fields cannot be matched with a term on `""`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Keyword,
    Wildcard,
}

/// A filterable string column and its companion byte-length field.
#[derive(Clone, Copy)]
pub(super) struct Col {
    name: &'static str,
    len: &'static str,
    kind: Kind,
    nullable: bool,
}

impl Col {
    const fn keyword(name: &'static str, len: &'static str) -> Self {
        Self {
            name,
            len,
            kind: Kind::Keyword,
            nullable: false,
        }
    }
    const fn wildcard(name: &'static str, len: &'static str) -> Self {
        Self {
            name,
            len,
            kind: Kind::Wildcard,
            nullable: false,
        }
    }
    const fn nullable(name: &'static str, len: &'static str) -> Self {
        Self {
            name,
            len,
            kind: Kind::Keyword,
            nullable: true,
        }
    }
}

const HOST: Col = Col::keyword("host", "len.host");
const METHOD: Col = Col::keyword("method", "len.method");
const PATH: Col = Col::wildcard("path", "len.path");
const REQUEST_BODY: Col = Col::wildcard("request_body", "len.request_body");
const RESPONSE_BODY: Col = Col::wildcard("response_body", "len.response_body");
const CORRELATION_ID: Col = Col::nullable("correlation_id", "len.correlation_id");
const PARENT_CORRELATION_ID: Col =
    Col::nullable("parent_correlation_id", "len.parent_correlation_id");
const ACCOUNT_ID: Col = Col::nullable("account_id", "len.account_id");
const TOOL_CALL_ID: Col = Col::nullable("tool_call_id", "len.tool_call_id");
const MIME_TYPE: Col = Col::keyword("mime_type", "len.mime_type");

const WS_PAYLOAD: Col = Col::wildcard("payload", "len.payload");
const WS_DIRECTION: Col = Col::keyword("direction", "len.direction");
const WS_OPCODE: Col = Col::keyword("opcode", "len.opcode");
const WS_CLOSE_REASON: Col = Col::keyword("close_reason", "len.close_reason");

fn match_all() -> Value {
    json!({ "match_all": {} })
}

fn match_none() -> Value {
    json!({ "match_none": {} })
}

fn exists(field: &str) -> Value {
    json!({ "exists": { "field": field } })
}

fn and(clauses: Vec<Value>) -> Value {
    match clauses.len() {
        0 => match_all(),
        1 => clauses.into_iter().next().unwrap_or_else(match_all),
        _ => json!({ "bool": { "filter": clauses } }),
    }
}

fn or(clauses: Vec<Value>) -> Value {
    match clauses.len() {
        0 => match_none(),
        1 => clauses.into_iter().next().unwrap_or_else(match_none),
        _ => json!({ "bool": { "should": clauses, "minimum_should_match": 1 } }),
    }
}

/// Rows where the comparison `leaf` on `field` is FALSE, not NULL.
fn negate(nullable: bool, field: &str, leaf: Value) -> Value {
    if nullable {
        json!({ "bool": { "filter": [exists(field)], "must_not": [leaf] } })
    } else {
        json!({ "bool": { "must_not": [leaf] } })
    }
}

fn leaf(truth: bool, nullable: bool, field: &str, query: Value) -> Value {
    if truth {
        query
    } else {
        negate(nullable, field, query)
    }
}

/// Escape the wildcard operators `*`, `?` and the escape character.
fn escape_wildcard(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        if matches!(c, '*' | '?' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn int_leaf(field: &str, f: &IntFilter) -> Option<Value> {
    Some(match f {
        IntFilter::Exact { value } => json!({ "term": { field: value } }),
        IntFilter::Lt { value } => json!({ "range": { field: { "lt": value } } }),
        IntFilter::Lte { value } => json!({ "range": { field: { "lte": value } } }),
        IntFilter::Gt { value } => json!({ "range": { field: { "gt": value } } }),
        IntFilter::Gte { value } => json!({ "range": { field: { "gte": value } } }),
        _ => return None,
    })
}

/// Lower `f` on a numeric `field` for the rows where it is TRUE (`truth`) or
/// FALSE.
pub(super) fn int_filter(field: &str, nullable: bool, f: &IntFilter, truth: bool) -> Value {
    if let Some(query) = int_leaf(field, f) {
        return leaf(truth, nullable, field, query);
    }
    match f {
        IntFilter::All { filters } => {
            let parts = filters
                .0
                .iter()
                .map(|c| int_filter(field, nullable, c, truth))
                .collect();
            if truth { and(parts) } else { or(parts) }
        }
        IntFilter::Any { filters } => {
            let parts = filters
                .0
                .iter()
                .map(|c| int_filter(field, nullable, c, truth))
                .collect();
            if truth { or(parts) } else { and(parts) }
        }
        IntFilter::Not { filter } => int_filter(field, nullable, filter, !truth),
        _ => match_none(),
    }
}

fn string_filter(col: &Col, f: &StringFilter, truth: bool) -> Result<Value> {
    let field = col.name;
    Ok(match f {
        StringFilter::Contains { value } => leaf(
            truth,
            col.nullable,
            field,
            json!({ "wildcard": { field: {
                "value": format!("*{}*", escape_wildcard(value)),
                "case_insensitive": true,
            } } }),
        ),
        StringFilter::Exact { value } if value.is_empty() && col.kind == Kind::Wildcard => leaf(
            truth,
            col.nullable,
            field,
            json!({ "term": { col.len: 0 } }),
        ),
        StringFilter::Exact { value } => leaf(
            truth,
            col.nullable,
            field,
            json!({ "term": { field: value } }),
        ),
        StringFilter::RegexMatch { value } => {
            let translated = regex::translate(value).map_err(|reason| {
                StoreError::Rejected(format!(
                    "regex {value:?} on {field} cannot be lowered exactly to the opensearch \
                     capture store: {reason}"
                ))
            })?;
            let mut body = json!({ "value": translated.pattern });
            if translated.case_insensitive {
                body["case_insensitive"] = json!(true);
            }
            leaf(
                truth,
                col.nullable,
                field,
                json!({ "regexp": { field: body } }),
            )
        }
        StringFilter::Length { value } => int_filter(col.len, col.nullable, value, truth),
        StringFilter::IsNull | StringFilter::IsPresent => {
            let want_null = matches!(f, StringFilter::IsNull) == truth;
            match (col.nullable, want_null) {
                (true, true) => json!({ "bool": { "must_not": [exists(field)] } }),
                (true, false) => exists(field),
                (false, true) => match_none(),
                (false, false) => match_all(),
            }
        }
        StringFilter::All { filters } => {
            let parts = filters
                .0
                .iter()
                .map(|c| string_filter(col, c, truth))
                .collect::<Result<Vec<_>>>()?;
            if truth { and(parts) } else { or(parts) }
        }
        StringFilter::Any { filters } => {
            let parts = filters
                .0
                .iter()
                .map(|c| string_filter(col, c, truth))
                .collect::<Result<Vec<_>>>()?;
            if truth { or(parts) } else { and(parts) }
        }
        StringFilter::Not { filter } => string_filter(col, filter, !truth)?,
    })
}

fn push_string(
    conditions: &mut Vec<Value>,
    col: &Col,
    filter: &Option<StringFilter>,
) -> Result<()> {
    if let Some(f) = filter {
        conditions.push(string_filter(col, f, true)?);
    }
    Ok(())
}

fn push_bool(conditions: &mut Vec<Value>, field: &str, value: Option<bool>) {
    if let Some(v) = value {
        conditions.push(json!({ "term": { field: v } }));
    }
}

fn header_term(field: &str, f: &HeaderExactFilter) -> Result<Value> {
    if f.value.is_empty() {
        return Err(StoreError::Rejected(format!(
            "{field} filter with an empty value cannot be lowered exactly to the opensearch \
             capture store (ClickHouse also matches a missing header)"
        )));
    }
    Ok(json!({ "term": { field: format!("{}:{}", f.key.to_lowercase(), f.value) } }))
}

/// Milliseconds since the epoch, flooring like `DateTime64(3)`.
pub(super) fn epoch_millis(ts: OffsetDateTime) -> i64 {
    ts.unix_timestamp_nanos().div_euclid(1_000_000) as i64
}

/// A broker position as a `long` field value.
pub(super) fn offset_value(session_offset: u64) -> i64 {
    i64::try_from(session_offset).unwrap_or(i64::MAX)
}

fn lower_branch(b: &QueryBranch) -> Result<Value> {
    let mut c: Vec<Value> = Vec::new();

    if let Some(ids) = &b.source_id {
        match ids.len() {
            0 => {}
            1 => c.push(json!({ "term": { "source_id": ids[0] } })),
            _ => c.push(json!({ "terms": { "source_id": ids } })),
        }
    }
    if let Some(source) = &b.source {
        c.push(json!({ "term": { "source": source } }));
    }
    if let Some(window) = b.time_window {
        let mut range = json!({ "gte": epoch_millis(window.start) });
        if let Some(end) = window.end {
            range["lte"] = json!(epoch_millis(end));
        }
        c.push(json!({ "range": { "timestamp": range } }));
    }
    push_string(&mut c, &HOST, &b.host)?;
    push_string(&mut c, &METHOD, &b.method)?;
    push_string(&mut c, &PATH, &b.path)?;
    push_string(&mut c, &REQUEST_BODY, &b.request_body)?;
    push_string(&mut c, &RESPONSE_BODY, &b.response_body)?;
    push_string(&mut c, &CORRELATION_ID, &b.correlation_id)?;
    push_string(&mut c, &PARENT_CORRELATION_ID, &b.parent_correlation_id)?;
    push_string(&mut c, &ACCOUNT_ID, &b.account_id)?;
    push_string(&mut c, &TOOL_CALL_ID, &b.tool_call_id)?;
    if let Some(f) = &b.status_code {
        c.push(int_filter("status_code", false, f, true));
    }
    if let Some(f) = &b.response_size {
        c.push(int_filter("response_size", false, f, true));
    }
    if let Some(f) = &b.duration_ms {
        c.push(int_filter("duration_ms", false, f, true));
    }
    push_string(&mut c, &MIME_TYPE, &b.mime_type)?;
    push_bool(&mut c, "request_sends_cookies", b.request_sends_cookies);
    push_bool(&mut c, "response_sets_cookies", b.response_sets_cookies);
    if let Some(f) = &b.request_header {
        c.push(header_term("request_header_kv", f)?);
    }
    if let Some(f) = &b.response_header {
        c.push(header_term("response_header_kv", f)?);
    }
    Ok(and(c))
}

/// `OR` of the branch clauses, or `None` when it matches everything.
fn or_of_branches(branches: Vec<Value>) -> Option<Value> {
    let trivial = |v: &Value| v == &match_all();
    if branches.iter().any(trivial) {
        return None;
    }
    Some(or(branches))
}

/// Typed key of a sort field.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum SortKind {
    Str,
    Num,
}

/// Index field a search orders by ahead of the timestamp key, `None` for the
/// timestamp key itself.
pub(super) fn sort_field(field: SortField) -> Option<(&'static str, SortKind)> {
    match field {
        SortField::Timestamp => None,
        SortField::Method => Some(("method", SortKind::Str)),
        SortField::Url => Some(("url_sort", SortKind::Str)),
        SortField::StatusCode => Some(("status_code", SortKind::Num)),
        SortField::ResponseSize => Some(("response_size", SortKind::Num)),
        SortField::MimeType => Some(("mime_type", SortKind::Str)),
        SortField::Cookies => Some(("cookies", SortKind::Num)),
        SortField::DurationMs => Some(("duration_ms", SortKind::Num)),
    }
}

/// The cursor's sort value as a typed JSON value.
fn sort_value(kind: SortKind, key: &str) -> Result<Value> {
    match kind {
        SortKind::Str => Ok(json!(key)),
        SortKind::Num => key
            .parse::<i64>()
            .map(|n| json!(n))
            .map_err(|_| StoreError::Rejected("invalid cursor sort key".to_string())),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Cmp {
    Gt,
    Lt,
    Gte,
    Lte,
}

impl Cmp {
    fn strict(self) -> &'static str {
        match self {
            Self::Gt | Self::Gte => "gt",
            Self::Lt | Self::Lte => "lt",
        }
    }
    fn inclusive(self) -> bool {
        matches!(self, Self::Gte | Self::Lte)
    }
}

/// `(f1, f2, ...) <op> (v1, v2, ...)`, expanded lexicographically.
fn tuple_cmp(keys: &[(&str, Value)], op: Cmp) -> Value {
    let strict = op.strict();
    let mut alternatives: Vec<Value> = Vec::with_capacity(keys.len() + 1);
    for (i, (field, value)) in keys.iter().enumerate() {
        let mut clause: Vec<Value> = keys[..i]
            .iter()
            .map(|(f, v)| json!({ "term": { *f: v } }))
            .collect();
        clause.push(json!({ "range": { *field: { strict: value } } }));
        alternatives.push(and(clause));
    }
    if op.inclusive() {
        alternatives.push(and(keys
            .iter()
            .map(|(f, v)| json!({ "term": { *f: v } }))
            .collect()));
    }
    or(alternatives)
}

fn position_keys(ts: OffsetDateTime, session_offset: u64, id: Uuid) -> Vec<(&'static str, Value)> {
    vec![
        ("timestamp", json!(epoch_millis(ts))),
        ("session_offset", json!(offset_value(session_offset))),
        ("id", json!(id.to_string())),
    ]
}

/// The `query` of an HTTP search or count: org, branches, and the cursor
/// bounds. A search resumes with `search_after` instead of the start bound,
/// so it passes `include_start = false`.
pub(super) fn http_query(
    query: &TrafficQuery,
    boundaries: &CursorBoundaries,
    include_start: bool,
) -> Result<Value> {
    let mut top: Vec<Value> = Vec::new();
    if let Some(org) = &query.org_id {
        top.push(json!({ "term": { "org_id": org } }));
    }

    let branches = query
        .branches
        .0
        .iter()
        .map(lower_branch)
        .collect::<Result<Vec<_>>>()?;
    if let Some(clause) = or_of_branches(branches) {
        top.push(clause);
    }

    if include_start && let Some((ts, session_offset, id)) = boundaries.start {
        let op = if query.order.is_desc() {
            Cmp::Lt
        } else {
            Cmp::Gt
        };
        let mut keys = Vec::new();
        if let Some((field, kind)) = sort_field(query.order_by)
            && let Some(key) = boundaries.start_key.as_deref()
        {
            keys.push((field, sort_value(kind, key)?));
        }
        keys.extend(position_keys(ts, session_offset, id));
        top.push(tuple_cmp(&keys, op));
    }
    if let Some((ts, session_offset, id)) = boundaries.end {
        let op = if query.order.is_desc() {
            Cmp::Gte
        } else {
            Cmp::Lte
        };
        top.push(tuple_cmp(&position_keys(ts, session_offset, id), op));
    }

    Ok(json!({ "bool": { "filter": top } }))
}

fn order_str(order: SortOrder) -> &'static str {
    if order.is_desc() { "desc" } else { "asc" }
}

/// The `sort` of an HTTP search: the sort field, then the unique position.
pub(super) fn http_sort(query: &TrafficQuery) -> Value {
    let order = order_str(query.order);
    let mut sort: Vec<Value> = Vec::new();
    if let Some((field, _)) = sort_field(query.order_by) {
        sort.push(json!({ field: { "order": order } }));
    }
    sort.extend(position_sort(order));
    Value::Array(sort)
}

fn position_sort(order: &str) -> [Value; 3] {
    [
        json!({ "timestamp": { "order": order } }),
        json!({ "session_offset": { "order": order } }),
        json!({ "id": { "order": order } }),
    ]
}

/// The `search_after` values that resume after the start cursor.
pub(super) fn http_search_after(
    query: &TrafficQuery,
    boundaries: &CursorBoundaries,
) -> Result<Option<Value>> {
    let Some((ts, session_offset, id)) = boundaries.start else {
        return Ok(None);
    };
    let mut after: Vec<Value> = Vec::new();
    if let Some((_, kind)) = sort_field(query.order_by)
        && let Some(key) = boundaries.start_key.as_deref()
    {
        after.push(sort_value(kind, key)?);
    }
    after.extend(
        position_keys(ts, session_offset, id)
            .into_iter()
            .map(|(_, v)| v),
    );
    Ok(Some(Value::Array(after)))
}

fn ws_branch(b: &WsQueryBranch) -> Result<Value> {
    let mut c: Vec<Value> = Vec::new();
    if let Some(v) = &b.source_id {
        c.push(json!({ "term": { "source_id": v } }));
    }
    if let Some(v) = &b.source {
        c.push(json!({ "term": { "source": v } }));
    }
    if let Some(v) = &b.session_id {
        c.push(json!({ "term": { "session_id": v } }));
    }
    if let Some(v) = &b.parent_event_id {
        // ClickHouse parses the bound value as a UUID, so any spelling of
        // one matches; the index stores the canonical lowercase form.
        let canonical = Uuid::parse_str(v).map_or_else(|_| v.clone(), |u| u.to_string());
        c.push(json!({ "term": { "parent_event_id": canonical } }));
    }
    push_string(&mut c, &HOST, &b.host)?;
    push_string(&mut c, &WS_PAYLOAD, &b.payload)?;
    push_string(&mut c, &WS_DIRECTION, &b.direction)?;
    push_string(&mut c, &WS_OPCODE, &b.opcode)?;
    push_string(&mut c, &WS_CLOSE_REASON, &b.close_reason)?;
    if let Some(f) = &b.close_code {
        c.push(int_filter("close_code", false, f, true));
    }
    if let Some(f) = &b.payload_size {
        c.push(int_filter("payload_size", false, f, true));
    }
    push_bool(&mut c, "was_compressed", b.was_compressed);
    push_bool(&mut c, "payload_is_text", b.payload_is_text);
    push_bool(&mut c, "payload_truncated", b.payload_truncated);
    Ok(and(c))
}

/// The `query` of a WebSocket search or count.
pub(super) fn ws_query(
    query: &WsTrafficQuery,
    start: Option<(OffsetDateTime, u64, Uuid)>,
    include_start: bool,
) -> Result<Value> {
    let mut top: Vec<Value> = Vec::new();
    if let Some(org) = &query.org_id {
        top.push(json!({ "term": { "org_id": org } }));
    }
    let branches = query
        .branches
        .0
        .iter()
        .map(ws_branch)
        .collect::<Result<Vec<_>>>()?;
    if let Some(clause) = or_of_branches(branches) {
        top.push(clause);
    }
    if include_start && let Some((ts, session_offset, id)) = start {
        let op = if query.order.is_desc() {
            Cmp::Lt
        } else {
            Cmp::Gt
        };
        top.push(tuple_cmp(&position_keys(ts, session_offset, id), op));
    }
    Ok(json!({ "bool": { "filter": top } }))
}

pub(super) fn ws_sort(order: SortOrder) -> Value {
    Value::Array(position_sort(order_str(order)).into())
}

pub(super) fn position_search_after(ts: OffsetDateTime, session_offset: u64, id: Uuid) -> Value {
    Value::Array(
        position_keys(ts, session_offset, id)
            .into_iter()
            .map(|(_, v)| v)
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::query::{NonEmpty, TimeWindow};

    fn golden(name: &str, actual: &Value) {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src/capture_store/opensearch/golden")
            .join(format!("{name}.json"));
        if std::env::var_os("UPDATE_GOLDEN").is_some() {
            let pretty = serde_json::to_string_pretty(actual).unwrap();
            std::fs::write(&path, pretty + "\n").unwrap();
            return;
        }
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!(
                "golden file {}: {e} (UPDATE_GOLDEN=1 writes it)",
                path.display()
            )
        });
        let expected: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            actual,
            &expected,
            "{name} differs from its golden file; actual:\n{}",
            serde_json::to_string_pretty(actual).unwrap()
        );
    }

    fn query(branches: Vec<QueryBranch>) -> TrafficQuery {
        TrafficQuery {
            org_id: Some("org-1".into()),
            branches: NonEmpty(branches),
            cursor: None,
            end_cursor: None,
            limit: None,
            order: SortOrder::Asc,
            order_by: SortField::Timestamp,
            request_body_max_fetch_size: None,
            response_body_max_fetch_size: None,
        }
    }

    fn lower_http(q: &TrafficQuery) -> Value {
        let boundaries = crate::query::cursor_boundaries(q).unwrap();
        http_query(q, &boundaries, true).unwrap()
    }

    fn contains(value: &str) -> Option<StringFilter> {
        Some(StringFilter::Contains {
            value: value.into(),
        })
    }

    fn exact(value: &str) -> Option<StringFilter> {
        Some(StringFilter::Exact {
            value: value.into(),
        })
    }

    #[test]
    fn empty_branch_is_org_only() {
        golden(
            "http_empty_branch",
            &lower_http(&query(vec![QueryBranch::default()])),
        );
    }

    #[test]
    fn single_branch_contains_and_status() {
        let q = query(vec![QueryBranch {
            host: contains("Stripe*?"),
            status_code: Some(IntFilter::Gte { value: 500 }),
            ..Default::default()
        }]);
        golden("http_contains_status", &lower_http(&q));
    }

    #[test]
    fn two_branches_are_ored() {
        let q = query(vec![
            QueryBranch {
                host: contains("stripe"),
                status_code: Some(IntFilter::Gte { value: 500 }),
                ..Default::default()
            },
            QueryBranch {
                path: contains("/api"),
                status_code: Some(IntFilter::Exact { value: 429 }),
                ..Default::default()
            },
        ]);
        golden("http_two_branches", &lower_http(&q));
    }

    #[test]
    fn a_match_all_branch_makes_the_or_trivial() {
        let q = query(vec![
            QueryBranch {
                host: exact("a"),
                ..Default::default()
            },
            QueryBranch::default(),
        ]);
        golden("http_match_all_branch", &lower_http(&q));
    }

    #[test]
    fn not_on_a_nullable_column_excludes_nulls() {
        let q = query(vec![QueryBranch {
            correlation_id: Some(StringFilter::Not {
                filter: Box::new(StringFilter::Exact { value: "x".into() }),
            }),
            ..Default::default()
        }]);
        golden("http_not_nullable", &lower_http(&q));
    }

    #[test]
    fn de_morgan_through_all_any_not() {
        let q = query(vec![QueryBranch {
            tool_call_id: Some(StringFilter::Not {
                filter: Box::new(StringFilter::Any {
                    filters: NonEmpty(vec![
                        StringFilter::Exact { value: "a".into() },
                        StringFilter::IsNull,
                    ]),
                }),
            }),
            ..Default::default()
        }]);
        golden("http_not_any_isnull", &lower_http(&q));
    }

    #[test]
    fn null_checks_on_nullable_and_plain_columns() {
        let q = query(vec![
            QueryBranch {
                account_id: Some(StringFilter::IsNull),
                ..Default::default()
            },
            QueryBranch {
                account_id: Some(StringFilter::IsPresent),
                host: Some(StringFilter::IsNull),
                ..Default::default()
            },
        ]);
        golden("http_null_checks", &lower_http(&q));
    }

    #[test]
    fn length_and_int_composition() {
        let q = query(vec![QueryBranch {
            request_body: Some(StringFilter::Length {
                value: IntFilter::All {
                    filters: NonEmpty(vec![
                        IntFilter::Gt { value: 10 },
                        IntFilter::Not {
                            filter: Box::new(IntFilter::Exact { value: 20 }),
                        },
                    ]),
                },
            }),
            duration_ms: Some(IntFilter::Lt { value: 1000 }),
            ..Default::default()
        }]);
        golden("http_length_int", &lower_http(&q));
    }

    #[test]
    fn exact_empty_on_a_wildcard_column_uses_the_length_field() {
        let q = query(vec![QueryBranch {
            response_body: exact(""),
            host: exact(""),
            ..Default::default()
        }]);
        golden("http_exact_empty", &lower_http(&q));
    }

    #[test]
    fn regex_lowers_to_a_wrapped_lucene_regexp() {
        let q = query(vec![QueryBranch {
            path: Some(StringFilter::RegexMatch {
                value: "(?i)^/v[0-9]+/users/\\d+$".into(),
            }),
            ..Default::default()
        }]);
        golden("http_regex", &lower_http(&q));
    }

    #[test]
    fn untranslatable_regex_is_rejected() {
        let q = query(vec![QueryBranch {
            path: Some(StringFilter::RegexMatch {
                value: r"\bfoo".into(),
            }),
            ..Default::default()
        }]);
        let boundaries = crate::query::cursor_boundaries(&q).unwrap();
        let err = http_query(&q, &boundaries, true).unwrap_err();
        assert!(matches!(err, StoreError::Rejected(m) if m.contains("word boundary")));
    }

    #[test]
    fn header_and_cookie_filters() {
        let q = query(vec![QueryBranch {
            source_id: Some(vec!["s1".into(), "s2".into()]),
            source: Some("crawler".into()),
            mime_type: contains("json"),
            request_sends_cookies: Some(true),
            response_sets_cookies: Some(false),
            request_header: Some(HeaderExactFilter {
                key: "X-Trace".into(),
                value: "abc".into(),
            }),
            response_header: Some(HeaderExactFilter {
                key: "Server".into(),
                value: "nginx".into(),
            }),
            ..Default::default()
        }]);
        golden("http_headers_cookies", &lower_http(&q));
    }

    #[test]
    fn empty_header_value_is_rejected() {
        let q = query(vec![QueryBranch {
            request_header: Some(HeaderExactFilter {
                key: "x".into(),
                value: String::new(),
            }),
            ..Default::default()
        }]);
        let boundaries = crate::query::cursor_boundaries(&q).unwrap();
        assert!(matches!(
            http_query(&q, &boundaries, true),
            Err(StoreError::Rejected(_))
        ));
    }

    #[test]
    fn time_window_bounds_the_timestamp() {
        let mut q = query(vec![QueryBranch {
            source_id: Some(vec!["s1".into()]),
            ..Default::default()
        }]);
        q.branches.0[0].time_window = Some(TimeWindow {
            start: OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            end: Some(OffsetDateTime::from_unix_timestamp(1_700_003_600).unwrap()),
        });
        golden("http_time_window", &lower_http(&q));
    }

    #[test]
    fn cursor_bounds_and_search_after() {
        let ts = OffsetDateTime::from_unix_timestamp_nanos(1_700_000_000_123_000_000).unwrap();
        let id = Uuid::parse_str("018f0000-0000-7000-8000-000000000001").unwrap();
        let end_ts = OffsetDateTime::from_unix_timestamp_nanos(1_700_000_900_000_000_000).unwrap();
        let mut q = query(vec![QueryBranch::default()]);
        q.cursor = Some(crate::query::cursor::encode_cursor(ts, 7, id));
        q.end_cursor = Some(crate::query::cursor::encode_cursor(end_ts, 9, id));
        let boundaries = crate::query::cursor_boundaries(&q).unwrap();
        golden(
            "http_cursor_asc",
            &json!({
                "query": http_query(&q, &boundaries, true).unwrap(),
                "search_query": http_query(&q, &boundaries, false).unwrap(),
                "sort": http_sort(&q),
                "search_after": http_search_after(&q, &boundaries).unwrap(),
            }),
        );

        q.order = SortOrder::Desc;
        q.cursor = Some(crate::query::cursor::encode_cursor(end_ts, 9, id));
        q.end_cursor = Some(crate::query::cursor::encode_cursor(ts, 7, id));
        let boundaries = crate::query::cursor_boundaries(&q).unwrap();
        golden(
            "http_cursor_desc",
            &json!({
                "query": http_query(&q, &boundaries, true).unwrap(),
                "sort": http_sort(&q),
                "search_after": http_search_after(&q, &boundaries).unwrap(),
            }),
        );
    }

    #[test]
    fn sorted_search_carries_the_sort_value_in_the_cursor() {
        let ts = OffsetDateTime::from_unix_timestamp_nanos(1_700_000_000_123_000_000).unwrap();
        let id = Uuid::parse_str("018f0000-0000-7000-8000-000000000001").unwrap();
        let mut q = query(vec![QueryBranch::default()]);
        q.order = SortOrder::Desc;
        q.order_by = SortField::StatusCode;
        q.cursor = Some(crate::query::cursor::encode_sorted_cursor(
            q.order_by.cursor_tag(q.order),
            "404",
            ts,
            3,
            id,
        ));
        let boundaries = crate::query::cursor_boundaries(&q).unwrap();
        golden(
            "http_sorted_cursor",
            &json!({
                "query": http_query(&q, &boundaries, true).unwrap(),
                "sort": http_sort(&q),
                "search_after": http_search_after(&q, &boundaries).unwrap(),
            }),
        );
    }

    fn ws_branch_all() -> WsQueryBranch {
        WsQueryBranch {
            source_id: Some("s1".into()),
            source: Some("crawler".into()),
            session_id: Some("sess".into()),
            parent_event_id: Some("018F0000-0000-7000-8000-000000000001".into()),
            host: exact("ws.example.com"),
            payload: Some(StringFilter::Contains {
                value: "ticker".into(),
            }),
            direction: exact("s2c"),
            opcode: Some(StringFilter::Any {
                filters: NonEmpty(vec![
                    StringFilter::Exact {
                        value: "text".into(),
                    },
                    StringFilter::Exact {
                        value: "binary".into(),
                    },
                ]),
            }),
            close_reason: Some(StringFilter::Length {
                value: IntFilter::Gt { value: 0 },
            }),
            close_code: Some(IntFilter::Exact { value: 1000 }),
            payload_size: Some(IntFilter::Lte { value: 4096 }),
            was_compressed: Some(false),
            payload_is_text: Some(true),
            payload_truncated: Some(false),
        }
    }

    #[test]
    fn ws_branch_lowers_every_column() {
        let q = WsTrafficQuery {
            org_id: Some("org-1".into()),
            branches: NonEmpty(vec![ws_branch_all()]),
            cursor: None,
            limit: None,
            order: SortOrder::Desc,
            payload_max_fetch_size: None,
        };
        let ts = OffsetDateTime::from_unix_timestamp_nanos(1_700_000_000_123_000_000).unwrap();
        let id = Uuid::parse_str("018f0000-0000-7000-8000-000000000001").unwrap();
        golden(
            "ws_all_columns",
            &json!({
                "query": ws_query(&q, Some((ts, 5, id)), true).unwrap(),
                "sort": ws_sort(q.order),
                "search_after": position_search_after(ts, 5, id),
            }),
        );
    }
}
