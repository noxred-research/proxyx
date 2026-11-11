//! Read side: [`CaptureStore`] over `_search`, `_count` and aggregations.

use std::collections::HashMap;

use anyhow::{Context, Result};
use async_trait::async_trait;
use proxyx_control_graphql::{
    RequestRatePointDto, ScanTrafficSummaryDto, SourceTrafficTotalDto, TrafficBucketDto,
    TrafficTimeSeriesPointDto, WsConversationDto, WsConversationSearchResponse,
};
use serde::Deserialize;
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use super::OpenSearchStore;
use super::client::OsResponse;
use super::lower::{self, epoch_millis};
use super::schema::{Kind, read_pattern};
use crate::capture_store::{
    CaptureBackend, CaptureStore, ConversationQuery, Sequence, StoreError, TimeSeriesQuery,
};
use crate::models::{
    BodyFetch, HttpCapture, HttpCaptureSummary, SearchResponse, WsCapture, WsCaptureSummary,
    WsSearchResponse,
};
use crate::query::ws::WsTrafficQuery;
use crate::query::{TrafficQuery, cursor, cursor_boundaries, limit_clamped};
use crate::views::ViewExporter;

/// Server-side limit of one search.
const SEARCH_TIMEOUT: &str = "30s";

/// Buckets fetched per page of a composite aggregation.
const COMPOSITE_PAGE: u64 = 1000;

/// Distinct conversations (or sources) counted exactly; above it the count
/// is approximate.
const CARDINALITY_PRECISION: u64 = 40_000;

/// Conversations each shard considers before the top N are merged.
const CONVERSATION_SHARD_SIZE: u64 = 10_000;

const HTTP_SUMMARY_FIELDS: &[&str] = &[
    "id",
    "org_id",
    "timestamp",
    "session_offset",
    "method",
    "path",
    "host",
    "scheme",
    "session_id",
    "proxy_id",
    "request_headers",
    "request_size",
    "status_code",
    "response_headers",
    "response_size",
    "duration_ms",
    "ratelimit_wait_ms",
    "source",
    "source_id",
    "correlation_id",
    "parent_correlation_id",
    "account_id",
    "tool_call_id",
];

const HTTP_FULL_FIELDS: &[&str] = &[
    "id",
    "org_id",
    "timestamp",
    "session_offset",
    "method",
    "path",
    "host",
    "scheme",
    "session_id",
    "proxy_id",
    "request_headers",
    "request_body",
    "request_size",
    "status_code",
    "response_headers",
    "response_body",
    "response_size",
    "duration_ms",
    "ratelimit_wait_ms",
    "source",
    "source_id",
    "correlation_id",
    "parent_correlation_id",
    "account_id",
    "tool_call_id",
];

const WS_SUMMARY_FIELDS: &[&str] = &[
    "id",
    "parent_event_id",
    "org_id",
    "timestamp",
    "session_offset",
    "direction",
    "opcode",
    "session_id",
    "proxy_id",
    "source",
    "source_id",
    "host",
    "payload_size",
    "payload_truncated",
    "payload_is_text",
    "was_compressed",
    "close_code",
    "close_reason",
];

const WS_FULL_FIELDS: &[&str] = &[
    "id",
    "parent_event_id",
    "org_id",
    "timestamp",
    "session_offset",
    "direction",
    "opcode",
    "session_id",
    "proxy_id",
    "source",
    "source_id",
    "host",
    "payload",
    "payload_size",
    "payload_truncated",
    "payload_is_text",
    "was_compressed",
    "close_code",
    "close_reason",
];

#[derive(Deserialize)]
struct HeaderPair {
    name: String,
    value: String,
}

fn pairs(headers: Vec<HeaderPair>) -> Vec<(String, String)> {
    headers.into_iter().map(|h| (h.name, h.value)).collect()
}

fn from_millis(ms: i64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH)
}

fn offset_of(value: i64) -> u64 {
    u64::try_from(value).unwrap_or_default()
}

/// `_source` of an HTTP capture; the bodies are present only when asked for.
#[derive(Deserialize)]
struct HttpSource {
    id: Uuid,
    org_id: String,
    timestamp: i64,
    #[serde(default)]
    session_offset: i64,
    method: String,
    path: String,
    host: String,
    scheme: String,
    session_id: String,
    proxy_id: String,
    #[serde(default)]
    request_headers: Vec<HeaderPair>,
    #[serde(default)]
    request_body: String,
    request_size: u32,
    status_code: u16,
    #[serde(default)]
    response_headers: Vec<HeaderPair>,
    #[serde(default)]
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

impl From<HttpSource> for HttpCapture {
    fn from(s: HttpSource) -> Self {
        Self {
            id: s.id,
            org_id: s.org_id,
            timestamp: from_millis(s.timestamp),
            method: s.method,
            path: s.path,
            host: s.host,
            scheme: s.scheme,
            session_id: s.session_id,
            proxy_id: s.proxy_id,
            request_headers: pairs(s.request_headers),
            request_body: s.request_body,
            request_size: s.request_size,
            status_code: s.status_code,
            response_headers: pairs(s.response_headers),
            response_body: s.response_body,
            response_size: s.response_size,
            duration_ms: s.duration_ms,
            ratelimit_wait_ms: s.ratelimit_wait_ms,
            source: s.source,
            source_id: s.source_id,
            correlation_id: s.correlation_id,
            parent_correlation_id: s.parent_correlation_id,
            account_id: s.account_id,
            tool_call_id: s.tool_call_id,
        }
    }
}

impl From<HttpSource> for HttpCaptureSummary {
    fn from(s: HttpSource) -> Self {
        Self {
            id: s.id,
            org_id: s.org_id,
            timestamp: from_millis(s.timestamp),
            session_offset: offset_of(s.session_offset),
            method: s.method,
            path: s.path,
            host: s.host,
            scheme: s.scheme,
            session_id: s.session_id,
            proxy_id: s.proxy_id,
            request_size: s.request_size,
            status_code: s.status_code,
            response_size: s.response_size,
            duration_ms: s.duration_ms,
            ratelimit_wait_ms: s.ratelimit_wait_ms,
            source: s.source,
            source_id: s.source_id,
            correlation_id: s.correlation_id,
            parent_correlation_id: s.parent_correlation_id,
            account_id: s.account_id,
            tool_call_id: s.tool_call_id,
            request_headers: pairs(s.request_headers),
            response_headers: pairs(s.response_headers),
            request_body: None,
            response_body: None,
        }
    }
}

#[derive(Deserialize)]
struct WsSource {
    id: Uuid,
    parent_event_id: Uuid,
    org_id: String,
    timestamp: i64,
    #[serde(default)]
    session_offset: i64,
    direction: String,
    opcode: String,
    session_id: String,
    proxy_id: String,
    source: String,
    source_id: String,
    host: String,
    #[serde(default)]
    payload: String,
    payload_size: u32,
    payload_truncated: bool,
    payload_is_text: bool,
    was_compressed: bool,
    close_code: u16,
    close_reason: String,
}

impl From<WsSource> for WsCapture {
    fn from(s: WsSource) -> Self {
        Self {
            id: s.id,
            parent_event_id: s.parent_event_id,
            org_id: s.org_id,
            timestamp: from_millis(s.timestamp),
            session_offset: offset_of(s.session_offset),
            direction: s.direction,
            opcode: s.opcode,
            session_id: s.session_id,
            proxy_id: s.proxy_id,
            source: s.source,
            source_id: s.source_id,
            host: s.host,
            payload: s.payload,
            payload_size: s.payload_size,
            payload_truncated: s.payload_truncated,
            payload_is_text: s.payload_is_text,
            was_compressed: s.was_compressed,
            close_code: s.close_code,
            close_reason: s.close_reason,
        }
    }
}

impl From<WsSource> for WsCaptureSummary {
    fn from(s: WsSource) -> Self {
        Self {
            id: s.id,
            parent_event_id: s.parent_event_id,
            org_id: s.org_id,
            timestamp: from_millis(s.timestamp),
            session_offset: offset_of(s.session_offset),
            direction: s.direction,
            opcode: s.opcode,
            session_id: s.session_id,
            proxy_id: s.proxy_id,
            source: s.source,
            source_id: s.source_id,
            host: s.host,
            payload_size: s.payload_size,
            payload_truncated: s.payload_truncated,
            payload_is_text: s.payload_is_text,
            was_compressed: s.was_compressed,
            close_code: s.close_code,
            close_reason: s.close_reason,
            payload: None,
        }
    }
}

/// A body is returned when the capture's wire size is within `max`; a larger
/// one is reported as too large with its size.
fn body_fetch(raw: String, size: u32, max: Option<u32>) -> Option<BodyFetch> {
    let max = max?;
    if size > max {
        Some(BodyFetch::TooLarge { size })
    } else {
        Some(BodyFetch::Body { value: raw })
    }
}

/// One hit: its parsed `_source` and `sort` values.
struct Hit<S> {
    source: S,
    sort: Vec<Value>,
}

fn parse_hits<S: for<'de> Deserialize<'de>>(response: &OsResponse) -> Result<Vec<Hit<S>>> {
    let hits = response.body["hits"]["hits"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default();
    hits.iter()
        .map(|hit| {
            Ok(Hit {
                source: serde_json::from_value(hit["_source"].clone())
                    .context("a stored capture does not match the index mapping")?,
                sort: hit["sort"].as_array().cloned().unwrap_or_default(),
            })
        })
        .collect()
}

/// The sort value as the text a cursor carries.
fn sort_text(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(text)) => text.clone(),
        Some(other) => other.to_string(),
        None => String::new(),
    }
}

fn ids_query(org_id: Option<&str>, ids: impl IntoIterator<Item = String>) -> Value {
    let mut filter = vec![json!({ "ids": { "values": ids.into_iter().collect::<Vec<_>>() } })];
    if let Some(org) = org_id {
        filter.push(json!({ "term": { "org_id": org } }));
    }
    json!({ "bool": { "filter": filter } })
}

fn rfc3339(ts: OffsetDateTime) -> String {
    ts.format(&Rfc3339).unwrap_or_default()
}

impl OpenSearchStore {
    fn search_path(&self, kind: Kind) -> String {
        format!(
            "/{}/_search?ignore_unavailable=true&allow_no_indices=true\
             &allow_partial_search_results=false",
            read_pattern(&self.config, kind)
        )
    }

    /// Run a search; a query the engine refuses as too complex is a
    /// rejection, anything else an error.
    async fn search_raw(&self, kind: Kind, body: Value) -> Result<OsResponse> {
        let response = self
            .client
            .post_json(&self.search_path(kind), &body)
            .await?;
        if response.is_success() {
            return Ok(response);
        }
        if response
            .body
            .to_string()
            .contains("too_complex_to_determinize_exception")
        {
            return Err(StoreError::Rejected(format!(
                "a regular expression is too complex for the opensearch capture store: {}",
                response.error_summary()
            ))
            .into());
        }
        response.ensure_success("_search")?;
        Ok(response)
    }

    async fn count_raw(&self, kind: Kind, query: Value) -> Result<u64> {
        let path = format!(
            "/{}/_count?ignore_unavailable=true&allow_no_indices=true",
            read_pattern(&self.config, kind)
        );
        let response = self
            .client
            .post_json(&path, &json!({ "query": query }))
            .await?;
        if !response.is_success()
            && response
                .body
                .to_string()
                .contains("too_complex_to_determinize_exception")
        {
            return Err(StoreError::Rejected(format!(
                "a regular expression is too complex for the opensearch capture store: {}",
                response.error_summary()
            ))
            .into());
        }
        response.ensure_success("_count")?;
        Ok(response.body["count"].as_u64().unwrap_or_default())
    }

    /// Every bucket of a composite aggregation over `query`, page by page.
    async fn composite(
        &self,
        kind: Kind,
        query: Value,
        sources: Value,
        sub_aggs: Option<Value>,
    ) -> Result<Vec<Value>> {
        let mut buckets: Vec<Value> = Vec::new();
        let mut after: Option<Value> = None;
        loop {
            let mut composite = json!({ "size": COMPOSITE_PAGE, "sources": sources });
            if let Some(after) = &after {
                composite["after"] = after.clone();
            }
            let mut agg = json!({ "composite": composite });
            if let Some(sub) = &sub_aggs {
                agg["aggs"] = sub.clone();
            }
            let response = self
                .search_raw(
                    kind,
                    json!({
                        "size": 0,
                        "track_total_hits": false,
                        "timeout": SEARCH_TIMEOUT,
                        "query": query,
                        "aggs": { "c": agg },
                    }),
                )
                .await?;
            let page = &response.body["aggregations"]["c"];
            let page_buckets = page["buckets"]
                .as_array()
                .map(Vec::as_slice)
                .unwrap_or_default();
            buckets.extend(page_buckets.iter().cloned());
            match page.get("after_key") {
                Some(key) if page_buckets.len() as u64 == COMPOSITE_PAGE => {
                    after = Some(key.clone())
                }
                _ => return Ok(buckets),
            }
        }
    }

    /// Fetch the bodies of one page and attach them: a side whose size is
    /// over its cap is reported as too large without being read.
    async fn attach_http_bodies(
        &self,
        items: &mut [HttpCaptureSummary],
        request_max: Option<u32>,
        response_max: Option<u32>,
    ) -> Result<()> {
        let wants = |size: u32, max: Option<u32>| max.is_some_and(|max| size <= max);
        let mut fetch: Vec<usize> = Vec::new();
        for (i, item) in items.iter_mut().enumerate() {
            if let Some(max) = request_max
                && item.request_size > max
            {
                item.request_body = Some(BodyFetch::TooLarge {
                    size: item.request_size,
                });
            }
            if let Some(max) = response_max
                && item.response_size > max
            {
                item.response_body = Some(BodyFetch::TooLarge {
                    size: item.response_size,
                });
            }
            if wants(item.request_size, request_max) || wants(item.response_size, response_max) {
                fetch.push(i);
            }
        }
        if fetch.is_empty() {
            return Ok(());
        }

        let mut includes = vec!["id"];
        if request_max.is_some() {
            includes.push("request_body");
        }
        if response_max.is_some() {
            includes.push("response_body");
        }
        let org = items.first().map(|i| i.org_id.clone());
        let response = self
            .search_raw(
                Kind::Http,
                json!({
                    "size": fetch.len(),
                    "track_total_hits": false,
                    "timeout": SEARCH_TIMEOUT,
                    "_source": { "includes": includes },
                    "query": ids_query(org.as_deref(), fetch.iter().map(|&i| items[i].id.to_string())),
                }),
            )
            .await?;
        #[derive(Deserialize)]
        struct Bodies {
            id: Uuid,
            #[serde(default)]
            request_body: String,
            #[serde(default)]
            response_body: String,
        }
        let mut bodies: HashMap<Uuid, Bodies> = parse_hits::<Bodies>(&response)?
            .into_iter()
            .map(|h| (h.source.id, h.source))
            .collect();
        for item in items.iter_mut() {
            if let Some(b) = bodies.remove(&item.id) {
                if wants(item.request_size, request_max) {
                    item.request_body = body_fetch(b.request_body, item.request_size, request_max);
                }
                if wants(item.response_size, response_max) {
                    item.response_body =
                        body_fetch(b.response_body, item.response_size, response_max);
                }
            }
        }
        Ok(())
    }
}

#[async_trait]
impl CaptureStore for OpenSearchStore {
    fn backend(&self) -> CaptureBackend {
        CaptureBackend::OpenSearch
    }

    fn check_http_query(&self, query: &TrafficQuery) -> Result<(), StoreError> {
        let boundaries =
            cursor_boundaries(query).map_err(|e| StoreError::Rejected(e.to_string()))?;
        lower::http_query(query, &boundaries, true).map(|_| ())
    }

    fn check_ws_query(&self, query: &WsTrafficQuery) -> Result<(), StoreError> {
        let start = crate::query::ws::cursor_boundary(query)
            .map_err(|e| StoreError::Rejected(e.to_string()))?;
        lower::ws_query(query, start, true).map(|_| ())
    }

    async fn ping(&self) -> Result<()> {
        self.client.ping().await
    }

    async fn search_requests(&self, query: &TrafficQuery) -> Result<SearchResponse> {
        let boundaries = cursor_boundaries(query)?;
        let limit = limit_clamped(query);
        let mut body = json!({
            "size": limit + 1,
            "track_total_hits": false,
            "timeout": SEARCH_TIMEOUT,
            "_source": { "includes": HTTP_SUMMARY_FIELDS },
            "query": lower::http_query(query, &boundaries, false)?,
            "sort": lower::http_sort(query),
        });
        if let Some(after) = lower::http_search_after(query, &boundaries)? {
            body["search_after"] = after;
        }
        let response = self.search_raw(Kind::Http, body).await?;
        let mut hits = parse_hits::<HttpSource>(&response)?;

        let more = hits.len() as u32 > limit;
        hits.truncate(limit as usize);
        let next_cursor = if more {
            hits.last().map(|hit| {
                let s = &hit.source;
                let (ts, off) = (from_millis(s.timestamp), offset_of(s.session_offset));
                match lower::sort_field(query.order_by) {
                    Some(_) => cursor::encode_sorted_cursor(
                        query.order_by.cursor_tag(query.order),
                        &sort_text(hit.sort.first()),
                        ts,
                        off,
                        s.id,
                    ),
                    None => cursor::encode_cursor(ts, off, s.id),
                }
            })
        } else {
            None
        };

        let mut items: Vec<HttpCaptureSummary> =
            hits.into_iter().map(|h| h.source.into()).collect();
        self.attach_http_bodies(
            &mut items,
            query.request_body_max_fetch_size,
            query.response_body_max_fetch_size,
        )
        .await?;
        Ok(SearchResponse {
            items,
            next_cursor,
            total_count: None,
        })
    }

    async fn count_requests(&self, query: &TrafficQuery) -> Result<u64> {
        let boundaries = cursor_boundaries(query)?;
        self.count_raw(Kind::Http, lower::http_query(query, &boundaries, true)?)
            .await
    }

    async fn get_request(&self, org_id: &str, id: Uuid) -> Result<Option<HttpCapture>> {
        let response = self
            .search_raw(
                Kind::Http,
                json!({
                    "size": 1,
                    "track_total_hits": false,
                    "_source": { "includes": HTTP_FULL_FIELDS },
                    "query": ids_query(Some(org_id), [id.to_string()]),
                }),
            )
            .await?;
        Ok(parse_hits::<HttpSource>(&response)?
            .into_iter()
            .next()
            .map(|h| h.source.into()))
    }

    async fn search_ws(&self, query: &WsTrafficQuery) -> Result<WsSearchResponse> {
        let start = crate::query::ws::cursor_boundary(query)?;
        let limit = crate::query::ws::limit_clamped(query);
        let mut body = json!({
            "size": limit + 1,
            "track_total_hits": false,
            "timeout": SEARCH_TIMEOUT,
            "_source": { "includes": WS_SUMMARY_FIELDS },
            "query": lower::ws_query(query, start, false)?,
            "sort": lower::ws_sort(query.order),
        });
        if let Some((ts, off, id)) = start {
            body["search_after"] = lower::position_search_after(ts, off, id);
        }
        let response = self.search_raw(Kind::Ws, body).await?;
        let mut hits = parse_hits::<WsSource>(&response)?;

        let more = hits.len() as u32 > limit;
        hits.truncate(limit as usize);
        let next_cursor = if more {
            hits.last().map(|hit| {
                cursor::encode_cursor(
                    from_millis(hit.source.timestamp),
                    offset_of(hit.source.session_offset),
                    hit.source.id,
                )
            })
        } else {
            None
        };
        let mut items: Vec<WsCaptureSummary> = hits.into_iter().map(|h| h.source.into()).collect();

        if let Some(max) = query.payload_max_fetch_size {
            let mut fetch: Vec<usize> = Vec::new();
            for (i, item) in items.iter_mut().enumerate() {
                if item.payload_size > max {
                    item.payload = Some(BodyFetch::TooLarge {
                        size: item.payload_size,
                    });
                } else {
                    fetch.push(i);
                }
            }
            if !fetch.is_empty() {
                let response = self
                    .search_raw(
                        Kind::Ws,
                        json!({
                            "size": fetch.len(),
                            "track_total_hits": false,
                            "timeout": SEARCH_TIMEOUT,
                            "_source": { "includes": ["id", "payload"] },
                            "query": ids_query(
                                query.org_id.as_deref(),
                                fetch.iter().map(|&i| items[i].id.to_string()),
                            ),
                        }),
                    )
                    .await?;
                #[derive(Deserialize)]
                struct Payload {
                    id: Uuid,
                    #[serde(default)]
                    payload: String,
                }
                let mut payloads: HashMap<Uuid, String> = parse_hits::<Payload>(&response)?
                    .into_iter()
                    .map(|h| (h.source.id, h.source.payload))
                    .collect();
                for &i in &fetch {
                    if let Some(raw) = payloads.remove(&items[i].id) {
                        items[i].payload = body_fetch(raw, items[i].payload_size, Some(max));
                    }
                }
            }
        }
        Ok(WsSearchResponse {
            items,
            next_cursor,
            total_count: None,
        })
    }

    async fn count_ws(&self, query: &WsTrafficQuery) -> Result<u64> {
        let start = crate::query::ws::cursor_boundary(query)?;
        self.count_raw(Kind::Ws, lower::ws_query(query, start, true)?)
            .await
    }

    async fn get_ws_message(&self, org_id: &str, id: Uuid) -> Result<Option<WsCapture>> {
        let response = self
            .search_raw(
                Kind::Ws,
                json!({
                    "size": 1,
                    "track_total_hits": false,
                    "_source": { "includes": WS_FULL_FIELDS },
                    "query": ids_query(Some(org_id), [id.to_string()]),
                }),
            )
            .await?;
        Ok(parse_hits::<WsSource>(&response)?
            .into_iter()
            .next()
            .map(|h| h.source.into()))
    }

    async fn ws_conversations(
        &self,
        query: &ConversationQuery<'_>,
    ) -> Result<WsConversationSearchResponse> {
        let mut filter = vec![json!({ "term": { "org_id": query.org_id } })];
        if let Some(ids) = query.source_ids.filter(|v| !v.is_empty()) {
            filter.push(json!({ "terms": { "source_id": ids } }));
        }
        if let Some(source) = query.source {
            filter.push(json!({ "term": { "source": source } }));
        }
        if let Some(host) = query.host {
            filter.push(json!({ "term": { "host": host } }));
        }
        let order = if query.descending { "desc" } else { "asc" };
        let limit = u64::from(query.limit);

        let response = self
            .search_raw(
                Kind::Ws,
                json!({
                    "size": 0,
                    "track_total_hits": false,
                    "timeout": SEARCH_TIMEOUT,
                    "query": { "bool": { "filter": filter } },
                    "aggs": {
                        "total": { "cardinality": {
                            "field": "parent_event_id",
                            "precision_threshold": CARDINALITY_PRECISION,
                        } },
                        "conversations": {
                            "terms": {
                                "field": "parent_event_id",
                                "size": limit,
                                "shard_size": limit.max(CONVERSATION_SHARD_SIZE),
                                "order": [{ "last_at": order }, { "_key": order }],
                            },
                            "aggs": {
                                "last_at": { "max": { "field": "timestamp" } },
                                "first_at": { "min": { "field": "timestamp" } },
                                "c2s": { "filter": { "term": { "direction": "c2s" } } },
                                "s2c": { "filter": { "term": { "direction": "s2c" } } },
                                "any": { "top_hits": {
                                    "size": 1,
                                    "_source": { "includes": ["host", "source", "source_id", "session_id"] },
                                } },
                            },
                        },
                    },
                }),
            )
            .await?;

        let aggs = &response.body["aggregations"];
        let total = aggs["total"]["value"].as_u64().unwrap_or_default();
        let buckets = aggs["conversations"]["buckets"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default();

        let parents: Vec<Uuid> = buckets
            .iter()
            .filter_map(|b| b["key"].as_str().and_then(|k| Uuid::parse_str(k).ok()))
            .collect();
        let mut paths: HashMap<Uuid, String> = HashMap::new();
        if !parents.is_empty() {
            let response = self
                .search_raw(
                    Kind::Http,
                    json!({
                        "size": parents.len(),
                        "track_total_hits": false,
                        "timeout": SEARCH_TIMEOUT,
                        "_source": { "includes": ["id", "path"] },
                        "query": ids_query(Some(query.org_id), parents.iter().map(Uuid::to_string)),
                    }),
                )
                .await?;
            #[derive(Deserialize)]
            struct PathRow {
                id: Uuid,
                path: String,
            }
            for hit in parse_hits::<PathRow>(&response)? {
                paths.insert(hit.source.id, hit.source.path);
            }
        }

        let millis = |v: &Value| from_millis(v["value"].as_f64().unwrap_or_default() as i64);
        let items = buckets
            .iter()
            .filter_map(|b| {
                let parent_event_id = Uuid::parse_str(b["key"].as_str()?).ok()?;
                let any = &b["any"]["hits"]["hits"][0]["_source"];
                let text = |field: &str| any[field].as_str().unwrap_or_default().to_string();
                Some(WsConversationDto {
                    path: paths.get(&parent_event_id).cloned(),
                    parent_event_id,
                    host: text("host"),
                    source: text("source"),
                    source_id: text("source_id"),
                    session_id: text("session_id"),
                    message_count: b["doc_count"].as_u64().unwrap_or_default(),
                    client_to_server: b["c2s"]["doc_count"].as_u64().unwrap_or_default(),
                    server_to_client: b["s2c"]["doc_count"].as_u64().unwrap_or_default(),
                    first_at: millis(&b["first_at"]),
                    last_at: millis(&b["last_at"]),
                })
            })
            .collect();
        Ok(WsConversationSearchResponse {
            items,
            total_count: Some(total),
        })
    }

    async fn request_rate_series(
        &self,
        org_id: &str,
        start: OffsetDateTime,
        end: OffsetDateTime,
    ) -> Result<Vec<RequestRatePointDto>> {
        let query = json!({ "bool": { "filter": [
            { "term": { "org_id": org_id } },
            { "range": { "timestamp": { "gte": epoch_millis(start), "lt": epoch_millis(end) } } },
        ] } });
        let buckets = self
            .composite(
                Kind::Http,
                query,
                json!([{ "minute": { "date_histogram": {
                    "field": "timestamp",
                    "fixed_interval": "60s",
                } } }]),
                None,
            )
            .await?;
        Ok(buckets
            .iter()
            .map(|b| RequestRatePointDto {
                minute: from_millis(b["key"]["minute"].as_i64().unwrap_or_default()),
                requests: b["doc_count"].as_u64().unwrap_or_default(),
            })
            .collect())
    }

    async fn http_traffic_time_series(
        &self,
        query: &TimeSeriesQuery<'_>,
    ) -> Result<Vec<TrafficTimeSeriesPointDto>> {
        let buckets = self
            .bucket_by_source(query, query.source_ids.filter(|ids| !ids.is_empty()), true)
            .await?;
        Ok(buckets
            .into_iter()
            .map(|b| TrafficTimeSeriesPointDto {
                bucket_start: rfc3339(b.bucket),
                source_id: b.source_id,
                source: b.source,
                count: b.count,
            })
            .collect())
    }

    async fn scan_traffic_summary(
        &self,
        query: &TimeSeriesQuery<'_>,
    ) -> Result<ScanTrafficSummaryDto> {
        let chunks = crate::capture_store::clickhouse::chunk_scan_traffic_source_ids(
            query.source_ids.unwrap_or_default().to_vec(),
        )?;
        let mut buckets = std::collections::BTreeMap::<String, u64>::new();
        let mut by_source = std::collections::HashMap::<String, u64>::new();
        let mut total: u64 = 0;
        for chunk in chunks {
            for b in self.bucket_by_source(query, Some(&chunk), false).await? {
                total += b.count;
                *by_source.entry(b.source_id).or_insert(0) += b.count;
                *buckets.entry(rfc3339(b.bucket)).or_insert(0) += b.count;
            }
        }
        Ok(ScanTrafficSummaryDto {
            buckets: buckets
                .into_iter()
                .map(|(bucket_start, count)| TrafficBucketDto {
                    bucket_start,
                    count,
                })
                .collect(),
            by_source: by_source
                .into_iter()
                .map(|(source_id, count)| SourceTrafficTotalDto { source_id, count })
                .collect(),
            total,
        })
    }

    async fn sequence(&self, org_id: &str, source_id: &str) -> Result<Sequence> {
        let query = json!({ "bool": { "filter": [
            { "term": { "org_id": org_id } },
            { "term": { "source_id": source_id } },
        ] } });
        let response = self
            .search_raw(
                Kind::Http,
                json!({
                    "size": 1,
                    "track_total_hits": false,
                    "timeout": SEARCH_TIMEOUT,
                    "_source": { "includes": ["id", "timestamp", "session_offset"] },
                    "query": query,
                    "sort": [
                        { "timestamp": { "order": "desc" } },
                        { "session_offset": { "order": "desc" } },
                        { "id": { "order": "desc" } },
                    ],
                }),
            )
            .await?;
        #[derive(Deserialize)]
        struct Newest {
            id: Uuid,
            timestamp: i64,
            session_offset: i64,
        }
        let cursor = parse_hits::<Newest>(&response)?
            .into_iter()
            .next()
            .map(|h| {
                cursor::encode_cursor(
                    from_millis(h.source.timestamp),
                    offset_of(h.source.session_offset),
                    h.source.id,
                )
            });
        let count = self.count_raw(Kind::Http, query).await?;
        Ok(Sequence { cursor, count })
    }

    fn view_exporter(&self) -> Option<&dyn ViewExporter> {
        None
    }
}

/// One `(bucket, source)` cell of a request count aggregation.
struct SourceBucket {
    bucket: OffsetDateTime,
    source_id: String,
    source: String,
    count: u64,
}

impl OpenSearchStore {
    /// Request counts per `(bucket, source_id)` over `[start, end)`; `with_source`
    /// also resolves the source name.
    async fn bucket_by_source(
        &self,
        query: &TimeSeriesQuery<'_>,
        source_ids: Option<&[String]>,
        with_source: bool,
    ) -> Result<Vec<SourceBucket>> {
        let mut filter = vec![json!({ "range": { "timestamp": {
            "gte": epoch_millis(query.start),
            "lt": epoch_millis(query.end),
        } } })];
        if let Some(org) = query.org_id {
            filter.push(json!({ "term": { "org_id": org } }));
        }
        if let Some(ids) = source_ids {
            filter.push(json!({ "terms": { "source_id": ids } }));
        }
        let sources = json!([
            { "bucket": { "date_histogram": {
                "field": "timestamp",
                "fixed_interval": format!("{}s", query.bucket_seconds),
            } } },
            { "source_id": { "terms": { "field": "source_id" } } },
        ]);
        let sub =
            with_source.then(|| json!({ "name": { "terms": { "field": "source", "size": 1 } } }));
        let buckets = self
            .composite(
                Kind::Http,
                json!({ "bool": { "filter": filter } }),
                sources,
                sub,
            )
            .await?;
        Ok(buckets
            .iter()
            .map(|b| SourceBucket {
                bucket: from_millis(b["key"]["bucket"].as_i64().unwrap_or_default()),
                source_id: b["key"]["source_id"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                source: b["name"]["buckets"][0]["key"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                count: b["doc_count"].as_u64().unwrap_or_default(),
            })
            .collect())
    }
}
