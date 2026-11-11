//! Reading captured traffic through the control plane (`/rpc/requests`, `/rpc/ws`).
//!
//! Search takes a list of OR-ed [`QueryBranch`]es; fields inside a branch are AND-ed. Results
//! are paged by an opaque cursor: pass `next_cursor` back as `cursor` until it is `None`.
//! Bodies are returned only when a `*_max_fetch_size` is set, as [`BodyFetch`].
//!
//! ```no_run
//! # use proxyx_client::sessions::SessionsClient;
//! use proxyx_client::traffic::{IntFilter, QueryBranch, TrafficQuery};
//!
//! # async fn run(client: SessionsClient) -> Result<(), proxyx_client::Error> {
//! let branch = QueryBranch::for_source("crawl-42").status_code(IntFilter::gte(400));
//! let mut query = TrafficQuery::new(vec![branch]).limit(500);
//! loop {
//!     let page = client.search_requests(&query).await?;
//!     for item in &page.items {
//!         println!("{} {}{} {}", item.method, item.host, item.path, item.status_code);
//!     }
//!     match page.next_cursor {
//!         Some(cursor) => query.cursor = Some(cursor),
//!         None => break,
//!     }
//! }
//! # Ok(()) }
//! ```

use std::fmt;

use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::{Error, Result};
use crate::http;
use crate::sessions::SessionsClient;

// --- filters --------------------------------------------------------------------------------

/// Filter on a string column.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum StringFilter {
    /// Case-insensitive substring.
    Contains {
        /// Text to find.
        value: String,
    },
    /// Equality.
    Exact {
        /// Text to equal.
        value: String,
    },
    /// RE2 regex, unanchored and case-sensitive; use `(?i)` to fold case.
    RegexMatch {
        /// Pattern.
        value: String,
    },
    /// Byte length of the column.
    Length {
        /// Condition on the length.
        value: IntFilter,
    },
    /// The column is NULL.
    IsNull,
    /// The column is not NULL.
    IsPresent,
    /// Every filter matches. The list must not be empty.
    All {
        /// Conditions.
        filters: Vec<StringFilter>,
    },
    /// At least one filter matches. The list must not be empty.
    Any {
        /// Conditions.
        filters: Vec<StringFilter>,
    },
    /// The filter does not match.
    Not {
        /// Condition.
        filter: Box<StringFilter>,
    },
}

impl StringFilter {
    /// Case-insensitive substring match.
    pub fn contains(value: impl Into<String>) -> Self {
        Self::Contains {
            value: value.into(),
        }
    }

    /// Equality.
    pub fn exact(value: impl Into<String>) -> Self {
        Self::Exact {
            value: value.into(),
        }
    }

    /// RE2 regex match.
    pub fn regex(value: impl Into<String>) -> Self {
        Self::RegexMatch {
            value: value.into(),
        }
    }
}

/// Filter on an integer column.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum IntFilter {
    /// Equal.
    Exact {
        /// Value to equal.
        value: i64,
    },
    /// Less than.
    Lt {
        /// Bound.
        value: i64,
    },
    /// Less than or equal.
    Lte {
        /// Bound.
        value: i64,
    },
    /// Greater than.
    Gt {
        /// Bound.
        value: i64,
    },
    /// Greater than or equal.
    Gte {
        /// Bound.
        value: i64,
    },
    /// Every filter matches. The list must not be empty.
    All {
        /// Conditions.
        filters: Vec<IntFilter>,
    },
    /// At least one filter matches. The list must not be empty.
    Any {
        /// Conditions.
        filters: Vec<IntFilter>,
    },
    /// The filter does not match.
    Not {
        /// Condition.
        filter: Box<IntFilter>,
    },
}

impl IntFilter {
    /// Equal to `value`.
    pub fn exact(value: i64) -> Self {
        Self::Exact { value }
    }

    /// Less than `value`.
    pub fn lt(value: i64) -> Self {
        Self::Lt { value }
    }

    /// Less than or equal to `value`.
    pub fn lte(value: i64) -> Self {
        Self::Lte { value }
    }

    /// Greater than `value`.
    pub fn gt(value: i64) -> Self {
        Self::Gt { value }
    }

    /// Greater than or equal to `value`.
    pub fn gte(value: i64) -> Self {
        Self::Gte { value }
    }
}

/// Exact match on one header; the key is compared lowercase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HeaderExact {
    /// Header name.
    pub key: String,
    /// Header value.
    pub value: String,
}

/// Sort direction by capture time.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SortOrder {
    /// Oldest first.
    #[default]
    Asc,
    /// Newest first.
    Desc,
}

// --- HTTP queries ---------------------------------------------------------------------------

/// One OR-branch of a search. Unset fields match everything; an empty branch matches every
/// capture of the org.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct QueryBranch {
    /// Match any of these source ids.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_id: Option<Vec<String>>,
    /// Source label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Request host.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<StringFilter>,
    /// Request method.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<StringFilter>,
    /// Request path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<StringFilter>,
    /// Request body.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_body: Option<StringFilter>,
    /// Response body.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_body: Option<StringFilter>,
    /// Correlation id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<StringFilter>,
    /// Parent correlation id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_correlation_id: Option<StringFilter>,
    /// Account id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_id: Option<StringFilter>,
    /// Tool call id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<StringFilter>,
    /// Response status code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<IntFilter>,
    /// Response size in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_size: Option<IntFilter>,
    /// Duration in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<IntFilter>,
    /// Media type of the response `Content-Type`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<StringFilter>,
    /// The request carries a `Cookie` header.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_sends_cookies: Option<bool>,
    /// The response sets a cookie.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_sets_cookies: Option<bool>,
    /// A request header equals a value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_header: Option<HeaderExact>,
    /// A response header equals a value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_header: Option<HeaderExact>,
}

impl QueryBranch {
    /// A branch for the captures of one source id.
    pub fn for_source(source_id: impl Into<String>) -> Self {
        Self {
            source_id: Some(vec![source_id.into()]),
            ..Self::default()
        }
    }

    /// Filter on the host.
    #[must_use]
    pub fn host(mut self, filter: StringFilter) -> Self {
        self.host = Some(filter);
        self
    }

    /// Filter on the method.
    #[must_use]
    pub fn method(mut self, filter: StringFilter) -> Self {
        self.method = Some(filter);
        self
    }

    /// Filter on the path.
    #[must_use]
    pub fn path(mut self, filter: StringFilter) -> Self {
        self.path = Some(filter);
        self
    }

    /// Filter on the response status.
    #[must_use]
    pub fn status_code(mut self, filter: IntFilter) -> Self {
        self.status_code = Some(filter);
        self
    }
}

/// Body of `POST /rpc/requests/search` and `/count`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TrafficQuery {
    /// Org; defaults to the key's org.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
    /// OR-ed branches. Must not be empty.
    pub branches: Vec<QueryBranch>,
    /// Resume after this cursor (a previous `next_cursor` or [`crate::sessions::Sequence`]).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// Stop at this cursor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_cursor: Option<String>,
    /// Page size; the server defaults to 100 and caps at 5000. Ignored by count.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    /// Sort direction.
    pub order: SortOrder,
    /// Return request bodies up to this many bytes; larger ones come back as
    /// [`BodyFetch::TooLarge`]. Unset returns no request body.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_body_max_fetch_size: Option<u32>,
    /// Same for response bodies.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_body_max_fetch_size: Option<u32>,
}

impl TrafficQuery {
    /// A query over `branches`, oldest first.
    pub fn new(branches: Vec<QueryBranch>) -> Self {
        Self {
            org_id: None,
            branches,
            cursor: None,
            end_cursor: None,
            limit: None,
            order: SortOrder::Asc,
            request_body_max_fetch_size: None,
            response_body_max_fetch_size: None,
        }
    }

    /// Page size.
    #[must_use]
    pub fn limit(mut self, limit: u32) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Sort direction.
    #[must_use]
    pub fn order(mut self, order: SortOrder) -> Self {
        self.order = order;
        self
    }

    /// Return bodies up to these sizes.
    #[must_use]
    pub fn fetch_bodies(mut self, request_max: u32, response_max: u32) -> Self {
        self.request_body_max_fetch_size = Some(request_max);
        self.response_body_max_fetch_size = Some(response_max);
        self
    }

    fn validate(&self) -> Result<()> {
        if self.branches.is_empty() {
            return Err(Error::InvalidInput(
                "a query needs at least one branch".into(),
            ));
        }
        Ok(())
    }
}

// --- WebSocket queries ----------------------------------------------------------------------

/// One OR-branch of a WebSocket message search.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct WsQueryBranch {
    /// Source id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
    /// Source label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Proxy session id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// The capture id of the `101` upgrade that opened the conversation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_event_id: Option<String>,
    /// Host.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<StringFilter>,
    /// Message payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<StringFilter>,
    /// `c2s` or `s2c`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<StringFilter>,
    /// `text`, `binary`, `close`, `ping` or `pong`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opcode: Option<StringFilter>,
    /// Close reason.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub close_reason: Option<StringFilter>,
    /// Close code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub close_code: Option<IntFilter>,
    /// Payload size in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_size: Option<IntFilter>,
    /// The message was permessage-deflate compressed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub was_compressed: Option<bool>,
    /// The payload is valid UTF-8 text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_is_text: Option<bool>,
    /// The stored payload was cut at the capture limit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_truncated: Option<bool>,
}

impl WsQueryBranch {
    /// A branch for the messages of one source id.
    pub fn for_source(source_id: impl Into<String>) -> Self {
        Self {
            source_id: Some(source_id.into()),
            ..Self::default()
        }
    }
}

/// Body of `POST /rpc/ws/search` and `/count`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WsTrafficQuery {
    /// Org; defaults to the key's org.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
    /// OR-ed branches. Must not be empty.
    pub branches: Vec<WsQueryBranch>,
    /// Resume after this cursor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// Page size.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    /// Sort direction.
    pub order: SortOrder,
    /// Return payloads up to this many bytes; larger ones come back as
    /// [`BodyFetch::TooLarge`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_max_fetch_size: Option<u32>,
}

impl WsTrafficQuery {
    /// A query over `branches`, oldest first.
    pub fn new(branches: Vec<WsQueryBranch>) -> Self {
        Self {
            org_id: None,
            branches,
            cursor: None,
            limit: None,
            order: SortOrder::Asc,
            payload_max_fetch_size: None,
        }
    }

    fn validate(&self) -> Result<()> {
        if self.branches.is_empty() {
            return Err(Error::InvalidInput(
                "a query needs at least one branch".into(),
            ));
        }
        Ok(())
    }
}

// --- results --------------------------------------------------------------------------------

/// A body in a search result.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum BodyFetch {
    /// The body, within the requested cap.
    Body {
        /// Body text.
        value: String,
    },
    /// The body is larger than the cap; fetch the full capture by id.
    TooLarge {
        /// Actual size in bytes.
        size: u32,
    },
}

/// Header pairs in order. The search path sends `[["name","value"], ...]`, the by-id path a
/// JSON object; both are accepted, and so is `[{"name":..,"value":..}]`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Headers(pub Vec<(String, String)>);

impl Headers {
    /// First value of `name`, compared case-insensitively.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

impl<'de> Deserialize<'de> for Headers {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Entry {
            Pair((String, String)),
            Named { name: String, value: String },
        }

        struct HeadersVisitor;

        impl<'de> Visitor<'de> for HeadersVisitor {
            type Value = Headers;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a header map or a list of header pairs")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Headers, A::Error> {
                let mut out = Vec::with_capacity(map.size_hint().unwrap_or(0));
                while let Some(pair) = map.next_entry::<String, String>()? {
                    out.push(pair);
                }
                Ok(Headers(out))
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Headers, A::Error> {
                let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0));
                while let Some(entry) = seq.next_element::<Entry>()? {
                    out.push(match entry {
                        Entry::Pair(pair) => pair,
                        Entry::Named { name, value } => (name, value),
                    });
                }
                Ok(Headers(out))
            }

            fn visit_unit<E: de::Error>(self) -> Result<Headers, E> {
                Ok(Headers::default())
            }
        }

        deserializer.deserialize_any(HeadersVisitor)
    }
}

/// One capture in a search result.
#[derive(Debug, Clone, Deserialize)]
pub struct HttpCaptureSummary {
    /// Capture id.
    pub id: Uuid,
    /// Org.
    pub org_id: String,
    /// When the exchange happened.
    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,
    /// Method.
    pub method: String,
    /// Path and query.
    pub path: String,
    /// Host.
    pub host: String,
    /// `http` or `https`.
    pub scheme: String,
    /// Proxy session id.
    pub session_id: String,
    /// Proxy instance that captured it.
    pub proxy_id: String,
    /// Request body size in bytes.
    pub request_size: u32,
    /// Response status.
    pub status_code: u16,
    /// Response body size in bytes.
    pub response_size: u32,
    /// Duration in milliseconds.
    pub duration_ms: u32,
    /// Time spent waiting for the rate limiter, in milliseconds.
    pub ratelimit_wait_ms: u32,
    /// Source label.
    pub source: String,
    /// Source id.
    pub source_id: String,
    /// Correlation id.
    #[serde(default)]
    pub correlation_id: Option<String>,
    /// Parent correlation id.
    #[serde(default)]
    pub parent_correlation_id: Option<String>,
    /// Account id.
    #[serde(default)]
    pub account_id: Option<String>,
    /// Tool call id.
    #[serde(default)]
    pub tool_call_id: Option<String>,
    /// Request headers. May be empty for searches served from the timeline index.
    #[serde(default)]
    pub request_headers: Headers,
    /// Response headers.
    #[serde(default)]
    pub response_headers: Headers,
    /// Request body, when asked for.
    #[serde(default)]
    pub request_body: Option<BodyFetch>,
    /// Response body, when asked for.
    #[serde(default)]
    pub response_body: Option<BodyFetch>,
}

/// A page of captures.
#[derive(Debug, Clone, Deserialize)]
pub struct SearchResponse {
    /// Captures in order.
    pub items: Vec<HttpCaptureSummary>,
    /// Cursor of the next page; `None` after the last.
    #[serde(default)]
    pub next_cursor: Option<String>,
    /// Matches ignoring paging, when the server computed it.
    #[serde(default)]
    pub total_count: Option<u64>,
}

/// A full capture with both bodies, from `GET /rpc/orgs/{org}/requests/{id}`.
#[derive(Debug, Clone, Deserialize)]
pub struct HttpCapture {
    /// Capture id.
    pub id: Uuid,
    /// Org.
    pub org_id: String,
    /// When the exchange happened.
    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,
    /// Method.
    pub method: String,
    /// Path and query.
    pub path: String,
    /// Host.
    pub host: String,
    /// `http` or `https`.
    pub scheme: String,
    /// Proxy session id.
    pub session_id: String,
    /// Proxy instance that captured it.
    pub proxy_id: String,
    /// Request headers.
    pub request_headers: Headers,
    /// Request body.
    pub request_body: String,
    /// Request body size in bytes.
    pub request_size: u32,
    /// Response status.
    pub status_code: u16,
    /// Response headers.
    pub response_headers: Headers,
    /// Response body.
    pub response_body: String,
    /// Response body size in bytes.
    pub response_size: u32,
    /// Duration in milliseconds.
    pub duration_ms: u32,
    /// Time spent waiting for the rate limiter, in milliseconds.
    pub ratelimit_wait_ms: u32,
    /// Source label.
    pub source: String,
    /// Source id.
    pub source_id: String,
    /// Correlation id.
    #[serde(default)]
    pub correlation_id: Option<String>,
    /// Parent correlation id.
    #[serde(default)]
    pub parent_correlation_id: Option<String>,
    /// Account id.
    #[serde(default)]
    pub account_id: Option<String>,
    /// Tool call id.
    #[serde(default)]
    pub tool_call_id: Option<String>,
}

/// One WebSocket message in a search result.
#[derive(Debug, Clone, Deserialize)]
pub struct WsCaptureSummary {
    /// Message id.
    pub id: Uuid,
    /// Capture id of the upgrade that opened the conversation.
    pub parent_event_id: Uuid,
    /// Org.
    pub org_id: String,
    /// When the message passed.
    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,
    /// `c2s` or `s2c`.
    pub direction: String,
    /// `text`, `binary`, `close`, `ping` or `pong`.
    pub opcode: String,
    /// Proxy session id.
    pub session_id: String,
    /// Proxy instance that captured it.
    pub proxy_id: String,
    /// Source label.
    pub source: String,
    /// Source id.
    pub source_id: String,
    /// Host.
    pub host: String,
    /// Payload size in bytes.
    pub payload_size: u32,
    /// The stored payload was cut at the capture limit.
    pub payload_truncated: bool,
    /// The payload is valid UTF-8 text.
    pub payload_is_text: bool,
    /// The message was compressed on the wire.
    pub was_compressed: bool,
    /// Close code, for a close frame.
    pub close_code: u16,
    /// Close reason, for a close frame.
    pub close_reason: String,
    /// Payload, when asked for.
    #[serde(default)]
    pub payload: Option<BodyFetch>,
}

/// A page of WebSocket messages.
#[derive(Debug, Clone, Deserialize)]
pub struct WsSearchResponse {
    /// Messages in order.
    pub items: Vec<WsCaptureSummary>,
    /// Cursor of the next page; `None` after the last.
    #[serde(default)]
    pub next_cursor: Option<String>,
    /// Matches ignoring paging, when the server computed it.
    #[serde(default)]
    pub total_count: Option<u64>,
}

#[derive(Deserialize)]
struct CountResponse {
    count: u64,
}

// --- client methods -------------------------------------------------------------------------

impl SessionsClient {
    /// `POST /rpc/requests/search`: one page of captures.
    pub async fn search_requests(&self, query: &TrafficQuery) -> Result<SearchResponse> {
        query.validate()?;
        http::json(
            self.send(self.post(self.url(&["requests", "search"])).json(query))
                .await?,
        )
        .await
    }

    /// `POST /rpc/requests/count`: how many captures match, honouring `cursor`, ignoring `limit`.
    pub async fn count_requests(&self, query: &TrafficQuery) -> Result<u64> {
        query.validate()?;
        let body: CountResponse = http::json(
            self.send(self.post(self.url(&["requests", "count"])).json(query))
                .await?,
        )
        .await?;
        Ok(body.count)
    }

    /// `GET /rpc/orgs/{org}/requests/{id}`: one capture with headers and both bodies.
    pub async fn get_capture(&self, org_id: &str, id: Uuid) -> Result<HttpCapture> {
        let id = id.to_string();
        http::json(
            self.send(self.get(self.url(&["orgs", org_id, "requests", &id])))
                .await?,
        )
        .await
    }

    /// `POST /rpc/ws/search`: one page of WebSocket messages.
    pub async fn search_ws(&self, query: &WsTrafficQuery) -> Result<WsSearchResponse> {
        query.validate()?;
        http::json(
            self.send(self.post(self.url(&["ws", "search"])).json(query))
                .await?,
        )
        .await
    }

    /// `POST /rpc/ws/count`: how many WebSocket messages match.
    pub async fn count_ws(&self, query: &WsTrafficQuery) -> Result<u64> {
        query.validate()?;
        let body: CountResponse = http::json(
            self.send(self.post(self.url(&["ws", "count"])).json(query))
                .await?,
        )
        .await?;
        Ok(body.count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn filters_serialize_with_the_server_tags() {
        let branch = QueryBranch::for_source("c1")
            .host(StringFilter::contains("example.com"))
            .status_code(IntFilter::All {
                filters: vec![
                    IntFilter::gte(400),
                    IntFilter::Not {
                        filter: Box::new(IntFilter::exact(404)),
                    },
                ],
            });
        let value = serde_json::to_value(&branch).expect("json");
        assert_eq!(
            value,
            json!({
                "source_id": ["c1"],
                "host": {"op": "contains", "value": "example.com"},
                "status_code": {"op": "all", "filters": [
                    {"op": "gte", "value": 400},
                    {"op": "not", "filter": {"op": "exact", "value": 404}},
                ]},
            })
        );
        let unit = serde_json::to_value(StringFilter::IsNull).expect("json");
        assert_eq!(unit, json!({"op": "is_null"}));
        let nested = serde_json::to_value(StringFilter::Length {
            value: IntFilter::lt(10),
        })
        .expect("json");
        assert_eq!(
            nested,
            json!({"op": "length", "value": {"op": "lt", "value": 10}})
        );
    }

    #[test]
    fn query_omits_unset_fields() {
        let query = TrafficQuery::new(vec![QueryBranch::default()]).limit(10);
        let value = serde_json::to_value(&query).expect("json");
        assert_eq!(
            value,
            json!({"branches": [{}], "limit": 10, "order": "asc"})
        );
    }

    #[test]
    fn empty_branch_list_is_refused_locally() {
        assert!(TrafficQuery::new(Vec::new()).validate().is_err());
        assert!(WsTrafficQuery::new(Vec::new()).validate().is_err());
    }

    #[test]
    fn headers_accept_every_server_shape() {
        let pairs: Headers =
            serde_json::from_value(json!([["a", "1"], ["a", "2"]])).expect("pairs");
        assert_eq!(
            pairs.0,
            [("a".into(), "1".into()), ("a".into(), "2".into())]
        );
        let map: Headers =
            serde_json::from_value(json!({"Content-Type": "text/html"})).expect("map");
        assert_eq!(map.get("content-type"), Some("text/html"));
        let named: Headers =
            serde_json::from_value(json!([{"name": "x", "value": "y"}])).expect("named");
        assert_eq!(named.get("X"), Some("y"));
        let null: Headers = serde_json::from_value(json!(null)).expect("null");
        assert!(null.0.is_empty());
    }

    #[test]
    fn search_response_decodes_bodies_and_cursor() {
        let value = json!({
            "items": [{
                "id": "11111111-1111-1111-1111-111111111111", "org_id": "acme",
                "timestamp": "2026-11-10T10:00:00Z", "session_offset": 7,
                "method": "GET", "path": "/", "host": "example.com", "scheme": "https",
                "session_id": "s", "proxy_id": "p", "request_size": 0, "status_code": 200,
                "response_size": 5, "duration_ms": 12, "ratelimit_wait_ms": 0,
                "source": "crawl", "source_id": "c1", "correlation_id": null,
                "request_headers": [["a", "b"]], "response_headers": [],
                "request_body": null,
                "response_body": {"status": "too_large", "size": 99999}
            }],
            "next_cursor": "abc", "total_count": null
        });
        let page: SearchResponse = serde_json::from_value(value).expect("page");
        assert_eq!(page.next_cursor.as_deref(), Some("abc"));
        let item = &page.items[0];
        assert_eq!(item.status_code, 200);
        assert_eq!(
            item.response_body,
            Some(BodyFetch::TooLarge { size: 99_999 })
        );
        assert_eq!(item.request_body, None);
        assert_eq!(item.request_headers.get("a"), Some("b"));
        let body: BodyFetch =
            serde_json::from_value(json!({"status": "body", "value": "hi"})).expect("body");
        assert_eq!(body, BodyFetch::Body { value: "hi".into() });
    }
}
