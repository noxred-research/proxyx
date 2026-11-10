//! WebSocket traffic query envelope.
//!
//! Sibling of the HTTP `TrafficQuery` in `super`. Same OR-of-AND
//! envelope, same cursor + pagination, same filter primitives
//! (`StringFilter`, `IntFilter`). Different filterable column set
//! tied to the `ws_messages` schema.
//!
//! `search` and `count` lower each branch's filters through
//! [`super::string_filter`] and [`super::int_filter`], join the branch
//! fragments with `OR`, AND the result against `org_id` and the cursor
//! clause, and run the query.

use anyhow::{Context, Result};
use serde::Deserialize;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::models::{WsCaptureSummary, WsSearchResponse};
use crate::ws_traffic;

use super::{
    DEFAULT_LIMIT, MAX_LIMIT, QUERY_MAX_EXECUTION_TIME_SECS, QUERY_MAX_MEMORY_USAGE_BYTES,
    RegexValidationError, SortOrder, cursor, int_filter, push_bool, push_string_filter,
    string_filter, ws_routing,
};
use super::{IntFilter, NonEmpty, StringFilter};

/// Top-level WS search request. Holds the shared org/cursor/order
/// plus a non-empty list of branches that get OR'd together.
#[derive(Debug, Clone, Deserialize)]
pub struct WsTrafficQuery {
    pub org_id: Option<String>,
    pub branches: NonEmpty<WsQueryBranch>,
    pub cursor: Option<String>,
    pub limit: Option<u32>,
    #[serde(default)]
    pub order: SortOrder,
    /// When `Some(N)`, the search response carries each row's
    /// `payload` provided its size is `<= N`; otherwise carries
    /// `BodyFetch::TooLarge { size }`. `None` skips payload fetching
    /// entirely — the column is not read from CH.
    pub payload_max_fetch_size: Option<u32>,
}

/// One OR-branch. All fields are optional; an empty branch matches
/// every row in the org (effectively `TRUE`).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct WsQueryBranch {
    pub source_id: Option<String>,
    pub source: Option<String>,
    pub session_id: Option<String>,
    /// Pin to a single conversation. UUID string (validated at the API
    /// entrypoint when used as a path parameter, otherwise bound as-is).
    pub parent_event_id: Option<String>,

    pub host: Option<StringFilter>,
    pub payload: Option<StringFilter>,
    pub direction: Option<StringFilter>,
    pub opcode: Option<StringFilter>,
    pub close_reason: Option<StringFilter>,

    pub close_code: Option<IntFilter>,
    pub payload_size: Option<IntFilter>,

    /// CH `UInt8` boolean — render as `column = 1` / `column = 0`.
    pub was_compressed: Option<bool>,
    pub payload_is_text: Option<bool>,
    pub payload_truncated: Option<bool>,
}

impl WsQueryBranch {
    /// Lower the branch's filters into a parenthesized AND of SQL
    /// fragments, pushing positional binds onto `binds`. Empty
    /// branches lower to the literal `1` so the surrounding OR
    /// composition still makes sense.
    fn lower(&self, binds: &mut Vec<String>) -> String {
        let mut conditions: Vec<String> = Vec::new();

        if let Some(ref source_id) = self.source_id {
            conditions.push("source_id = ?".to_string());
            binds.push(source_id.clone());
        }
        if let Some(ref source) = self.source {
            conditions.push("source = ?".to_string());
            binds.push(source.clone());
        }
        if let Some(ref session_id) = self.session_id {
            conditions.push("session_id = ?".to_string());
            binds.push(session_id.clone());
        }
        if let Some(ref parent_event_id) = self.parent_event_id {
            conditions.push("parent_event_id = ?".to_string());
            binds.push(parent_event_id.clone());
        }

        push_string_filter(&mut conditions, binds, &string_filter::WS_HOST, &self.host);
        push_string_filter(
            &mut conditions,
            binds,
            &string_filter::WS_PAYLOAD,
            &self.payload,
        );
        push_string_filter(
            &mut conditions,
            binds,
            &string_filter::WS_DIRECTION,
            &self.direction,
        );
        push_string_filter(
            &mut conditions,
            binds,
            &string_filter::WS_OPCODE,
            &self.opcode,
        );
        push_string_filter(
            &mut conditions,
            binds,
            &string_filter::WS_CLOSE_REASON,
            &self.close_reason,
        );

        if let Some(ref f) = self.close_code {
            conditions.push(int_filter::lower_int("close_code", f, binds));
        }
        if let Some(ref f) = self.payload_size {
            conditions.push(int_filter::lower_int("payload_size", f, binds));
        }

        push_bool(&mut conditions, "was_compressed", self.was_compressed);
        push_bool(&mut conditions, "payload_is_text", self.payload_is_text);
        push_bool(&mut conditions, "payload_truncated", self.payload_truncated);

        match conditions.len() {
            0 => "1".to_string(),
            1 => conditions.into_iter().next().unwrap(),
            _ => format!("({})", conditions.join(" AND ")),
        }
    }
}

impl WsTrafficQuery {
    /// True when the caller asked for payload fetching. Drives table
    /// projection in `search`. `count` ignores payloads.
    fn want_payload(&self) -> bool {
        self.payload_max_fetch_size.is_some()
    }
}

/// Build the WHERE clause + positional bind list. Shape is always:
/// `org_id = ? AND (b1 OR b2 OR ...) [AND (timestamp, session_offset, id) <cmp> (?, ?, ?)]`.
fn build_where(
    query: &WsTrafficQuery,
    cursor_boundary: Option<(OffsetDateTime, u64, Uuid)>,
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
    if or_clause != "1" {
        top.push(or_clause);
    }

    if let Some((ts, session_offset, id)) = cursor_boundary {
        if query.order.is_desc() {
            top.push("(timestamp, session_offset, id) < (?, ?, ?)".to_string());
        } else {
            top.push("(timestamp, session_offset, id) > (?, ?, ?)".to_string());
        }
        binds.push(cursor::ts_literal(ts));
        binds.push(session_offset.to_string());
        binds.push(id.to_string());
    }

    let where_clause = if top.is_empty() {
        "1".to_string()
    } else {
        top.join(" AND ")
    };
    (where_clause, binds)
}

/// Pre-validate every `RegexMatch.value` across every WS branch.
pub fn validate_regex_patterns(query: &WsTrafficQuery) -> Result<(), RegexValidationError> {
    for (idx, branch) in query.branches.0.iter().enumerate() {
        let fields: [(&str, &Option<StringFilter>); 5] = [
            ("host", &branch.host),
            ("payload", &branch.payload),
            ("direction", &branch.direction),
            ("opcode", &branch.opcode),
            ("close_reason", &branch.close_reason),
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

pub(crate) fn cursor_boundary(
    query: &WsTrafficQuery,
) -> Result<Option<(OffsetDateTime, u64, Uuid)>> {
    match query.cursor {
        Some(ref c) => Ok(Some(cursor::decode_cursor(c)?)),
        None => Ok(None),
    }
}

pub(crate) fn limit_clamped(query: &WsTrafficQuery) -> u32 {
    query.limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT)
}

/// Run the WS search and return paginated summaries.
#[tracing::instrument(name = "clickhouse.search_ws_messages", skip_all, fields(db.system = "clickhouse", org_id = ?query.org_id))]
pub async fn search(
    client: &clickhouse::Client,
    query: &WsTrafficQuery,
) -> Result<WsSearchResponse> {
    let boundary = cursor_boundary(query)?;
    let (where_clause, binds) = build_where(query, boundary);
    let limit = limit_clamped(query);
    let want_payload = query.want_payload();
    let table = ws_routing::select_table(query);
    let order = query.order.sql();
    let fetch_limit = limit + 1;
    let payload_max = query.payload_max_fetch_size;

    // Stage 1: page metadata + sort-key tuples only — never the heavy
    // `payload` column, which through `ORDER BY ... LIMIT 1 BY id` would
    // buffer every matched row before the LIMIT collapses it (the HTTP
    // analog OOM'd at ~8 GiB). Mirrors `crate::query::search`.
    let sql = format!(
        "SELECT {summary} FROM {table} WHERE {where_clause} \
         ORDER BY timestamp {order}, session_offset {order}, id {order} \
         LIMIT 1 BY id LIMIT {fetch_limit}",
        summary = ws_traffic::projection::SUMMARY,
    );

    let mut q = client
        .query(&sql)
        .with_option("max_execution_time", QUERY_MAX_EXECUTION_TIME_SECS)
        .with_option("max_memory_usage", QUERY_MAX_MEMORY_USAGE_BYTES);
    for b in &binds {
        q = q.bind(b);
    }
    let mut rows = q
        .fetch_all::<ws_traffic::ClickHouseWsSummary>()
        .await
        .context("ws search query failed")?;

    let last_ts_id = if rows.len() as u32 > limit {
        rows.truncate(limit as usize);
        rows.last().map(|r| (r.timestamp, r.session_offset, r.id))
    } else {
        None
    };

    let mut items: Vec<WsCaptureSummary> = rows.into_iter().map(WsCaptureSummary::from).collect();

    // Stage 2: fetch payloads for exactly the page's rows via a full
    // sort-key tuple seek (~15 ms) instead of a partition-scanning JOIN.
    if want_payload && !items.is_empty() {
        let keys: Vec<ws_traffic::WsBodyKey> = items
            .iter()
            .map(|i| ws_traffic::WsBodyKey {
                id: i.id,
                org_id: i.org_id.clone(),
                source_id: i.source_id.clone(),
                timestamp: i.timestamp,
                session_offset: i.session_offset,
            })
            .collect();
        let mut payloads = ws_traffic::fetch_page_payloads(client, &keys, payload_max).await?;
        for item in &mut items {
            if let Some(p) = payloads.remove(&item.id) {
                item.payload = p;
            }
        }
    }

    let next_cursor =
        last_ts_id.map(|(ts, session_offset, id)| cursor::encode_cursor(ts, session_offset, id));
    Ok(WsSearchResponse {
        items,
        next_cursor,
        total_count: None,
    })
}

/// Count rows matching the WS query under the same cursor / order
/// semantics as [`search`]. Ignores `limit` and never reads payloads.
#[tracing::instrument(name = "clickhouse.count_ws_messages", skip_all, fields(db.system = "clickhouse", org_id = ?query.org_id))]
pub async fn count(client: &clickhouse::Client, query: &WsTrafficQuery) -> Result<u64> {
    let boundary = cursor_boundary(query)?;
    let (where_clause, binds) = build_where(query, boundary);
    // count never reads payload; pick the table the same way search would
    // when payload-fetching is off.
    let table = ws_routing::select_table(query);

    // uniqCombined (not uniqExact): bounded ~12 MiB regardless of
    // cardinality vs an unbounded exact hash set. The count is a
    // progress/size metric, not an exact-equality gate. See query::count.
    let sql = format!("SELECT uniqCombined(id) FROM {table} WHERE {where_clause}");

    let mut q = client
        .query(&sql)
        .with_option("max_execution_time", QUERY_MAX_EXECUTION_TIME_SECS);
    for b in &binds {
        q = q.bind(b);
    }

    let count: u64 = q.fetch_one().await.context("ws count query failed")?;
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lower(query: &WsTrafficQuery) -> (String, Vec<String>) {
        build_where(query, None)
    }

    fn empty() -> WsTrafficQuery {
        WsTrafficQuery {
            org_id: Some("org-1".into()),
            branches: NonEmpty(vec![WsQueryBranch::default()]),
            cursor: None,
            limit: None,
            order: SortOrder::Asc,
            payload_max_fetch_size: None,
        }
    }

    #[test]
    fn empty_branch_collapses_to_org_only() {
        let q = empty();
        let (sql, binds) = lower(&q);
        assert_eq!(sql, "org_id = ?");
        assert_eq!(binds, vec!["org-1"]);
    }

    #[test]
    fn parent_event_id_branch_uses_by_parent_view() {
        let q = WsTrafficQuery {
            org_id: Some("org-1".into()),
            branches: NonEmpty(vec![WsQueryBranch {
                parent_event_id: Some("11111111-1111-1111-1111-111111111111".into()),
                ..Default::default()
            }]),
            cursor: None,
            limit: None,
            order: SortOrder::Asc,
            payload_max_fetch_size: None,
        };
        assert_eq!(ws_routing::select_table(&q), "ws_messages_by_parent");
        let (sql, binds) = lower(&q);
        assert_eq!(sql, "org_id = ? AND parent_event_id = ?");
        assert_eq!(binds, vec!["org-1", "11111111-1111-1111-1111-111111111111"]);
    }

    #[test]
    fn parent_plus_payload_filter_uses_base_table() {
        let q = WsTrafficQuery {
            org_id: Some("org-1".into()),
            branches: NonEmpty(vec![WsQueryBranch {
                parent_event_id: Some("11111111-1111-1111-1111-111111111111".into()),
                payload: Some(StringFilter::Contains {
                    value: "ping".into(),
                }),
                ..Default::default()
            }]),
            cursor: None,
            limit: None,
            order: SortOrder::Asc,
            payload_max_fetch_size: None,
        };
        assert_eq!(ws_routing::select_table(&q), "ws_messages");
    }

    #[test]
    fn direction_filter_uses_to_string_cast() {
        let q = WsTrafficQuery {
            org_id: Some("org-1".into()),
            branches: NonEmpty(vec![WsQueryBranch {
                direction: Some(StringFilter::Exact {
                    value: "c2s".into(),
                }),
                ..Default::default()
            }]),
            cursor: None,
            limit: None,
            order: SortOrder::Asc,
            payload_max_fetch_size: None,
        };
        let (sql, binds) = lower(&q);
        assert_eq!(sql, "org_id = ? AND toString(direction) = ?");
        assert_eq!(binds, vec!["org-1", "c2s"]);
    }

    #[test]
    fn bool_filter_renders_as_zero_one() {
        let q = WsTrafficQuery {
            org_id: Some("org-1".into()),
            branches: NonEmpty(vec![WsQueryBranch {
                was_compressed: Some(true),
                payload_is_text: Some(false),
                ..Default::default()
            }]),
            cursor: None,
            limit: None,
            order: SortOrder::Asc,
            payload_max_fetch_size: None,
        };
        let (sql, binds) = lower(&q);
        assert_eq!(
            sql,
            "org_id = ? AND (was_compressed = 1 AND payload_is_text = 0)"
        );
        assert_eq!(binds, vec!["org-1"]);
    }

    #[test]
    fn payload_size_int_filter() {
        let q = WsTrafficQuery {
            org_id: Some("org-1".into()),
            branches: NonEmpty(vec![WsQueryBranch {
                payload_size: Some(IntFilter::Gte { value: 1024 }),
                ..Default::default()
            }]),
            cursor: None,
            limit: None,
            order: SortOrder::Asc,
            payload_max_fetch_size: None,
        };
        let (sql, _) = lower(&q);
        assert_eq!(sql, "org_id = ? AND payload_size >= 1024");
    }

    #[test]
    fn multi_branch_or_composes() {
        let q = WsTrafficQuery {
            org_id: Some("org-1".into()),
            branches: NonEmpty(vec![
                WsQueryBranch {
                    direction: Some(StringFilter::Exact {
                        value: "c2s".into(),
                    }),
                    payload_size: Some(IntFilter::Gte { value: 100 }),
                    ..Default::default()
                },
                WsQueryBranch {
                    opcode: Some(StringFilter::Exact {
                        value: "close".into(),
                    }),
                    ..Default::default()
                },
            ]),
            cursor: None,
            limit: None,
            order: SortOrder::Asc,
            payload_max_fetch_size: None,
        };
        let (sql, binds) = lower(&q);
        assert_eq!(
            sql,
            "org_id = ? AND ((toString(direction) = ? AND payload_size >= 100) \
             OR toString(opcode) = ?)"
        );
        assert_eq!(binds, vec!["org-1", "c2s", "close"]);
    }

    #[test]
    fn json_round_trip() {
        let json = r#"{
            "org_id": "org-1",
            "branches": [
                {"host": {"op":"contains","value":"example"}},
                {"opcode": {"op":"exact","value":"text"}, "was_compressed": true}
            ],
            "limit": 50,
            "order": "desc"
        }"#;
        let q: WsTrafficQuery = serde_json::from_str(json).unwrap();
        let (sql, _) = lower(&q);
        assert_eq!(
            sql,
            "org_id = ? AND (lower(host) LIKE lower(?) \
             OR (toString(opcode) = ? AND was_compressed = 1))"
        );
        assert!(q.order.is_desc());
    }

    #[test]
    fn empty_branches_list_rejected_at_deserialize() {
        let bad = r#"{"org_id":"x","branches":[]}"#;
        let err = serde_json::from_str::<WsTrafficQuery>(bad).unwrap_err();
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn validate_regex_patterns_catches_bad_pattern() {
        let q = WsTrafficQuery {
            org_id: Some("org-1".into()),
            branches: NonEmpty(vec![WsQueryBranch {
                payload: Some(StringFilter::RegexMatch {
                    value: "[invalid".into(),
                }),
                ..Default::default()
            }]),
            cursor: None,
            limit: None,
            order: SortOrder::Asc,
            payload_max_fetch_size: None,
        };
        let err = validate_regex_patterns(&q).unwrap_err();
        assert_eq!(err.field, "payload");
    }

    #[test]
    fn parent_only_routing_requires_no_other_filters() {
        // Parent + session_id is NOT eligible for the by_parent MV: the
        // sort key on ws_messages_by_parent is (parent_event_id, ...) so
        // session_id forces a full granule scan. Routing should fall
        // back to the base table where session_id has its own index.
        let q = WsTrafficQuery {
            org_id: Some("org-1".into()),
            branches: NonEmpty(vec![WsQueryBranch {
                parent_event_id: Some("11111111-1111-1111-1111-111111111111".into()),
                session_id: Some("11111111-1111-1111-1111-111111111111".into()),
                ..Default::default()
            }]),
            cursor: None,
            limit: None,
            order: SortOrder::Asc,
            payload_max_fetch_size: None,
        };
        assert_eq!(ws_routing::select_table(&q), "ws_messages");
    }
}
