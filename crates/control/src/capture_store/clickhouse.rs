//! ClickHouse capture store: adapts the SQL query layer ([`crate::query`],
//! [`crate::traffic`], [`crate::ws_traffic`]) to [`CaptureStore`] and owns the
//! aggregate queries and the Parquet export that are ClickHouse SQL.

use anyhow::Result;
use async_trait::async_trait;
use proxyx_control_graphql::{
    RequestRatePointDto, ScanTrafficSummaryDto, SourceTrafficTotalDto, TrafficBucketDto,
    TrafficTimeSeriesPointDto, WsConversationDto, WsConversationSearchResponse,
};
use serde::Deserialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use super::{CaptureBackend, CaptureStore, ConversationQuery, Sequence, TimeSeriesQuery};
use crate::config::ControlConfig;
use crate::models::{HttpCapture, SearchResponse, WsCapture, WsSearchResponse};
use crate::query::ws::WsTrafficQuery;
use crate::query::{TrafficQuery, build_export_select};
use crate::view_store::ViewStore;
use crate::views::{ExportOutcome, ExportProgress, ViewExporter};

// Keep bound source-id literals comfortably below ClickHouse's default
// 256 KiB SQL parser limit. The estimate allows every source-id byte to be
// escaped once, plus quotes and a separator.
const SCAN_TRAFFIC_SOURCE_IDS_QUERY_BUDGET: usize = 192 * 1024;

pub(super) fn chunk_scan_traffic_source_ids(
    mut source_ids: Vec<String>,
) -> anyhow::Result<Vec<Vec<String>>> {
    source_ids.sort_unstable();
    source_ids.dedup();

    let mut chunks = Vec::new();
    let mut chunk = Vec::new();
    let mut chunk_bytes: usize = 0;
    for source_id in source_ids {
        let query_bytes = source_id.len().saturating_mul(2).saturating_add(4);
        if query_bytes > SCAN_TRAFFIC_SOURCE_IDS_QUERY_BUDGET {
            anyhow::bail!("source_id is too large to query safely");
        }
        if !chunk.is_empty()
            && chunk_bytes.saturating_add(query_bytes) > SCAN_TRAFFIC_SOURCE_IDS_QUERY_BUDGET
        {
            chunks.push(chunk);
            chunk = Vec::new();
            chunk_bytes = 0;
        }
        chunk_bytes += query_bytes;
        chunk.push(source_id);
    }
    if !chunk.is_empty() {
        chunks.push(chunk);
    }
    Ok(chunks)
}

/// Capture store over a ClickHouse HTTP client.
pub struct ClickHouseStore {
    client: clickhouse::Client,
}

impl ClickHouseStore {
    pub fn new(client: clickhouse::Client) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CaptureStore for ClickHouseStore {
    fn backend(&self) -> CaptureBackend {
        CaptureBackend::ClickHouse
    }

    async fn ping(&self) -> Result<()> {
        let one: u8 = self.client.query("SELECT 1").fetch_one().await?;
        anyhow::ensure!(one == 1, "ClickHouse answered SELECT 1 with {one}");
        Ok(())
    }

    async fn search_requests(&self, query: &TrafficQuery) -> Result<SearchResponse> {
        crate::query::search(&self.client, query).await
    }

    async fn count_requests(&self, query: &TrafficQuery) -> Result<u64> {
        crate::query::count(&self.client, query).await
    }

    async fn get_request(&self, org_id: &str, id: Uuid) -> Result<Option<HttpCapture>> {
        crate::traffic::get_by_id(&self.client, org_id, id).await
    }

    async fn search_ws(&self, query: &WsTrafficQuery) -> Result<WsSearchResponse> {
        crate::query::ws::search(&self.client, query).await
    }

    async fn count_ws(&self, query: &WsTrafficQuery) -> Result<u64> {
        crate::query::ws::count(&self.client, query).await
    }

    async fn get_ws_message(&self, org_id: &str, id: Uuid) -> Result<Option<WsCapture>> {
        crate::ws_traffic::get_ws_by_id(&self.client, org_id, id).await
    }

    async fn ws_conversations(
        &self,
        query: &ConversationQuery<'_>,
    ) -> Result<WsConversationSearchResponse> {
        let order = if query.descending { "DESC" } else { "ASC" };
        let limit = query.limit;

        let mut conds: Vec<String> = vec!["ws_messages.org_id = ?".to_string()];
        let mut binds: Vec<String> = vec![query.org_id.to_string()];
        if let Some(ids) = query.source_ids.filter(|v| !v.is_empty()) {
            let ph = ids.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
            conds.push(format!("ws_messages.source_id IN ({ph})"));
            binds.extend(ids.iter().cloned());
        }
        if let Some(s) = query.source {
            conds.push("ws_messages.source = ?".to_string());
            binds.push(s.to_string());
        }
        if let Some(h) = query.host {
            conds.push("ws_messages.host = ?".to_string());
            binds.push(h.to_string());
        }
        let where_clause = conds.join(" AND ");

        #[derive(clickhouse::Row, Deserialize)]
        struct ConvRow {
            #[serde(with = "clickhouse::serde::uuid")]
            parent_event_id: Uuid,
            host: String,
            source: String,
            source_id: String,
            session_id: String,
            message_count: u64,
            client_to_server: u64,
            server_to_client: u64,
            #[serde(with = "clickhouse::serde::time::datetime64::millis")]
            first_at: OffsetDateTime,
            #[serde(with = "clickhouse::serde::time::datetime64::millis")]
            last_at: OffsetDateTime,
        }

        let sql = format!(
            "SELECT parent_event_id, any(host) AS host, any(source) AS source, \
             any(source_id) AS source_id, any(session_id) AS session_id, \
             count() AS message_count, \
             countIf(direction = 'c2s') AS client_to_server, \
             countIf(direction = 's2c') AS server_to_client, \
             toDateTime64(min(timestamp), 3, 'UTC') AS first_at, \
             toDateTime64(max(timestamp), 3, 'UTC') AS last_at \
             FROM ws_messages WHERE {where_clause} \
             GROUP BY parent_event_id \
             ORDER BY last_at {order}, parent_event_id {order} \
             LIMIT {limit}"
        );
        let mut q = self
            .client
            .query(&sql)
            .with_option("max_execution_time", "30");
        for b in &binds {
            q = q.bind(b);
        }
        let rows = q.fetch_all::<ConvRow>().await?;

        let count_sql =
            format!("SELECT uniqExact(parent_event_id) FROM ws_messages WHERE {where_clause}");
        let mut cq = self.client.query(&count_sql);
        for b in &binds {
            cq = cq.bind(b);
        }
        let total: u64 = cq.fetch_one().await?;

        let mut paths: std::collections::HashMap<Uuid, String> = std::collections::HashMap::new();
        if !rows.is_empty() {
            #[derive(clickhouse::Row, Deserialize)]
            struct PathRow {
                #[serde(with = "clickhouse::serde::uuid")]
                id: Uuid,
                path: String,
            }
            let ph = rows.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
            let path_sql = format!(
                "SELECT id, path FROM http_captures WHERE org_id = ? AND id IN ({ph}) LIMIT 1 BY id"
            );
            let mut pq = self.client.query(&path_sql).bind(query.org_id);
            for r in &rows {
                pq = pq.bind(r.parent_event_id.to_string());
            }
            for pr in pq.fetch_all::<PathRow>().await? {
                paths.insert(pr.id, pr.path);
            }
        }

        let items = rows
            .into_iter()
            .map(|r| WsConversationDto {
                path: paths.get(&r.parent_event_id).cloned(),
                parent_event_id: r.parent_event_id,
                host: r.host,
                source: r.source,
                source_id: r.source_id,
                session_id: r.session_id,
                message_count: r.message_count,
                client_to_server: r.client_to_server,
                server_to_client: r.server_to_client,
                first_at: r.first_at,
                last_at: r.last_at,
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
        let start = crate::query::cursor::ts_literal(start);
        let end = crate::query::cursor::ts_literal(end);

        #[derive(clickhouse::Row, Deserialize)]
        struct RequestRateRow {
            #[serde(with = "clickhouse::serde::time::datetime64::millis")]
            minute: OffsetDateTime,
            requests: u64,
        }

        let rows = self
            .client
            .query(
                "SELECT toDateTime64(minute, 3, 'UTC') AS minute, sum(requests) AS requests \
                 FROM http_request_counts_per_minute \
                 WHERE org_id = ? \
                   AND minute >= toDateTime64(?, 3, 'UTC') \
                   AND minute < toDateTime64(?, 3, 'UTC') \
                 GROUP BY minute \
                 ORDER BY minute ASC",
            )
            .bind(org_id)
            .bind(start)
            .bind(end)
            .fetch_all::<RequestRateRow>()
            .await?;

        Ok(rows
            .into_iter()
            .map(|row| RequestRatePointDto {
                minute: row.minute,
                requests: row.requests,
            })
            .collect())
    }

    async fn http_traffic_time_series(
        &self,
        query: &TimeSeriesQuery<'_>,
    ) -> Result<Vec<TrafficTimeSeriesPointDto>> {
        let bucket_seconds = query.bucket_seconds;
        let start = crate::query::cursor::ts_literal(query.start);
        let end = crate::query::cursor::ts_literal(query.end);
        let source_ids = query.source_ids.filter(|ids| !ids.is_empty());

        // `bucket_seconds` cannot be a bound parameter inside INTERVAL, so it
        // is formatted directly into the SQL. It is a validated positive
        // integer (u32), so this is injection-safe.
        let mut sql = format!(
            "SELECT toDateTime64(toStartOfInterval(timestamp, INTERVAL {bucket_seconds} SECOND), 3, 'UTC') AS bucket, \
             source_id, any(source) AS source, count() AS requests \
             FROM http_captures \
             WHERE timestamp >= toDateTime64(?, 3, 'UTC') \
               AND timestamp < toDateTime64(?, 3, 'UTC')"
        );
        if query.org_id.is_some() {
            sql.push_str(" AND org_id = ?");
        }
        if source_ids.is_some() {
            sql.push_str(" AND source_id IN ?");
        }
        sql.push_str(" GROUP BY bucket, source_id ORDER BY bucket ASC");

        #[derive(clickhouse::Row, Deserialize)]
        struct TrafficTimeSeriesRow {
            #[serde(with = "clickhouse::serde::time::datetime64::millis")]
            bucket: OffsetDateTime,
            source_id: String,
            source: String,
            requests: u64,
        }

        let mut q = self.client.query(&sql).bind(start).bind(end);
        if let Some(org) = query.org_id {
            q = q.bind(org);
        }
        if let Some(ids) = source_ids {
            q = q.bind(ids);
        }
        let rows = q.fetch_all::<TrafficTimeSeriesRow>().await?;

        Ok(rows
            .into_iter()
            .map(|row| TrafficTimeSeriesPointDto {
                bucket_start: row.bucket.format(&Rfc3339).unwrap_or_default(),
                source_id: row.source_id,
                source: row.source,
                count: row.requests,
            })
            .collect())
    }

    async fn scan_traffic_summary(
        &self,
        query: &TimeSeriesQuery<'_>,
    ) -> Result<ScanTrafficSummaryDto> {
        let bucket_seconds = query.bucket_seconds;
        let start = crate::query::cursor::ts_literal(query.start);
        let end = crate::query::cursor::ts_literal(query.end);
        let source_id_chunks =
            chunk_scan_traffic_source_ids(query.source_ids.unwrap_or_default().to_vec())?;

        // `bucket_seconds` is a validated positive integer, so formatting it
        // into the INTERVAL is injection-safe (it cannot be a bound param).
        let mut sql = format!(
            "SELECT toDateTime64(toStartOfInterval(timestamp, INTERVAL {bucket_seconds} SECOND), 3, 'UTC') AS bucket, \
             source_id, count() AS requests \
             FROM http_captures \
             WHERE timestamp >= toDateTime64(?, 3, 'UTC') \
               AND timestamp < toDateTime64(?, 3, 'UTC')"
        );
        if query.org_id.is_some() {
            sql.push_str(" AND org_id = ?");
        }
        sql.push_str(" AND source_id IN ? GROUP BY bucket, source_id ORDER BY bucket ASC");

        #[derive(clickhouse::Row, Deserialize)]
        struct SummaryRow {
            #[serde(with = "clickhouse::serde::time::datetime64::millis")]
            bucket: OffsetDateTime,
            source_id: String,
            requests: u64,
        }

        let mut buckets = std::collections::BTreeMap::<String, u64>::new();
        let mut by_source = std::collections::HashMap::<String, u64>::new();
        let mut total: u64 = 0;
        for source_ids in source_id_chunks {
            let mut q = self.client.query(&sql).bind(&start).bind(&end);
            if let Some(org) = query.org_id {
                q = q.bind(org);
            }
            let rows = q.bind(&source_ids).fetch_all::<SummaryRow>().await?;

            for row in rows {
                total += row.requests;
                *by_source.entry(row.source_id).or_insert(0) += row.requests;
                *buckets
                    .entry(row.bucket.format(&Rfc3339).unwrap_or_default())
                    .or_insert(0) += row.requests;
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
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct Watermark {
            #[serde(with = "clickhouse::serde::time::datetime64::millis")]
            max_ts: time::OffsetDateTime,
            #[serde(with = "clickhouse::serde::uuid")]
            latest_id: uuid::Uuid,
            max_session_offset: u64,
        }

        let row: Option<Watermark> = self
            .client
            .query(
                "SELECT timestamp AS max_ts, \
                        id AS latest_id, \
                        session_offset AS max_session_offset \
                 FROM http_captures \
                 WHERE org_id = ? AND source_id = ? \
                 ORDER BY timestamp DESC, session_offset DESC, id DESC \
                 LIMIT 1",
            )
            .bind(org_id)
            .bind(source_id)
            .fetch_optional()
            .await?;

        let cursor = row.map(|w| {
            crate::query::cursor::encode_cursor(w.max_ts, w.max_session_offset, w.latest_id)
        });

        // Deduplicated count via uniqCombined(id) — bounded ~12 MiB vs an
        // unbounded exact hash set, no FINAL needed. The count is a
        // progress/size metric (SequenceResponse.count), not an exact gate.
        let count: u64 = self
            .client
            .query(
                "SELECT uniqCombined(id) FROM http_captures \
                 WHERE org_id = ? AND source_id = ?",
            )
            .bind(org_id)
            .bind(source_id)
            .fetch_one()
            .await?;

        Ok(Sequence { cursor, count })
    }

    fn view_exporter(&self) -> Option<&dyn ViewExporter> {
        Some(self)
    }
}

#[async_trait]
impl ViewExporter for ClickHouseStore {
    /// `INSERT INTO FUNCTION <object store> SELECT ...`, submitted with
    /// `wait_end_of_query=0` so ClickHouse accepts it and returns
    /// immediately; the query continues in ClickHouse independently. `qid`
    /// becomes the ClickHouse `query_id`.
    async fn submit(
        &self,
        config: &ControlConfig,
        store: &ViewStore,
        query: &TrafficQuery,
        qid: &str,
        key: &str,
    ) -> Result<()> {
        use anyhow::Context as _;

        let target = store.export_target_sql(key).await?;

        let (select_sql, binds) = build_export_select(query, "http_captures");
        let settings_clause = format!(
            "SETTINGS preferred_block_size_bytes = {}, \
                     max_block_size = {}, \
                     output_format_parquet_row_group_size_bytes = {}, \
                     output_format_parquet_row_group_size = {}",
            config.export_preferred_block_size_bytes,
            config.export_max_block_size,
            config.export_row_group_size_bytes,
            config.export_row_group_size,
        );
        let insert_sql = format!("INSERT INTO FUNCTION {target} {select_sql} {settings_clause}");

        #[allow(deprecated)]
        let mut q = self
            .client
            .query(&insert_sql)
            .with_option("query_id", qid)
            .with_option("wait_end_of_query", "0");

        for b in &binds {
            q = q.bind(b.as_str());
        }

        q.execute()
            .await
            .context("failed to submit ClickHouse export query")?;
        Ok(())
    }

    /// Check `system.processes` on every replica for a running query with the
    /// given query_id. The export runs on whichever replica the submit request
    /// reached, and a later poll may land on another one behind the Service.
    async fn progress(&self, qid: &str) -> Result<Option<ExportProgress>> {
        use anyhow::Context as _;

        #[derive(clickhouse::Row, Deserialize)]
        struct Row {
            read_rows: u64,
            written_rows: u64,
            total_rows_approx: u64,
        }

        let result: Option<Row> = self
            .client
            .query(
                "SELECT read_rows, written_rows, total_rows_approx \
                 FROM clusterAllReplicas('{cluster}', system.processes) WHERE query_id = ?",
            )
            .bind(qid)
            .fetch_optional::<Row>()
            .await
            .context("failed to query system.processes")?;

        Ok(result.map(|r| ExportProgress {
            read_rows: r.read_rows as i64,
            written_rows: r.written_rows as i64,
            total_rows: r.total_rows_approx as i64,
        }))
    }

    /// Check `system.query_log` on every replica for a completed or failed query.
    /// Only the replica that ran the export logs it.
    async fn outcome(&self, qid: &str) -> Result<Option<ExportOutcome>> {
        use anyhow::Context as _;

        #[derive(clickhouse::Row, Deserialize)]
        struct Row {
            #[serde(rename = "type")]
            type_: String,
            exception: String,
        }

        let result: Option<Row> = self
            .client
            .query(
                // `type` is Enum8; the client rejects decoding it into a String.
                "SELECT toString(type) AS type, exception \
                 FROM clusterAllReplicas('{cluster}', system.query_log) \
                 WHERE query_id = ? \
                   AND type IN ('QueryFinish', 'ExceptionWhileProcessing') \
                 ORDER BY event_time DESC \
                 LIMIT 1",
            )
            .bind(qid)
            .fetch_optional::<Row>()
            .await
            .context("failed to query system.query_log")?;

        Ok(result.map(|r| {
            if r.type_ == "QueryFinish" {
                ExportOutcome::Finished
            } else {
                ExportOutcome::Failed(r.exception)
            }
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_traffic_source_ids_are_deduplicated_and_bounded() {
        let mut source_ids: Vec<String> = (0..19_139)
            .map(|n| format!("{n:08x}-0000-4000-8000-{n:012x}"))
            .collect();
        let duplicates = source_ids[..159].to_vec();
        source_ids.extend(duplicates);

        let chunks = chunk_scan_traffic_source_ids(source_ids).unwrap();
        assert!(chunks.len() > 1);
        assert_eq!(chunks.iter().map(Vec::len).sum::<usize>(), 19_139);
        for chunk in chunks {
            let estimated_bytes: usize = chunk
                .iter()
                .map(|id| id.len().saturating_mul(2).saturating_add(4))
                .sum();
            assert!(estimated_bytes <= SCAN_TRAFFIC_SOURCE_IDS_QUERY_BUDGET);
        }
    }

    #[test]
    fn scan_traffic_rejects_a_single_oversized_source_id() {
        let source_id = "x".repeat(SCAN_TRAFFIC_SOURCE_IDS_QUERY_BUDGET);
        assert!(chunk_scan_traffic_source_ids(vec![source_id]).is_err());
    }
}
