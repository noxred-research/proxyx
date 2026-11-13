//! Index naming, templates, mappings and document shapes.
//!
//! Captures go to time-based indices `<prefix>-http-<period>` and
//! `<prefix>-ws-<period>`, one per UTC day or ISO week of the capture's
//! timestamp. Two composable index templates, `<prefix>-http` and
//! `<prefix>-ws`, give them their settings and a strict mapping. Searches
//! read the patterns `<prefix>-http-*` and `<prefix>-ws-*`.
//!
//! Besides the columns of the ClickHouse tables, a document carries fields
//! derived at ingest that the ClickHouse query layer computes at query time:
//! `len.*` (byte lengths), `mime_type`, `request_sends_cookies`,
//! `response_sets_cookies`, `cookies`, `request_header_kv`,
//! `response_header_kv` and `url_sort`. See `lower.rs` for how they are used.

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value, json};
use time::OffsetDateTime;

use super::client::OsClient;
use super::{OpenSearchConfig, Rollover};
use crate::pipeline::{NormalizedCapturedRequest, NormalizedWsMessage};

/// Bumped when a template change needs `proxyx migrate control` to run
/// again; `verify_templates` compares it.
pub(super) const SCHEMA_VERSION: u64 = 1;

/// Longest `url_sort` value, in bytes (a Lucene term holds 32 766).
const URL_SORT_MAX_BYTES: usize = 4096;

/// Longest value indexed as a header `name:value` term, in characters
/// (4 x 8191 bytes stays below the Lucene term limit).
const HEADER_TERM_IGNORE_ABOVE: usize = 8191;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    Http,
    Ws,
}

impl Kind {
    fn slug(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Ws => "ws",
        }
    }
}

pub(super) fn template_name(config: &OpenSearchConfig, kind: Kind) -> String {
    format!("{}-{}", config.index_prefix, kind.slug())
}

/// Pattern that matches every index of `kind`.
pub(super) fn read_pattern(config: &OpenSearchConfig, kind: Kind) -> String {
    format!("{}-{}-*", config.index_prefix, kind.slug())
}

/// Index a document with capture time `ts` is written to.
pub(super) fn index_name(config: &OpenSearchConfig, kind: Kind, ts: OffsetDateTime) -> String {
    let ts = ts.to_offset(time::UtcOffset::UTC);
    let period = match config.rollover {
        Rollover::Daily => format!("{:04}.{:02}.{:02}", ts.year(), ts.month() as u8, ts.day()),
        Rollover::Weekly => {
            let (year, week, _) = ts.to_iso_week_date();
            format!("{year:04}.w{week:02}")
        }
    };
    format!("{}-{}-{period}", config.index_prefix, kind.slug())
}

fn keyword() -> Value {
    json!({ "type": "keyword" })
}

fn wildcard() -> Value {
    json!({ "type": "wildcard" })
}

fn long() -> Value {
    json!({ "type": "long" })
}

fn boolean() -> Value {
    json!({ "type": "boolean" })
}

fn date() -> Value {
    json!({ "type": "date", "format": "epoch_millis||strict_date_optional_time" })
}

/// Pairs stored for display only: not indexed.
fn stored_object() -> Value {
    json!({ "type": "object", "enabled": false })
}

fn header_terms() -> Value {
    json!({ "type": "keyword", "ignore_above": HEADER_TERM_IGNORE_ABOVE })
}

fn len_fields(names: &[&str]) -> Value {
    let mut props = Map::new();
    for name in names {
        props.insert((*name).to_string(), long());
    }
    json!({ "properties": props })
}

fn http_properties() -> Value {
    json!({
        "id": keyword(),
        "org_id": keyword(),
        "timestamp": date(),
        "session_offset": long(),
        "method": keyword(),
        "scheme": keyword(),
        "host": keyword(),
        "path": wildcard(),
        "session_id": keyword(),
        "proxy_id": keyword(),
        "source": keyword(),
        "source_id": keyword(),
        "request_headers": stored_object(),
        "response_headers": stored_object(),
        "request_header_kv": header_terms(),
        "response_header_kv": header_terms(),
        "request_body": wildcard(),
        "response_body": wildcard(),
        "request_size": long(),
        "response_size": long(),
        "status_code": { "type": "integer" },
        "duration_ms": long(),
        "ratelimit_wait_ms": long(),
        "correlation_id": keyword(),
        "parent_correlation_id": keyword(),
        "account_id": keyword(),
        "tool_call_id": keyword(),
        "mime_type": keyword(),
        "request_sends_cookies": boolean(),
        "response_sets_cookies": boolean(),
        "cookies": { "type": "byte" },
        "url_sort": keyword(),
        "len": len_fields(&[
            "host", "method", "path", "request_body", "response_body", "correlation_id",
            "parent_correlation_id", "account_id", "tool_call_id", "mime_type",
        ]),
        "inserted_at": date(),
    })
}

fn ws_properties() -> Value {
    json!({
        "id": keyword(),
        "parent_event_id": keyword(),
        "org_id": keyword(),
        "timestamp": date(),
        "session_offset": long(),
        "direction": keyword(),
        "opcode": keyword(),
        "session_id": keyword(),
        "proxy_id": keyword(),
        "source": keyword(),
        "source_id": keyword(),
        "host": keyword(),
        "payload": wildcard(),
        "payload_size": long(),
        "payload_truncated": boolean(),
        "payload_is_text": boolean(),
        "was_compressed": boolean(),
        "close_code": { "type": "integer" },
        "close_reason": keyword(),
        "len": len_fields(&["host", "payload", "direction", "opcode", "close_reason"]),
        "inserted_at": date(),
    })
}

/// The composable index template of `kind`.
pub(super) fn template(config: &OpenSearchConfig, kind: Kind) -> Value {
    let mut settings = Map::new();
    settings.insert(
        "index.number_of_shards".into(),
        json!(config.number_of_shards),
    );
    settings.insert(
        "index.number_of_replicas".into(),
        json!(config.number_of_replicas),
    );
    settings.insert(
        "index.refresh_interval".into(),
        json!(config.refresh_interval),
    );
    settings.insert("index.codec".into(), json!("best_compression"));
    // Lucene regexes of long RE2 patterns outgrow the 1 000 character default.
    settings.insert("index.max_regex_length".into(), json!(10_000));
    // Full setting names, e.g. `index.lifecycle.name` or
    // `index.plugins.index_state_management.policy_id`.
    for (key, value) in &config.index_settings {
        settings.insert(key.clone(), value.clone());
    }
    let properties = match kind {
        Kind::Http => http_properties(),
        Kind::Ws => ws_properties(),
    };
    json!({
        "index_patterns": [read_pattern(config, kind)],
        "priority": 200,
        "template": {
            "settings": settings,
            "mappings": {
                "dynamic": "strict",
                "_meta": { "schema_version": SCHEMA_VERSION },
                "properties": properties,
            },
        },
        "_meta": { "managed_by": "proxyx", "schema_version": SCHEMA_VERSION },
    })
}

/// Create or replace both templates. Existing indices keep the mapping they
/// were created with.
pub(super) async fn install_templates(client: &OsClient, config: &OpenSearchConfig) -> Result<()> {
    let engine = client
        .detect(config.kind)
        .await
        .context("the search engine is not reachable or not supported")?;
    tracing::info!(engine = engine.kind.as_str(), version = %engine.version, "search engine detected");
    for kind in [Kind::Http, Kind::Ws] {
        let name = template_name(config, kind);
        let response = client
            .put_json(&format!("/_index_template/{name}"), &template(config, kind))
            .await?;
        response.ensure_success(&format!("installing index template {name}"))?;
        tracing::info!(template = %name, "OpenSearch index template installed");
    }
    Ok(())
}

/// Fail unless both templates exist at the schema version of this binary.
pub(super) async fn verify_templates(client: &OsClient, config: &OpenSearchConfig) -> Result<()> {
    let engine = client
        .detect(config.kind)
        .await
        .context("the search engine is not reachable or not supported")?;
    tracing::info!(engine = engine.kind.as_str(), version = %engine.version, "search engine detected");
    for kind in [Kind::Http, Kind::Ws] {
        let name = template_name(config, kind);
        let response = client
            .get(&format!("/_index_template/{name}"))
            .await
            .with_context(|| format!("reading index template {name}"))?;
        if response.status == 404 {
            bail!("index template {name} is not installed");
        }
        response.ensure_success(&format!("reading index template {name}"))?;
        let version =
            response.body["index_templates"][0]["index_template"]["_meta"]["schema_version"]
                .as_u64();
        if version != Some(SCHEMA_VERSION) {
            bail!(
                "index template {name} has schema version {version:?}, this build needs \
                 {SCHEMA_VERSION}"
            );
        }
    }
    tracing::info!("OpenSearch index templates up to date");
    Ok(())
}

pub(super) fn epoch_millis(ts: OffsetDateTime) -> i64 {
    super::lower::epoch_millis(ts)
}

fn header_pairs(headers: &[(String, String)]) -> Value {
    Value::Array(
        headers
            .iter()
            .map(|(name, value)| json!({ "name": name, "value": value }))
            .collect(),
    )
}

fn header_terms_of(headers: &[(String, String)]) -> Value {
    Value::Array(
        headers
            .iter()
            .map(|(name, value)| json!(format!("{}:{value}", name.to_lowercase())))
            .collect(),
    )
}

/// The response media type as ClickHouse derives it: the first
/// `Content-Type` value up to `;`, trimmed of spaces, ASCII-lowercased; empty
/// without the header.
pub(super) fn media_type(headers: &[(String, String)]) -> String {
    headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        .and_then(|(_, value)| value.split(';').next())
        .map(|m| m.trim_matches(' ').to_ascii_lowercase())
        .unwrap_or_default()
}

fn has_header(headers: &[(String, String)], wanted: &str) -> bool {
    headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case(wanted))
}

/// `host` + `path`, cut to [`URL_SORT_MAX_BYTES`] at a character boundary.
fn url_sort(host: &str, path: &str) -> String {
    let mut url = format!("{host}{path}");
    if url.len() > URL_SORT_MAX_BYTES {
        let mut end = URL_SORT_MAX_BYTES;
        while !url.is_char_boundary(end) {
            end -= 1;
        }
        url.truncate(end);
    }
    url
}

fn clamp_u32(value: u64) -> u64 {
    value.min(u64::from(u32::MAX))
}

/// The document of an HTTP capture.
pub(super) fn http_document(n: &NormalizedCapturedRequest) -> Value {
    let sends_cookies = has_header(&n.request_headers, "cookie");
    let sets_cookies = has_header(&n.response_headers, "set-cookie");
    let mime_type = media_type(&n.response_headers);
    let mut len = Map::new();
    let mut put_len = |name: &str, value: &str| {
        len.insert(name.to_string(), json!(value.len()));
    };
    put_len("host", &n.host);
    put_len("method", &n.method);
    put_len("path", &n.path);
    put_len("request_body", &n.request_body);
    put_len("response_body", &n.response_body);
    put_len("mime_type", &mime_type);

    let mut doc = json!({
        "id": n.event_id.to_string(),
        "org_id": n.org_id,
        "timestamp": epoch_millis(n.timestamp),
        "session_offset": super::lower::offset_value(n.session_offset),
        "method": n.method,
        "scheme": n.scheme,
        "host": n.host,
        "path": n.path,
        "session_id": n.session_id.to_string(),
        "proxy_id": n.proxy_id,
        "source": n.source,
        "source_id": n.source_id,
        "request_headers": header_pairs(&n.request_headers),
        "response_headers": header_pairs(&n.response_headers),
        "request_header_kv": header_terms_of(&n.request_headers),
        "response_header_kv": header_terms_of(&n.response_headers),
        "request_body": n.request_body,
        "response_body": n.response_body,
        "request_size": clamp_u32(n.request_size),
        "response_size": clamp_u32(n.response_size),
        "status_code": n.status_code.min(u32::from(u16::MAX)),
        "duration_ms": clamp_u32(n.duration_ms),
        "ratelimit_wait_ms": clamp_u32(n.ratelimit_wait_ms),
        "mime_type": mime_type,
        "request_sends_cookies": sends_cookies,
        "response_sets_cookies": sets_cookies,
        "cookies": u8::from(sends_cookies) + u8::from(sets_cookies),
        "url_sort": url_sort(&n.host, &n.path),
        "inserted_at": epoch_millis(OffsetDateTime::now_utc()),
    });
    for (name, value) in [
        ("correlation_id", &n.correlation_id),
        ("parent_correlation_id", &n.parent_correlation_id),
        ("account_id", &n.account_id),
        ("tool_call_id", &n.tool_call_id),
    ] {
        if let Some(value) = value {
            doc[name] = json!(value);
            len.insert(name.to_string(), json!(value.len()));
        }
    }
    doc["len"] = Value::Object(len);
    doc
}

/// The document of a WebSocket message. A payload that is not UTF-8 is
/// indexed as its lossy conversion, which is also what the API returns.
pub(super) fn ws_document(n: &NormalizedWsMessage) -> Value {
    let payload = String::from_utf8_lossy(&n.payload).replace('\0', "");
    json!({
        "id": n.event_id.to_string(),
        "parent_event_id": n.parent_event_id.to_string(),
        "org_id": n.org_id,
        "timestamp": epoch_millis(n.timestamp),
        "session_offset": super::lower::offset_value(n.session_offset),
        "direction": n.direction.as_str(),
        "opcode": n.opcode.as_str(),
        "session_id": n.session_id.to_string(),
        "proxy_id": n.proxy_id,
        "source": n.source,
        "source_id": n.source_id,
        "host": n.host,
        "payload": payload,
        "payload_size": clamp_u32(n.payload_size),
        "payload_truncated": n.payload_truncated,
        "payload_is_text": n.payload_is_text,
        "was_compressed": n.was_compressed,
        "close_code": n.close_code,
        "close_reason": n.close_reason,
        "len": {
            "host": n.host.len(),
            "payload": n.payload.len(),
            "direction": n.direction.as_str().len(),
            "opcode": n.opcode.as_str().len(),
            "close_reason": n.close_reason.len(),
        },
        "inserted_at": epoch_millis(OffsetDateTime::now_utc()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(rollover: Rollover) -> OpenSearchConfig {
        OpenSearchConfig {
            rollover,
            ..OpenSearchConfig::new("http://localhost:9200")
        }
    }

    #[test]
    fn daily_and_weekly_index_names() {
        let ts = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(); // 2023-11-14
        assert_eq!(
            index_name(&config(Rollover::Daily), Kind::Http, ts),
            "proxyx-http-2023.11.14"
        );
        assert_eq!(
            index_name(&config(Rollover::Weekly), Kind::Ws, ts),
            "proxyx-ws-2023.w46"
        );
    }

    #[test]
    fn iso_week_year_differs_from_calendar_year_at_new_year() {
        // 2021-01-01 is in ISO week 53 of 2020.
        let ts = OffsetDateTime::from_unix_timestamp(1_609_459_200).unwrap();
        assert_eq!(
            index_name(&config(Rollover::Weekly), Kind::Http, ts),
            "proxyx-http-2020.w53"
        );
    }

    #[test]
    fn media_type_matches_the_clickhouse_expression() {
        let h = |v: &str| vec![("Content-Type".to_string(), v.to_string())];
        assert_eq!(
            media_type(&h(" Application/JSON ; charset=utf-8")),
            "application/json"
        );
        assert_eq!(media_type(&h("")), "");
        assert_eq!(media_type(&[]), "");
        // The first Content-Type wins.
        let two = vec![
            ("content-type".to_string(), "a/b".to_string()),
            ("Content-Type".to_string(), "c/d".to_string()),
        ];
        assert_eq!(media_type(&two), "a/b");
    }

    #[test]
    fn url_sort_is_cut_on_a_char_boundary() {
        let long_path = "é".repeat(URL_SORT_MAX_BYTES);
        let sort = url_sort("h", &long_path);
        assert!(sort.len() <= URL_SORT_MAX_BYTES);
        assert!(sort.starts_with("hé"));
    }

    #[test]
    fn templates_have_strict_mappings_and_the_schema_version() {
        for kind in [Kind::Http, Kind::Ws] {
            let t = template(&config(Rollover::Daily), kind);
            assert_eq!(t["template"]["mappings"]["dynamic"], "strict");
            assert_eq!(t["_meta"]["schema_version"], SCHEMA_VERSION);
        }
    }
}
