//! The ClickHouse capture store, written through the ingester pipeline and
//! read back through the `CaptureStore` trait, against a real ClickHouse.
//!
//! Skipped with a message unless `PROXYX_TEST_CLICKHOUSE_URL` is set and the
//! ClickHouse DDL is told to run on a single node:
//!
//! ```text
//! docker run -d --name proxyx-ch -p 45594:8123 -e CLICKHOUSE_USER=proxyx \
//!     -e CLICKHOUSE_PASSWORD=proxyx clickhouse/clickhouse-server:26.10
//! export PROXYX_TEST_CLICKHOUSE_URL=http://127.0.0.1:45594
//! export PROXYX_TEST_CLICKHOUSE_USER=proxyx PROXYX_TEST_CLICKHOUSE_PASSWORD=proxyx
//! export PROXYX_CONTROL_CLICKHOUSE__LOCAL_SINGLE_NODE=1
//! ```
//!
//! The test creates its own database and drops it at the end.

use std::sync::Arc;

use common::wire;
use proxyx_control::capture_store::{
    CaptureStore, ClickHouseStore, ConversationQuery, TimeSeriesQuery,
};
use proxyx_control::pipeline::ClickHouseSink;
use proxyx_control::pipeline::clickhouse::ClickHouseConfig;
use serde_json::{Value, json};
use uuid::Uuid;

mod support;
use support::*;

#[tokio::test]
async fn write_through_the_pipeline_and_read_back() {
    let Ok(url) = std::env::var("PROXYX_TEST_CLICKHOUSE_URL") else {
        eprintln!("SKIP: PROXYX_TEST_CLICKHOUSE_URL is not set");
        return;
    };
    if std::env::var_os("PROXYX_CONTROL_CLICKHOUSE__LOCAL_SINGLE_NODE").is_none() {
        eprintln!("SKIP: PROXYX_CONTROL_CLICKHOUSE__LOCAL_SINGLE_NODE is not set");
        return;
    }
    let user = std::env::var("PROXYX_TEST_CLICKHOUSE_USER").ok();
    let password = std::env::var("PROXYX_TEST_CLICKHOUSE_PASSWORD").ok();

    // The tables expire rows older than 12 months: capture "now".
    let now = time::OffsetDateTime::now_utc().unix_timestamp_nanos() as i64;
    set_base_nanos(now - now % 1_000_000_000 - 3_600 * 1_000_000_000);

    let database = format!("pxt_{}", &Uuid::new_v4().simple().to_string()[..12]);
    let mut admin = clickhouse::Client::default().with_url(&url);
    if let Some(user) = &user {
        admin = admin.with_user(user);
    }
    if let Some(password) = &password {
        admin = admin.with_password(password);
    }
    admin
        .query(&format!("CREATE DATABASE {database}"))
        .execute()
        .await
        .unwrap();

    let config = ClickHouseConfig {
        url,
        database: Some(database.clone()),
        user,
        password,
        table: None,
        bulk_size: 500,
        flush_interval_secs: 1,
        max_buffer_bytes: 256 * 1024 * 1024,
        circuit_breaker_threshold: 5,
        circuit_breaker_reset_secs: 60,
    };
    let client = proxyx_control::runtime::clickhouse_client(&config);
    proxyx_control::migrations::run_clickhouse(&client)
        .await
        .unwrap();
    let store = ClickHouseStore::new(client);

    let sink = |config: &ClickHouseConfig| -> Arc<ClickHouseSink> {
        Arc::new(
            ClickHouseSink::new(
                config.clone(),
                Some("X-ProxyX-Agent".into()),
                None,
                None,
                None,
            )
            .unwrap(),
        )
    };

    // HTTP captures: a plain series plus one with headers and bodies.
    let mut rich = capture(30);
    rich.method = "POST".into();
    rich.request_headers = vec![
        wire::Header {
            name: "X-Trace".into(),
            value: "abc".into(),
        },
        wire::Header {
            name: "X-ProxyX-Agent".into(),
            value: "agent-7".into(),
        },
        wire::Header {
            name: "cookie".into(),
            value: "a=b".into(),
        },
    ];
    rich.request_body = br#"{"query":"Hello World"}"#.to_vec().into();
    rich.request_body_size = 23;
    rich.response_headers = vec![wire::Header {
        name: "Content-Type".into(),
        value: "Application/JSON; charset=utf-8".into(),
    }];
    rich.response_body = br#"{"ok":true}"#.to_vec().into();
    rich.response_body_size = 11;
    let mut messages = series(25);
    messages.push(Message::Http(rich));

    // WebSocket: a handshake and three messages.
    let parent = uuid_n(500);
    let mut handshake = capture(500);
    handshake.path = "/stream".into();
    messages.push(Message::Http(handshake));
    for (event, direction) in [
        (601, wire::WsDirection::C2s),
        (602, wire::WsDirection::S2c),
        (603, wire::WsDirection::S2c),
    ] {
        messages.push(Message::Ws(wire::CapturedWsMessage {
            event_id: bytes::Bytes::copy_from_slice(uuid_n(event).as_bytes()),
            parent_event_id: bytes::Bytes::copy_from_slice(parent.as_bytes()),
            session_id: bytes::Bytes::copy_from_slice(uuid_n(9_000).as_bytes()),
            proxy_id: "proxy-1".into(),
            org_id: ORG.into(),
            source: "crawler".into(),
            source_id: "run-1".into(),
            timestamp_nanos: base_nanos() + event as i64 * 1_000_000_000,
            direction: direction as i32,
            opcode: wire::WsOpcode::Text as i32,
            payload: b"ticker".to_vec().into(),
            payload_size: 6,
            host: "ws.example.com".into(),
            ..Default::default()
        }));
    }
    let sent = messages.len();
    assert_eq!(deliver_via(sink(&config), messages).await, sent);

    // Search, count, get.
    let all = tq(json!({ "limit": 100 }));
    let found = ids(&store, &all).await;
    assert_eq!(found.len(), 27, "25 + rich + handshake");
    assert_eq!(store.count_requests(&all).await.unwrap(), 27);
    assert_eq!(
        ids(
            &store,
            &branch(json!({ "correlation_id": exact("agent-7") }))
        )
        .await,
        vec![uuid_n(30)]
    );
    assert_eq!(
        ids(
            &store,
            &branch(json!({ "correlation_id": not(exact("agent-7")) }))
        )
        .await
        .len(),
        0,
        "NOT on a NULL correlation id excludes the row"
    );
    assert_eq!(
        ids(
            &store,
            &branch(json!({ "mime_type": exact("application/json") }))
        )
        .await,
        vec![uuid_n(30)]
    );
    assert_eq!(
        ids(&store, &branch(json!({ "request_sends_cookies": true }))).await,
        vec![uuid_n(30)]
    );
    for (filter, keys, value) in [
        ("request_header", ["x-trace", "X-TRACE", "x-TrAcE"], "abc"),
        (
            "request_header",
            ["x-proxyx-agent", "X-PROXYX-AGENT", "x-PrOxYx-AgEnT"],
            "agent-7",
        ),
        (
            "response_header",
            ["content-type", "CONTENT-TYPE", "cOnTeNt-TyPe"],
            "Application/JSON; charset=utf-8",
        ),
    ] {
        for key in keys {
            let query = branch(json!({ (filter): { "key": key, "value": value } }));
            assert_eq!(ids(&store, &query).await, vec![uuid_n(30)]);
            assert_eq!(store.count_requests(&query).await.unwrap(), 1);
        }
        let wrong_value = branch(json!({
            (filter): { "key": keys[0], "value": value.to_ascii_uppercase() }
        }));
        assert!(ids(&store, &wrong_value).await.is_empty());
        assert_eq!(store.count_requests(&wrong_value).await.unwrap(), 0);
    }
    for filter in ["request_header", "response_header"] {
        for (value, expected_count) in [("", 27), ("nonempty", 0)] {
            let query = branch(json!({
                (filter): { "key": "X-ProxyX-Missing-Header", "value": value }
            }));
            assert_eq!(store.count_requests(&query).await.unwrap(), expected_count);
        }
    }
    assert_eq!(
        ids(
            &store,
            &branch(json!({ "request_body": contains("hello world") }))
        )
        .await,
        vec![uuid_n(30)]
    );
    let got = store.get_request(ORG, uuid_n(30)).await.unwrap().unwrap();
    assert_eq!(got.request_body, r#"{"query":"Hello World"}"#);
    assert_eq!(got.timestamp, ts_of(30));
    assert!(
        store
            .get_request("another-org", uuid_n(30))
            .await
            .unwrap()
            .is_none()
    );

    // Paging.
    let mut seen = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let page = store
            .search_requests(&tq(
                json!({ "limit": 10, "cursor": cursor, "order": "desc" }),
            ))
            .await
            .unwrap();
        seen.extend(page.items.iter().map(|i| i.id));
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    assert_eq!(seen.len(), 27);
    assert!(seen.windows(2).all(|w| w[0] != w[1]));

    // A redelivered capture is returned once (de-duplicated on read).
    let acked = deliver_via(sink(&config), vec![Message::Http(capture(1))]).await;
    assert_eq!(acked, 1);
    assert_eq!(ids(&store, &all).await.len(), 27);
    assert_eq!(store.count_requests(&all).await.unwrap(), 27);

    // WebSocket.
    let messages = wq(json!({ "branches": [{ "parent_event_id": parent.to_string() }] }));
    assert_eq!(store.search_ws(&messages).await.unwrap().items.len(), 3);
    assert_eq!(store.count_ws(&messages).await.unwrap(), 3);
    let one = store
        .get_ws_message(ORG, uuid_n(602))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(one.direction, "s2c");
    let conversations = store
        .ws_conversations(&ConversationQuery {
            org_id: ORG,
            source_ids: None,
            source: None,
            host: None,
            limit: 10,
            descending: true,
        })
        .await
        .unwrap();
    assert_eq!(conversations.total_count, Some(1));
    assert_eq!(conversations.items[0].path.as_deref(), Some("/stream"));
    assert_eq!(conversations.items[0].message_count, 3);
    assert_eq!(conversations.items[0].client_to_server, 1);

    // Aggregates and the sequence watermark.
    let start = ts_of(0) - time::Duration::seconds(20);
    let window = TimeSeriesQuery {
        org_id: Some(ORG),
        source_ids: None,
        start,
        end: start + time::Duration::minutes(5),
        bucket_seconds: 60,
    };
    let series = store.http_traffic_time_series(&window).await.unwrap();
    assert!(!series.is_empty());
    assert_eq!(store.sequence(ORG, "run-1").await.unwrap().count, 27);

    // Exports are available with this store.
    let dynamic: &dyn CaptureStore = &store;
    let exporter = dynamic.require_view_exporter().unwrap();

    // A stock single node has no `cluster` macro: polling an unknown query id
    // must read the local system tables and find nothing, not fail.
    let missing_qid = format!("pxt-missing-{}", Uuid::new_v4());
    assert!(exporter.progress(&missing_qid).await.unwrap().is_none());
    assert!(exporter.outcome(&missing_qid).await.unwrap().is_none());

    admin
        .query(&format!("DROP DATABASE {database}"))
        .execute()
        .await
        .unwrap();
}

/// The values at the edges of the query language return the rows the
/// OpenSearch store returns ([`boundary_cases`]): `.` does not match a
/// newline although ClickHouse's own RE2 default lets it, and numeric filters
/// beyond a column's type are answered, not rejected.
#[tokio::test]
async fn boundary_values_match_opensearch() {
    let Ok(url) = std::env::var("PROXYX_TEST_CLICKHOUSE_URL") else {
        eprintln!("SKIP: PROXYX_TEST_CLICKHOUSE_URL is not set");
        return;
    };
    if std::env::var_os("PROXYX_CONTROL_CLICKHOUSE__LOCAL_SINGLE_NODE").is_none() {
        eprintln!("SKIP: PROXYX_CONTROL_CLICKHOUSE__LOCAL_SINGLE_NODE is not set");
        return;
    }
    let user = std::env::var("PROXYX_TEST_CLICKHOUSE_USER").ok();
    let password = std::env::var("PROXYX_TEST_CLICKHOUSE_PASSWORD").ok();

    let now = time::OffsetDateTime::now_utc().unix_timestamp_nanos() as i64;
    set_base_nanos(now - now % 1_000_000_000 - 3_600 * 1_000_000_000);

    let database = format!("pxt_{}", &Uuid::new_v4().simple().to_string()[..12]);
    let mut admin = clickhouse::Client::default().with_url(&url);
    if let Some(user) = &user {
        admin = admin.with_user(user);
    }
    if let Some(password) = &password {
        admin = admin.with_password(password);
    }
    admin
        .query(&format!("CREATE DATABASE {database}"))
        .execute()
        .await
        .unwrap();
    let config = ClickHouseConfig {
        url,
        database: Some(database.clone()),
        user,
        password,
        table: None,
        bulk_size: 500,
        flush_interval_secs: 1,
        max_buffer_bytes: 256 * 1024 * 1024,
        circuit_breaker_threshold: 5,
        circuit_breaker_reset_secs: 60,
    };
    let client = proxyx_control::runtime::clickhouse_client(&config);
    proxyx_control::migrations::run_clickhouse(&client)
        .await
        .unwrap();
    let store = ClickHouseStore::new(client);
    let sink = Arc::new(ClickHouseSink::new(config.clone(), None, None, None, None).unwrap());
    let mut messages = boundary_messages();
    messages.extend(boundary_close_messages());
    let sent = messages.len();
    assert_eq!(deliver_via(sink, messages).await, sent);

    // ClickHouse's `lower` folds ASCII only, which is a documented difference
    // from the OpenSearch store.
    let (a, b, c, d, e) = (uuid_n(1), uuid_n(2), uuid_n(3), uuid_n(4), uuid_n(5));
    let (f, g) = (uuid_n(6), uuid_n(7));
    let all = vec![a, b, c, d, e, f, g];
    let rx = |value: &str| json!({ "op": "regex_match", "value": value });
    let mut cases = boundary_cases();
    cases.extend([
        (
            "contains folds ASCII letters only",
            json!({ "response_body": contains("ÜNÏ") }),
            vec![d],
        ),
        (
            "contains folds around ASCII and a space",
            json!({ "response_body": contains("ünï b") }),
            vec![c],
        ),
        (
            "not contains a non-ASCII letter",
            json!({ "response_body": not(contains("ünï")) }),
            vec![a, b, d, e, f, g],
        ),
        // ASCII-only folding: `k` and `s` do not match their Unicode variants.
        (
            "k does not match KELVIN SIGN",
            json!({ "response_body": contains("k") }),
            vec![],
        ),
        (
            "KELVIN SIGN matches itself",
            json!({ "response_body": contains("\u{212a}") }),
            vec![f],
        ),
        (
            "s does not match LONG S",
            json!({ "response_body": contains("S") }),
            vec![],
        ),
        (
            "LONG S matches itself",
            json!({ "response_body": contains("\u{17f}") }),
            vec![g],
        ),
        ("not k", json!({ "response_body": not(contains("k")) }), all),
        (
            "(?i)k matches KELVIN SIGN",
            json!({ "response_body": rx("(?i)^k$") }),
            vec![f],
        ),
        (
            "(?i) class matches LONG S",
            json!({ "response_body": rx("(?i)^[r-t]$") }),
            vec![g],
        ),
        (
            "(?i)\\w matches KELVIN SIGN",
            json!({ "response_body": rx(r"(?i)^\w$") }),
            vec![f, g],
        ),
        (
            "(?i)\\W does not",
            json!({ "response_body": rx(r"(?i)^\W$") }),
            vec![],
        ),
    ]);
    for (name, filter, expected) in cases {
        let query = branch(filter);
        assert_eq!(ids(&store, &query).await, expected, "{name}");
        assert_eq!(
            store.count_requests(&query).await.unwrap(),
            expected.len() as u64,
            "{name} count"
        );
    }
    // An explicit `(?s)` is the caller's choice and still lets `.` match.
    let dotall =
        branch(json!({ "request_body": { "op": "regex_match", "value": "(?s)line1.line2" } }));
    assert_eq!(ids(&store, &dotall).await, vec![c, d]);
    let mut ws_cases = boundary_ws_cases();
    let payload = |filter: Value| json!({ "payload": filter });
    ws_cases.extend([
        (
            "ws k does not match KELVIN SIGN",
            payload(contains("k")),
            vec![],
        ),
        (
            "ws KELVIN SIGN matches itself",
            payload(contains("\u{212a}")),
            vec![uuid_n(603)],
        ),
        (
            "ws LONG S matches itself",
            payload(contains("\u{17f}")),
            vec![uuid_n(604)],
        ),
    ]);
    for (name, filter, expected) in ws_cases {
        let query = wq(json!({ "branches": [filter] }));
        let found: Vec<Uuid> = store
            .search_ws(&query)
            .await
            .unwrap()
            .items
            .iter()
            .map(|i| i.id)
            .collect();
        assert_eq!(found, expected, "{name}");
        assert_eq!(
            store.count_ws(&query).await.unwrap(),
            expected.len() as u64,
            "{name} count"
        );
    }

    admin
        .query(&format!("DROP DATABASE {database}"))
        .execute()
        .await
        .unwrap();
}
