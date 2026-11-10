//! The ClickHouse capture store, written through the ingester pipeline and
//! read back through the `CaptureStore` trait, against a real ClickHouse.
//!
//! Skipped with a message unless `PROXYX_TEST_CLICKHOUSE_URL` is set and the
//! ClickHouse DDL is told to run on a single node:
//!
//! ```text
//! docker run -d --name proxyx-ch -p 45594:8123 -e CLICKHOUSE_USER=proxyx \
//!     -e CLICKHOUSE_PASSWORD=proxyx clickhouse/clickhouse-server:26.3
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
use serde_json::json;
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
            name: "x-trace".into(),
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
    assert_eq!(
        ids(
            &store,
            &branch(json!({ "request_header": { "key": "x-trace", "value": "abc" } }))
        )
        .await,
        vec![uuid_n(30)]
    );
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
    assert!(dynamic.require_view_exporter().is_ok());

    admin
        .query(&format!("DROP DATABASE {database}"))
        .execute()
        .await
        .unwrap();
}
