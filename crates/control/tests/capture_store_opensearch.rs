//! The OpenSearch capture store against a real OpenSearch or Elasticsearch.
//!
//! Skipped with a message when `PROXYX_TEST_OPENSEARCH_URL` is unset, like the
//! `PROXYX_TEST_DATABASE_URL` tests. Start a node with
//!
//! ```text
//! docker run -d --name proxyx-os -p 45592:9200 -e discovery.type=single-node \
//!     -e DISABLE_SECURITY_PLUGIN=true opensearchproject/opensearch:2
//! export PROXYX_TEST_OPENSEARCH_URL=http://127.0.0.1:45592
//! ```
//!
//! A secured cluster is reached with `PROXYX_TEST_OPENSEARCH_USER`,
//! `PROXYX_TEST_OPENSEARCH_PASSWORD` (or `PROXYX_TEST_OPENSEARCH_API_KEY`) and
//! `PROXYX_TEST_OPENSEARCH_CA_CERT` (a PEM file).
//!
//! Each test uses its own index prefix and deletes its indices at the end.

use std::sync::Arc;

use common::wire;
use proxyx_control::capture_store::opensearch::{self, OpenSearchConfig, OpenSearchSink};
use proxyx_control::capture_store::{
    CaptureStore, ConversationQuery, OpenSearchStore, StoreError, TimeSeriesQuery,
};
use proxyx_control::models::BodyFetch;
use serde_json::{Value, json};
use uuid::Uuid;

mod support;
use support::*;

/// One test at a time: index creation and template changes are cluster-state
/// updates that a small or slow node serializes anyway, and concurrent
/// tests only multiply the time each of them waits.
static ONE_AT_A_TIME: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Harness {
    config: OpenSearchConfig,
    store: OpenSearchStore,
    http: reqwest::Client,
    _turn: tokio::sync::MutexGuard<'static, ()>,
}

impl Harness {
    /// A harness with fresh index names, or `None` (after printing why) when
    /// no OpenSearch is configured.
    async fn start(test: &str) -> Option<Self> {
        let Ok(url) = std::env::var("PROXYX_TEST_OPENSEARCH_URL") else {
            eprintln!("SKIP: PROXYX_TEST_OPENSEARCH_URL is not set ({test})");
            return None;
        };
        let turn = ONE_AT_A_TIME.lock().await;
        let mut config = OpenSearchConfig::new(url);
        config.username = std::env::var("PROXYX_TEST_OPENSEARCH_USER").ok();
        config.password = std::env::var("PROXYX_TEST_OPENSEARCH_PASSWORD").ok();
        config.api_key = std::env::var("PROXYX_TEST_OPENSEARCH_API_KEY").ok();
        config.ca_cert = std::env::var_os("PROXYX_TEST_OPENSEARCH_CA_CERT").map(Into::into);
        config.index_prefix = format!("pxt-{}", &Uuid::new_v4().simple().to_string()[..12]);
        config.number_of_replicas = 0;
        config.refresh_interval = "1s".to_string();
        config.flush_interval_secs = 1;
        // Cluster-state updates on a loaded node can take many seconds.
        config.request_timeout_secs = 120;
        opensearch::install_templates(&config).await.unwrap();
        opensearch::verify_templates(&config).await.unwrap();
        let store = OpenSearchStore::new(&config).unwrap();
        let mut http = reqwest::Client::builder();
        if let Some(ca) = &config.ca_cert {
            let pem = std::fs::read(ca).unwrap();
            http = http.add_root_certificate(reqwest::Certificate::from_pem(&pem).unwrap());
        }
        Some(Self {
            config,
            store,
            http: http.build().unwrap(),
            _turn: turn,
        })
    }

    /// Delete this test's indices and templates.
    async fn finish(self) {
        let base = self.config.url.trim_end_matches('/');
        let prefix = &self.config.index_prefix;
        for path in [
            format!("{base}/{prefix}-*"),
            format!("{base}/_index_template/{prefix}-http"),
            format!("{base}/_index_template/{prefix}-ws"),
        ] {
            let mut request = self.http.delete(path);
            if let Some(user) = &self.config.username {
                request = request.basic_auth(user, self.config.password.as_deref());
            }
            if let Some(key) = &self.config.api_key {
                request = request.header("Authorization", format!("ApiKey {key}"));
            }
            let _ = request.send().await;
        }
    }

    /// Run `messages` through a pipeline into a fresh sink and flush it, then
    /// make them searchable. Returns how many broker acks fired.
    async fn deliver(&self, messages: Vec<Message>) -> usize {
        let sink = OpenSearchSink::connect(
            &self.config,
            Some("X-ProxyX-Agent".into()),
            Some("X-ProxyX-Parent-Agent".into()),
            Some("X-ProxyX-Account".into()),
            Some("X-ProxyX-Tool".into()),
        )
        .unwrap();
        let acked = deliver_via(Arc::new(sink), messages).await;
        self.store.refresh().await.unwrap();
        acked
    }
}

#[tokio::test]
async fn write_search_count_get() {
    let Some(h) = Harness::start("write_search_count_get").await else {
        return;
    };

    let mut a = capture(1);
    a.method = "POST".into();
    a.request_headers = vec![
        header("Cookie", "a=b"),
        header("X-ProxyX-Agent", "agent-7"),
        header("X-Trace", "abc"),
    ];
    a.request_body = br#"{"query":"Hello World"}"#.to_vec().into();
    a.request_body_size = a.request_body.len() as u64;
    a.response_headers = vec![
        header("Content-Type", "Application/JSON; charset=utf-8"),
        header("Set-Cookie", "s=1"),
    ];
    a.response_body = br#"{"ok":true}"#.to_vec().into();
    a.response_body_size = a.response_body.len() as u64;
    a.response_status = 201;

    let mut b = capture(2);
    b.host = "other.example.org".into();
    b.response_status = 503;
    b.response_headers = vec![header("content-type", "text/html")];
    b.response_body = b"<html>down</html>".to_vec().into();
    b.response_body_size = b.response_body.len() as u64;
    b.request_body = b"ping".to_vec().into();
    b.request_body_size = 4;

    let mut c = capture(3);
    c.path = "/v2/users/42".into();
    c.request_headers = vec![header("X-ProxyX-Agent", "agent-8")];

    h.deliver(vec![
        Message::Http(a.clone()),
        Message::Http(b),
        Message::Http(c),
    ])
    .await;

    let store = &h.store;
    let (a_id, b_id, c_id) = (uuid_n(1), uuid_n(2), uuid_n(3));
    let all = tq(json!({}));
    assert_eq!(ids(store, &all).await, vec![a_id, b_id, c_id]);
    assert_eq!(store.count_requests(&all).await.unwrap(), 3);

    // (filter, expected ids). Every row is the exact set ClickHouse returns.
    let cases: Vec<(&str, Value, Vec<Uuid>)> = vec![
        (
            "host contains, case-insensitive",
            json!({ "host": contains("EXAMPLE.ORG") }),
            vec![b_id],
        ),
        (
            "method exact",
            json!({ "method": exact("POST") }),
            vec![a_id],
        ),
        (
            "status gte",
            json!({ "status_code": { "op": "gte", "value": 500 } }),
            vec![b_id],
        ),
        (
            "status all(gte, not exact)",
            json!({ "status_code": { "op": "all", "filters": [
                { "op": "gte", "value": 200 },
                { "op": "not", "filter": { "op": "exact", "value": 201 } },
            ] } }),
            vec![b_id, c_id],
        ),
        (
            "path regex with anchors and classes",
            json!({ "path": { "op": "regex_match", "value": r"^/v\d+/users/\d+$" } }),
            vec![c_id],
        ),
        (
            "path regex, leading (?i)",
            json!({ "path": { "op": "regex_match", "value": "(?i)ITEMS/1$" } }),
            vec![a_id],
        ),
        (
            "request body contains",
            json!({ "request_body": contains("hello world") }),
            vec![a_id],
        ),
        (
            "request body is empty",
            json!({ "request_body": exact("") }),
            vec![c_id],
        ),
        (
            "response body length",
            json!({ "response_body": { "op": "length", "value": { "op": "gt", "value": 11 } } }),
            vec![b_id],
        ),
        (
            "correlation id exact",
            json!({ "correlation_id": exact("agent-7") }),
            vec![a_id],
        ),
        (
            "not on a nullable column leaves out NULL rows",
            json!({ "correlation_id": not(exact("agent-7")) }),
            vec![c_id],
        ),
        (
            "is null",
            json!({ "correlation_id": { "op": "is_null" } }),
            vec![b_id],
        ),
        (
            "is present",
            json!({ "correlation_id": { "op": "is_present" } }),
            vec![a_id, c_id],
        ),
        (
            "not(any(exact, is_null))",
            json!({ "correlation_id": not(json!({ "op": "any", "filters": [exact("agent-7"), { "op": "is_null" }] })) }),
            vec![c_id],
        ),
        (
            "mime type",
            json!({ "mime_type": exact("application/json") }),
            vec![a_id],
        ),
        (
            "mime type, lowercase header name",
            json!({ "mime_type": contains("html") }),
            vec![b_id],
        ),
        (
            "request cookies",
            json!({ "request_sends_cookies": true }),
            vec![a_id],
        ),
        (
            "no response cookies",
            json!({ "response_sets_cookies": false }),
            vec![b_id, c_id],
        ),
        (
            "request header",
            json!({ "request_header": { "key": "X-Trace", "value": "abc" } }),
            vec![a_id],
        ),
        (
            "source id list",
            json!({ "source_id": ["run-1", "run-2"] }),
            vec![a_id, b_id, c_id],
        ),
        ("source id miss", json!({ "source_id": "run-9" }), vec![]),
    ];
    for (name, filter, expected) in cases {
        let query = branch(filter);
        assert_eq!(ids(store, &query).await, expected, "{name}");
        assert_eq!(
            store.count_requests(&query).await.unwrap(),
            expected.len() as u64,
            "{name} count"
        );
    }

    // Branches are ORed.
    let ored = tq(json!({ "branches": [
        { "host": exact("other.example.org") },
        { "method": exact("POST") },
    ] }));
    assert_eq!(ids(store, &ored).await, vec![a_id, b_id]);

    // A query that cannot be lowered exactly is rejected up front.
    let bad = branch(json!({ "path": { "op": "regex_match", "value": r"\bfoo" } }));
    match store.check_http_query(&bad) {
        Err(StoreError::Rejected(message)) => assert!(message.contains("word boundary")),
        other => panic!("expected a rejection, got {other:?}"),
    }
    assert!(store.check_http_query(&all).is_ok());

    // Single record: full row, headers in order, derived fields not leaked.
    let got = store.get_request(ORG, a_id).await.unwrap().unwrap();
    assert_eq!(got.id, a_id);
    assert_eq!(got.method, "POST");
    assert_eq!(got.status_code, 201);
    assert_eq!(got.timestamp, ts_of(1));
    assert_eq!(got.correlation_id.as_deref(), Some("agent-7"));
    assert_eq!(got.request_body, r#"{"query":"Hello World"}"#);
    assert_eq!(got.response_body, r#"{"ok":true}"#);
    assert_eq!(
        got.request_headers
            .iter()
            .map(|(k, _)| k.as_str())
            .collect::<Vec<_>>(),
        ["Cookie", "X-ProxyX-Agent", "X-Trace"]
    );
    assert!(
        store
            .get_request("another-org", a_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .get_request(ORG, Uuid::new_v4())
            .await
            .unwrap()
            .is_none()
    );

    // Body fetch honours the size cap per side.
    let with_bodies = tq(json!({
        "request_body_max_fetch_size": 10,
        "response_body_max_fetch_size": 100,
    }));
    let page = store.search_requests(&with_bodies).await.unwrap();
    let (first, second) = (&page.items[0], &page.items[1]);
    assert!(
        matches!(&first.request_body, Some(BodyFetch::TooLarge { size: 23 })),
        "the request body of the first capture is 23 bytes, over the cap of 10: {:?}",
        first.request_body
    );
    assert!(
        matches!(&first.response_body, Some(BodyFetch::Body { value }) if value == r#"{"ok":true}"#)
    );
    assert!(matches!(&second.request_body, Some(BodyFetch::Body { value }) if value == "ping"));
    let no_bodies = store.search_requests(&all).await.unwrap();
    assert!(
        no_bodies
            .items
            .iter()
            .all(|i| i.request_body.is_none() && i.response_body.is_none())
    );

    h.finish().await;
}

/// Values at the edges of what the index can express, each with the rows
/// ClickHouse returns ([`boundary_cases`]): whole-string regexes (which the
/// `wildcard` field answers wrongly as a regexp), a status beyond the 32-bit
/// `integer` type, and case folding beyond ASCII.
#[tokio::test]
async fn boundary_values_match_clickhouse() {
    let Some(h) = Harness::start("boundary_values_match_clickhouse").await else {
        return;
    };
    let mut messages = boundary_messages();
    messages.extend(boundary_close_messages());
    h.deliver(messages).await;
    let store = &h.store;

    // This store folds `contains` with Unicode simple case folding;
    // ClickHouse folds ASCII only, which is a documented difference.
    let (c, d) = (uuid_n(3), uuid_n(4));
    let (a, b, e) = (uuid_n(1), uuid_n(2), uuid_n(5));
    let (f, g) = (uuid_n(6), uuid_n(7));
    let all = [a, b, c, d, e, f, g];
    let without = |gone: Uuid| {
        all.iter()
            .copied()
            .filter(|id| *id != gone)
            .collect::<Vec<_>>()
    };
    let rx = |value: &str| json!({ "op": "regex_match", "value": value });
    let mut cases = boundary_cases();
    cases.extend([
        (
            "contains folds a non-ASCII letter",
            json!({ "response_body": contains("ÜNÏ") }),
            vec![c, d],
        ),
        (
            "contains folds around ASCII and a space",
            json!({ "response_body": contains("ünï b") }),
            vec![c, d],
        ),
        (
            "not contains a non-ASCII letter",
            json!({ "response_body": not(contains("ünï")) }),
            vec![a, b, e, f, g],
        ),
        (
            "k matches KELVIN SIGN",
            json!({ "response_body": contains("k") }),
            vec![f],
        ),
        (
            "K matches KELVIN SIGN",
            json!({ "response_body": contains("K") }),
            vec![f],
        ),
        (
            "KELVIN SIGN matches k",
            json!({ "response_body": contains("\u{212a}") }),
            vec![f],
        ),
        (
            "s matches LONG S",
            json!({ "response_body": contains("s") }),
            vec![g],
        ),
        (
            "S matches LONG S",
            json!({ "response_body": contains("S") }),
            vec![g],
        ),
        (
            "LONG S matches s",
            json!({ "response_body": contains("\u{17f}") }),
            vec![g],
        ),
        (
            "not k leaves out KELVIN SIGN",
            json!({ "response_body": not(contains("k")) }),
            without(f),
        ),
        (
            "not LONG S leaves out s",
            json!({ "response_body": not(contains("\u{17f}")) }),
            without(g),
        ),
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
        assert_eq!(ids(store, &query).await, expected, "{name}");
        assert_eq!(
            store.count_requests(&query).await.unwrap(),
            expected.len() as u64,
            "{name} count"
        );
    }
    let mut ws_cases = boundary_ws_cases();
    let (k, s) = (uuid_n(603), uuid_n(604));
    let payload = |filter: Value| json!({ "payload": filter });
    ws_cases.extend([
        ("ws k matches KELVIN SIGN", payload(contains("k")), vec![k]),
        ("ws KELVIN SIGN matches K", payload(contains("K")), vec![k]),
        ("ws s matches LONG S", payload(contains("s")), vec![s]),
        ("ws LONG S matches S", payload(contains("\u{17f}")), vec![s]),
        (
            "ws not k",
            payload(not(contains("k"))),
            vec![uuid_n(601), uuid_n(602), s],
        ),
        (
            "ws not S",
            payload(not(contains("S"))),
            vec![uuid_n(601), uuid_n(602), k],
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

    h.finish().await;
}

#[tokio::test]
async fn cursor_paging_in_every_order() {
    let Some(h) = Harness::start("cursor_paging_in_every_order").await else {
        return;
    };
    h.deliver(series(25)).await;
    let store = &h.store;

    let page_through = |query: Value| async move {
        let mut seen: Vec<Uuid> = Vec::new();
        let mut cursor: Option<String> = None;
        let mut pages = 0;
        loop {
            let mut q = query.clone();
            q["cursor"] = json!(cursor);
            let page = store.search_requests(&tq(q)).await.unwrap();
            seen.extend(page.items.iter().map(|i| i.id));
            pages += 1;
            match page.next_cursor {
                Some(next) => cursor = Some(next),
                None => return (seen, pages),
            }
            assert!(pages < 20, "paging does not terminate");
        }
    };

    // Ascending, three pages of 10, 10 and 5 with no row lost or repeated.
    let (seen, pages) = page_through(json!({ "limit": 10 })).await;
    assert_eq!(pages, 3);
    assert_eq!(seen, (1..=25).map(uuid_n).collect::<Vec<_>>());

    // Descending.
    let (seen, pages) = page_through(json!({ "limit": 10, "order": "desc" })).await;
    assert_eq!(pages, 3);
    assert_eq!(seen, (1..=25).rev().map(uuid_n).collect::<Vec<_>>());

    // A page that exactly fills the limit has no next page.
    let page = store
        .search_requests(&tq(json!({ "limit": 25 })))
        .await
        .unwrap();
    assert_eq!(page.items.len(), 25);
    assert!(page.next_cursor.is_none());

    // Ordered by a column: status descending, newest first within a status.
    let mut expected: Vec<u64> = (1..=25).collect();
    expected.sort_by_key(|i| std::cmp::Reverse((200 + i % 5, *i)));
    let (seen, _) =
        page_through(json!({ "limit": 7, "order": "desc", "order_by": "status_code" })).await;
    assert_eq!(
        seen,
        expected.iter().map(|i| uuid_n(*i)).collect::<Vec<_>>()
    );

    // Ordered by URL (host + path), ascending: lexicographic, not numeric.
    let mut by_url: Vec<u64> = (1..=25).collect();
    by_url.sort_by_key(|i| format!("/items/{i}"));
    let (seen, _) = page_through(json!({ "limit": 8, "order_by": "url" })).await;
    assert_eq!(seen, by_url.iter().map(|i| uuid_n(*i)).collect::<Vec<_>>());

    // The count follows the cursor like the SQL count does: it counts what
    // comes after it.
    let first = store
        .search_requests(&tq(json!({ "limit": 10 })))
        .await
        .unwrap();
    let cursor = first.next_cursor.unwrap();
    assert_eq!(
        store
            .count_requests(&tq(json!({ "cursor": cursor })))
            .await
            .unwrap(),
        15
    );

    // `end_cursor` bounds the range from above (inclusive).
    let tenth = first.items.last().unwrap().id;
    let end = store
        .search_requests(&tq(json!({ "limit": 10 })))
        .await
        .unwrap()
        .next_cursor
        .unwrap();
    let bounded = tq(json!({ "cursor": null, "end_cursor": end }));
    assert_eq!(ids(store, &bounded).await.last().copied(), Some(tenth));

    // A cursor of another order is refused, as ClickHouse does.
    let by_status = tq(json!({ "limit": 3, "order_by": "status_code" }));
    let status_cursor = store
        .search_requests(&by_status)
        .await
        .unwrap()
        .next_cursor
        .unwrap();
    let wrong = tq(json!({ "limit": 3, "cursor": status_cursor }));
    assert!(store.search_requests(&wrong).await.is_err());

    // Newest capture and distinct count of the slice.
    let seq = store.sequence(ORG, "run-1").await.unwrap();
    assert_eq!(seq.count, 25);
    let newest = seq.cursor.unwrap();
    assert!(
        ids(store, &tq(json!({ "cursor": newest })))
            .await
            .is_empty()
    );
    assert_eq!(store.sequence(ORG, "nobody").await.unwrap().count, 0);

    h.finish().await;
}

#[tokio::test]
async fn redelivery_does_not_duplicate() {
    let Some(h) = Harness::start("redelivery_does_not_duplicate").await else {
        return;
    };

    // Case B: the proxy publishes the same capture twice (two broker
    // positions); both reach one bulk request. Then the broker redelivers.
    let ws = |event: u64| {
        Message::Ws(wire::CapturedWsMessage {
            event_id: uuid_n(event).as_bytes().to_vec().into(),
            parent_event_id: uuid_n(500).as_bytes().to_vec().into(),
            session_id: uuid_n(9_000).as_bytes().to_vec().into(),
            proxy_id: "proxy-1".into(),
            org_id: ORG.into(),
            source: "crawler".into(),
            source_id: "run-1".into(),
            timestamp_nanos: base_nanos() + event as i64 * 1_000_000_000,
            direction: wire::WsDirection::C2s as i32,
            opcode: wire::WsOpcode::Text as i32,
            payload: b"hi".to_vec().into(),
            payload_size: 2,
            host: "ws.example.com".into(),
            ..Default::default()
        })
    };
    let acked = h
        .deliver(vec![
            Message::Http(capture(1)),
            Message::Http(capture(1)),
            Message::Http(capture(2)),
            ws(600),
            ws(600),
        ])
        .await;
    assert_eq!(acked, 5, "duplicates are acked too");

    // Case A: the whole batch is redelivered after a lost ack.
    let acked = h
        .deliver(vec![
            Message::Http(capture(1)),
            Message::Http(capture(2)),
            ws(600),
        ])
        .await;
    assert_eq!(acked, 3);

    let store = &h.store;
    let all = tq(json!({}));
    assert_eq!(ids(store, &all).await, vec![uuid_n(1), uuid_n(2)]);
    assert_eq!(store.count_requests(&all).await.unwrap(), 2);
    assert_eq!(store.sequence(ORG, "run-1").await.unwrap().count, 2);
    let messages = wq(json!({}));
    assert_eq!(store.count_ws(&messages).await.unwrap(), 1);
    assert_eq!(store.search_ws(&messages).await.unwrap().items.len(), 1);

    h.finish().await;
}

#[tokio::test]
async fn websocket_messages_and_conversations() {
    let Some(h) = Harness::start("websocket_messages_and_conversations").await else {
        return;
    };

    let parent = uuid_n(500);
    let mut handshake = capture(500);
    handshake.path = "/stream".into();
    handshake.response_status = 101;
    handshake.host = "ws.example.com".into();

    let message =
        |event: u64, direction: wire::WsDirection, opcode: wire::WsOpcode, payload: &[u8]| {
            Message::Ws(wire::CapturedWsMessage {
                event_id: uuid_n(event).as_bytes().to_vec().into(),
                parent_event_id: parent.as_bytes().to_vec().into(),
                session_id: uuid_n(9_000).as_bytes().to_vec().into(),
                proxy_id: "proxy-1".into(),
                org_id: ORG.into(),
                source: "crawler".into(),
                source_id: "run-1".into(),
                timestamp_nanos: base_nanos() + event as i64 * 1_000_000_000,
                direction: direction as i32,
                opcode: opcode as i32,
                payload: payload.to_vec().into(),
                payload_size: payload.len() as u64,
                host: "ws.example.com".into(),
                ..Default::default()
            })
        };
    use wire::{WsDirection::*, WsOpcode::*};
    h.deliver(vec![
        Message::Http(handshake),
        message(601, C2s, Text, br#"{"subscribe":"ticker"}"#),
        message(602, S2c, Text, br#"{"ticker":"BTC","px":1}"#),
        message(603, S2c, Binary, &[0xff, 0xfe, b'o', b'k']),
        message(604, S2c, Text, br#"{"ticker":"ETH","px":2}"#),
        message(605, C2s, Text, b"bye"),
    ])
    .await;

    let store = &h.store;
    let by_parent =
        wq(json!({ "branches": [{ "parent_event_id": parent.to_string().to_uppercase() }] }));
    let page = store.search_ws(&by_parent).await.unwrap();
    assert_eq!(page.items.len(), 5);
    assert_eq!(page.items[0].id, uuid_n(601));
    assert_eq!(page.items[0].direction, "c2s");
    assert_eq!(page.items[2].opcode, "binary");
    assert!(page.items.iter().all(|i| i.payload.is_none()));
    assert_eq!(store.count_ws(&by_parent).await.unwrap(), 5);

    // Filters.
    let ticker = wq(
        json!({ "branches": [{ "payload": { "op": "contains", "value": "TICKER" },
                                           "direction": { "op": "exact", "value": "s2c" } }] }),
    );
    let found: Vec<Uuid> = store
        .search_ws(&ticker)
        .await
        .unwrap()
        .items
        .iter()
        .map(|i| i.id)
        .collect();
    assert_eq!(found, vec![uuid_n(602), uuid_n(604)]);

    // Payload fetch obeys the cap; a binary payload comes back lossy.
    let with_payload = wq(json!({ "payload_max_fetch_size": 10, "order": "asc" }));
    let items = store.search_ws(&with_payload).await.unwrap().items;
    assert!(matches!(
        &items[0].payload,
        Some(BodyFetch::TooLarge { size: 22 })
    ));
    assert!(matches!(&items[4].payload, Some(BodyFetch::Body { value }) if value == "bye"));
    assert!(matches!(&items[2].payload, Some(BodyFetch::Body { value }) if value.ends_with("ok")));

    // Paging two at a time, descending.
    let mut seen = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let page = store
            .search_ws(&wq(
                json!({ "limit": 2, "order": "desc", "cursor": cursor }),
            ))
            .await
            .unwrap();
        seen.extend(page.items.iter().map(|i| i.id));
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    assert_eq!(seen, [605, 604, 603, 602, 601].map(uuid_n));

    let one = store
        .get_ws_message(ORG, uuid_n(602))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(one.payload, r#"{"ticker":"BTC","px":1}"#);
    assert_eq!(one.parent_event_id, parent);
    assert!(
        store
            .get_ws_message("another-org", uuid_n(602))
            .await
            .unwrap()
            .is_none()
    );

    // Conversation discovery.
    let conversations = store
        .ws_conversations(&ConversationQuery {
            org_id: ORG,
            source_ids: None,
            source: Some("crawler"),
            host: None,
            limit: 10,
            descending: true,
        })
        .await
        .unwrap();
    assert_eq!(conversations.total_count, Some(1));
    let conversation = &conversations.items[0];
    assert_eq!(conversation.parent_event_id, parent);
    assert_eq!(conversation.path.as_deref(), Some("/stream"));
    assert_eq!(conversation.host, "ws.example.com");
    assert_eq!(conversation.message_count, 5);
    assert_eq!(conversation.client_to_server, 2);
    assert_eq!(conversation.server_to_client, 3);
    assert_eq!(conversation.first_at, ts_of(601));
    assert_eq!(conversation.last_at, ts_of(605));

    h.finish().await;
}

#[tokio::test]
async fn aggregates_and_unsupported_operations() {
    let Some(h) = Harness::start("aggregates_and_unsupported_operations").await else {
        return;
    };
    let store = &h.store;

    // Before any write: no indices yet, and no error.
    assert!(ids(store, &tq(json!({}))).await.is_empty());
    assert_eq!(store.count_requests(&tq(json!({}))).await.unwrap(), 0);

    h.deliver(series(25)).await;

    // 22:13:21 .. 22:13:45 is one minute.
    let start = ts_of(0) - time::Duration::seconds(20);
    let end = start + time::Duration::minutes(5);
    let rate = store.request_rate_series(ORG, start, end).await.unwrap();
    assert_eq!(rate.len(), 1);
    assert_eq!(rate[0].requests, 25);
    assert_eq!(rate[0].minute, ts_of(0) - time::Duration::seconds(20));

    // 10 s buckets are aligned to the epoch: :20 (9), :30 (10), :40 (6).
    let window = TimeSeriesQuery {
        org_id: Some(ORG),
        source_ids: None,
        start,
        end,
        bucket_seconds: 10,
    };
    let series = store.http_traffic_time_series(&window).await.unwrap();
    let counts: Vec<u64> = series.iter().map(|p| p.count).collect();
    assert_eq!(counts, [9, 10, 6]);
    assert!(
        series
            .iter()
            .all(|p| p.source_id == "run-1" && p.source == "crawler")
    );
    assert_eq!(series[0].bucket_start, "2023-11-14T22:13:20Z");

    let sources = ["run-1".to_string(), "run-2".to_string()];
    let summary = store
        .scan_traffic_summary(&TimeSeriesQuery {
            source_ids: Some(&sources),
            ..window.clone()
        })
        .await
        .unwrap();
    assert_eq!(summary.total, 25);
    assert_eq!(summary.by_source.len(), 1);
    assert_eq!(summary.by_source[0].source_id, "run-1");
    assert_eq!(
        summary.buckets.iter().map(|b| b.count).collect::<Vec<_>>(),
        [9, 10, 6]
    );

    // Another org sees nothing.
    assert!(
        store
            .request_rate_series("another-org", start, end)
            .await
            .unwrap()
            .is_empty()
    );

    // Traffic view exports are ClickHouse-only.
    let dynamic: &dyn CaptureStore = store;
    assert!(dynamic.view_exporter().is_none());
    assert!(matches!(
        dynamic.require_view_exporter(),
        Err(StoreError::Unsupported(message)) if message.contains("opensearch")
    ));

    // The ingester refuses to start without the templates.
    let mut elsewhere = h.config.clone();
    elsewhere.index_prefix = format!("{}-missing", h.config.index_prefix);
    assert!(opensearch::verify_templates(&elsewhere).await.is_err());

    h.finish().await;
}
