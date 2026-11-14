//! While capture analysis is on, every tool that returns stored captures stays inside the
//! operator's allowed sources and origins, with or without a scope handle. Also the opaque
//! correlation keys a scope can be limited to.

mod common;

use common::*;
use serde_json::{Value, json};

const OUTSIDE_SOURCE: &str = "lab-agent-r1";

/// Path markers: none of the "outside" ones may ever reach a result.
const INSIDE: &str = "/inside-marker";
const OUT_SOURCE: &str = "/outside-source-marker";
const OUT_ORIGIN: &str = "/outside-origin-marker";
const OUT_ORG: &str = "/outside-org-marker";

fn captures() -> Vec<Value> {
    let mut other_org = cap(4, "run-1", "api.example.com", "GET", OUT_ORG, 200);
    other_org["org_id"] = json!("rival");
    vec![
        cap(1, "run-1", "api.example.com", "GET", INSIDE, 200),
        cap(2, OUTSIDE_SOURCE, "api.example.com", "GET", OUT_SOURCE, 200),
        cap(3, "run-1", "internal.example.net", "GET", OUT_ORIGIN, 200),
        other_org,
    ]
}

fn ws_message(n: u32, parent: u32, source: &str, host: &str, payload: &str) -> Value {
    json!({
        "id": format!("0190cccc-0000-4000-8000-{n:012}"), "parent_event_id": uid(parent),
        "org_id": "acme", "source_id": source, "source": "mcp", "host": host,
        "direction": "c2s", "opcode": "text", "payload": payload, "payload_size": payload.len(),
        "timestamp": "2026-11-10T10:00:00.000Z", "session_offset": n, "proxy_id": "proxy-1",
        "session_id": SESSION_ID, "payload_truncated": false, "payload_is_text": true,
        "was_compressed": false, "close_code": 0, "close_reason": ""
    })
}

fn ws_messages() -> Vec<Value> {
    vec![
        ws_message(1, 1, "run-1", "api.example.com", "inside-ws"),
        ws_message(2, 2, OUTSIDE_SOURCE, "api.example.com", "outside-source-ws"),
        ws_message(3, 3, "run-1", "internal.example.net", "outside-origin-ws"),
        // a connection whose messages came from two sources: each message is judged alone
        ws_message(4, 1, OUTSIDE_SOURCE, "api.example.com", "outside-mixed-ws"),
    ]
}

fn assert_no_outside(what: &str, text: &str) {
    for marker in [
        OUT_SOURCE,
        OUT_ORIGIN,
        OUT_ORG,
        "outside-source-ws",
        "outside-origin-ws",
        "outside-mixed-ws",
        OUTSIDE_SOURCE,
        "internal.example.net",
    ] {
        assert!(!text.contains(marker), "{marker} reached {what}: {text}");
    }
}

fn any_branches() -> Value {
    json!([{"method": {"op": "exact", "value": "GET"}}])
}

async fn fixture() -> Fixture {
    let fx = Fixture::start().await;
    store(&fx, captures());
    fx.control_state.lock().expect("control").ws = Some(ws_messages());
    fx
}

#[tokio::test]
async fn every_capture_returning_tool_stays_inside_the_operator_ceiling() {
    let fx = fixture().await;
    let server = fx.analysis_server("", "", "[analysis.feeds]\nmin_poll_interval_ms = 20\n");

    // search: a source outside the ceiling is refused, and an unconstrained query only returns
    // what the ceiling allows even though the (fake) store ignores the filters
    for branches in [
        json!([{"source_id": OUTSIDE_SOURCE}]),
        json!([{"source_id": ["run-1", OUTSIDE_SOURCE]}]),
        json!([{"method": {"op": "exact", "value": "GET"}}, {"source_id": OUTSIDE_SOURCE}]),
    ] {
        for tool in ["search_traffic", "count_traffic"] {
            let error = tool_err(&server, tool, json!({"branches": branches})).await;
            assert!(
                error.to_string().contains("outside the analysis scope"),
                "{tool}: {error}"
            );
        }
    }
    // a WebSocket branch names one source
    let error = tool_err(
        &server,
        "search_ws",
        json!({"branches": [{"source_id": OUTSIDE_SOURCE}]}),
    )
    .await;
    assert!(
        error.to_string().contains("outside the analysis scope"),
        "{error}"
    );
    let found = tool_ok(
        &server,
        "search_traffic",
        json!({"branches": any_branches()}),
    )
    .await;
    assert_eq!(found["count"], 1, "{found}");
    assert!(found.to_string().contains(INSIDE));
    assert_eq!(found["withheld_outside_analysis_scope"], 3, "{found}");
    assert_no_outside("search_traffic", &found.to_string());
    let sent = fx.control.log.calls("POST", "/rpc/requests/search");
    let body = &sent.last().expect("search sent").body;
    for branch in body["branches"].as_array().expect("branches") {
        assert_eq!(branch["source_id"], json!(["run-1", "run-2"]), "{body}");
        assert!(
            branch["host"].is_object(),
            "an origin filter on every branch: {body}"
        );
    }

    // count: the query the store counts is the confined one
    tool_ok(
        &server,
        "count_traffic",
        json!({"branches": any_branches()}),
    )
    .await;
    let sent = fx.control.log.calls("POST", "/rpc/requests/count");
    for branch in sent.last().expect("count sent").body["branches"]
        .as_array()
        .expect("branches")
    {
        assert_eq!(branch["source_id"], json!(["run-1", "run-2"]));
        assert!(branch["host"].is_object());
    }

    // get_capture and the resource refuse a capture outside, whatever the reason
    for n in [2, 3, 4] {
        let error = tool_err(&server, "get_capture", json!({"id": uid(n)})).await;
        assert!(
            error.to_string().contains("outside the analysis scope"),
            "{n}: {error}"
        );
        assert_no_outside("get_capture", &error.to_string());
        let read = ask(
            &server,
            modern(
                n.into(),
                "resources/read",
                json!({"uri": format!("proxyx://captures/acme/{}", uid(n))}),
            ),
        )
        .await;
        assert!(
            read.to_string().contains("outside the analysis scope"),
            "{n}: {read}"
        );
        assert_no_outside("the capture resource", &read.to_string());
    }
    let inside = tool_ok(&server, "get_capture", json!({"id": uid(1)})).await;
    assert_eq!(inside["path"], INSIDE);
    let read = ask(
        &server,
        modern(
            9,
            "resources/read",
            json!({"uri": format!("proxyx://captures/acme/{}", uid(1))}),
        ),
    )
    .await;
    assert!(read.to_string().contains(INSIDE), "{read}");

    // WebSocket: search and conversation return only admitted messages
    let ws_branches = json!([{"direction": {"op": "exact", "value": "c2s"}}]);
    let found = tool_ok(&server, "search_ws", json!({"branches": ws_branches})).await;
    assert_eq!(found["count"], 1, "{found}");
    assert!(found.to_string().contains("inside-ws"));
    assert_no_outside("search_ws", &found.to_string());
    for parent in [1, 2, 3] {
        let conversation = tool_ok(
            &server,
            "get_ws_conversation",
            json!({"parent_event_id": uid(parent)}),
        )
        .await;
        assert_no_outside("get_ws_conversation", &conversation.to_string());
        assert_eq!(
            conversation["count"],
            u32::from(parent == 1),
            "{conversation}"
        );
    }
    let sent = fx.control.log.calls("POST", "/rpc/ws/search");
    for branch in sent.last().expect("ws search sent").body["branches"]
        .as_array()
        .expect("branches")
    {
        assert!(
            ["run-1", "run-2"].contains(&branch["source_id"].as_str().expect("one source")),
            "a WebSocket branch pins one allowed source: {branch}"
        );
    }

    // statistics without a model are confined too
    let stats = tool_ok(
        &server,
        "summarize_traffic",
        json!({"branches": any_branches()}),
    )
    .await;
    assert_eq!(stats["sampled"], 1, "{stats}");
    assert_no_outside("summarize_traffic", &stats.to_string());
    let error = tool_err(
        &server,
        "summarize_traffic",
        json!({"branches": [{"source_id": OUTSIDE_SOURCE}]}),
    )
    .await;
    assert!(
        error.to_string().contains("outside the analysis scope"),
        "{error}"
    );

    // classification of a stored capture needs a scope that admits it
    let scope_id = open_scope(&server, &["run-1"]).await;
    for n in [2, 3, 4] {
        let error = tool_err(
            &server,
            "classify_block_page",
            json!({"scope_id": scope_id, "capture_id": uid(n)}),
        )
        .await;
        assert!(error.to_string().contains("outside"), "{n}: {error}");
    }

    // a feed opened before the captures arrive returns only admitted ones
    store(
        &fx,
        vec![cap(9, "run-1", "api.example.com", "GET", "/seed", 200)],
    );
    let opened = tool_ok(&server, "open_capture_feed", json!({"scope_id": scope_id})).await;
    let feed_id = opened["feed_id"].as_str().expect("feed id").to_owned();
    store(&fx, captures());
    tokio::time::sleep(std::time::Duration::from_millis(40)).await;
    let page = tool_ok(&server, "read_capture_feed", json!({"feed_id": feed_id})).await;
    assert_no_outside("read_capture_feed", &page.to_string());
}

#[tokio::test]
async fn without_analysis_the_capture_tools_are_unchanged() {
    let fx = fixture().await;
    let server = fx.read_only();
    let found = tool_ok(
        &server,
        "search_traffic",
        json!({"branches": [{"source_id": OUTSIDE_SOURCE}]}),
    )
    .await;
    assert_eq!(found["count"], 4, "{found}");
    assert!(found.get("withheld_outside_analysis_scope").is_none());
    tool_ok(&server, "get_capture", json!({"id": uid(2)})).await;
}

// --- correlation keys -------------------------------------------------------------------------------------

fn with_correlation(mut capture: Value, key: &str) -> Value {
    capture["correlation_id"] = json!(key);
    capture
}

#[tokio::test]
async fn a_scope_limited_to_correlation_keys_filters_every_branch_and_admits_only_those() {
    let fx = Fixture::start().await;
    let server = fx.analysis_server("", "", "[analysis.feeds]\nmin_poll_interval_ms = 20\n");
    let opened = tool_ok(
        &server,
        "open_analysis_scope",
        json!({"source_ids": ["run-1"], "correlation_ids": ["sess_b", "sess_a", "sess_a"]}),
    )
    .await;
    assert_eq!(opened["correlation_ids"], json!(["sess_a", "sess_b"]));
    let scope_id = opened["scope_id"].as_str().expect("scope").to_owned();

    let seed = cap(9, "run-1", "api.example.com", "GET", "/seed", 200);
    store(&fx, vec![seed.clone()]);
    let feed = tool_ok(&server, "open_capture_feed", json!({"scope_id": scope_id})).await;
    let feed_id = feed["feed_id"].as_str().expect("feed").to_owned();
    store(
        &fx,
        vec![
            seed,
            with_correlation(
                cap(1, "run-1", "api.example.com", "GET", "/a", 200),
                "sess_a",
            ),
            with_correlation(
                cap(2, "run-1", "api.example.com", "GET", "/b", 200),
                "sess_b",
            ),
            with_correlation(
                cap(3, "run-1", "api.example.com", "GET", "/c", 200),
                "sess_c",
            ),
            cap(4, "run-1", "api.example.com", "GET", "/none", 200),
        ],
    );
    tokio::time::sleep(std::time::Duration::from_millis(40)).await;
    let page = tool_ok(&server, "read_capture_feed", json!({"feed_id": feed_id})).await;
    let paths: Vec<&str> = page["items"]
        .as_array()
        .expect("items")
        .iter()
        .filter_map(|item| item["path"].as_str())
        .collect();
    assert_eq!(paths, ["/a", "/b"], "{page}");
    let sent = fx.control.log.calls("POST", "/rpc/requests/search");
    let body = &sent.last().expect("search sent").body;
    for branch in body["branches"].as_array().expect("branches") {
        assert_eq!(
            branch["correlation_id"],
            json!({"op": "any", "filters": [
                {"op": "exact", "value": "sess_a"}, {"op": "exact", "value": "sess_b"}
            ]}),
            "{body}"
        );
    }
}

#[tokio::test]
async fn correlation_keys_are_validated_and_cannot_cover_websocket_messages() {
    let fx = Fixture::start().await;
    let server = fx.analysis_server("", "", "");
    for bad in [
        json!(["has space"]),
        json!(["semi;colon"]),
        json!([""]),
        json!(["k".repeat(65)]),
        json!([1]),
        json!("sess_a"),
    ] {
        let error = tool_err(
            &server,
            "open_analysis_scope",
            json!({"source_ids": ["run-1"], "correlation_ids": bad}),
        )
        .await;
        assert!(error.to_string().contains("correlation"), "{bad}: {error}");
    }
    let limited = tool_ok(
        &server,
        "open_analysis_scope",
        json!({"source_ids": ["run-1"], "correlation_ids": ["sess_a"]}),
    )
    .await;
    let plain = tool_ok(
        &server,
        "open_analysis_scope",
        json!({"source_ids": ["run-1"]}),
    )
    .await;
    assert_ne!(limited["scope_digest"], plain["scope_digest"]);
    assert_eq!(plain["correlation_ids"], json!([]));
}
