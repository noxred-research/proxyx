//! Protocol conformance over stdio: initialize, server/discover, tools, resources and prompts,
//! errors, and both protocol eras on one server.

mod common;

use common::*;
use serde_json::{Value, json};

#[tokio::test]
async fn legacy_handshake_negotiates_and_keeps_no_state() {
    let fx = Fixture::start().await;
    let server = fx.read_only();
    let frames = converse(
        &server,
        &[
            legacy(
                1,
                "initialize",
                json!({"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "desktop", "version": "9"}}),
            ),
            json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            legacy(2, "tools/list", json!({})),
            legacy(3, "ping", json!({})),
            legacy(
                4,
                "initialize",
                json!({"protocolVersion": "1999-01-01", "capabilities": {}}),
            ),
        ],
    )
    .await;
    assert_eq!(
        frames.len(),
        4,
        "the notification gets no reply: {frames:?}"
    );
    let by_id = |id: i64| frames.iter().find(|f| f["id"] == id).expect("reply by id");
    let init = &by_id(1)["result"];
    assert_eq!(init["protocolVersion"], "2025-06-18");
    assert_eq!(init["serverInfo"]["name"], "proxyx-mcp");
    assert!(init["capabilities"]["tools"].is_object());
    assert!(init["capabilities"]["resources"].is_object());
    assert!(init["capabilities"]["prompts"].is_object());
    assert!(
        init.get("resultType").is_none(),
        "legacy results have no envelope"
    );
    assert!(
        init["instructions"]
            .as_str()
            .expect("instructions")
            .contains("authorized")
    );
    assert!(by_id(2)["result"]["tools"].is_array());
    assert_eq!(by_id(3)["result"], json!({}));
    assert_eq!(
        by_id(4)["result"]["protocolVersion"],
        "2025-11-25",
        "an unknown version is answered with the newest legacy one"
    );
}

#[tokio::test]
async fn modern_requests_are_stateless_and_carry_the_envelope() {
    let fx = Fixture::start().await;
    let server = fx.read_only();
    let discover = ask(&server, modern(1, "server/discover", json!({}))).await;
    let result = &discover["result"];
    assert_eq!(result["resultType"], "complete");
    assert_eq!(result["supportedVersions"][0], "2026-07-28");
    assert!(
        result["supportedVersions"]
            .as_array()
            .expect("versions")
            .iter()
            .any(|v| v == "2025-11-25"),
        "dual-era server lists the legacy versions too"
    );
    assert_eq!(
        result["_meta"]["io.modelcontextprotocol/serverInfo"]["name"],
        "proxyx-mcp"
    );
    assert!(result["ttlMs"].as_u64().is_some());
    assert_eq!(result["cacheScope"], "public");

    let listed = ask(&server, modern(2, "tools/list", json!({}))).await;
    assert_eq!(listed["result"]["resultType"], "complete");
    assert!(listed["result"]["ttlMs"].is_u64());
    assert!(listed["result"]["cacheScope"].is_string());
    let again = ask(&server, modern(3, "tools/list", json!({}))).await;
    assert_eq!(
        tool_names(&listed),
        tool_names(&again),
        "tools/list is deterministic"
    );

    // A missing capability declaration is a malformed modern request.
    let missing = ask(
        &server,
        json!({"jsonrpc":"2.0","id":4,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}),
    )
    .await;
    assert_eq!(missing["error"]["code"], -32602);

    // An unknown version names the versions the server speaks.
    let unsupported = ask(
        &server,
        json!({"jsonrpc":"2.0","id":5,"method":"tools/list","params":{"_meta":{
            "io.modelcontextprotocol/protocolVersion":"1900-01-01","io.modelcontextprotocol/clientCapabilities":{}}}}),
    )
    .await;
    assert_eq!(unsupported["error"]["code"], -32022);
    assert_eq!(unsupported["error"]["data"]["requested"], "1900-01-01");
    assert!(
        unsupported["error"]["data"]["supported"]
            .as_array()
            .expect("supported")
            .len()
            >= 2
    );
}

#[tokio::test]
async fn tools_list_describes_every_tool_with_a_usable_schema() {
    let fx = Fixture::start().await;
    let server = fx.read_only();
    let reply = ask(&server, modern(1, "tools/list", json!({}))).await;
    let tools = reply["result"]["tools"].as_array().expect("tools");
    let names = tool_names(&reply);
    for expected in [
        "health",
        "metrics_snapshot",
        "pool_capacity",
        "breaker_states",
        "block_signal_rates",
        "recent_refusals",
        "diagnose",
        "capabilities",
        "list_inventory",
        "list_policies",
        "list_org_blocks",
        "get_org",
        "list_sessions",
        "session_status",
        "search_traffic",
        "count_traffic",
        "get_capture",
        "get_ws_conversation",
        "summarize_traffic",
        "classify_block_page",
        "explain_refusal",
        "explain_selector",
        "validate_policy",
        "propose_config_change",
        "apply_config_change",
    ] {
        assert!(names.iter().any(|n| n == expected), "{expected} is listed");
    }
    for tool in tools {
        let name = tool["name"].as_str().expect("name");
        assert!(
            name.len() <= 128
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
        );
        assert!(
            tool["description"].as_str().expect("description").len() > 20,
            "{name}"
        );
        assert_eq!(tool["inputSchema"]["type"], "object", "{name}");
        assert_eq!(tool["inputSchema"]["additionalProperties"], false, "{name}");
        assert!(tool["annotations"]["readOnlyHint"].is_boolean(), "{name}");
    }
    // A read-only server lists no mutating tool and no secret-returning tool.
    for hidden in [
        "create_session",
        "create_org_key",
        "put_policy",
        "put_inventory",
        "set_org_egress_proxy",
        "confirm_change",
        "suggest_policy",
    ] {
        assert!(
            !names.iter().any(|n| n == hidden),
            "{hidden} must not be listed on a read-only server"
        );
    }
    let readonly_hints = tools
        .iter()
        .filter(|t| t["annotations"]["readOnlyHint"] == true)
        .count();
    assert!(readonly_hints >= 20);
}

#[tokio::test]
async fn tools_call_errors_follow_the_spec() {
    let fx = Fixture::start().await;
    let server = fx.read_only();
    // unknown tool: protocol error
    let unknown = ask(&server, call(1, "no_such_tool", json!({}))).await;
    assert_eq!(unknown["error"]["code"], -32602);
    assert!(
        unknown["error"]["message"]
            .as_str()
            .expect("message")
            .contains("no_such_tool")
    );
    // bad arguments object: protocol error
    let bad_shape = ask(
        &server,
        modern(2, "tools/call", json!({"name": "health", "arguments": []})),
    )
    .await;
    assert_eq!(bad_shape["error"]["code"], -32602);
    // invalid arguments: tool execution error the model can fix
    let (is_error, value) = tool(
        &server,
        "list_inventory",
        json!({"state": "bogus", "limti": 3}),
    )
    .await;
    assert!(is_error);
    let text = value.to_string();
    assert!(
        text.contains("must be one of") && text.contains("unknown property"),
        "{text}"
    );
    // missing required argument
    let missing = tool_err(&server, "explain_selector", json!({})).await;
    assert!(missing.to_string().contains("required"));
    // unknown method
    let method = ask(&server, modern(3, "tools/frobnicate", json!({}))).await;
    assert_eq!(method["error"]["code"], -32601);
}

#[tokio::test]
async fn malformed_frames_are_answered_and_the_server_keeps_going() {
    let fx = Fixture::start().await;
    let server = fx.read_only();
    let input = format!(
        "{{not json\n[]\n{}\n{{\"jsonrpc\":\"2.0\",\"id\":null,\"method\":\"ping\"}}\n{}\n",
        json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}),
        json!({"jsonrpc": "2.0", "id": 2, "method": "ping"}),
    );
    let frames = converse_raw(server, input).await;
    assert_eq!(frames[0]["error"]["code"], -32700);
    assert_eq!(
        frames[1]["error"]["code"], -32600,
        "batches are not supported"
    );
    assert!(
        frames
            .iter()
            .any(|f| f["id"] == 1 && f["result"] == json!({}))
    );
    assert!(
        frames
            .iter()
            .any(|f| f["id"] == 2 && f["result"] == json!({}))
    );
    assert!(
        frames
            .iter()
            .any(|f| f["error"]["code"] == -32600 && f["id"].is_null()),
        "a null id is invalid"
    );
}

#[tokio::test]
async fn resources_list_read_and_templates() {
    let fx = Fixture::start().await;
    let server = fx.read_only();
    let listed = ask(&server, modern(1, "resources/list", json!({}))).await;
    assert_eq!(listed["result"]["resultType"], "complete");
    let uris: Vec<&str> = listed["result"]["resources"]
        .as_array()
        .expect("resources")
        .iter()
        .filter_map(|r| r["uri"].as_str())
        .collect();
    for expected in [
        "proxyx://docs/cause-codes",
        "proxyx://docs/query-dsl",
        "proxyx://docs/policy-format",
        "proxyx://docs/username-grammar",
        "proxyx://server/capabilities",
        "proxyx://health",
        "proxyx://pool/capacity",
        "proxyx://pool/policies",
        "proxyx://audit/recent",
    ] {
        assert!(uris.contains(&expected), "{expected} in {uris:?}");
    }
    for resource in listed["result"]["resources"].as_array().expect("resources") {
        assert!(resource["name"].is_string() && resource["mimeType"].is_string());
    }

    let causes = ask(
        &server,
        modern(
            2,
            "resources/read",
            json!({"uri": "proxyx://docs/cause-codes"}),
        ),
    )
    .await;
    let text = causes["result"]["contents"][0]["text"]
        .as_str()
        .expect("text");
    assert!(text.contains("`cache_empty`") && text.contains("`session_not_found`"));
    assert_eq!(causes["result"]["contents"][0]["mimeType"], "text/markdown");
    assert_eq!(
        causes["result"]["contents"][0]["uri"],
        "proxyx://docs/cause-codes"
    );
    assert!(causes["result"]["ttlMs"].is_u64());

    let health = ask(
        &server,
        modern(3, "resources/read", json!({"uri": "proxyx://health"})),
    )
    .await;
    let body: Value = serde_json::from_str(
        health["result"]["contents"][0]["text"]
            .as_str()
            .expect("text"),
    )
    .expect("json");
    assert_eq!(body["overall"], "ok");
    assert_eq!(health["result"]["cacheScope"], "private");

    let cause = ask(
        &server,
        modern(
            4,
            "resources/read",
            json!({"uri": "proxyx://causes/lease_timeout"}),
        ),
    )
    .await;
    let body: Value = serde_json::from_str(
        cause["result"]["contents"][0]["text"]
            .as_str()
            .expect("text"),
    )
    .expect("json");
    assert_eq!(body["http_status"], 504);

    let templates = ask(&server, modern(5, "resources/templates/list", json!({}))).await;
    let names: Vec<&str> = templates["result"]["resourceTemplates"]
        .as_array()
        .expect("templates")
        .iter()
        .filter_map(|t| t["uriTemplate"].as_str())
        .collect();
    assert!(
        names.contains(&"proxyx://sessions/{session_id}")
            && names.contains(&"proxyx://causes/{code}")
    );

    // Not found: -32602 in the modern era, -32002 for legacy clients.
    let modern_missing = ask(
        &server,
        modern(6, "resources/read", json!({"uri": "proxyx://nope"})),
    )
    .await;
    assert_eq!(modern_missing["error"]["code"], -32602);
    let legacy_missing = ask(
        &server,
        legacy(7, "resources/read", json!({"uri": "proxyx://nope"})),
    )
    .await;
    assert_eq!(legacy_missing["error"]["code"], -32002);
    let alias = existing_session_handle(&server).await;
    let live = ask(
        &server,
        modern(
            8,
            "resources/read",
            json!({"uri": format!("proxyx://sessions/{alias}")}),
        ),
    )
    .await;
    assert!(
        live["result"]["contents"][0]["text"]
            .as_str()
            .expect("text")
            .contains("captured_hosts")
    );
}

#[tokio::test]
async fn prompts_list_and_get() {
    let fx = Fixture::start().await;
    let server = fx.read_only();
    let listed = ask(&server, modern(1, "prompts/list", json!({}))).await;
    let names: Vec<&str> = listed["result"]["prompts"]
        .as_array()
        .expect("prompts")
        .iter()
        .filter_map(|p| p["name"].as_str())
        .collect();
    for expected in ["triage_blocks", "capacity_review", "session_debug"] {
        assert!(names.contains(&expected), "{expected} in {names:?}");
    }
    let got = ask(
        &server,
        modern(
            2,
            "prompts/get",
            json!({"name": "triage_blocks", "arguments": {"provider": "p1"}}),
        ),
    )
    .await;
    let message = &got["result"]["messages"][0];
    assert_eq!(message["role"], "user");
    let text = message["content"]["text"].as_str().expect("text");
    assert!(
        text.contains("block_signal_rates")
            && text.contains("provider `p1`")
            && text.contains("untrusted")
    );
    let missing = ask(
        &server,
        modern(
            3,
            "prompts/get",
            json!({"name": "session_debug", "arguments": {}}),
        ),
    )
    .await;
    assert_eq!(missing["error"]["code"], -32602);
    let unknown = ask(&server, modern(4, "prompts/get", json!({"name": "nope"}))).await;
    assert_eq!(unknown["error"]["code"], -32602);
}

#[tokio::test]
async fn requests_run_concurrently_and_cancellation_is_honoured() {
    let fx = Fixture::start().await;
    let server = fx.read_only();
    let frames = converse(
        &server,
        &[
            call(1, "health", json!({})),
            call(2, "explain_refusal", json!({"code": "cache_empty"})),
            call(3, "capabilities", json!({})),
            json!({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 99}}),
        ],
    )
    .await;
    assert_eq!(frames.len(), 3);
    for frame in &frames {
        assert_eq!(frame["result"]["resultType"], "complete");
        assert_eq!(frame["result"]["isError"], false);
    }
}
