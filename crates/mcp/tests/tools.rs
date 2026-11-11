//! Read-only tools against the fakes: monitoring, state, traffic, explanations.

mod common;

use std::time::Duration;

use common::*;
use serde_json::{Value, json};

fn find<'a>(rows: &'a Value, key: &str, value: &str) -> &'a Value {
    rows.as_array()
        .unwrap_or_else(|| panic!("rows are an array: {rows}"))
        .iter()
        .find(|row| row[key] == value)
        .unwrap_or_else(|| panic!("no row with {key}={value} in {rows}"))
}

#[tokio::test]
async fn health_reports_every_role_and_notices_trouble() {
    let fx = Fixture::start().await;
    let server = fx.read_only();
    let healthy = tool_ok(&server, "health", json!({})).await;
    assert_eq!(healthy["overall"], "ok");
    assert_eq!(healthy["roles"].as_array().expect("roles").len(), 3);
    assert_eq!(
        find(&healthy["roles"], "role", "gateway")["verdict"],
        "healthy"
    );

    *fx.warmer_ops.ready.lock().expect("ready") = (503, "redis unavailable".into());
    let degraded = tool_ok(&server, "health", json!({"role": "warmer"})).await;
    assert_eq!(degraded["overall"], "degraded");
    let warmer = find(&degraded["roles"], "role", "warmer");
    assert_eq!(warmer["verdict"], "not_ready");
    assert_eq!(warmer["ready"]["detail"], "redis unavailable");

    let missing = tool_err(&server, "health", json!({"role": "nope"})).await;
    assert!(missing.to_string().contains("nope"));

    // a role that is not running at all
    let dead = fx.server(
        "",
        "[[endpoints.roles]]\nname = \"dead\"\nkind = \"gateway\"\nurl = \"http://127.0.0.1:9\"\n",
    );
    let down = tool_ok(&dead, "health", json!({"role": "dead"})).await;
    assert_eq!(down["overall"], "down");
    assert_eq!(down["roles"][0]["verdict"], "down");
}

#[tokio::test]
async fn metrics_snapshot_summarizes_documented_families() {
    let fx = Fixture::start().await;
    let server = fx.read_only();
    let snapshot = tool_ok(
        &server,
        "metrics_snapshot",
        json!({"family": "connections"}),
    )
    .await;
    let families = snapshot["families"].as_array().expect("families");
    assert_eq!(families.len(), 1);
    assert_eq!(families[0]["family"], "proxyx_pool_connections_total");
    assert_eq!(families[0]["total"], 101.0);
    assert_eq!(families[0]["series"][0]["labels"]["outcome"], "ok");
    let warmer_only = tool_ok(
        &server,
        "metrics_snapshot",
        json!({"role": "warmer", "family": "cache_ready"}),
    )
    .await;
    assert_eq!(warmer_only["roles"], json!(["warmer"]));
    assert_eq!(warmer_only["families"][0]["total"], 15.0);
}

#[tokio::test]
async fn pool_capacity_and_breakers() {
    let fx = Fixture::start().await;
    let server = fx.read_only();
    let capacity = tool_ok(&server, "pool_capacity", json!({})).await;
    assert_eq!(capacity["status"], "below_watermark");
    let p1 = capacity["providers"]
        .as_array()
        .expect("providers")
        .iter()
        .find(|p| p["provider"] == "p1")
        .expect("p1");
    assert_eq!(p1["verdict"], "below_watermark");
    assert_eq!(p1["ready"], 3.0);
    assert_eq!(p1["ready_degraded"], 1.0);
    assert_eq!(p1["min_ready"], 10.0);
    assert_eq!(p1["shortfall"], 7.0);
    assert_eq!(p1["cache_low_alert_condition"], true);
    assert_eq!(p1["breaker"], "open");
    assert_eq!(p1["cost_used_ratio"], 0.4);
    let p2 = capacity["providers"]
        .as_array()
        .expect("providers")
        .iter()
        .find(|p| p["provider"] == "p2")
        .expect("p2");
    assert_eq!(p2["verdict"], "ok");
    assert_eq!(capacity["rotating_sessions_by_state"]["ready"], 15.0);
    assert_eq!(
        capacity["inventory_by_provider_and_state"]["isp1"]["available"],
        4.0
    );
    let only = tool_ok(&server, "pool_capacity", json!({"provider": "p2"})).await;
    assert_eq!(only["providers"].as_array().expect("providers").len(), 1);

    let breakers = tool_ok(&server, "breaker_states", json!({})).await;
    assert_eq!(breakers["open_providers"], json!(["p1"]));
    assert_eq!(
        find(&breakers["providers"], "provider", "p1")["tunnel_skips_total"],
        17.0
    );
    assert_eq!(
        find(&breakers["providers"], "provider", "p2")["state"],
        "closed"
    );
}

#[tokio::test]
async fn refusals_and_block_signals_report_rates_once_a_baseline_exists() {
    let fx = Fixture::start().await;
    let server = fx.read_only();
    let first = tool_ok(&server, "recent_refusals", json!({})).await;
    assert!(
        first["rates"]["window_secs"].is_null(),
        "no baseline on the first call"
    );
    let refusals = &first["refusals"];
    let cache_empty = find(refusals, "outcome", "cache_empty");
    assert_eq!(cache_empty["total"], 8.0);
    assert_eq!(cache_empty["http_status"], 503);
    assert!(
        cache_empty["meaning"]
            .as_str()
            .expect("meaning")
            .contains("No session or IP")
    );
    assert!(cache_empty["next_steps"].as_array().expect("steps").len() >= 2);
    assert_eq!(
        find(refusals, "outcome", "bad_request")["kind"],
        "connection_level"
    );
    assert_eq!(first["ok_total"], 90.0);
    let signals = tool_ok(&server, "block_signal_rates", json!({})).await;
    assert_eq!(
        find(&signals["signals"], "type", "rate_limited")["total"],
        5.0
    );

    // 12 more cache_empty refusals and 6 more rate-limited signals arrive.
    *fx.gateway_ops.metrics.lock().expect("metrics") = gateway_metrics(20).replace(
        "scope=\"target\",service=\"proxyx-gateway\"} 5",
        "scope=\"target\",service=\"proxyx-gateway\"} 11",
    );
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let second = tool_ok(&server, "recent_refusals", json!({"window_secs": 60})).await;
    assert!(second["rates"]["window_secs"].as_f64().expect("window") >= 1.0);
    let cache_empty = find(&second["refusals"], "outcome", "cache_empty");
    assert_eq!(cache_empty["recent"], 12.0);
    assert!(
        cache_empty["per_minute"].as_f64().expect("rate") > 100.0,
        "12 events in about a second"
    );
    assert_eq!(
        second["refusals"][0]["outcome"], "cache_empty",
        "sorted by recent volume"
    );
    let signals = tool_ok(&server, "block_signal_rates", json!({})).await;
    assert_eq!(
        find(&signals["signals"], "type", "rate_limited")["recent"],
        6.0
    );
}

#[tokio::test]
async fn diagnose_collects_ranked_evidence() {
    let fx = Fixture::start().await;
    let server = fx.read_only();
    let report = tool_ok(&server, "diagnose", json!({"org": "acme"})).await;
    let findings = report["findings"].as_array().expect("findings");
    let text = report.to_string();
    assert!(
        findings[0]["severity"] == "critical",
        "critical findings first"
    );
    for needle in [
        "org_blocked",
        "below_watermark",
        "breaker of provider p1 is open",
        "rate-limit bucket is empty",
        "cache_empty",
    ] {
        assert!(text.contains(needle), "{needle} missing from {text}");
    }
    let checked: Vec<&str> = report["checked"]
        .as_array()
        .expect("checked")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for part in ["metrics", "org_blocks", "policy", "rate_limit"] {
        assert!(checked.contains(&part), "{part} in {checked:?}");
    }
    // without any backend the tool says what it could not check
    let bare = Fixture::start().await;
    let offline = bare.server("", "").clone();
    drop(offline);
    let config = proxyx_mcp::config::Config::parse(&format!(
        "[safety]\nstate_dir = \"{}/s\"\n[audit]\npath = \"{}/a.jsonl\"",
        bare.dir.display(),
        bare.dir.display()
    ))
    .expect("config");
    let ctx = proxyx_mcp::tools::Ctx::new(config).expect("ctx");
    let empty = std::sync::Arc::new(proxyx_mcp::server::Server::new(ctx));
    let none = tool_ok(&empty, "diagnose", json!({})).await;
    assert!(none["findings"].as_array().expect("findings").is_empty());
    assert!(!none["skipped"].as_array().expect("skipped").is_empty());
    assert!(
        none["summary"]
            .as_str()
            .expect("summary")
            .contains("no problem")
    );
}

#[tokio::test]
async fn state_tools_read_the_backends() {
    let fx = Fixture::start().await;
    let server = fx.read_only();
    let inventory = tool_ok(
        &server,
        "list_inventory",
        json!({"provider": "isp1", "state": "available"}),
    )
    .await;
    assert_eq!(
        inventory["total"], 2,
        "the fake ignores the state filter; the provider filter applies"
    );
    assert!(
        fx.pool.log.calls("GET", "/v1/inventory")[0]
            .query
            .contains("state=available")
    );
    let policies = tool_ok(&server, "list_policies", json!({})).await;
    assert_eq!(policies["items"][0]["name"], "global");
    assert!(
        policies["items"][0].get("doc").is_none(),
        "documents only on request"
    );
    let with_doc = tool_ok(&server, "list_policies", json!({"name": "global"})).await;
    assert_eq!(with_doc["items"][0]["doc"]["min_ready"], 10);
    let blocks = tool_ok(&server, "list_org_blocks", json!({"org": "acme"})).await;
    assert_eq!(blocks["items"][0]["scope"], "provider");
    let upstream = tool_ok(&server, "get_customer_upstream", json!({"org": "acme"})).await;
    assert!(upstream["upstream"].is_null());
    let org = tool_ok(&server, "get_org", json!({})).await;
    assert_eq!(org["org"], "acme");
    assert_eq!(org["rate_limit"]["burst"], 1000);
    assert_eq!(org["rate_limit_state"]["tokens"], 0.0);
    assert!(org["egress_proxy"].is_null());
    let sessions = tool_ok(&server, "list_sessions", json!({})).await;
    assert_eq!(sessions["sessions"], json!([]));
    let alias = existing_session_handle(&server).await;
    let session = tool_ok(&server, "session_status", json!({"session_id": alias})).await;
    assert_eq!(session["lifecycle"]["state"], "active");
    assert_eq!(
        session["inject_header_names"],
        json!(["Authorization"]),
        "header values are never shown"
    );
    assert!(!session.to_string().contains("injected-secret-value"));
    assert_eq!(session["egress_proxy"]["has_credentials"], true);
    assert!(session["expires_in_secs"].as_i64().expect("expiry") > 0);
    let missing = tool_err(
        &server,
        "session_status",
        json!({"session_id": "11111111-2222-4333-8444-555555555555"}),
    )
    .await;
    assert!(missing.to_string().contains("404") || missing.to_string().contains("not found"));
    let capabilities = tool_ok(&server, "capabilities", json!({})).await;
    assert_eq!(capabilities["read_only"], true);
    assert_eq!(capabilities["backends"]["pool_api"], true);
}

#[tokio::test]
async fn traffic_tools_clean_what_they_return() {
    let fx = Fixture::start().await;
    let server = fx.read_only();
    let branches = json!([{"source_id": "run-1", "status_code": {"op": "gte", "value": 200}}]);
    let found = tool_ok(
        &server,
        "search_traffic",
        json!({"branches": branches, "limit": 2}),
    )
    .await;
    assert_eq!(found["count"], 2);
    assert_eq!(found["untrusted_content"], true);
    let first = &found["items"][0];
    assert!(
        first.get("session_id").is_none(),
        "the session id is a proxy credential"
    );
    assert!(
        first["session_alias"]
            .as_str()
            .expect("alias")
            .starts_with("sess:")
    );
    assert_eq!(first["request_headers"][1][1], "[redacted: 27 bytes]");
    assert_eq!(first["response_headers"][1][1], "[redacted: 7 bytes]");
    assert!(first["response_body"].is_null(), "bodies only on request");
    let sent = &fx.control.log.calls("POST", "/rpc/requests/search")[0].body;
    assert_eq!(sent["org_id"], "acme");
    assert_eq!(sent["limit"], 2);
    assert_eq!(sent["authorization_irrelevant"], Value::Null);
    assert_eq!(
        fx.control.log.calls("POST", "/rpc/requests/search")[0]
            .authorization
            .as_deref(),
        Some(format!("Bearer {SERVICE_KEY}").as_str())
    );

    let with_bodies = tool_ok(
        &server,
        "search_traffic",
        json!({"branches": branches, "include_bodies": "response"}),
    )
    .await;
    let page = &with_bodies["items"][2];
    assert_eq!(
        page["response_body"]["truncated"], true,
        "a 6 KB page is cut at the 4096-byte cap"
    );
    assert_eq!(
        page["response_body"]["text"].as_str().expect("text").len(),
        4096
    );
    assert_eq!(
        fx.control.log.calls("POST", "/rpc/requests/search")[1].body["response_body_max_fetch_size"],
        4096
    );

    let count = tool_ok(&server, "count_traffic", json!({"branches": branches})).await;
    assert_eq!(count["count"], 3);

    let capture = tool_ok(
        &server,
        "get_capture",
        json!({"id": "0190aaaa-0000-4000-8000-000000000003", "max_body_bytes": 100}),
    )
    .await;
    assert!(capture["response_body"]["bytes"].as_u64().expect("bytes") > 6000);
    assert_eq!(
        capture["response_body"]["text"]
            .as_str()
            .expect("text")
            .len(),
        100
    );
    assert!(
        !capture.to_string().contains("sid=abc"),
        "set-cookie values never leave the server"
    );
    assert!(!capture.to_string().contains("targetsecrettoken123"));
    assert_eq!(capture["untrusted_content"], true);

    let conversation = tool_ok(
        &server,
        "get_ws_conversation",
        json!({"parent_event_id": "0190aaaa-0000-4000-8000-000000000001"}),
    )
    .await;
    assert_eq!(conversation["messages"][0]["payload"]["text"], "hello");
    assert!(conversation["messages"][0].get("session_id").is_none());
    let ws = tool_ok(
        &server,
        "search_ws",
        json!({"branches": [{"host": {"op": "contains", "value": "example"}}]}),
    )
    .await;
    assert_eq!(ws["count"], 0);

    let bad = tool_err(
        &server,
        "search_traffic",
        json!({"branches": [{"hots": {"op": "contains", "value": "x"}}]}),
    )
    .await;
    assert!(bad.to_string().contains("unknown field"));
    assert_eq!(
        fx.control.log.calls("POST", "/rpc/requests/search").len(),
        2,
        "an invalid query never reaches the backend"
    );
}

#[tokio::test]
async fn explanations_work_offline_and_against_the_org_policy() {
    let fx = Fixture::start().await;
    let server = fx.read_only();
    let cause = tool_ok(
        &server,
        "explain_refusal",
        json!({"text": "proxy said: HTTP/1.1 503 cache_empty for example.com"}),
    )
    .await;
    assert_eq!(cause["code"], "cache_empty");
    assert_eq!(cause["http_status"], 503);
    assert_eq!(cause["socks5_reply"], "0x01");
    assert_eq!(cause["retryable"], true);
    let header = tool_ok(&server, "explain_refusal", json!({"code": "upstream_dns"})).await;
    assert_eq!(header["source"], "session_proxy");
    assert_eq!(header["retryable"], false);
    let unknown = tool_err(&server, "explain_refusal", json!({"code": "banana"})).await;
    assert!(
        unknown["error"]["detail"]["gateway_codes"]
            .as_array()
            .expect("codes")
            .len()
            == 16
    );

    let fine = tool_ok(
        &server,
        "explain_selector",
        json!({"username": "px-kind-rotating-cc-fr-sid-scan42"}),
    )
    .await;
    assert_eq!(fine["ok"], true);
    assert_eq!(fine["options"]["region"], "fr");
    assert_eq!(fine["options"]["sid"], "scan42");
    let bad = tool_ok(
        &server,
        "explain_selector",
        json!({"username": "px-sid-my-id"}),
    )
    .await;
    assert_eq!(bad["ok"], false);
    assert_eq!(bad["issues"][0]["rule"], "pairs");
    assert_eq!(bad["refusal"]["code"], "option_denied");
    let secret = tool_err(
        &server,
        "explain_selector",
        json!({"username": "px:ak_secret"}),
    )
    .await;
    assert!(secret.to_string().contains("never the org key"));

    // against the org policy: regions fr and de, lease_ttl 600s, kinds rotating and static
    let allowed = tool_ok(
        &server,
        "explain_selector",
        json!({"username": "px-kind-rotating-cc-de-ttl-5m", "org": "acme"}),
    )
    .await;
    assert_eq!(allowed["policy_check"]["allowed"], true);
    assert_eq!(allowed["policy_check"]["lease_request"]["ttl_secs"], 300);
    let denied = tool_ok(
        &server,
        "explain_selector",
        json!({"username": "px-cc-it-ttl-1d", "org": "acme"}),
    )
    .await;
    assert_eq!(denied["ok"], false);
    let rules: Vec<&str> = denied["policy_check"]["issues"]
        .as_array()
        .expect("issues")
        .iter()
        .filter_map(|i| i["rule"].as_str())
        .collect();
    assert!(
        rules.contains(&"policy_region") && rules.contains(&"policy_ttl"),
        "{rules:?}"
    );
    assert_eq!(denied["policy_check"]["refusal"]["code"], "option_denied");
}

#[tokio::test]
async fn validate_policy_uses_the_gateways_own_rules() {
    let fx = Fixture::start().await;
    let server = fx.read_only();
    let ok = tool_ok(
        &server,
        "validate_policy",
        json!({"toml": "[[policy]]\nname = \"acme-limits\"\nscope = \"org\"\nmatch = \"acme\"\nmax_tunnels_per_org = 50\n[policy.limits]\norg_max_gb_per_day = 20\n", "org": "acme"}),
    )
    .await;
    assert_eq!(ok["valid"], true);
    assert_eq!(ok["merged_with_stored_policies"], true);
    assert_eq!(ok["effective_preview"]["max_tunnels_per_org"], 50);
    assert_eq!(ok["effective_preview"]["org_max_gb_per_day"], 20.0);
    assert_eq!(ok["effective_preview"]["regions"], json!(["fr", "de"]));
    assert!(
        fx.pool.log.mutations().is_empty(),
        "validation writes nothing"
    );

    let unknown_field = tool_err(
        &server,
        "validate_policy",
        json!({"toml": "[[policy]]\nname = \"x\"\nmin_redy = 1"}),
    )
    .await;
    assert!(unknown_field.to_string().contains("min_redy"));
    let over_ceiling = tool_ok(
        &server,
        "validate_policy",
        json!({"policies": [{"name": "acme", "scope": "org", "match": "acme", "cost": {"max_gb_per_day": 500}, "limits": {"max_gb_per_day": 1}}]}),
    )
    .await;
    assert_eq!(over_ceiling["valid"], false);
    assert!(
        over_ceiling["error"]
            .as_str()
            .expect("error")
            .contains("ceiling"),
        "{over_ceiling}"
    );
}

#[tokio::test]
async fn traffic_summary_and_block_page_classification_run_without_an_llm() {
    let fx = Fixture::start().await;
    let server = fx.read_only();
    let summary = tool_ok(
        &server,
        "summarize_traffic",
        json!({"branches": [{"source_id": "run-1"}]}),
    )
    .await;
    let stats = &summary["statistics"];
    assert_eq!(stats["captures_analysed"], 3);
    assert_eq!(stats["rate_limited_share_percent"], 33.3);
    assert_eq!(stats["block_suspect_hosts"][0]["value"], "api.example.com");
    assert!(summary["narrative"].is_null());
    let no_llm = tool_err(
        &server,
        "summarize_traffic",
        json!({"branches": [{"source_id": "run-1"}], "use_llm": true}),
    )
    .await;
    assert!(no_llm.to_string().contains("no LLM is configured"));

    let page = tool_ok(
        &server,
        "classify_block_page",
        json!({"capture_id": "0190aaaa-0000-4000-8000-000000000003"}),
    )
    .await;
    assert_eq!(page["classification"], "challenge");
    assert_eq!(page["method"], "rules");
    assert_eq!(page["suggested_signal"]["type"], "challenge");
    assert_eq!(page["suggested_signal"]["target"], "www.example.com");
    let limited = tool_ok(
        &server,
        "classify_block_page",
        json!({"status": 429, "host": "api.example.com"}),
    )
    .await;
    assert_eq!(limited["classification"], "rate_limited");
    let fine = tool_ok(
        &server,
        "classify_block_page",
        json!({"status": 200, "body": "<html>hello</html>"}),
    )
    .await;
    assert_eq!(fine["classification"], "none");
    assert!(fine["suggested_signal"].is_null());
    // the read-only server may not report, and says so rather than pretending
    let refused = tool_ok(
        &server,
        "classify_block_page",
        json!({"status": 429, "host": "api.example.com", "exit_ip": "203.0.113.5", "report": true}),
    )
    .await;
    assert_eq!(refused["reported"]["error"]["kind"], "refused");
    assert!(fx.pool.log.mutations().is_empty());
}

#[tokio::test]
async fn breaker_states_discover_session_proxy_and_edge_breakers_by_name() {
    let fx = Fixture::start().await;
    let server = fx.read_only();
    let breakers = tool_ok(&server, "breaker_states", json!({})).await;
    let other = breakers["other_breakers"]
        .as_array()
        .expect("other breakers");
    let state_of = |metric: &str| {
        other
            .iter()
            .find(|row| row["metric"] == metric)
            .unwrap_or_else(|| panic!("{metric} in {other:?}"))["state"]
            .clone()
    };
    assert_eq!(
        state_of("proxyx_intercept_upstream_breaker_state"),
        "half_open",
        "session proxy numbering: 1 open, 2 half_open"
    );
    assert_eq!(state_of("proxyx_edge_parent_breaker_state"), "open");
    assert_eq!(state_of("proxyx_edge_parent_breaker_open"), "closed");
    let trips = other
        .iter()
        .find(|row| row["metric"] == "proxyx_edge_parent_breaker_trips_total")
        .expect("counter");
    assert_eq!(trips["kind"], "counter");
    assert!(trips["state"].is_null());
    assert!(
        !other
            .iter()
            .any(|row| row["metric"] == "proxyx_pool_provider_breaker_state"),
        "pool families are reported separately"
    );
}

#[tokio::test]
async fn assess_grades_findings_with_runbooks() {
    let fx = Fixture::start().await;
    let server = fx.read_only();
    let report = tool_ok(&server, "assess", json!({})).await;
    assert_eq!(report["overall"], "fail");
    let findings = report["findings"].as_array().expect("findings");
    assert_eq!(findings[0]["status"], "fail", "failures sort first");
    let get = |area: &str, check: &str| {
        findings
            .iter()
            .find(|f| f["area"] == area && f["check"] == check)
            .unwrap_or_else(|| panic!("{area}/{check} in {report}"))
    };
    let capacity = get("capacity", "rotating.p1");
    assert_eq!(capacity["status"], "fail");
    assert_eq!(
        capacity["runbook"],
        "docs/runbooks/003-cache-below-low-watermark.md"
    );
    assert!(
        capacity["remediation"]
            .as_array()
            .expect("remediation")
            .len()
            >= 2
    );
    assert_eq!(get("capacity", "rotating.p2")["status"], "pass");
    assert!(get("capacity", "rotating.p2")["runbook"].is_null());
    let breaker = get("breakers", "pool.p1");
    assert_eq!(breaker["status"], "fail");
    assert_eq!(
        breaker["runbook"],
        "docs/runbooks/004-provider-breaker-open.md"
    );
    assert_eq!(get("breakers", "pool.p2")["status"], "pass");
    assert!(
        findings.iter().any(|f| f["area"] == "breakers"
            && f["status"] == "fail"
            && f["summary"]
                .as_str()
                .unwrap_or("")
                .contains("proxyx_edge_parent_breaker_state")),
        "an open edge parent breaker found by name fails the assessment"
    );
    // 8 of 101 connections were refused with cache_empty: 7.9% is a warning, mapped to the capacity runbook.
    let refusals = get("refusals", "server_side");
    assert_eq!(refusals["status"], "warn");
    assert_eq!(
        refusals["runbook"],
        "docs/runbooks/003-cache-below-low-watermark.md"
    );
    assert_eq!(refusals["evidence"]["server_side"][0][0], "cache_empty");
    assert_eq!(get("budget", "cost.p1")["status"], "pass");
    assert_eq!(get("health", "role.gateway")["status"], "pass");
    assert_eq!(get("dependencies", "redis")["status"], "pass");
    let runbooks: Vec<&str> = report["runbooks_to_follow"]
        .as_array()
        .expect("runbooks")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(
        runbooks.contains(&"docs/runbooks/003-cache-below-low-watermark.md")
            && runbooks.contains(&"docs/runbooks/004-provider-breaker-open.md")
    );
    for runbook in &runbooks {
        if runbook.starts_with("docs/runbooks/") {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join(runbook);
            assert!(path.is_file(), "{runbook} must exist");
        }
    }
    assert!(report["counts"]["fail"].as_u64().expect("fails") >= 3);

    let no_passes = tool_ok(&server, "assess", json!({"include_passes": false})).await;
    assert!(
        no_passes["findings"]
            .as_array()
            .expect("findings")
            .iter()
            .all(|f| f["status"] != "pass")
    );
}

#[tokio::test]
async fn assess_reacts_to_readiness_dependencies_and_latency() {
    let fx = Fixture::start().await;
    let server = fx.read_only();
    *fx.warmer_ops.ready.lock().expect("ready") = (503, "redis unavailable".into());
    let extra = "\
proxyx_pool_redis_down{service=\"proxyx-gateway\"} 1\n\
proxyx_pool_dial_duration_seconds_bucket{provider=\"p1\",stage=\"handshake\",le=\"1\",service=\"g\"} 2\n\
proxyx_pool_dial_duration_seconds_bucket{provider=\"p1\",stage=\"handshake\",le=\"8\",service=\"g\"} 30\n\
proxyx_pool_dial_duration_seconds_bucket{provider=\"p1\",stage=\"handshake\",le=\"+Inf\",service=\"g\"} 30\n\
proxyx_pool_dial_duration_seconds_sum{provider=\"p1\",stage=\"handshake\",service=\"g\"} 120\n\
proxyx_pool_dial_duration_seconds_count{provider=\"p1\",stage=\"handshake\",service=\"g\"} 30\n\
proxyx_ingester_circuit_open{table=\"http_captures\",service=\"i\"} 1\n";
    let current = fx.gateway_ops.metrics.lock().expect("metrics").clone();
    *fx.gateway_ops.metrics.lock().expect("metrics") = format!("{current}{extra}");
    let report = tool_ok(&server, "assess", json!({})).await;
    let findings = report["findings"].as_array().expect("findings");
    let find = |area: &str, check: &str| {
        findings
            .iter()
            .find(|f| f["area"] == area && f["check"] == check)
            .unwrap_or_else(|| panic!("{area}/{check}"))
    };
    assert_eq!(find("health", "role.warmer")["status"], "warn");
    assert_eq!(
        find("health", "role.warmer")["runbook"],
        "docs/runbooks/001-redis-down.md"
    );
    assert_eq!(find("dependencies", "redis")["status"], "fail");
    assert_eq!(
        find("dependencies", "redis")["runbook"],
        "docs/runbooks/001-redis-down.md"
    );
    let dial = find("latency", "pool_dial_duration_seconds");
    assert_eq!(
        dial["status"], "fail",
        "p95 of a 30-sample handshake histogram is above 5s: {dial}"
    );
    assert_eq!(
        find("capture_pipeline", "ingester_circuit")["status"],
        "fail"
    );
}

#[tokio::test]
async fn assess_says_what_it_could_not_check() {
    let fx = Fixture::start().await;
    let server = fx.server(
        "",
        "[[endpoints.roles]]\nname = \"dead\"\nkind = \"gateway\"\nurl = \"http://127.0.0.1:9\"\n",
    );
    // only the dead role: health fails, metrics cannot be scraped
    let config = proxyx_mcp::config::Config::parse(&format!(
        "[[endpoints.roles]]\nname = \"dead\"\nkind = \"gateway\"\nurl = \"http://127.0.0.1:9\"\n[safety]\nstate_dir = \"{0}/s\"\n[audit]\npath = \"{0}/a.jsonl\"",
        fx.dir.display()
    ))
    .expect("config");
    drop(server);
    let alone = std::sync::Arc::new(proxyx_mcp::server::Server::new(
        proxyx_mcp::tools::Ctx::new(config).expect("ctx"),
    ));
    let report = tool_ok(&alone, "assess", json!({})).await;
    assert_eq!(report["overall"], "fail");
    assert_eq!(report["findings"][0]["check"], "role.dead");
    assert!(
        report["not_assessed"]
            .as_array()
            .expect("not assessed")
            .iter()
            .any(|n| n["check"] == "metrics")
    );
    // and without roles the tool is not even listed
    let bare = proxyx_mcp::config::Config::parse(&format!(
        "[safety]\nstate_dir = \"{0}/s2\"\n[audit]\npath = \"{0}/b.jsonl\"",
        fx.dir.display()
    ))
    .expect("config");
    let bare = std::sync::Arc::new(proxyx_mcp::server::Server::new(
        proxyx_mcp::tools::Ctx::new(bare).expect("ctx"),
    ));
    let listed = ask(&bare, modern(1, "tools/list", json!({}))).await;
    assert!(!tool_names(&listed).contains(&"assess".to_owned()));
    assert!(tool_names(&listed).contains(&"effective_config".to_owned()));
}

#[tokio::test]
async fn effective_config_reports_policy_timeouts_and_builtins() {
    let fx = Fixture::start().await;
    let server = fx.read_only();
    let view = tool_ok(&server, "effective_config", json!({"org": "acme"})).await;
    let policy = &view["policy"];
    assert_eq!(policy["available"], true);
    assert_eq!(policy["lease"]["lease_ttl_secs"], 600);
    let rotating = &policy["rotating"];
    let keepalive = rotating["keepalive_secs"].as_u64().expect("keepalive");
    assert_eq!(
        rotating["keepalive_interval_in_force_secs"]
            .as_u64()
            .expect("interval"),
        keepalive.min(300),
        "min(keepalive, lease_ttl / 2)"
    );
    assert!(policy["block_rules"]["target_cooldown_secs"].is_u64());
    let builtins = view["gateway_builtin"].as_array().expect("builtins");
    let dial = builtins
        .iter()
        .find(|b| b["name"] == "dial TCP connect stage")
        .expect("dial");
    assert_eq!(dial["value"], "2s over all addresses");
    assert!(builtins.iter().any(|b| b["name"] == "tunnel idle timeout"
        && b["configurable"].as_str().expect("c").starts_with("yes")));
    assert_eq!(view["mcp_server"]["backend_request_timeout_secs"], 20);
    assert!(
        view["builtin_note"]
            .as_str()
            .expect("note")
            .contains("not read from the running roles")
    );
    let for_provider = tool_ok(&server, "effective_config", json!({"provider": "p1"})).await;
    assert_eq!(for_provider["policy"]["provider"], "p1");
    assert!(fx.pool.log.mutations().is_empty());
}

#[tokio::test]
async fn scoped_reads_filter_tenants_before_pagination() {
    let fx = Fixture::start().await;
    {
        let mut pool = fx.pool_state.lock().expect("pool");
        pool.inventory = vec![
            json!({"ip": "203.0.113.99", "provider": "private", "owner": "other"}),
            json!({"ip": "203.0.113.10", "provider": "shared", "owner": null}),
            json!({"ip": "203.0.113.11", "provider": "private", "owner": "acme"}),
        ];
        pool.policies.extend([
            json!({"scope": "org", "name": "other-secret-policy", "match": "other", "doc": {"scope": "org", "match": "other"}}),
            json!({"scope": "org", "name": "acme-policy", "match": "acme", "doc": {"scope": "org", "match": "acme"}}),
        ]);
    }
    let server = fx.server(
        "",
        "[scope]\nallowed_orgs = [\"acme\"]\n[limits]\nmax_rows = 1",
    );
    for name in ["list_inventory", "inventory_replacements"] {
        let result = tool_ok(&server, name, json!({})).await;
        assert_eq!(result["total"], 2);
        assert_eq!(result["items"][0]["ip"], "203.0.113.10");
        assert!(!result.to_string().contains("203.0.113.99"));
    }
    for args in [
        json!({}),
        json!({"include_docs": true}),
        json!({"name": "other-secret-policy"}),
    ] {
        let result = tool_ok(&server, "list_policies", args).await;
        assert!(!result.to_string().contains("other-secret-policy"));
        assert!(!result.to_string().contains("\"other\""));
    }
    let missing = tool_err(&server, "list_org_blocks", json!({})).await;
    assert!(missing.to_string().contains("`org` is required"));
    let foreign = tool_err(&server, "list_org_blocks", json!({"org": "other"})).await;
    assert!(foreign.to_string().contains("authorized scope"));
    assert!(fx.pool.log.calls("GET", "/v1/org-blocks").is_empty());
    let blocks = tool_ok(&server, "list_org_blocks", json!({"org": "acme"})).await;
    assert_eq!(blocks["items"][0]["org"], "acme");

    for (id, org) in [(SESSION_ID, "acme"), ("foreign-session", "other")] {
        server
            .ctx
            .store
            .register_session(&json!({"session_id": id, "org": org}))
            .expect("register");
    }
    let sessions = tool_ok(
        &server,
        "list_sessions",
        json!({"limit": 1, "refresh": true}),
    )
    .await;
    assert_eq!(sessions["sessions"].as_array().expect("sessions").len(), 1);
    assert_eq!(sessions["sessions"][0]["org"], "acme");
    assert!(!sessions.to_string().contains(SESSION_ID));
    assert!(!sessions.to_string().contains("foreign-session"));
    assert!(
        fx.control
            .log
            .all()
            .iter()
            .all(|r| !r.path.contains("foreign-session"))
    );
    let status = tool_ok(
        &server,
        "session_status",
        json!({"session_id": sessions["sessions"][0]["session_id"]}),
    )
    .await;
    assert_eq!(status["org_id"], "acme");
}

#[tokio::test]
async fn session_status_checks_owner_before_lifecycle_and_audit_is_not_shared() {
    let fx = Fixture::start().await;
    let server = fx.server(
        "reveal_secrets_once = true",
        "[scope]\nallowed_orgs = [\"other\"]",
    );
    let refused = tool_err(&server, "session_status", json!({"session_id": SESSION_ID})).await;
    assert!(refused.to_string().contains("authorized scope"));
    assert!(
        fx.control
            .log
            .calls("GET", &format!("/rpc/sessions/{SESSION_ID}/status"))
            .is_empty()
    );
    let resources = ask(&server, modern(2, "resources/list", json!({}))).await;
    assert!(!resources.to_string().contains("proxyx://audit/recent"));
    let audit = ask(
        &server,
        modern(3, "resources/read", json!({"uri": "proxyx://audit/recent"})),
    )
    .await;
    assert!(audit.get("error").is_some());
}

#[tokio::test]
async fn scoped_change_listing_hides_other_orgs() {
    let fx = Fixture::start().await;
    let admin = fx.admin();
    for org in ["acme", "other"] {
        tool_ok(
            &admin,
            "propose_config_change",
            json!({
                "action": "set_org_rate_limit",
                "arguments": {"org": org, "requests_per_minute": 100, "burst": 10}
            }),
        )
        .await;
    }
    let scoped = fx.server("", "[scope]\nallowed_orgs = [\"acme\"]");
    let changes = tool_ok(&scoped, "list_changes", json!({"limit": 1})).await;
    assert_eq!(changes["changes"].as_array().expect("changes").len(), 1);
    assert!(!changes.to_string().contains("other"));
}
