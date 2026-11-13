//! Query drafts, inferred API drafts and capture feeds, against the in-process fakes.

mod common;

use std::collections::BTreeSet;
use std::time::Duration;

use common::*;
use serde_json::{Value, json};

fn searches(fx: &Fixture) -> Vec<common::Recorded> {
    fx.control.log.calls("POST", "/rpc/requests/search")
}

fn answer(fx: &Fixture, name: &str, content: &str) {
    fx.llm_script
        .answers
        .lock()
        .expect("answers")
        .insert(name.to_owned(), content.to_owned());
}

// --- query drafts -----------------------------------------------------------------------------------------

#[tokio::test]
async fn golden_questions_compile_to_scoped_branches_and_nothing_runs_until_asked() {
    let fx = Fixture::start().await;
    store(
        &fx,
        vec![
            with_response(
                cap(1, "run-1", "api.example.com", "POST", "/login", 401),
                &[],
                None,
            ),
            with_response(
                cap(2, "run-1", "other.example.net", "POST", "/login", 401),
                &[],
                None,
            ),
        ],
    );
    let server = fx.analysis_server("", "", "");
    let scope_id = open_scope(&server, &["run-1"]).await;
    let draft = tool_ok(
        &server,
        "draft_traffic_query",
        json!({"scope_id": scope_id, "request": "POST requests with status 401 or 403; server errors slower than 2 seconds"}),
    )
    .await;
    assert_eq!(draft["executable"], true, "{draft}");
    assert_eq!(draft["method"], "templates");
    assert_eq!(draft["estimated_cost"]["level"], "cheap");
    let branches = draft["branches"].as_array().expect("branches");
    assert_eq!(branches.len(), 2);
    assert_eq!(
        draft["branches_before_scope"],
        json!([
            {"method": {"op": "exact", "value": "POST"},
             "status_code": {"op": "any", "filters": [{"op": "exact", "value": 401}, {"op": "exact", "value": 403}]}},
            {"status_code": {"op": "gte", "value": 500}, "duration_ms": {"op": "gt", "value": 2000}}
        ])
    );
    for branch in branches {
        assert_eq!(
            branch["source_id"],
            json!(["run-1"]),
            "every OR branch is confined to the scope's source"
        );
        assert!(
            branch["host"].to_string().contains("api.example.com")
                || branch["host"].to_string().contains(".example.org")
        );
    }
    assert!(searches(&fx).is_empty(), "drafting fetches nothing");
    assert_eq!(draft["query_digest"].as_str().map(str::len), Some(64));

    let run = tool_ok(
        &server,
        "run_traffic_query",
        json!({"query_digest": draft["query_digest"]}),
    )
    .await;
    let sent = &searches(&fx)[0].body;
    assert_eq!(
        sent["branches"], draft["branches"],
        "exactly the reviewed query ran"
    );
    assert!(
        sent.get("response_body_max_fetch_size").is_none(),
        "no bodies are fetched"
    );
    assert_eq!(run["count"], 1, "the item outside the scope was dropped");
    assert_eq!(run["out_of_scope_dropped"], 1);
    assert_eq!(run["items"][0]["untrusted"], true);
    let count = tool_ok(
        &server,
        "run_traffic_query",
        json!({"query_digest": draft["query_digest"], "mode": "count"}),
    )
    .await;
    assert_eq!(count["approximate"], false);
    assert_eq!(
        count["count"], 1,
        "counted over the captures the scope admits: {count}"
    );
}

#[tokio::test]
async fn websocket_drafts_get_one_scoped_branch_per_source() {
    let fx = Fixture::start().await;
    let server = fx.analysis_server("", "", "");
    let scope_id = open_scope(&server, &["run-1", "run-2"]).await;
    let draft = tool_ok(
        &server,
        "draft_traffic_query",
        json!({"scope_id": scope_id, "request": "incoming messages on echo.example.com", "protocol": "ws"}),
    )
    .await;
    assert_eq!(draft["executable"], true, "{draft}");
    let branches = draft["branches"].as_array().expect("branches");
    assert_eq!(branches.len(), 2);
    let sources: BTreeSet<&str> = branches
        .iter()
        .map(|b| b["source_id"].as_str().expect("one source"))
        .collect();
    assert_eq!(sources, BTreeSet::from(["run-1", "run-2"]));
    assert_eq!(draft["estimated_cost"]["body_scan"], false);
    // a payload filter is a body scan: off until the operator allows it
    let scan = tool_ok(
        &server,
        "draft_traffic_query",
        json!({"scope_id": scope_id, "request": "messages with payload containing \"ping\"", "protocol": "ws"}),
    )
    .await;
    assert_eq!(scan["estimated_cost"]["body_scan"], true);
    assert_eq!(scan["executable"], false);
    let allowed = fx.analysis_server("", "", "[analysis.query]\nallow_body_scan = true\n");
    let scope_id = open_scope(&allowed, &["run-1"]).await;
    let ok = tool_ok(
        &allowed,
        "draft_traffic_query",
        json!({"scope_id": scope_id, "request": "messages with payload containing \"ping\"", "protocol": "ws"}),
    )
    .await;
    assert_eq!(ok["executable"], true, "{ok}");
}

#[tokio::test]
async fn unsupported_and_ambiguous_questions_never_run() {
    let fx = Fixture::start().await;
    let server = fx.analysis_server("", "", "");
    let scope_id = open_scope(&server, &["run-1"]).await;
    let time = tool_ok(
        &server,
        "draft_traffic_query",
        json!({"scope_id": scope_id, "request": "errors in the last hour"}),
    )
    .await;
    assert_eq!(time["executable"], false);
    assert!(
        time["unsupported_clauses"]
            .to_string()
            .contains("no time field"),
        "{time}"
    );
    // the error clause was still understood: nothing was silently dropped or simulated
    assert_eq!(
        time["branches_before_scope"],
        json!([{"status_code": {"op": "gte", "value": 400}}])
    );
    let vague = tool_ok(
        &server,
        "draft_traffic_query",
        json!({"scope_id": scope_id, "request": "requests that look suspicious"}),
    )
    .await;
    assert_eq!(vague["executable"], false);
    assert!(
        vague["unsupported_clauses"]
            .to_string()
            .contains("suspicious")
    );
    for draft in [&time, &vague] {
        let refused = tool_err(
            &server,
            "run_traffic_query",
            json!({"query_digest": draft["query_digest"]}),
        )
        .await;
        assert_eq!(refused["error"]["kind"], "refused", "{refused}");
    }
    assert!(searches(&fx).is_empty());
}

#[tokio::test]
async fn body_scans_and_regexes_need_the_operators_permission() {
    let fx = Fixture::start().await;
    let ask_for = |server: std::sync::Arc<proxyx_mcp::server::Server>, request: &'static str| async move {
        let scope_id = open_scope(&server, &["run-1"]).await;
        let draft = tool_ok(
            &server,
            "draft_traffic_query",
            json!({"scope_id": scope_id, "request": request}),
        )
        .await;
        (server, draft)
    };
    let (server, body) = ask_for(
        fx.analysis_server("", "", ""),
        "response body containing \"leak\"",
    )
    .await;
    assert_eq!(body["executable"], false);
    assert_eq!(body["estimated_cost"]["level"], "expensive");
    assert!(body["blocked_by"].to_string().contains("allow_body_scan"));
    tool_err(
        &server,
        "run_traffic_query",
        json!({"query_digest": body["query_digest"]}),
    )
    .await;
    let (_, regex) = ask_for(
        fx.analysis_server("", "", "[analysis.query]\nallow_body_scan = true\n"),
        "response body matching regex \"a+b\"",
    )
    .await;
    assert_eq!(regex["executable"], false, "a regex is its own permission");
    assert!(regex["blocked_by"].to_string().contains("allow_regex"));
    let (allowed, both) = ask_for(
        fx.analysis_server(
            "",
            "",
            "[analysis.query]\nallow_body_scan = true\nallow_regex = true\n",
        ),
        "response body matching regex \"a+b\"",
    )
    .await;
    assert_eq!(both["executable"], true, "{both}");
    assert_eq!(both["estimated_cost"]["regex"], true);
    tool_ok(
        &allowed,
        "run_traffic_query",
        json!({"query_digest": both["query_digest"]}),
    )
    .await;
    let (_, long) = ask_for(
        fx.analysis_server(
            "",
            "",
            "[analysis.query]\nallow_body_scan = true\nallow_regex = true\nmax_regex_bytes = 2\n",
        ),
        "response body matching regex \"a+b\"",
    )
    .await;
    assert_eq!(long["executable"], false);
    assert!(long["blocked_by"].to_string().contains("max_regex_bytes"));
}

#[tokio::test]
async fn stale_drafts_and_expired_scopes_refuse_to_run() {
    let fx = Fixture::start().await;
    let server = fx.analysis_server("", "", "[analysis.query]\ndraft_ttl_secs = 1\n");
    let scope_id = open_scope(&server, &["run-1"]).await;
    let draft = tool_ok(
        &server,
        "draft_traffic_query",
        json!({"scope_id": scope_id, "request": "errors"}),
    )
    .await;
    // another org's id is an unknown draft
    let other = tool_err(
        &server,
        "run_traffic_query",
        json!({"query_digest": draft["query_digest"], "org": "rival"}),
    )
    .await;
    assert_eq!(other["error"]["kind"], "refused");
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let stale = tool_err(
        &server,
        "run_traffic_query",
        json!({"query_digest": draft["query_digest"]}),
    )
    .await;
    assert!(stale.to_string().contains("expired"), "{stale}");
    assert!(searches(&fx).is_empty());

    let short = fx.analysis_server("", "", "");
    let scope = tool_ok(
        &short,
        "open_analysis_scope",
        json!({"source_ids": ["run-1"], "ttl_secs": 1}),
    )
    .await;
    let draft = tool_ok(
        &short,
        "draft_traffic_query",
        json!({"scope_id": scope["scope_id"], "request": "errors"}),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(2100)).await;
    tool_err(
        &short,
        "run_traffic_query",
        json!({"query_digest": draft["query_digest"]}),
    )
    .await;
    assert!(searches(&fx).is_empty(), "an expired scope runs nothing");
}

#[tokio::test]
async fn a_model_draft_passes_the_same_validator_and_scope_as_the_templates() {
    let fx = Fixture::start().await;
    let server = fx.analysis_server("", "allow_external_llm = true", &fx.llm_config());
    let scope_id = open_scope(&server, &["run-1"]).await;
    let propose = |branches: Value| {
        json!({"branches": branches, "explanation": "model draft", "assumptions": ["a"], "unsupported_clauses": []}).to_string()
    };
    let draft = |fx: &Fixture,
                 server: &std::sync::Arc<proxyx_mcp::server::Server>,
                 scope_id: &str,
                 content: String| {
        answer(fx, "traffic_query", &content);
        let server = server.clone();
        let scope_id = scope_id.to_owned();
        async move {
            tool_ok(&server, "draft_traffic_query", json!({"scope_id": scope_id, "request": "login failures on the api, please", "use_llm": true})).await
        }
    };
    // a field the language does not have (a time field) is rejected and the templates' draft stands
    let invented = draft(
        &fx,
        &server,
        &scope_id,
        propose(json!([{"timestamp": {"op": "gte", "value": 1}}])),
    )
    .await;
    assert_eq!(invented["llm"]["status"], "rejected", "{invented}");
    assert_eq!(invented["method"], "templates");
    // a branch that names another source cannot widen the scope
    let escape = draft(
        &fx,
        &server,
        &scope_id,
        propose(json!([{"source_id": "run-2"}])),
    )
    .await;
    assert_eq!(escape["llm"]["status"], "rejected", "{escape}");
    // an operator the language does not have
    let bad_op = draft(
        &fx,
        &server,
        &scope_id,
        propose(json!([{"host": {"op": "like", "value": "x"}}])),
    )
    .await;
    assert_eq!(bad_op["llm"]["status"], "rejected");
    // a valid proposal is used, then confined like any other: a hostile host filter is ANDed with the scope's
    let valid = draft(&fx, &server, &scope_id, propose(json!([{"host": {"op": "contains", "value": "evil.test"}, "status_code": {"op": "exact", "value": 401}}]))).await;
    assert_eq!(valid["method"], "llm", "{valid}");
    assert_eq!(valid["llm"]["status"], "used");
    let branch = &valid["branches"][0];
    assert_eq!(
        branch["host"]["op"], "all",
        "the scope's origin filter is intersected with the model's: {branch}"
    );
    assert_eq!(branch["source_id"], json!(["run-1"]));
    // the model is shown the generated language reference, never the scope's secrets
    let sent = fx.llm.log.calls("POST", "/v1/chat/completions")[0]
        .body
        .to_string();
    assert!(
        sent.contains("status_code") && sent.contains("no timestamp field"),
        "{sent}"
    );
}

// --- API drafts -------------------------------------------------------------------------------------------------

fn json_response(n: u32, method: &str, path: &str, status: u64, body: &str) -> Value {
    with_response(
        cap(n, "run-1", "api.example.com", method, path, status),
        &[("content-type", "application/json")],
        Some(body),
    )
}

fn api_fixture() -> Vec<Value> {
    let mut cut = json_response(14, "GET", "/cut", 200, "{\"a\":");
    cut["response_headers"] = json!([["content-type", "application/json"]]);
    let mut big = json_response(15, "GET", "/big", 200, "");
    big["response_body"] = json!({"status": "too_large", "size": 70000});
    vec![
        json_response(
            1,
            "GET",
            "/users/1",
            200,
            r#"{"id":1,"name":"a","email":null,"tags":["x"]}"#,
        ),
        json_response(
            2,
            "GET",
            "/users/2",
            200,
            r#"{"id":2,"name":"b","email":"b.secret@mail.test","tags":[]}"#,
        ),
        json_response(3, "GET", "/users/me", 200, r#"{"id":9,"name":"me"}"#),
        json_response(4, "GET", "/users/3", 404, r#"{"error":"not found"}"#),
        with_request(
            json_response(5, "POST", "/users", 201, r#"{"id":10,"name":"c"}"#),
            &[("content-type", "application/json")],
            Some(r#"{"name":"c","age":3}"#),
        ),
        with_request(
            json_response(6, "POST", "/users", 201, r#"{"id":11,"name":"d"}"#),
            &[("content-type", "application/json")],
            Some(r#"{"name":"d"}"#),
        ),
        json_response(
            7,
            "GET",
            "/items?limit=10&page=2",
            200,
            r#"[{"v":1},{"v":"x"}]"#,
        ),
        json_response(8, "GET", "/items?limit=20", 200, "[]"),
        with_response(
            cap(9, "run-1", "api.example.com", "GET", "/text", 200),
            &[("content-type", "text/html")],
            Some("<html></html>"),
        ),
        json_response(
            10,
            "GET",
            "/orders/550e8400-e29b-41d4-a716-446655440000",
            200,
            r#"{"total":5}"#,
        ),
        json_response(
            11,
            "GET",
            "/orders/6ba7b810-9dad-11d1-80b4-00c04fd430c8",
            200,
            r#"{"total":7.5}"#,
        ),
        json_response(12, "GET", "/accounts/777", 200, r#"{"ok":true}"#),
        with_response(
            cap(13, "run-1", "api.example.com", "PUT", "/users/1", 204),
            &[],
            None,
        ),
        cut,
        big,
        // a duplicate write of capture 1
        json_response(
            1,
            "GET",
            "/users/1",
            200,
            r#"{"id":1,"name":"a","email":null,"tags":["x"]}"#,
        ),
        with_response(
            cap(16, "run-1", "www.example.org", "GET", "/docs", 200),
            &[("content-type", "application/json")],
            Some(r#"{"title":"t"}"#),
        ),
    ]
}

/// A validator written apart from the generator: it checks the OpenAPI 3.1 rules this draft relies on.
fn validate_openapi(document: &Value) -> Vec<String> {
    let mut problems = Vec::new();
    if !document["openapi"]
        .as_str()
        .is_some_and(|v| v.starts_with("3.1."))
    {
        problems.push("openapi version".to_owned());
    }
    if document["info"]["title"].as_str().is_none()
        || document["info"]["version"].as_str().is_none()
    {
        problems.push("info".to_owned());
    }
    let types = [
        "string", "integer", "number", "boolean", "null", "object", "array",
    ];
    fn walk(
        schema: &Value,
        here: &str,
        types: &[&str],
        problems: &mut Vec<String>,
        fields: &mut usize,
    ) {
        let Some(map) = schema.as_object() else {
            problems.push(format!("{here}: a schema is an object"));
            return;
        };
        match map.get("type") {
            Some(Value::String(t)) if types.contains(&t.as_str()) => {}
            Some(Value::Array(list))
                if list
                    .iter()
                    .all(|t| t.as_str().is_some_and(|t| types.contains(&t))) => {}
            None => {}
            other => problems.push(format!("{here}: bad type {other:?}")),
        }
        if map.contains_key("required") {
            problems.push(format!("{here}: `required` claims a server requirement"));
        }
        if map.contains_key("example")
            || map.contains_key("examples")
            || map.contains_key("default")
            || map.contains_key("enum")
        {
            problems.push(format!("{here}: carries values"));
        }
        if map
            .get("x-proxyx-observed")
            .and_then(|o| o["evidence"].as_array())
            .is_none_or(Vec::is_empty)
        {
            problems.push(format!("{here}: no evidence"));
        }
        for (name, property) in map
            .get("properties")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
        {
            *fields += 1;
            walk(property, &format!("{here}.{name}"), types, problems, fields);
        }
        if let Some(items) = map.get("items") {
            walk(items, &format!("{here}[]"), types, problems, fields);
        }
    }
    let mut fields = 0;
    for (path, item) in document["paths"].as_object().expect("paths") {
        let placeholders: Vec<&str> = path
            .split('/')
            .filter_map(|s| s.strip_prefix('{').and_then(|s| s.strip_suffix('}')))
            .collect();
        for (method, operation) in item.as_object().expect("path item") {
            let here = format!("{method} {path}");
            let declared: Vec<&str> = operation["parameters"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|p| p["in"] == "path")
                .filter_map(|p| p["name"].as_str())
                .collect();
            if placeholders.iter().any(|p| !declared.contains(p)) {
                problems.push(format!("{here}: undeclared path parameter"));
            }
            if operation["x-proxyx-observed"]["evidence"]
                .as_array()
                .is_none_or(Vec::is_empty)
            {
                problems.push(format!("{here}: route without evidence"));
            }
            let responses = operation["responses"].as_object().expect("responses");
            if responses.is_empty() {
                problems.push(format!("{here}: no responses"));
            }
            for (code, response) in responses {
                if !(code.len() == 3 && code.bytes().all(|b| b.is_ascii_digit()))
                    || response["description"].as_str().is_none()
                {
                    problems.push(format!("{here} {code}: malformed response"));
                }
                for content in response["content"]
                    .as_object()
                    .into_iter()
                    .flat_map(|c| c.values())
                {
                    walk(
                        &content["schema"],
                        &format!("{here} {code}"),
                        &types,
                        &mut problems,
                        &mut fields,
                    );
                }
            }
            for content in operation["requestBody"]["content"]
                .as_object()
                .into_iter()
                .flat_map(|c| c.values())
            {
                walk(
                    &content["schema"],
                    &format!("{here} request"),
                    &types,
                    &mut problems,
                    &mut fields,
                );
            }
        }
    }
    problems
}

#[tokio::test]
async fn an_api_draft_documents_only_what_was_observed() {
    let fx = Fixture::start().await;
    store(&fx, api_fixture());
    let server = fx.analysis_server("", "", "");
    let scope_id = open_scope(&server, &["run-1"]).await;
    let summary = tool_ok(&server, "infer_api_schema", json!({"scope_id": scope_id})).await;
    assert_eq!(
        summary["validation"]["valid"], true,
        "{}",
        summary["validation"]
    );
    let draft_id = summary["draft_id"].as_str().expect("draft id").to_owned();
    let origins = summary["origins"].as_array().expect("origins");
    assert_eq!(
        origins.len(),
        2,
        "one document per observed origin: {origins:?}"
    );
    // several origins: an index, then one document per origin
    let index = tool_ok(
        &server,
        "get_api_schema_draft",
        json!({"draft_id": draft_id}),
    )
    .await;
    assert_eq!(index["kind"], "index");
    let envelope = tool_ok(
        &server,
        "get_api_schema_draft",
        json!({"draft_id": draft_id, "origin": "https://api.example.com"}),
    )
    .await;
    let document = &envelope["openapi_document"];
    let problems = validate_openapi(document);
    assert!(problems.is_empty(), "{problems:#?}");

    let paths = document["paths"].as_object().expect("paths");
    for expected in [
        "/users/{userId}",
        "/users/me",
        "/users",
        "/items",
        "/orders/{orderId}",
        "/accounts/{accountId}",
        "/cut",
        "/big",
        "/text",
    ] {
        assert!(
            paths.contains_key(expected),
            "{expected} in {:?}",
            paths.keys().collect::<Vec<_>>()
        );
    }
    // identifier-like segments are parameters, never printed; a word stays a word
    assert!(
        !paths.contains_key("/users/1")
            && !paths.contains_key("/orders/550e8400-e29b-41d4-a716-446655440000")
    );
    let user = &paths["/users/{userId}"]["get"];
    assert_eq!(user["parameters"][0]["name"], "userId");
    assert_eq!(user["parameters"][0]["schema"]["type"], "integer");
    assert_eq!(
        paths["/orders/{orderId}"]["get"]["parameters"][0]["schema"]["format"],
        "uuid"
    );
    // only observed status codes exist
    let codes: BTreeSet<&str> = user["responses"]
        .as_object()
        .expect("responses")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(codes, BTreeSet::from(["200", "404"]));
    assert!(
        paths["/users/{userId}"]["put"]["responses"]["204"]["content"].is_null(),
        "an empty response has no body schema"
    );
    // observed, not required
    let schema = &user["responses"]["200"]["content"]["application/json"]["schema"];
    assert_eq!(
        schema["properties"]["email"]["type"],
        json!(["null", "string"])
    );
    assert_eq!(
        schema["x-proxyx-observed-required"],
        json!(["email", "id", "name", "tags"])
    );
    assert_eq!(schema["properties"]["tags"]["items"]["type"], "string");
    let created = &paths["/users"]["post"];
    let request = &created["requestBody"]["content"]["application/json"]["schema"];
    assert_eq!(
        request["x-proxyx-observed-required"],
        json!(["name"]),
        "age was seen in one of two samples"
    );
    // numbers: integer and decimal samples merge into number
    assert_eq!(
        paths["/orders/{orderId}"]["get"]["responses"]["200"]["content"]["application/json"]["schema"]
            ["properties"]["total"]["type"],
        "number"
    );
    // conflicting array element types stay a union, with a note; query parameters are optional unless always present
    let items = &paths["/items"]["get"];
    let element = &items["responses"]["200"]["content"]["application/json"]["schema"]["items"]["properties"]
        ["v"];
    assert_eq!(element["x-proxyx-observed"]["conflicting_types"], true);
    let query: Vec<(&str, bool)> = items["parameters"]
        .as_array()
        .expect("parameters")
        .iter()
        .map(|p| {
            (
                p["name"].as_str().unwrap_or(""),
                p["x-proxyx-observed"]["observed_required"]
                    .as_bool()
                    .unwrap_or(false),
            )
        })
        .collect();
    assert!(
        query.contains(&("limit", true)) && query.contains(&("page", false)),
        "{query:?}"
    );
    // gaps are stated, not filled
    let kinds: Vec<&str> = summary["diagnostics"]
        .as_array()
        .expect("diagnostics")
        .iter()
        .filter_map(|d| d["kind"].as_str())
        .collect();
    for kind in [
        "bodies_unknown",
        "content_type_not_allowed",
        "duplicate_captures_ignored",
        "identifier_segments_parameterized",
    ] {
        assert!(kinds.contains(&kind), "{kind} in {kinds:?}");
    }
    assert!(
        paths["/cut"]["get"]["responses"]["200"]["content"].is_null(),
        "a cut body leaves the schema unknown"
    );
    assert!(paths["/text"]["get"]["responses"]["200"]["content"].is_null());
    // no examples or sample values, and every route's evidence exists in the result
    assert_absent("the draft", &envelope.to_string(), &["b.secret@mail.test"]);
    let refs: BTreeSet<&str> = summary["evidence"]["refs"]
        .as_array()
        .expect("refs")
        .iter()
        .filter_map(|r| r["id"].as_str())
        .collect();
    for route in summary["routes"].as_array().expect("routes") {
        assert!(
            route["evidence"]
                .as_array()
                .is_some_and(|e| !e.is_empty()
                    && e.iter().all(|id| refs.contains(id.as_str().unwrap_or("")))),
            "{route}"
        );
    }
    assert!(fx.pool.log.all().is_empty());
}

#[tokio::test]
async fn a_single_origin_draft_is_served_as_the_document_through_the_resource() {
    let fx = Fixture::start().await;
    store(&fx, api_fixture());
    let server = fx.analysis_server("", "", "");
    let scope = tool_ok(
        &server,
        "open_analysis_scope",
        json!({"source_ids": ["run-1"], "origins": ["api.example.com"]}),
    )
    .await;
    let summary = tool_ok(
        &server,
        "infer_api_schema",
        json!({"scope_id": scope["scope_id"]}),
    )
    .await;
    let uri = summary["resource"].as_str().expect("resource").to_owned();
    assert!(uri.starts_with("proxyx://analysis/acme/draft_") && uri.ends_with("/openapi"));
    let read = ask(&server, modern(1, "resources/read", json!({"uri": uri}))).await;
    let text = read["result"]["contents"][0]["text"]
        .as_str()
        .expect("text");
    let document: Value = serde_json::from_str(text).expect("a JSON document");
    assert_eq!(document["openapi"], "3.1.0");
    assert!(validate_openapi(&document).is_empty());
    // a property called `token` or `password` is a name, not a secret
    store(
        &fx,
        vec![json_response(
            1,
            "POST",
            "/login",
            200,
            r#"{"token":"abc","password_hint":"x","api_key":"k"}"#,
        )],
    );
    let named = tool_ok(
        &server,
        "infer_api_schema",
        json!({"scope_id": scope["scope_id"]}),
    )
    .await;
    let envelope = tool_ok(
        &server,
        "get_api_schema_draft",
        json!({"draft_id": named["draft_id"]}),
    )
    .await;
    let properties = &envelope["openapi_document"]["paths"]["/login"]["post"]["responses"]["200"]["content"]
        ["application/json"]["schema"]["properties"];
    assert_eq!(properties["token"]["type"], "string", "{properties}");
    assert_eq!(properties["api_key"]["type"], "string");
    // another org cannot read it
    let other = ask(
        &server,
        modern(
            2,
            "resources/read",
            json!({"uri": uri.replace("/acme/", "/rival/")}),
        ),
    )
    .await;
    assert!(other["error"].is_object());
}

#[tokio::test]
async fn a_model_can_only_name_the_routes_the_draft_has() {
    let fx = Fixture::start().await;
    store(&fx, api_fixture());
    let server = fx.analysis_server("", "allow_external_llm = true", &fx.llm_config());
    let scope = tool_ok(
        &server,
        "open_analysis_scope",
        json!({"source_ids": ["run-1"], "origins": ["api.example.com"]}),
    )
    .await;
    let plain = tool_ok(
        &server,
        "infer_api_schema",
        json!({"scope_id": scope["scope_id"]}),
    )
    .await;
    let baseline = tool_ok(
        &server,
        "get_api_schema_draft",
        json!({"draft_id": plain["draft_id"]}),
    )
    .await;
    let shape = |envelope: &Value| -> BTreeSet<String> {
        envelope["openapi_document"]["paths"]
            .as_object()
            .expect("paths")
            .iter()
            .flat_map(|(path, item)| {
                item.as_object()
                    .expect("item")
                    .keys()
                    .map(move |m| format!("{m} {path}"))
            })
            .collect()
    };
    answer(
        &fx,
        "operation_names",
        r#"{"operations":[{"route_ref":"r999","operation_id":"invented","summary":"a route that does not exist"}]}"#,
    );
    let invented = tool_ok(
        &server,
        "infer_api_schema",
        json!({"scope_id": scope["scope_id"], "use_llm": true}),
    )
    .await;
    assert_eq!(invented["llm"]["status"], "rejected", "{}", invented["llm"]);
    let doc = tool_ok(
        &server,
        "get_api_schema_draft",
        json!({"draft_id": invented["draft_id"]}),
    )
    .await;
    assert_eq!(shape(&doc), shape(&baseline), "no route was added");
    assert!(!doc.to_string().contains("invented"));
    // valid names apply to operationId and summary only
    let first = plain["routes"][0]["route_ref"]
        .as_str()
        .expect("route ref")
        .to_owned();
    answer(
        &fx,
        "operation_names",
        &json!({"operations": [{"route_ref": first, "operation_id": "listThings", "summary": "Lists things, sent as Bearer abcdefghij0123456789"}]}).to_string(),
    );
    let named = tool_ok(
        &server,
        "infer_api_schema",
        json!({"scope_id": scope["scope_id"], "use_llm": true}),
    )
    .await;
    assert_eq!(named["llm"]["status"], "used", "{}", named["llm"]);
    let doc = tool_ok(
        &server,
        "get_api_schema_draft",
        json!({"draft_id": named["draft_id"]}),
    )
    .await;
    assert_eq!(shape(&doc), shape(&baseline));
    assert!(doc.to_string().contains("listThings"));
    assert_absent("the draft", &doc.to_string(), &["abcdefghij0123456789"]);
    for call in fx.llm.log.calls("POST", "/v1/chat/completions") {
        assert_absent(
            "the model request",
            &call.body.to_string(),
            &["b.secret@mail.test"],
        );
    }
}

#[tokio::test]
async fn the_route_limit_is_visible() {
    let fx = Fixture::start().await;
    store(&fx, api_fixture());
    let server = fx.analysis_server("", "", "[analysis.openapi]\nmax_routes = 3\n");
    let scope = tool_ok(
        &server,
        "open_analysis_scope",
        json!({"source_ids": ["run-1"], "origins": ["api.example.com"]}),
    )
    .await;
    let summary = tool_ok(
        &server,
        "infer_api_schema",
        json!({"scope_id": scope["scope_id"]}),
    )
    .await;
    assert_eq!(summary["routes"].as_array().map(Vec::len), Some(3));
    assert!(
        summary["diagnostics"]
            .to_string()
            .contains("routes_truncated")
    );
}

// --- capture feeds ------------------------------------------------------------------------------------------------

fn feed_server(fx: &Fixture, feeds: &str) -> std::sync::Arc<proxyx_mcp::server::Server> {
    fx.analysis_server(
        "",
        "",
        &format!("[analysis.feeds]\nmin_poll_interval_ms = 20\n{feeds}"),
    )
}

async fn open_feed(server: &std::sync::Arc<proxyx_mcp::server::Server>, scope_id: &str) -> Value {
    tool_ok(server, "open_capture_feed", json!({"scope_id": scope_id})).await
}

async fn poll(server: &std::sync::Arc<proxyx_mcp::server::Server>, feed_id: &str) -> Value {
    tokio::time::sleep(Duration::from_millis(40)).await;
    tool_ok(server, "read_capture_feed", json!({"feed_id": feed_id})).await
}

fn ids(page: &Value) -> Vec<String> {
    page["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|i| i["id"].as_str().unwrap_or("").to_owned())
        .collect()
}

fn pushed(fx: &Fixture, captures: Vec<Value>) {
    fx.control_state
        .lock()
        .expect("control")
        .captures
        .extend(captures);
}

#[tokio::test]
async fn a_feed_reads_only_what_is_stored_after_it_opened_and_never_claims_live() {
    let fx = Fixture::start().await;
    store(
        &fx,
        vec![
            cap(1, "run-1", "api.example.com", "GET", "/old", 200),
            cap(2, "run-1", "api.example.com", "GET", "/old2", 200),
        ],
    );
    let server = feed_server(&fx, "");
    let scope_id = open_scope(&server, &["run-1"]).await;
    let opened = open_feed(&server, &scope_id).await;
    let feed_id = opened["feed_id"].as_str().expect("feed id").to_owned();
    assert_eq!(opened["live_stream"], false);
    assert_eq!(opened["delivery"], "stored_poll");
    assert_eq!(opened["starts_after_existing_captures"], true);
    assert_eq!(
        fx.control.log.calls("GET", "/rpc/sequence").len(),
        1,
        "the start position comes from the sequence route"
    );

    // nothing new: an empty page that says what that means
    let empty = poll(&server, &feed_id).await;
    assert_eq!(empty["count"], 0);
    assert_eq!(empty["lag_unknown"], true);
    assert_eq!(empty["live_stream"], false);
    assert!(
        empty["notice"]
            .as_str()
            .expect("notice")
            .contains("does not mean")
    );
    assert_eq!(
        searches(&fx).len(),
        0,
        "no search while nothing was stored after the start"
    );

    // captures arrive later: oldest first, once each
    pushed(
        &fx,
        vec![
            cap(3, "run-1", "api.example.com", "GET", "/a", 200),
            cap(4, "run-1", "api.example.com", "GET", "/b", 200),
        ],
    );
    let first = poll(&server, &feed_id).await;
    assert_eq!(ids(&first), vec![uid(3), uid(4)]);
    assert_eq!(searches(&fx)[0].body["order"], "asc");
    assert_eq!(
        searches(&fx)[0].body["branches"][0]["source_id"],
        json!(["run-1"])
    );
    let again = poll(&server, &feed_id).await;
    assert_eq!(again["count"], 0, "already delivered");
    // a duplicate write and a late arrival
    pushed(
        &fx,
        vec![
            cap(4, "run-1", "api.example.com", "GET", "/b", 200),
            cap(5, "run-1", "api.example.com", "GET", "/c", 200),
        ],
    );
    let third = poll(&server, &feed_id).await;
    assert_eq!(
        ids(&third),
        vec![uid(5)],
        "the duplicate write of capture 4 is dropped by id"
    );
    // other sources and origins never appear
    pushed(
        &fx,
        vec![
            cap(6, "run-2", "api.example.com", "GET", "/x", 200),
            cap(7, "run-1", "other.example.net", "GET", "/y", 200),
        ],
    );
    let fourth = poll(&server, &feed_id).await;
    assert_eq!(fourth["count"], 0);
    assert_eq!(fourth["out_of_scope_dropped"], 2);
    // the cursor only moves forward
    let mut last = String::new();
    for page in [&first, &third, &fourth] {
        let next = page["next_cursor"]
            .as_str()
            .expect("next cursor")
            .to_owned();
        assert!(
            !proxyx_mcp::analysis::feeds::later(&last, &next),
            "the cursor moved backwards: {last} then {next}"
        );
        last = next;
    }
    let closed = tool_ok(&server, "close_capture_feed", json!({"feed_id": feed_id})).await;
    assert_eq!(closed["closed"], true);
    tool_err(&server, "read_capture_feed", json!({"feed_id": feed_id})).await;
}

#[tokio::test]
async fn an_empty_start_reads_everything_stored_afterwards() {
    let fx = Fixture::start().await;
    store(&fx, Vec::new());
    let server = feed_server(&fx, "max_page_rows = 2\n");
    let scope_id = open_scope(&server, &["run-1"]).await;
    let opened = open_feed(&server, &scope_id).await;
    assert_eq!(opened["starts_after_existing_captures"], false);
    let feed_id = opened["feed_id"].as_str().expect("feed id").to_owned();
    pushed(
        &fx,
        (1..=5)
            .map(|n| cap(n, "run-1", "api.example.com", "GET", "/", 200))
            .collect(),
    );
    // pages are bounded and continue without gaps or repeats
    let mut seen = Vec::new();
    for _ in 0..4 {
        let page = poll(&server, &feed_id).await;
        assert!(page["count"].as_u64().expect("count") <= 2);
        seen.extend(ids(&page));
    }
    assert_eq!(seen, (1..=5).map(uid).collect::<Vec<_>>());
}

#[tokio::test]
async fn polling_is_throttled_and_feeds_are_bounded() {
    let fx = Fixture::start().await;
    let server = fx.analysis_server(
        "",
        "",
        "[analysis.feeds]\nmin_poll_interval_ms = 5000\nmax_feeds = 2\n",
    );
    let scope_id = open_scope(&server, &["run-1"]).await;
    let feed = open_feed(&server, &scope_id).await;
    let feed_id = feed["feed_id"].as_str().expect("id").to_owned();
    tool_ok(&server, "read_capture_feed", json!({"feed_id": feed_id})).await;
    let early = tool_err(&server, "read_capture_feed", json!({"feed_id": feed_id})).await;
    assert!(early.to_string().contains("polled too soon"), "{early}");
    assert!(
        early["error"]["detail"]["retry_after_ms"]
            .as_u64()
            .expect("retry")
            <= 5000
    );
    open_feed(&server, &scope_id).await;
    let third = tool_err(&server, "open_capture_feed", json!({"scope_id": scope_id})).await;
    assert!(third.to_string().contains("max_feeds"), "{third}");
}

#[tokio::test]
async fn feed_ids_are_bound_to_their_org_and_end_with_expiry_or_restart() {
    let fx = Fixture::start().await;
    let server = feed_server(&fx, "ttl_secs = 1\n");
    let scope_id = open_scope(&server, &["run-1"]).await;
    let feed_id = open_feed(&server, &scope_id).await["feed_id"]
        .as_str()
        .expect("id")
        .to_owned();
    for (id, org) in [
        (feed_id.as_str(), "rival"),
        ("feed_00000000000000000000000000000000", "acme"),
    ] {
        let refused = tool_err(
            &server,
            "read_capture_feed",
            json!({"feed_id": id, "org": org}),
        )
        .await;
        assert_eq!(refused["error"]["kind"], "refused", "{refused}");
    }
    let resource = ask(
        &server,
        modern(
            1,
            "resources/read",
            json!({"uri": format!("proxyx://feeds/rival/{feed_id}")}),
        ),
    )
    .await;
    assert!(
        resource["error"].is_object(),
        "a guessed org does not find the feed: {resource}"
    );
    // a restarted server does not know the feed
    let restarted = feed_server(&fx, "ttl_secs = 1\n");
    tool_err(&restarted, "read_capture_feed", json!({"feed_id": feed_id})).await;
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let expired = tool_err(&server, "read_capture_feed", json!({"feed_id": feed_id})).await;
    assert!(expired.to_string().contains("expired"), "{expired}");
}

#[tokio::test]
async fn a_scope_that_ends_closes_its_feeds() {
    let fx = Fixture::start().await;
    let server = feed_server(&fx, "");
    let scope = tool_ok(
        &server,
        "open_analysis_scope",
        json!({"source_ids": ["run-1"], "ttl_secs": 1}),
    )
    .await;
    let feed_id = open_feed(&server, scope["scope_id"].as_str().expect("scope")).await["feed_id"]
        .as_str()
        .expect("id")
        .to_owned();
    tokio::time::sleep(Duration::from_millis(2100)).await;
    tool_err(&server, "read_capture_feed", json!({"feed_id": feed_id})).await;
    let gone = tool_err(&server, "read_capture_feed", json!({"feed_id": feed_id})).await;
    assert!(
        gone.to_string().contains("unknown or expired"),
        "the feed was removed: {gone}"
    );
}

#[tokio::test]
async fn a_lost_cursor_is_reported_as_a_possible_retention_gap() {
    let fx = Fixture::start().await;
    store(
        &fx,
        vec![cap(1, "run-1", "api.example.com", "GET", "/", 200)],
    );
    let server = feed_server(&fx, "");
    let scope_id = open_scope(&server, &["run-1"]).await;
    let feed_id = open_feed(&server, &scope_id).await["feed_id"]
        .as_str()
        .expect("id")
        .to_owned();
    pushed(
        &fx,
        vec![cap(2, "run-1", "api.example.com", "GET", "/", 200)],
    );
    fx.control_state.lock().expect("control").reject_cursors = true;
    tokio::time::sleep(Duration::from_millis(40)).await;
    let error = tool_err(&server, "read_capture_feed", json!({"feed_id": feed_id})).await;
    assert_eq!(error["error"]["detail"]["retention_gap"], true, "{error}");
    // a cursor from before the feed began is refused outright
    fx.control_state.lock().expect("control").reject_cursors = false;
    tokio::time::sleep(Duration::from_millis(40)).await;
    use base64::Engine as _;
    let before_the_start = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0_u8; 40]);
    let replay = tool_err(
        &server,
        "read_capture_feed",
        json!({"feed_id": feed_id, "cursor": before_the_start}),
    )
    .await;
    assert!(
        replay.to_string().contains("older than the feed's start")
            || replay.to_string().contains("not a cursor"),
        "{replay}"
    );
}

#[tokio::test]
async fn feed_bodies_are_off_by_default_and_cleaned_like_the_tools() {
    let fx = Fixture::start().await;
    let secret_body = r#"{"api_key":"feedsecret-0123456789","ok":true}"#;
    let secret = with_response(
        cap(
            2,
            "run-1",
            "api.example.com",
            "GET",
            "/p?token=feedquery0123",
            200,
        ),
        &[
            ("x-session-token", "feedheader-0123456789"),
            ("content-type", "application/json"),
        ],
        Some(secret_body),
    );
    store(
        &fx,
        vec![cap(1, "run-1", "api.example.com", "GET", "/", 200)],
    );
    let server = feed_server(&fx, "");
    let scope_id = open_scope(&server, &["run-1"]).await;
    let refused = tool_err(
        &server,
        "open_capture_feed",
        json!({"scope_id": scope_id, "include_bodies": true}),
    )
    .await;
    assert!(refused.to_string().contains("include_bodies"), "{refused}");

    let with_bodies = feed_server(&fx, "include_bodies = true\n");
    let scope_id = open_scope(&with_bodies, &["run-1"]).await;
    let feed_id = tool_ok(
        &with_bodies,
        "open_capture_feed",
        json!({"scope_id": scope_id, "include_bodies": true}),
    )
    .await["feed_id"]
        .as_str()
        .expect("id")
        .to_owned();
    pushed(&fx, vec![secret]);
    let page = poll(&with_bodies, &feed_id).await;
    assert_eq!(page["count"], 1);
    assert_absent(
        "the feed page",
        &page.to_string(),
        &[
            "feedsecret-0123456789",
            "feedquery0123",
            "feedheader-0123456789",
        ],
    );
    let listed = tool_ok(
        &with_bodies,
        "search_traffic",
        json!({"branches": [{"source_id": "run-1"}], "include_bodies": "response"}),
    )
    .await;
    let same = listed["items"]
        .as_array()
        .expect("items")
        .iter()
        .find(|i| i["id"] == uid(2))
        .expect("capture");
    assert_eq!(
        page["items"][0]["response_body"], same["response_body"],
        "the feed and the tool clean a capture identically"
    );
    assert_eq!(page["items"][0]["path"], same["path"]);
    assert!(
        page["items"][0]["response_body"]["text"]
            .as_str()
            .expect("text")
            .contains("[redacted]")
    );
    // the resource is the same page through the same gate
    pushed(
        &fx,
        vec![cap(3, "run-1", "api.example.com", "GET", "/z", 200)],
    );
    tokio::time::sleep(Duration::from_millis(40)).await;
    let read = ask(
        &with_bodies,
        modern(
            1,
            "resources/read",
            json!({"uri": format!("proxyx://feeds/acme/{feed_id}")}),
        ),
    )
    .await;
    let text = read["result"]["contents"][0]["text"]
        .as_str()
        .expect("resource text");
    let resource: Value = serde_json::from_str(text).expect("JSON page");
    assert_eq!(ids(&resource), vec![uid(3)]);
    assert_eq!(resource["live_stream"], false);
}
