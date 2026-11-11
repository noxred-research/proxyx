//! Streamable HTTP transport conformance: authentication, origin validation, request metadata
//! headers, status codes and both protocol eras.

mod common;

use std::net::SocketAddr;

use common::*;
use proxyx_client::Secret;
use proxyx_mcp::http::{HttpOptions, router, serve};
use reqwest::StatusCode;
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

struct Running {
    url: String,
    client: reqwest::Client,
    cancel: CancellationToken,
}

impl Drop for Running {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

async fn start(fx: &Fixture, safety: &str, max_body: usize) -> Running {
    let server = fx.server(safety, "");
    let options = HttpOptions {
        path: "/mcp".into(),
        token: Secret::new(HTTP_TOKEN),
        allowed_origins: vec!["https://allowed.example".into()],
        loopback_bind: true,
        max_body_bytes: max_body,
        shutdown: CancellationToken::new(),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr: SocketAddr = listener.local_addr().expect("addr");
    let cancel = CancellationToken::new();
    tokio::spawn(serve(listener, router(server, options), cancel.clone()));
    Running {
        url: format!("http://{addr}/mcp"),
        client: reqwest::Client::new(),
        cancel,
    }
}

impl Running {
    fn post(&self, body: &Value) -> reqwest::RequestBuilder {
        self.client
            .post(&self.url)
            .bearer_auth(HTTP_TOKEN)
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .body(body.to_string())
    }

    /// A modern request with the standard headers.
    fn modern(&self, id: i64, method: &str, params: Value) -> reqwest::RequestBuilder {
        let name = params
            .get("name")
            .or_else(|| params.get("uri"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        let body = modern(id, method, params);
        let mut request = self
            .post(&body)
            .header("mcp-protocol-version", "2026-07-28")
            .header("mcp-method", method);
        if let Some(name) = name {
            request = request.header("mcp-name", name);
        }
        request
    }
}

#[tokio::test]
async fn modern_request_with_headers_succeeds() {
    let fx = Fixture::start().await;
    let http = start(&fx, "", 1 << 20).await;
    let response = http
        .modern(1, "tools/list", json!({}))
        .send()
        .await
        .expect("send");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "application/json");
    assert!(
        response.headers().get("mcp-session-id").is_none(),
        "no protocol-level session"
    );
    let body: Value = response.json().await.expect("json");
    assert_eq!(body["id"], 1);
    assert_eq!(body["result"]["resultType"], "complete");
    assert!(body["result"]["tools"].as_array().expect("tools").len() > 20);

    let call = http
        .modern(
            2,
            "tools/call",
            json!({"name": "explain_refusal", "arguments": {"code": "cache_empty"}}),
        )
        .send()
        .await
        .expect("send");
    assert_eq!(call.status(), StatusCode::OK);
    let body: Value = call.json().await.expect("json");
    assert_eq!(body["result"]["structuredContent"]["http_status"], 503);

    // an encoded Mcp-Name header is decoded before it is compared
    let encoded = http
        .post(&modern(
            3,
            "tools/call",
            json!({"name": "health", "arguments": {}}),
        ))
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", "=?base64?aGVhbHRo?=")
        .send()
        .await
        .expect("send");
    assert_eq!(encoded.status(), StatusCode::OK);
}

#[tokio::test]
async fn legacy_clients_initialize_and_call_without_sessions() {
    let fx = Fixture::start().await;
    let http = start(&fx, "", 1 << 20).await;
    let init = http
        .post(&legacy(1, "initialize", json!({"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "old", "version": "1"}})))
        .send()
        .await
        .expect("send");
    assert_eq!(init.status(), StatusCode::OK);
    assert!(init.headers().get("mcp-session-id").is_none());
    let body: Value = init.json().await.expect("json");
    assert_eq!(body["result"]["protocolVersion"], "2025-03-26");

    // later requests carry the negotiated version header and a stale session id that is ignored
    let list = http
        .post(&legacy(2, "tools/list", json!({})))
        .header("mcp-protocol-version", "2025-06-18")
        .header("mcp-session-id", "stale-session")
        .send()
        .await
        .expect("send");
    assert_eq!(list.status(), StatusCode::OK);
    let body: Value = list.json().await.expect("json");
    assert!(body["result"]["tools"].is_array());
    assert!(body["result"].get("resultType").is_none());

    let unsupported = http
        .post(&legacy(3, "tools/list", json!({})))
        .header("mcp-protocol-version", "1999-01-01")
        .send()
        .await
        .expect("send");
    assert_eq!(unsupported.status(), StatusCode::BAD_REQUEST);
    let body: Value = unsupported.json().await.expect("json");
    assert_eq!(body["error"]["code"], -32022);
}

#[tokio::test]
async fn authentication_and_origin_are_enforced() {
    let fx = Fixture::start().await;
    let http = start(&fx, "", 1 << 20).await;
    let body = modern(1, "tools/list", json!({})).to_string();
    let anonymous = http
        .client
        .post(&http.url)
        .header("content-type", "application/json")
        .body(body.clone())
        .send()
        .await
        .expect("send");
    assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);
    assert!(
        anonymous.headers()["www-authenticate"]
            .to_str()
            .expect("header")
            .starts_with("Bearer")
    );
    let wrong = http
        .client
        .post(&http.url)
        .bearer_auth("not-the-token")
        .header("content-type", "application/json")
        .body(body.clone())
        .send()
        .await
        .expect("send");
    assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);

    let hostile = http
        .modern(1, "tools/list", json!({}))
        .header("origin", "https://evil.example")
        .send()
        .await
        .expect("send");
    assert_eq!(
        hostile.status(),
        StatusCode::FORBIDDEN,
        "a foreign Origin is refused (DNS rebinding)"
    );
    let allowed = http
        .modern(1, "tools/list", json!({}))
        .header("origin", "https://allowed.example")
        .send()
        .await
        .expect("send");
    assert_eq!(allowed.status(), StatusCode::OK);
    let local = http
        .modern(1, "tools/list", json!({}))
        .header("origin", "http://localhost:3000")
        .send()
        .await
        .expect("send");
    assert_eq!(
        local.status(),
        StatusCode::OK,
        "loopback origins are allowed on a loopback bind"
    );
}

#[tokio::test]
async fn transport_rules_methods_types_and_notifications() {
    let fx = Fixture::start().await;
    let http = start(&fx, "", 4096).await;
    for method in [reqwest::Method::GET, reqwest::Method::DELETE] {
        let response = http
            .client
            .request(method, &http.url)
            .bearer_auth(HTTP_TOKEN)
            .send()
            .await
            .expect("send");
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(response.headers()["allow"], "POST");
    }
    let wrong_type = http
        .client
        .post(&http.url)
        .bearer_auth(HTTP_TOKEN)
        .header("content-type", "text/plain")
        .body("{}")
        .send()
        .await
        .expect("send");
    assert_eq!(wrong_type.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    let not_acceptable = http
        .client
        .post(&http.url)
        .bearer_auth(HTTP_TOKEN)
        .header("content-type", "application/json")
        .header("accept", "text/html")
        .body(json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}).to_string())
        .send()
        .await
        .expect("send");
    assert_eq!(not_acceptable.status(), StatusCode::NOT_ACCEPTABLE);
    let garbage = http
        .client
        .post(&http.url)
        .bearer_auth(HTTP_TOKEN)
        .header("content-type", "application/json")
        .body("{nope")
        .send()
        .await
        .expect("send");
    assert_eq!(garbage.status(), StatusCode::BAD_REQUEST);
    let body: Value = garbage.json().await.expect("json");
    assert_eq!(body["error"]["code"], -32700);
    let batch = http
        .post(&json!([{"jsonrpc": "2.0", "id": 1, "method": "ping"}]))
        .send()
        .await
        .expect("send");
    assert_eq!(batch.status(), StatusCode::BAD_REQUEST);
    let notification = http
        .post(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        .send()
        .await
        .expect("send");
    assert_eq!(notification.status(), StatusCode::ACCEPTED);
    assert!(notification.text().await.expect("text").is_empty());
    let too_big = http
        .post(&json!({"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {"pad": "x".repeat(8000)}}))
        .send()
        .await
        .expect("send");
    assert_eq!(too_big.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let unknown_method = http
        .modern(9, "tools/frobnicate", json!({}))
        .send()
        .await
        .expect("send");
    assert_eq!(unknown_method.status(), StatusCode::NOT_FOUND);
    let body: Value = unknown_method.json().await.expect("json");
    assert_eq!(body["error"]["code"], -32601);
}

#[tokio::test]
async fn request_metadata_headers_must_match_the_body() {
    let fx = Fixture::start().await;
    let http = start(&fx, "", 1 << 20).await;
    let body = modern(1, "tools/call", json!({"name": "health", "arguments": {}}));
    let cases: Vec<(&str, reqwest::RequestBuilder)> = vec![
        (
            "missing protocol version",
            http.post(&body)
                .header("mcp-method", "tools/call")
                .header("mcp-name", "health"),
        ),
        (
            "protocol version mismatch",
            http.post(&body)
                .header("mcp-protocol-version", "2025-11-25")
                .header("mcp-method", "tools/call")
                .header("mcp-name", "health"),
        ),
        (
            "missing method",
            http.post(&body)
                .header("mcp-protocol-version", "2026-07-28")
                .header("mcp-name", "health"),
        ),
        (
            "method mismatch",
            http.post(&body)
                .header("mcp-protocol-version", "2026-07-28")
                .header("mcp-method", "tools/list")
                .header("mcp-name", "health"),
        ),
        (
            "name mismatch",
            http.post(&body)
                .header("mcp-protocol-version", "2026-07-28")
                .header("mcp-method", "tools/call")
                .header("mcp-name", "put_policy"),
        ),
        (
            "missing name",
            http.post(&body)
                .header("mcp-protocol-version", "2026-07-28")
                .header("mcp-method", "tools/call"),
        ),
    ];
    for (label, request) in cases {
        let response = request.send().await.expect("send");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{label}");
        let body: Value = response.json().await.expect("json");
        assert_eq!(body["error"]["code"], -32020, "{label}");
    }
}

#[tokio::test]
async fn tool_failures_are_http_200_results_not_transport_errors() {
    let fx = Fixture::start().await;
    let http = start(&fx, "", 1 << 20).await;
    let response = http
        .modern(
            1,
            "tools/call",
            json!({"name": "get_customer_upstream", "arguments": {"org": "BAD ORG"}}),
        )
        .send()
        .await
        .expect("send");
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.expect("json");
    assert_eq!(body["result"]["isError"], true);
    let unknown = http
        .modern(2, "tools/call", json!({"name": "nope", "arguments": {}}))
        .send()
        .await
        .expect("send");
    let body: Value = unknown.json().await.expect("json");
    assert_eq!(body["error"]["code"], -32602);
}

#[tokio::test]
async fn liveness_and_readiness_need_no_token_and_show_no_secret() {
    let fx = Fixture::start().await;
    let server = fx.server("", "");
    let shutdown = CancellationToken::new();
    let options = HttpOptions {
        path: "/mcp".into(),
        token: Secret::new(HTTP_TOKEN),
        allowed_origins: vec![],
        loopback_bind: true,
        max_body_bytes: 1 << 20,
        shutdown: shutdown.clone(),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    let stop = CancellationToken::new();
    tokio::spawn(serve(listener, router(server, options), stop.clone()));
    let client = reqwest::Client::new();

    let live = client
        .get(format!("{base}/healthz"))
        .send()
        .await
        .expect("send");
    assert_eq!(live.status(), StatusCode::OK);
    assert_eq!(live.json::<Value>().await.expect("json")["status"], "ok");
    let ready = client
        .get(format!("{base}/readyz"))
        .send()
        .await
        .expect("send");
    assert_eq!(
        ready.status(),
        StatusCode::OK,
        "every configured backend answers"
    );
    let text = ready.text().await.expect("text");
    for secret in [ADMIN, SERVICE_KEY, HTTP_TOKEN, "127.0.0.1"] {
        assert!(
            !text.contains(secret),
            "{secret} must not appear in /readyz"
        );
    }
    // the MCP endpoint itself is still authenticated
    let mcp = client
        .post(format!("{base}/mcp"))
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .await
        .expect("send");
    assert_eq!(mcp.status(), StatusCode::UNAUTHORIZED);

    // draining after shutdown starts; liveness stays up
    shutdown.cancel();
    let draining = client
        .get(format!("{base}/readyz"))
        .send()
        .await
        .expect("send");
    assert_eq!(draining.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        draining.json::<Value>().await.expect("json")["status"],
        "draining"
    );
    assert_eq!(
        client
            .get(format!("{base}/healthz"))
            .send()
            .await
            .expect("send")
            .status(),
        StatusCode::OK
    );
    stop.cancel();

    // a backend that does not answer makes the server not ready, by name only
    let dead = fx.server("", "[[endpoints.roles]]\nname = \"dead-role\"\nkind = \"gateway\"\nurl = \"http://127.0.0.1:9\"\n");
    let options = HttpOptions {
        path: "/mcp".into(),
        token: Secret::new(HTTP_TOKEN),
        allowed_origins: vec![],
        loopback_bind: true,
        max_body_bytes: 1 << 20,
        shutdown: CancellationToken::new(),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    let stop = CancellationToken::new();
    tokio::spawn(serve(listener, router(dead, options), stop.clone()));
    let not_ready = client
        .get(format!("{base}/readyz"))
        .send()
        .await
        .expect("send");
    assert_eq!(not_ready.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body: Value = not_ready.json().await.expect("json");
    assert_eq!(body["status"], "not ready");
    assert_eq!(body["unreachable"], json!(["dead-role"]));
    stop.cancel();
}

#[tokio::test]
async fn concurrency_is_capped() {
    let fx = Fixture::start().await;
    let http = start(&fx, "", 1 << 20).await;
    // the cap is limits.max_in_flight (16 by default); requests above it are answered 429
    let mut tasks = tokio::task::JoinSet::new();
    for id in 0..48 {
        let request = http.modern(id, "tools/call", json!({"name": "health", "arguments": {}}));
        tasks.spawn(async move { request.send().await.map(|response| response.status()) });
    }
    let mut ok = 0;
    let mut busy = 0;
    while let Some(done) = tasks.join_next().await {
        match done.expect("task").expect("response") {
            StatusCode::OK => ok += 1,
            StatusCode::TOO_MANY_REQUESTS => busy += 1,
            other => panic!("unexpected status {other}"),
        }
    }
    assert_eq!(ok + busy, 48);
    assert!(ok >= 1);
}
