//! In-process fakes of the ProxyX control surfaces on loopback, and a fixture that builds an MCP
//! server pointed at them.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Json;
use axum::Router;
use axum::body::Body;
use axum::extract::{Path as AxPath, Query, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use proxyx_mcp::config::Config;
use proxyx_mcp::server::Server;
use proxyx_mcp::stdio;
use proxyx_mcp::tools::Ctx;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, BufReader};

pub const ADMIN: &str = "admin-token-value-0123456789";
pub const SERVICE_KEY: &str = "pxk_servicekeyservicekeyservicekey0123456789a";
pub const ORG_KEY: &str = "ak_orgkeyorgkeyorgkeyorgkeyorgkey0123456789abc";
pub const HTTP_TOKEN: &str = "mcp-http-token-0123456789";
pub const CONFIRM_TOKEN: &str = "operator-confirm-token-9876543210";
pub const UPSTREAM_PASSWORD: &str = "upstream-password-s3cr3t";
pub const NEW_ORG_KEY: &str = "ak_newkeynewkeynewkeynewkeynewkey0123456789xyz";
pub const SESSION_ID: &str = "0f6d3a4e-5b1c-4d52-9a0e-7c1b2e8d4f10";
pub const SESSION_PROXY_URL: &str =
    "http://0f6d3a4e-5b1c-4d52-9a0e-7c1b2e8d4f10:password@localhost:8443";

/// One request a fake saw.
#[derive(Debug, Clone)]
pub struct Recorded {
    pub method: String,
    pub path: String,
    pub query: String,
    pub authorization: Option<String>,
    pub operator: Option<String>,
    pub body: Value,
}

#[derive(Clone, Default)]
pub struct Log(Arc<Mutex<Vec<Recorded>>>);

impl Log {
    pub fn all(&self) -> Vec<Recorded> {
        self.0.lock().expect("log").clone()
    }

    pub fn calls(&self, method: &str, path: &str) -> Vec<Recorded> {
        self.all()
            .into_iter()
            .filter(|r| r.method == method && r.path == path)
            .collect()
    }

    pub fn mutations(&self) -> Vec<Recorded> {
        self.all()
            .into_iter()
            .filter(|r| r.method != "GET")
            .collect()
    }
}

async fn record(State(log): State<Log>, req: Request, next: Next) -> Response {
    let (parts, body) = req.into_parts();
    let bytes = axum::body::to_bytes(body, 16 << 20)
        .await
        .unwrap_or_default();
    let header = |name: &str| {
        parts
            .headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    };
    log.0.lock().expect("log").push(Recorded {
        method: parts.method.to_string(),
        path: parts.uri.path().to_owned(),
        query: parts.uri.query().unwrap_or("").to_owned(),
        authorization: header("authorization"),
        operator: header("x-operator"),
        body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    });
    next.run(axum::http::Request::from_parts(parts, Body::from(bytes)))
        .await
}

pub struct Fake {
    pub addr: SocketAddr,
    pub log: Log,
}

impl Fake {
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }
}

async fn spawn(router: Router) -> Fake {
    let log = Log::default();
    let app = router.layer(middleware::from_fn_with_state(log.clone(), record));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Fake { addr, log }
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({"error": "unauthorized"})),
    )
        .into_response()
}

fn bearer_is(headers: &HeaderMap, token: &str) -> bool {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v == format!("Bearer {token}"))
}

// --- pool control API ------------------------------------------------------------------------

#[derive(Default)]
pub struct PoolState {
    pub policies: Vec<Value>,
    pub inventory: Vec<Value>,
    pub blocks: Vec<Value>,
    pub upstream: Option<Value>,
}

pub type Pool = Arc<Mutex<PoolState>>;

pub fn global_policy() -> Value {
    json!({
        "scope": "global", "name": "global", "match": null, "version": 3, "actor": "gitops",
        "created_at": 1_767_225_600,
        "doc": {"name": "global", "scope": "global", "kinds": ["rotating", "static"],
                "providers": ["p1", "p2"], "regions": ["fr", "de"], "min_ready": 10, "lease_ttl": 600}
    })
}

fn pool_state() -> Pool {
    Arc::new(Mutex::new(PoolState {
        policies: vec![global_policy()],
        inventory: vec![
            json!({"ip": "203.0.113.10", "provider": "isp1", "region": "fr/paris", "state": "available", "owner": null}),
            json!({"ip": "203.0.113.11", "provider": "isp1", "region": "fr/paris", "state": "cooldown", "owner": null}),
        ],
        blocks: vec![json!({
            "id": "6f1f6d5e-3c7a-4d4b-9c52-2f1a5a5d8f10", "org": "acme", "scope": "provider",
            "value": "p1", "reason": "abuse report", "operator": "admin", "created_at": 1_767_225_600,
            "expires_at": null, "revoked_at": null
        })],
        upstream: None,
    }))
}

async fn admin_guard(headers: HeaderMap, req: Request, next: Next) -> Response {
    if bearer_is(&headers, ADMIN) {
        next.run(req).await
    } else {
        unauthorized()
    }
}

pub async fn fake_pool() -> (Fake, Pool) {
    let state = pool_state();
    let admin = Router::new()
        .route(
            "/v1/policies",
            get(pool_policies_get).put(pool_policies_put),
        )
        .route("/v1/policies/{scope}/{name}", delete(pool_policy_delete))
        .route("/v1/orgs/{org}/cache-policy", put(pool_org_policy))
        .route("/v1/inventory", get(pool_inventory))
        .route("/v1/inventory/replacements", get(pool_inventory))
        .route("/v1/inventory/{provider}", put(pool_inventory_put))
        .route("/v1/orgs/{org}/sessions", get(pool_sessions_list))
        .route("/v1/orgs/{org}/sessions/{sid}", delete(pool_session_drop))
        .route("/v1/orgs/{org}/endpoints", post(pool_endpoints))
        .route("/v1/org-blocks", get(pool_blocks).post(pool_block_create))
        .route("/v1/org-blocks/{id}", delete(pool_block_delete))
        .route(
            "/v1/orgs/{org}/keys",
            post(pool_key_create).delete(pool_keys_disable),
        )
        .route(
            "/v1/orgs/{org}/upstream",
            get(pool_upstream_get)
                .put(pool_upstream_put)
                .delete(pool_upstream_delete),
        )
        .route(
            "/v1/orgs/{org}/upstream/validate",
            post(pool_upstream_validate),
        )
        .route(
            "/v1/ips/{ip}/block",
            post(|| async { Json(json!({"scope": "target"})) }),
        )
        .route_layer(middleware::from_fn(admin_guard));
    let router = Router::new()
        .route("/v1/block-signals", post(pool_block_signals))
        .merge(admin)
        .with_state(Arc::clone(&state));
    (spawn(router).await, state)
}

async fn pool_policies_get(State(s): State<Pool>) -> Json<Value> {
    Json(json!({"items": s.lock().expect("pool").policies.clone()}))
}

fn store_doc(state: &mut PoolState, doc: &Value) -> String {
    let scope = doc["scope"].as_str().unwrap_or("global").to_owned();
    let name = doc["name"].as_str().unwrap_or("").to_owned();
    state
        .policies
        .retain(|p| !(p["scope"] == scope && p["name"] == name));
    state.policies.push(json!({
        "scope": scope, "name": name, "match": doc["match"], "version": 1,
        "actor": "admin", "created_at": 1_767_225_700, "doc": doc
    }));
    format!("{scope}/{name}")
}

async fn pool_policies_put(State(s): State<Pool>, Json(body): Json<Value>) -> Json<Value> {
    let mut state = s.lock().expect("pool");
    let stored: Vec<String> = body["policies"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|doc| store_doc(&mut state, doc))
        .collect();
    Json(json!({"stored": stored, "unchanged": 0}))
}

async fn pool_org_policy(
    State(s): State<Pool>,
    AxPath(_org): AxPath<String>,
    Json(doc): Json<Value>,
) -> Json<Value> {
    let mut state = s.lock().expect("pool");
    let stored = store_doc(&mut state, &doc);
    Json(json!({"stored": [stored], "unchanged": 0}))
}

async fn pool_policy_delete(
    State(s): State<Pool>,
    AxPath((scope, name)): AxPath<(String, String)>,
) -> Json<Value> {
    s.lock()
        .expect("pool")
        .policies
        .retain(|p| !(p["scope"] == scope && p["name"] == name));
    Json(json!({"deactivated": format!("{scope}/{name}"), "written_by": "admin"}))
}

async fn pool_inventory(
    State(s): State<Pool>,
    Query(q): Query<BTreeMap<String, String>>,
) -> Json<Value> {
    let items: Vec<Value> = s
        .lock()
        .expect("pool")
        .inventory
        .iter()
        .filter(|row| {
            q.get("provider")
                .is_none_or(|p| row["provider"] == p.as_str())
        })
        .cloned()
        .collect();
    Json(json!({"items": items}))
}

async fn pool_inventory_put(
    State(s): State<Pool>,
    AxPath(provider): AxPath<String>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let mut state = s.lock().expect("pool");
    let entries = body["entries"].as_array().cloned().unwrap_or_default();
    let added: Vec<Value> = entries.iter().map(|e| e["ip"].clone()).collect();
    state
        .inventory
        .retain(|row| row["provider"] != provider.as_str());
    state.inventory.extend(entries);
    Json(
        json!({"provider": provider, "added": added, "updated": [], "revived": [], "retired": [], "unchanged": 0}),
    )
}

async fn pool_sessions_list(AxPath(org): AxPath<String>) -> Json<Value> {
    Json(json!({
        "org": org,
        "sessions": [
            {"sid": "scan42", "provider": "p1", "region": "fr/paris", "exit_ip": "203.0.113.50", "age_seconds": 120, "bytes": 4096},
            {"sid": "job_7", "provider": "p2", "region": "de", "exit_ip": "203.0.113.51", "age_seconds": 30, "bytes": 10},
            {"sid": "job_8", "provider": "p2", "region": "de", "exit_ip": "203.0.113.52", "age_seconds": 20, "bytes": 0}
        ],
        "affinity": {"entries": 3, "hits": 40, "misses": 3, "evictions": 0, "rotations": 1}
    }))
}

async fn pool_session_drop(AxPath((org, sid)): AxPath<(String, String)>) -> Response {
    if sid == "gone" {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "no live session with this sid"})),
        )
            .into_response();
    }
    Json(json!({"org": org, "sid": sid, "rotated": true})).into_response()
}

/// Echoes `count` username-only endpoints. A request that carries an org key is refused, like
/// the real route would not need it.
async fn pool_endpoints(AxPath(org): AxPath<String>, Json(body): Json<Value>) -> Response {
    if body.get("org_key").is_some() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "unexpected org_key"})),
        )
            .into_response();
    }
    let count = body["count"].as_u64().unwrap_or(1);
    let scheme = if body["style"] == "socks5" {
        "socks5"
    } else {
        "http"
    };
    let endpoints: Vec<Value> = (0..count)
        .map(|n| {
            json!({
                "sid": format!("gen{n}"),
                "url": format!("{scheme}://px-cc-fr-sid-gen{n}@{}:8080", body["gateway_host"].as_str().unwrap_or("")),
                "username": format!("px-cc-fr-sid-gen{n}"),
            })
        })
        .collect();
    (
        StatusCode::CREATED,
        Json(json!({"org": org, "count": count, "endpoints": endpoints})),
    )
        .into_response()
}

async fn pool_blocks(
    State(s): State<Pool>,
    Query(q): Query<BTreeMap<String, String>>,
) -> Json<Value> {
    let items: Vec<Value> = s
        .lock()
        .expect("pool")
        .blocks
        .iter()
        .filter(|b| q.get("org").is_none_or(|o| b["org"] == o.as_str()))
        .cloned()
        .collect();
    Json(json!({"items": items}))
}

async fn pool_block_create(State(s): State<Pool>, Json(body): Json<Value>) -> Response {
    let block = json!({
        "id": "11111111-2222-4333-8444-555555555555", "org": body["org"], "scope": body["scope"],
        "value": body["value"], "reason": body["reason"], "operator": "admin",
        "created_at": 1_767_225_800, "expires_at": null, "revoked_at": null, "drained": 2
    });
    s.lock().expect("pool").blocks.push(block.clone());
    (StatusCode::CREATED, Json(block)).into_response()
}

async fn pool_block_delete(State(s): State<Pool>, AxPath(id): AxPath<String>) -> Response {
    let mut state = s.lock().expect("pool");
    let before = state.blocks.len();
    state.blocks.retain(|b| b["id"] != id.as_str());
    if state.blocks.len() == before {
        return (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response();
    }
    Json(json!({"id": id, "revoked_at": 1_767_225_900})).into_response()
}

async fn pool_key_create(AxPath(org): AxPath<String>) -> Response {
    (
        StatusCode::CREATED,
        Json(json!({"org": org, "key": NEW_ORG_KEY})),
    )
        .into_response()
}

async fn pool_keys_disable(AxPath(org): AxPath<String>) -> Json<Value> {
    Json(json!({"org": org, "disabled": 2}))
}

async fn pool_upstream_get(State(s): State<Pool>, AxPath(org): AxPath<String>) -> Response {
    match s.lock().expect("pool").upstream.clone() {
        Some(mut up) => {
            up["org"] = json!(org);
            Json(up).into_response()
        }
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "no upstream"}))).into_response(),
    }
}

async fn pool_upstream_put(
    State(s): State<Pool>,
    AxPath(org): AxPath<String>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let up = json!({
        "org": org, "provider": "customer", "scheme": body["scheme"], "host": body["host"],
        "port": body["port"], "region": body["region"], "state": "candidate",
        "has_login": body.get("password").is_some(), "leasable": false
    });
    s.lock().expect("pool").upstream = Some(up.clone());
    Json(up)
}

async fn pool_upstream_delete(State(s): State<Pool>, AxPath(org): AxPath<String>) -> Json<Value> {
    s.lock().expect("pool").upstream = None;
    Json(json!({"org": org, "unit": "fd00::1", "state": "retired"}))
}

async fn pool_upstream_validate(State(s): State<Pool>, AxPath(org): AxPath<String>) -> Response {
    let host = s
        .lock()
        .expect("pool")
        .upstream
        .as_ref()
        .and_then(|u| u["host"].as_str().map(str::to_owned))
        .unwrap_or_default();
    if host.contains("bad") {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"org": org, "reason": "refused", "error": "connection refused", "valid": false})),
        )
            .into_response();
    }
    Json(json!({"org": org, "state": "available", "leasable": true, "exit_ip": "198.51.100.77", "valid": true, "country": "fr"}))
        .into_response()
}

async fn pool_block_signals(headers: HeaderMap, Json(body): Json<Value>) -> Response {
    let ok = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("Basic "));
    if !ok {
        return unauthorized();
    }
    let n = body.as_array().map_or(0, Vec::len);
    Json(json!({"accepted": n, "ignored": 0})).into_response()
}

// --- session control plane ----------------------------------------------------------------------

pub fn capture(id: &str, status: u64, host: &str, body: &str) -> Value {
    json!({
        "id": id, "org_id": "acme", "timestamp": "2026-11-10T10:01:02.345Z", "session_offset": 1,
        "method": "GET", "path": "/v1/items", "host": host, "scheme": "https",
        "session_id": SESSION_ID, "proxy_id": "proxy-1", "request_size": 0,
        "status_code": status, "response_size": body.len(), "duration_ms": 42, "ratelimit_wait_ms": 0,
        "source": "mcp", "source_id": "run-1",
        "request_headers": [["accept", "*/*"], ["Authorization", "Bearer targetsecrettoken123"]],
        "response_headers": [["content-type", "text/html"], ["set-cookie", "sid=abc"]],
        "request_body": null,
        "response_body": {"status": "body", "value": body}
    })
}

pub struct ControlState {
    pub captures: Vec<Value>,
    pub sessions_created: u32,
}

pub type Control = Arc<Mutex<ControlState>>;

async fn service_guard(headers: HeaderMap, req: Request, next: Next) -> Response {
    if req.uri().path().starts_with("/rpc/") && !bearer_is(&headers, SERVICE_KEY) {
        return unauthorized();
    }
    next.run(req).await
}

pub async fn fake_control() -> (Fake, Control) {
    let state = Arc::new(Mutex::new(ControlState {
        captures: vec![
            capture(
                "0190aaaa-0000-4000-8000-000000000001",
                200,
                "api.example.com",
                "{\"ok\":true}",
            ),
            capture(
                "0190aaaa-0000-4000-8000-000000000002",
                429,
                "api.example.com",
                "Too Many Requests",
            ),
            capture(
                "0190aaaa-0000-4000-8000-000000000003",
                403,
                "www.example.com",
                &format!("<html>Just a moment... {}</html>", "x".repeat(6000)),
            ),
        ],
        sessions_created: 0,
    }));
    let router = Router::new()
        .route("/rpc/sessions", post(ctl_session_create))
        .route(
            "/rpc/sessions/{id}",
            get(ctl_session_get).patch(ctl_session_patch).delete(ctl_session_delete),
        )
        .route("/rpc/sessions/{id}/status", get(ctl_session_status))
        .route("/rpc/requests/search", post(ctl_search))
        .route("/rpc/requests/count", post(ctl_count))
        .route("/rpc/orgs/{org}/requests/{id}", get(ctl_capture))
        .route("/rpc/ws/search", post(|| async { Json(json!({"items": [], "next_cursor": null})) }))
        .route(
            "/rpc/orgs/{org}/captures/{parent}/ws-messages",
            get(|| async {
                Json(json!({"items": [{"id": "m1", "direction": "c2s", "payload": "hello", "session_id": SESSION_ID}], "next_cursor": null}))
            }),
        )
        .route("/rpc/orgs/{org}", get(|AxPath(org): AxPath<String>| async move {
            Json(json!({"org_id": org, "rate_limit_settings": {"requests_per_minute": 6000, "burst": 1000}, "egress_proxy": null}))
        }))
        .route(
            "/rpc/orgs/{org}/rate-limit",
            get(|| async { Json(json!({"requests_per_minute": 6000, "burst": 1000})) })
                .put(|Json(body): Json<Value>| async move { Json(body) }),
        )
        .route(
            "/rpc/orgs/{org}/rate-limit-state",
            get(|AxPath(org): AxPath<String>| async move {
                Json(json!({"org_id": org, "exists": true, "tokens": 0.0, "burst": 1000, "rpm": 6000, "last_refill_ms": 1}))
            }),
        )
        .route(
            "/rpc/orgs/{org}/proxy",
            get(|| async { (StatusCode::NOT_FOUND, Json(json!({"error": "no proxy"}))) })
                .put(|| async { Json(json!({})) })
                .delete(|| async { StatusCode::NO_CONTENT }),
        )
        .route("/rpc/certificate", get(|| async { "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n" }))
        .route("/health/live", get(|| async { "" }))
        .route("/health/ready", get(|| async { "ok" }))
        .route("/metrics", get(|| async { "proxyx_control_api_requests_total{route=\"/rpc/sessions\",status_class=\"2xx\",service=\"proxyx-control-api\"} 7\n" }))
        .route_layer(middleware::from_fn(service_guard))
        .with_state(Arc::clone(&state));
    (spawn(router).await, state)
}

async fn ctl_session_create(State(s): State<Control>, Json(body): Json<Value>) -> Response {
    s.lock().expect("control").sessions_created += 1;
    let expires = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_millis() as i64)
        + body["ttl_secs"].as_i64().unwrap_or(600) * 1000;
    (
        StatusCode::CREATED,
        Json(json!({
            "session_id": SESSION_ID,
            "ca_cert_pem": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
            "expires_at_ms": expires,
            "proxy_url": SESSION_PROXY_URL,
            "proxy_url_socks5": "socks5://0f6d3a4e-5b1c-4d52-9a0e-7c1b2e8d4f10:password@localhost:1080",
            "upstream_overrides": {}, "success": true
        })),
    )
        .into_response()
}

async fn ctl_session_get(AxPath(id): AxPath<String>) -> Response {
    if id != SESSION_ID {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "session not found"})),
        )
            .into_response();
    }
    let expires = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_millis() as i64)
        + 600_000;
    Json(json!({
        "session_id": id, "org_id": "acme", "source": "mcp", "source_id": "run-1", "agent": null,
        "captured_hosts": ["*.example.com"], "excluded_hosts": [], "upstream_overrides": {},
        "inject_headers": [["Authorization", "Bearer injected-secret-value"]], "serialize": false,
        "expires_at_ms": expires, "egress_proxy": {"proxy_type": "socks5", "address": "h:1080", "username": "u", "password": "<redacted>"},
        "rate_limit": {"requests_per_minute": 6000, "burst": 1000}
    }))
    .into_response()
}

async fn ctl_session_status(AxPath(id): AxPath<String>) -> Response {
    if id != SESSION_ID {
        return (StatusCode::NOT_FOUND, Json(json!({"error": "no session"}))).into_response();
    }
    Json(json!({"state": "active", "opened_at": "2026-11-10T10:00:00Z", "closing_at": null, "closed_at": null})).into_response()
}

async fn ctl_session_patch(Json(body): Json<Value>) -> Json<Value> {
    let add = body["additional_secs"].as_i64().unwrap_or(0);
    Json(json!({"expires_at_ms": 1_900_000_000_000_i64 + add * 1000}))
}

async fn ctl_session_delete() -> Json<Value> {
    Json(json!({}))
}

async fn ctl_search(State(s): State<Control>, Json(body): Json<Value>) -> Json<Value> {
    let limit = body["limit"].as_u64().unwrap_or(100) as usize;
    let want_bodies = body.get("response_body_max_fetch_size").is_some();
    let items: Vec<Value> = s
        .lock()
        .expect("control")
        .captures
        .iter()
        .take(limit)
        .map(|c| {
            let mut c = c.clone();
            if !want_bodies {
                c["response_body"] = Value::Null;
            }
            c
        })
        .collect();
    Json(json!({"items": items, "next_cursor": null, "total_count": null}))
}

async fn ctl_count(State(s): State<Control>) -> Json<Value> {
    Json(json!({"count": s.lock().expect("control").captures.len()}))
}

async fn ctl_capture(
    State(s): State<Control>,
    AxPath((_org, id)): AxPath<(String, String)>,
) -> Response {
    let found = s
        .lock()
        .expect("control")
        .captures
        .iter()
        .find(|c| c["id"] == id.as_str())
        .cloned();
    match found {
        Some(mut c) => {
            // the full capture has header objects and plain string bodies
            for key in ["request_headers", "response_headers"] {
                if let Some(pairs) = c[key].as_array() {
                    c[key] = Value::Object(
                        pairs
                            .iter()
                            .filter_map(|pair| {
                                Some((pair[0].as_str()?.to_ascii_lowercase(), pair[1].clone()))
                            })
                            .collect(),
                    );
                }
            }
            c["response_body"] = json!(c["response_body"]["value"].clone());
            Json(c).into_response()
        }
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response(),
    }
}

// --- ops ports ------------------------------------------------------------------------------------

pub type Text = Arc<Mutex<String>>;
pub type Ready = Arc<Mutex<(u16, String)>>;

pub struct OpsState {
    pub metrics: Text,
    pub ready: Ready,
}

pub async fn fake_ops(metrics: &str) -> (Fake, OpsState) {
    let text: Text = Arc::new(Mutex::new(metrics.to_owned()));
    let ready = Arc::new(Mutex::new((200_u16, "ok".to_owned())));
    let router =
        Router::new()
            .route("/healthz", get(|| async { "ok" }))
            .route(
                "/readyz",
                get(|State((_, r)): State<(Text, Ready)>| async move {
                    let (code, body) = r.lock().expect("ready").clone();
                    (StatusCode::from_u16(code).expect("status"), body)
                }),
            )
            .route(
                "/metrics",
                get(|State((t, _)): State<(Text, Ready)>| async move {
                    t.lock().expect("metrics").clone()
                }),
            )
            .with_state((Arc::clone(&text), Arc::clone(&ready)));
    (
        spawn(router).await,
        OpsState {
            metrics: text,
            ready,
        },
    )
}

pub fn gateway_metrics(cache_empty: u32) -> String {
    format!(
        r#"# TYPE proxyx_pool_connections_total counter
proxyx_pool_connections_total{{listener="connect",outcome="ok",provider="p1",service="proxyx-gateway"}} 90
proxyx_pool_connections_total{{listener="connect",outcome="cache_empty",provider="none",service="proxyx-gateway"}} {cache_empty}
proxyx_pool_connections_total{{listener="connect",outcome="option_denied",provider="none",service="proxyx-gateway"}} 2
proxyx_pool_connections_total{{listener="connect",outcome="bad_request",provider="none",service="proxyx-gateway"}} 1
proxyx_pool_block_signals_total{{source="client",type="rate_limited",scope="target",service="proxyx-gateway"}} 5
proxyx_pool_block_signals_total{{source="probe",type="challenge",scope="ip",service="proxyx-gateway"}} 1
proxyx_pool_block_signals_ignored_total{{service="proxyx-gateway"}} 1
proxyx_pool_tunnels_open{{service="proxyx-gateway"}} 3
"#
    )
}

pub const WARMER_METRICS: &str = r#"# TYPE proxyx_pool_cache_ready gauge
proxyx_pool_cache_ready{kind="rotating",provider="p1",tier="normal",service="proxyx-warmer"} 2
proxyx_pool_cache_ready{kind="rotating",provider="p1",tier="degraded",service="proxyx-warmer"} 1
proxyx_pool_cache_ready{kind="rotating",provider="p2",tier="normal",service="proxyx-warmer"} 12
proxyx_pool_cache_min_ready{kind="rotating",provider="p1",service="proxyx-warmer"} 10
proxyx_pool_cache_min_ready{kind="rotating",provider="p2",service="proxyx-warmer"} 10
proxyx_pool_cache_low_watermark{kind="rotating",provider="p1",service="proxyx-warmer"} 5
proxyx_pool_cache_low_watermark{kind="rotating",provider="p2",service="proxyx-warmer"} 5
proxyx_pool_cache_low{kind="rotating",provider="p1",tier="all",service="proxyx-warmer"} 1
proxyx_pool_cache_low{kind="rotating",provider="p2",tier="all",service="proxyx-warmer"} 0
proxyx_pool_provider_breaker_state{provider="p1",service="proxyx-warmer"} 2
proxyx_pool_provider_breaker_state{provider="p2",service="proxyx-warmer"} 0
proxyx_pool_cost_used_ratio{provider="p1",service="proxyx-warmer"} 0.4
proxyx_pool_breaker_skips_total{provider="p1",service="proxyx-warmer"} 17
proxyx_pool_warm_creates_total{provider="p1",outcome="failed",service="proxyx-warmer"} 9
proxyx_pool_warm_creates_total{provider="p2",outcome="ok",service="proxyx-warmer"} 30
proxyx_pool_cache_sessions{kind="rotating",state="ready",service="proxyx-warmer"} 15
proxyx_pool_redis_down{service="proxyx-warmer"} 0
proxyx_pool_postgres_down{service="proxyx-warmer"} 0
proxyx_pool_inventory_ips{provider="isp1",state="available",service="proxyx-warmer"} 4
proxyx_intercept_upstream_breaker_state{target_kind="egress_proxy",service="proxyx-warmer"} 2
proxyx_edge_parent_breaker_state{parent="parent-1",service="proxyx-warmer"} 2
proxyx_edge_parent_breaker_open{parent="parent-2",service="proxyx-warmer"} 0
proxyx_edge_parent_breaker_trips_total{parent="parent-1",service="proxyx-warmer"} 4
"#;

// --- LLM ------------------------------------------------------------------------------------------

#[derive(Clone, Default)]
pub struct LlmScript {
    /// Content to answer with, by `response_format.json_schema.name`.
    pub answers: Arc<Mutex<BTreeMap<String, String>>>,
    /// Reject `json_schema` response formats with a 400, like a server that lacks support.
    pub refuse_json_schema: Arc<Mutex<bool>>,
}

pub async fn fake_llm() -> (Fake, LlmScript) {
    let script = LlmScript::default();
    let router = Router::new()
        .route("/v1/chat/completions", post(llm_complete))
        .with_state(script.clone());
    (spawn(router).await, script)
}

async fn llm_complete(
    State(s): State<LlmScript>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if !bearer_is(&headers, "llm-api-key-0123456789") {
        return unauthorized();
    }
    let format = &body["response_format"];
    if format["type"] == "json_schema" && *s.refuse_json_schema.lock().expect("flag") {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": {"message": "response_format json_schema is not supported"}})),
        )
            .into_response();
    }
    let name = format["json_schema"]["name"]
        .as_str()
        .unwrap_or("")
        .to_owned();
    let answer = {
        let answers = s.answers.lock().expect("answers");
        answers
            .get(&name)
            .or_else(|| answers.get("*"))
            .or_else(|| answers.values().next())
            .cloned()
            .unwrap_or_else(|| "{}".to_owned())
    };
    Json(json!({"choices": [{"message": {"role": "assistant", "content": answer}}]}))
        .into_response()
}

// --- fixture ---------------------------------------------------------------------------------------

pub struct Fixture {
    pub dir: PathBuf,
    pub pool: Fake,
    pub pool_state: Pool,
    pub control: Fake,
    pub control_state: Control,
    pub gateway: Fake,
    pub gateway_ops: OpsState,
    pub warmer: Fake,
    pub warmer_ops: OpsState,
    pub llm: Fake,
    pub llm_script: LlmScript,
}

pub fn write_file(dir: &Path, name: &str, content: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, content).expect("write file");
    path
}

impl Fixture {
    pub async fn start() -> Self {
        let dir = std::env::temp_dir().join(format!("proxyx-mcp-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let (pool, pool_state) = fake_pool().await;
        let (control, control_state) = fake_control().await;
        let (gateway, gateway_ops) = fake_ops(&gateway_metrics(8)).await;
        let (warmer, warmer_ops) = fake_ops(WARMER_METRICS).await;
        let (llm, llm_script) = fake_llm().await;
        for (name, value) in [
            ("admin-token", ADMIN),
            ("service-key", SERVICE_KEY),
            ("org-key", ORG_KEY),
            ("http-token", HTTP_TOKEN),
            ("confirm-token", CONFIRM_TOKEN),
            ("upstream-password", UPSTREAM_PASSWORD),
            ("llm-key", "llm-api-key-0123456789"),
        ] {
            write_file(&dir, name, &format!("{value}\n"));
        }
        Self {
            dir,
            pool,
            pool_state,
            control,
            control_state,
            gateway,
            gateway_ops,
            warmer,
            warmer_ops,
            llm,
            llm_script,
        }
    }

    pub fn state_dir(&self) -> PathBuf {
        self.dir.join("state")
    }

    pub fn audit_path(&self) -> PathBuf {
        self.dir.join("audit.jsonl")
    }

    /// Configuration text. `safety` lines go inside `[safety]`, `extra` is appended as is.
    pub fn config_text(&self, safety: &str, extra: &str) -> String {
        let d = self.dir.display();
        format!(
            r#"
[endpoints.pool]
url = "{pool}"
admin_token_file = "{d}/admin-token"
org_key_file = "{d}/org-key"
operator = "mcp-test"

[endpoints.control]
url = "{control}"
key_file = "{d}/service-key"
org = "acme"

[[endpoints.roles]]
name = "gateway"
kind = "gateway"
url = "{gateway}"

[[endpoints.roles]]
name = "warmer"
kind = "warmer"
url = "{warmer}"

[[endpoints.roles]]
name = "control"
kind = "control-api"
url = "{control}"

[http]
token_file = "{d}/http-token"
allowed_origins = ["https://allowed.example"]

[metrics]
sample_interval_secs = 0

[audit]
path = "{d}/audit.jsonl"

[credentials.upstream-main]
username = "svc-user"
password_file = "{d}/upstream-password"

[safety]
state_dir = "{d}/state"
{safety}

{extra}
"#,
            pool = self.pool.url(),
            control = self.control.url(),
            gateway = self.gateway.url(),
            warmer = self.warmer.url(),
        )
    }

    pub fn llm_config(&self) -> String {
        format!(
            "[llm]\nendpoint = \"{}/v1\"\nmodel = \"test-model\"\napi_key_file = \"{}/llm-key\"\ntimeout_secs = 5\n",
            self.llm.url(),
            self.dir.display()
        )
    }

    pub fn server(&self, safety: &str, extra: &str) -> Arc<Server> {
        let config = Config::parse(&self.config_text(safety, extra)).expect("config parses");
        Arc::new(Server::new(Ctx::new(config).expect("context")))
    }

    pub fn read_only(&self) -> Arc<Server> {
        self.server("", "")
    }

    pub fn admin(&self) -> Arc<Server> {
        self.server("profile = \"admin\"", "")
    }
}

// --- protocol helpers --------------------------------------------------------------------------------

pub fn modern_meta() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": {"name": "conformance-client", "version": "1.2.3"},
        "io.modelcontextprotocol/clientCapabilities": {}
    })
}

pub fn modern(id: i64, method: &str, mut params: Value) -> Value {
    params["_meta"] = modern_meta();
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
}

pub fn legacy(id: i64, method: &str, params: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
}

pub fn call(id: i64, tool: &str, arguments: Value) -> Value {
    modern(
        id,
        "tools/call",
        json!({"name": tool, "arguments": arguments}),
    )
}

/// Feed `input` to a server over an in-process duplex and collect every frame until it exits.
pub async fn converse_raw(server: Arc<Server>, input: String) -> Vec<Value> {
    let (mut reader, writer) = tokio::io::duplex(8 << 20);
    let served = stdio::serve(
        BufReader::new(std::io::Cursor::new(input.into_bytes())),
        writer,
        server,
    );
    let collected = async {
        let mut out = String::new();
        reader.read_to_string(&mut out).await.expect("read output");
        out
    };
    let (served, out) = tokio::time::timeout(Duration::from_secs(60), async {
        tokio::join!(served, collected)
    })
    .await
    .expect("serve finished");
    served.expect("serve ok");
    out.lines()
        .map(|line| serde_json::from_str(line).expect("each output line is JSON"))
        .collect()
}

pub async fn converse(server: &Arc<Server>, messages: &[Value]) -> Vec<Value> {
    let input: String = messages.iter().map(|m| format!("{m}\n")).collect();
    converse_raw(Arc::clone(server), input).await
}

/// One request, one response.
pub async fn ask(server: &Arc<Server>, message: Value) -> Value {
    let mut frames = converse(server, &[message]).await;
    assert_eq!(frames.len(), 1, "one reply: {frames:?}");
    frames.remove(0)
}

/// Import an existing session into the private registry and return its model-safe handle.
pub async fn existing_session_handle(server: &Arc<Server>) -> String {
    server
        .ctx
        .store
        .register_session(&json!({"session_id": SESSION_ID, "org": "acme"}))
        .expect("register existing session");
    let listed = tool_ok(server, "list_sessions", json!({})).await;
    listed["sessions"][0]["session_id"]
        .as_str()
        .expect("session handle")
        .to_owned()
}

/// Call a tool and return `(is_error, structured content or parsed text)`.
pub async fn tool(server: &Arc<Server>, name: &str, arguments: Value) -> (bool, Value) {
    let reply = ask(server, call(1, name, arguments)).await;
    let result = &reply["result"];
    assert!(
        result.is_object(),
        "tools/call answers with a result: {reply}"
    );
    let is_error = result["isError"].as_bool().expect("isError");
    let text = result["content"][0]["text"].as_str().expect("text content");
    let value = result
        .get("structuredContent")
        .cloned()
        .unwrap_or_else(|| serde_json::from_str(text).unwrap_or(Value::String(text.to_owned())));
    (is_error, value)
}

pub async fn tool_ok(server: &Arc<Server>, name: &str, arguments: Value) -> Value {
    let (is_error, value) = tool(server, name, arguments).await;
    assert!(!is_error, "{name} failed: {value}");
    value
}

pub async fn tool_err(server: &Arc<Server>, name: &str, arguments: Value) -> Value {
    let (is_error, value) = tool(server, name, arguments).await;
    assert!(is_error, "{name} should have failed: {value}");
    value
}

pub fn tool_names(reply: &Value) -> Vec<String> {
    reply["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .map(|t| t["name"].as_str().expect("tool name").to_owned())
        .collect()
}
