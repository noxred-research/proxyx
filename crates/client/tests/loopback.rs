//! End-to-end tests against fake servers on loopback: the control-plane routes, the pool
//! control API, and a CONNECT listener.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU16, AtomicU32, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use proxyx_client::Error;
use proxyx_client::gateway::{Cause, ConnectError, Kind, PoolGateway, PoolSelector};
use proxyx_client::provider::{ProxyProvider, SessionsProvider};
use proxyx_client::sessions::{
    CreateSessionRequest, Extend, KeepaliveConfig, KeepaliveState, SessionOptions, SessionState,
    SessionsClient,
};
use proxyx_client::signals::{BlockSignal, MAX_BATCH, PoolControlClient, SignalType};
use proxyx_client::traffic::{IntFilter, QueryBranch, TrafficQuery, WsQueryBranch, WsTrafficQuery};
use proxyx_client::{Secret, gateway::ConnectInfo};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use uuid::Uuid;

const KEY: &str = "pxk_test";
const SESSION_ID: &str = "7d444840-9dc0-11d1-b245-5ffdce74fad2";
const CA_PEM: &str = "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n";

fn now_ms() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_millis(),
    )
    .expect("fits")
}

fn session_id() -> Uuid {
    Uuid::parse_str(SESSION_ID).expect("uuid")
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum CreateMode {
    Ok,
    Attached,
    Conflict,
    SuccessFalse,
    NoSuccessField,
    NoProxyUrl,
    EmptySocks,
    BadScheme,
    OverridesDropped,
    OverridesAdded,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum ExtendMode {
    Ok,
    Gone404,
    Gone409,
    Fail500,
}

/// What the control-plane fake saw and how it answers.
struct Fake {
    create_mode: Mutex<CreateMode>,
    extend_mode: Mutex<ExtendMode>,
    /// Expiry the fake reports after create and after each extend.
    lifetime_ms: i64,
    creates: AtomicU32,
    extends: AtomicU32,
    deletes: AtomicU32,
    delete_status: AtomicU16,
    get_status: AtomicU16,
    processed_polls: AtomicU32,
    processed_after: AtomicU32,
    processed_status: AtomicU16,
    last_create: Mutex<Option<Value>>,
    last_extend: Mutex<Option<Value>>,
    last_body: Mutex<Option<Value>>,
    last_query: Mutex<HashMap<String, String>>,
    bad_auth: AtomicU32,
}

impl Fake {
    fn new(lifetime_ms: i64) -> Arc<Self> {
        Arc::new(Self {
            create_mode: Mutex::new(CreateMode::Ok),
            extend_mode: Mutex::new(ExtendMode::Ok),
            lifetime_ms,
            creates: AtomicU32::new(0),
            extends: AtomicU32::new(0),
            deletes: AtomicU32::new(0),
            delete_status: AtomicU16::new(200),
            get_status: AtomicU16::new(200),
            processed_polls: AtomicU32::new(0),
            processed_after: AtomicU32::new(1),
            processed_status: AtomicU16::new(200),
            last_create: Mutex::new(None),
            last_extend: Mutex::new(None),
            last_body: Mutex::new(None),
            last_query: Mutex::new(HashMap::new()),
            bad_auth: AtomicU32::new(0),
        })
    }

    fn set_create(&self, mode: CreateMode) {
        *self.create_mode.lock().expect("lock") = mode;
    }

    fn set_extend(&self, mode: ExtendMode) {
        *self.extend_mode.lock().expect("lock") = mode;
    }

    fn count(counter: &AtomicU32) -> u32 {
        counter.load(Ordering::SeqCst)
    }

    /// 401 unless the bearer key is right, as the real service answers.
    fn authorize(&self, headers: &HeaderMap) -> Option<Response> {
        let expected = format!("Bearer {KEY}");
        if headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            == Some(expected.as_str())
        {
            return None;
        }
        self.bad_auth.fetch_add(1, Ordering::SeqCst);
        Some(
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "unauthorized"})),
            )
                .into_response(),
        )
    }
}

fn status_of(code: u16) -> StatusCode {
    StatusCode::from_u16(code).expect("status")
}

async fn create(
    State(fake): State<Arc<Fake>>,
    headers: HeaderMap,
    Json(request): Json<Value>,
) -> Response {
    if let Some(refusal) = fake.authorize(&headers) {
        return refusal;
    }
    fake.creates.fetch_add(1, Ordering::SeqCst);
    *fake.last_create.lock().expect("lock") = Some(request.clone());
    let mode = *fake.create_mode.lock().expect("lock");
    if mode == CreateMode::Conflict {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error": "upstream_overrides differ from the active session"})),
        )
            .into_response();
    }
    let mut body = json!({
        "session_id": SESSION_ID,
        "ca_cert_pem": CA_PEM,
        "expires_at_ms": now_ms() + fake.lifetime_ms,
        "proxy_url": format!("http://{SESSION_ID}:password@127.0.0.1:8443"),
        "proxy_url_socks5": format!("socks5://{SESSION_ID}:password@127.0.0.1:1080"),
        "success": true,
        "upstream_overrides": request["upstream_overrides"].clone(),
    });
    match mode {
        CreateMode::Ok | CreateMode::Conflict => {}
        CreateMode::Attached => {
            body["attached"] = json!(true);
            body["warning"] =
                json!("attached to existing session but config differs on: captured_hosts");
        }
        CreateMode::SuccessFalse => {
            body["success"] = json!(false);
            body["error"] = json!("backend exploded");
        }
        CreateMode::NoSuccessField => {
            body.as_object_mut().map(|m| m.remove("success"));
        }
        CreateMode::NoProxyUrl => {
            body.as_object_mut().map(|m| m.remove("proxy_url"));
        }
        CreateMode::EmptySocks => body["proxy_url_socks5"] = json!(""),
        CreateMode::BadScheme => body["proxy_url"] = json!("ftp://127.0.0.1:21"),
        CreateMode::OverridesDropped => body["upstream_overrides"] = json!({}),
        CreateMode::OverridesAdded => {
            body["upstream_overrides"] = json!({"x.internal:1": "http://10.0.0.1:2"})
        }
    }
    (StatusCode::CREATED, Json(body)).into_response()
}

async fn extend(
    State(fake): State<Arc<Fake>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<Value>,
) -> Response {
    if let Some(refusal) = fake.authorize(&headers) {
        return refusal;
    }
    assert_eq!(id, SESSION_ID);
    fake.extends.fetch_add(1, Ordering::SeqCst);
    *fake.last_extend.lock().expect("lock") = Some(request);
    let mode = *fake.extend_mode.lock().expect("lock");
    match mode {
        ExtendMode::Ok => {
            Json(json!({"expires_at_ms": now_ms() + fake.lifetime_ms})).into_response()
        }
        ExtendMode::Gone404 => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Session not found"})),
        )
            .into_response(),
        ExtendMode::Gone409 => (
            StatusCode::CONFLICT,
            Json(json!({"error": "session expired and cannot be extended"})),
        )
            .into_response(),
        ExtendMode::Fail500 => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "internal error"})),
        )
            .into_response(),
    }
}

async fn delete(
    State(fake): State<Arc<Fake>>,
    headers: HeaderMap,
    Path(_id): Path<String>,
) -> Response {
    if let Some(refusal) = fake.authorize(&headers) {
        return refusal;
    }
    fake.deletes.fetch_add(1, Ordering::SeqCst);
    match fake.delete_status.load(Ordering::SeqCst) {
        200 => StatusCode::OK.into_response(),
        code => (status_of(code), Json(json!({"error": "nope"}))).into_response(),
    }
}

async fn get_session(
    State(fake): State<Arc<Fake>>,
    headers: HeaderMap,
    Path(_id): Path<String>,
) -> Response {
    if let Some(refusal) = fake.authorize(&headers) {
        return refusal;
    }
    match fake.get_status.load(Ordering::SeqCst) {
        200 => Json(json!({
            "session_id": SESSION_ID, "org_id": "acme", "source": "crawl", "source_id": "c1",
            "agent": null, "captured_hosts": ["*"], "excluded_hosts": [],
            "inject_headers": [["Authorization", "Bearer topsecret"]], "serialize": false,
            "expires_at_ms": 1, "egress_proxy": {"proxy_type": "socks5", "address": "p:1", "username": "u", "password": "hunter2"},
            "rate_limit": {"requests_per_minute": 60, "burst": 10}
        }))
        .into_response(),
        429 => {
            let mut response = (StatusCode::TOO_MANY_REQUESTS, Json(json!({"error": "slow down"}))).into_response();
            response.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from_static("7"));
            response
        }
        499 => (status_of(400), "plain text, not json").into_response(),
        code => (status_of(code), Json(json!({"error": "boom"}))).into_response(),
    }
}

async fn status(
    State(fake): State<Arc<Fake>>,
    headers: HeaderMap,
    Path(_id): Path<String>,
) -> Response {
    if let Some(refusal) = fake.authorize(&headers) {
        return refusal;
    }
    Json(json!({"state": "closing_soon_new_state", "opened_at": "2026-11-10T10:00:00Z", "closing_at": null, "closed_at": null}))
        .into_response()
}

async fn processed(
    State(fake): State<Arc<Fake>>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    if let Some(refusal) = fake.authorize(&headers) {
        return refusal;
    }
    *fake.last_query.lock().expect("lock") = query;
    match fake.processed_status.load(Ordering::SeqCst) {
        200 => {
            let poll = fake.processed_polls.fetch_add(1, Ordering::SeqCst) + 1;
            Json(json!({"all_processed": poll >= fake.processed_after.load(Ordering::SeqCst)}))
                .into_response()
        }
        code => (status_of(code), Json(json!({"error": "nope"}))).into_response(),
    }
}

async fn certificate(State(fake): State<Arc<Fake>>, headers: HeaderMap) -> Response {
    if let Some(refusal) = fake.authorize(&headers) {
        return refusal;
    }
    CA_PEM.into_response()
}

async fn sequence(
    State(fake): State<Arc<Fake>>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    if let Some(refusal) = fake.authorize(&headers) {
        return refusal;
    }
    let source = query.get("source_id").cloned().unwrap_or_default();
    *fake.last_query.lock().expect("lock") = query;
    Json(json!({"org_id": "acme", "source_id": source, "cursor": "cur1", "count": 12}))
        .into_response()
}

fn capture_row() -> Value {
    json!({
        "id": "11111111-1111-1111-1111-111111111111", "org_id": "acme",
        "timestamp": "2026-11-10T10:00:00Z", "session_offset": 7,
        "method": "GET", "path": "/", "host": "example.com", "scheme": "https",
        "session_id": "s", "proxy_id": "p", "request_size": 0, "status_code": 503,
        "response_size": 5, "duration_ms": 12, "ratelimit_wait_ms": 0,
        "source": "crawl", "source_id": "c1", "correlation_id": null,
        "request_headers": [["a", "b"]], "response_headers": [["retry-after", "5"]],
        "request_body": null, "response_body": {"status": "body", "value": "hello"}
    })
}

async fn search(
    State(fake): State<Arc<Fake>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if let Some(refusal) = fake.authorize(&headers) {
        return refusal;
    }
    let cursor = body["cursor"].as_str().map(str::to_owned);
    *fake.last_body.lock().expect("lock") = Some(body);
    // two pages: the first has a next cursor, the second ends
    match cursor.as_deref() {
        None => {
            Json(json!({"items": [capture_row()], "next_cursor": "page2", "total_count": null}))
                .into_response()
        }
        Some(_) => {
            Json(json!({"items": [capture_row()], "next_cursor": null, "total_count": null}))
                .into_response()
        }
    }
}

async fn count(
    State(fake): State<Arc<Fake>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if let Some(refusal) = fake.authorize(&headers) {
        return refusal;
    }
    *fake.last_body.lock().expect("lock") = Some(body);
    Json(json!({"count": 41})).into_response()
}

async fn get_capture(
    State(fake): State<Arc<Fake>>,
    headers: HeaderMap,
    Path((org, id)): Path<(String, String)>,
) -> Response {
    if let Some(refusal) = fake.authorize(&headers) {
        return refusal;
    }
    assert_eq!(org, "ac me");
    assert_eq!(id, "11111111-1111-1111-1111-111111111111");
    Json(json!({
        "id": id, "org_id": "ac me", "timestamp": "2026-11-10T10:00:00Z",
        "method": "GET", "path": "/", "host": "example.com", "scheme": "https",
        "session_id": "s", "proxy_id": "p",
        "request_headers": {"A": "b"}, "request_body": "", "request_size": 0, "status_code": 200,
        "response_headers": {"Content-Type": "text/plain"}, "response_body": "full body",
        "response_size": 9, "duration_ms": 3, "ratelimit_wait_ms": 0,
        "source": "crawl", "source_id": "c1", "correlation_id": null,
        "parent_correlation_id": null, "account_id": null, "tool_call_id": null
    }))
    .into_response()
}

fn control_router(fake: &Arc<Fake>) -> Router {
    Router::new()
        .route("/rpc/sessions", post(create))
        .route(
            "/rpc/sessions/{id}",
            get(get_session).delete(delete).patch(extend),
        )
        .route("/rpc/sessions/{id}/status", get(status))
        .route("/rpc/processed", get(processed))
        .route("/rpc/certificate", get(certificate))
        .route("/rpc/sequence", get(sequence))
        .route("/rpc/requests/search", post(search))
        .route("/rpc/requests/count", post(count))
        .route("/rpc/ws/count", post(count))
        .route("/rpc/orgs/{org}/requests/{id}", get(get_capture))
        .with_state(Arc::clone(fake))
}

async fn serve(router: Router) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    addr
}

async fn control(fake: &Arc<Fake>) -> SessionsClient {
    let addr = serve(control_router(fake)).await;
    SessionsClient::new(&format!("http://{addr}"), KEY).expect("client")
}

fn fast_keepalive() -> SessionOptions {
    SessionOptions {
        keepalive: Some(KeepaliveConfig {
            ttl_secs: 1,
            threshold: 0.2,
            max_failures: 3,
            min_sleep: Duration::from_millis(10),
        }),
    }
}

fn request() -> CreateSessionRequest {
    CreateSessionRequest::new("acme", "crawl", "c1").captured_hosts(["*"])
}

async fn settle(session: &proxyx_client::sessions::Session, want: KeepaliveState) {
    let mut state = session.watch_keepalive();
    tokio::time::timeout(Duration::from_secs(5), state.wait_for(|s| *s == want))
        .await
        .unwrap_or_else(|_| {
            panic!(
                "keepalive never reached {want:?}, is {:?}",
                session.keepalive_state()
            )
        })
        .expect("watch");
}

// --- create, keepalive, delete ------------------------------------------------------------

#[tokio::test]
async fn create_keepalive_extend_delete() {
    let fake = Fake::new(400);
    let client = control(&fake).await;
    let session = client
        .open_session_with(
            request().upstream_override("a.internal:80", "http://10.0.0.5:8080"),
            fast_keepalive(),
        )
        .await
        .expect("open");

    // the request carried every field the server requires
    let sent = fake
        .last_create
        .lock()
        .expect("lock")
        .clone()
        .expect("create body");
    assert_eq!(sent["org_id"], "acme");
    assert_eq!(sent["source"], "crawl");
    assert_eq!(sent["source_id"], "c1");
    assert_eq!(sent["captured_hosts"], json!(["*"]));
    assert_eq!(sent["excluded_hosts"], json!([]));
    assert_eq!(sent["inject_headers"], json!([]));
    assert_eq!(sent["serialize"], false);
    assert_eq!(sent["ttl_secs"], 1800);
    assert_eq!(
        sent["upstream_overrides"],
        json!({"a.internal:80": "http://10.0.0.5:8080"})
    );
    assert_eq!(Fake::count(&fake.bad_auth), 0);

    assert_eq!(session.id(), session_id());
    assert!(session.proxy_url().starts_with("http://7d444840"));
    assert!(session.proxy_url_socks5().starts_with("socks5://7d444840"));
    assert_eq!(session.ca_cert_pem(), CA_PEM);
    assert!(!session.created().attached());
    let created_expiry = session.created().expires_at_ms();

    // lifetime 400 ms, renewal at 20% left: several renewals within a second and a half
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let extends = Fake::count(&fake.extends);
    assert!(extends >= 2, "extends {extends}");
    assert_eq!(
        *fake.last_extend.lock().expect("lock"),
        Some(json!({"new_ttl_secs": 1}))
    );
    assert!(session.expires_at_ms() > created_expiry);
    assert_eq!(session.keepalive_state(), KeepaliveState::Running);

    assert!(session.end().await.expect("end"));
    assert_eq!(Fake::count(&fake.deletes), 1);
    settle(&session, KeepaliveState::Cancelled).await;
    let after_end = Fake::count(&fake.extends);
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        Fake::count(&fake.extends) <= after_end + 1,
        "keepalive kept running after end"
    );

    // end is idempotent: no second delete
    assert!(!session.end().await.expect("end again"));
    assert_eq!(Fake::count(&fake.deletes), 1);
}

#[tokio::test]
async fn failed_end_can_be_repeated() {
    let fake = Fake::new(60_000);
    let client = control(&fake).await;
    let session = client
        .open_session_with(request(), SessionOptions { keepalive: None })
        .await
        .expect("open");
    assert_eq!(session.keepalive_state(), KeepaliveState::Disabled);
    fake.delete_status.store(500, Ordering::SeqCst);
    assert!(matches!(
        session.end().await,
        Err(Error::Unavailable { .. })
    ));
    fake.delete_status.store(200, Ordering::SeqCst);
    assert!(session.end().await.expect("retry"));
    assert_eq!(Fake::count(&fake.deletes), 2);
}

#[tokio::test]
async fn end_of_an_already_gone_session_is_not_an_error() {
    let fake = Fake::new(60_000);
    let client = control(&fake).await;
    let session = client
        .open_session_with(request(), SessionOptions { keepalive: None })
        .await
        .expect("open");
    fake.delete_status.store(404, Ordering::SeqCst);
    assert!(!session.end().await.expect("404 is false, not an error"));
    assert!(!session.end().await.expect("and stays ended"));
    assert_eq!(Fake::count(&fake.deletes), 1);
}

#[tokio::test]
async fn dropping_stops_the_keepalive_without_releasing() {
    let fake = Fake::new(400);
    let client = control(&fake).await;
    let session = client
        .open_session_with(request(), fast_keepalive())
        .await
        .expect("open");
    let mut state = session.watch_keepalive();
    drop(session);
    tokio::time::timeout(
        Duration::from_secs(5),
        state.wait_for(|s| *s == KeepaliveState::Cancelled),
    )
    .await
    .expect("keepalive should stop on drop")
    .expect("watch");
    let seen = Fake::count(&fake.extends);
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(Fake::count(&fake.extends), seen);
    assert_eq!(Fake::count(&fake.deletes), 0);
}

#[tokio::test]
async fn keepalive_stops_when_the_session_is_gone() {
    for mode in [ExtendMode::Gone404, ExtendMode::Gone409] {
        let fake = Fake::new(300);
        fake.set_extend(mode);
        let client = control(&fake).await;
        let session = client
            .open_session_with(request(), fast_keepalive())
            .await
            .expect("open");
        settle(&session, KeepaliveState::SessionGone).await;
        assert_eq!(Fake::count(&fake.extends), 1, "{mode:?}");
    }
}

#[tokio::test]
async fn keepalive_stops_after_three_consecutive_failures() {
    let fake = Fake::new(300);
    fake.set_extend(ExtendMode::Fail500);
    let client = control(&fake).await;
    let session = client
        .open_session_with(request(), fast_keepalive())
        .await
        .expect("open");
    settle(&session, KeepaliveState::TooManyFailures).await;
    assert_eq!(Fake::count(&fake.extends), 3);
}

#[tokio::test]
async fn a_success_resets_the_failure_count() {
    let fake = Fake::new(300);
    let client = control(&fake).await;
    fake.set_extend(ExtendMode::Fail500);
    let session = client
        .open_session_with(request(), fast_keepalive())
        .await
        .expect("open");
    // two failures, then the server recovers
    while Fake::count(&fake.extends) < 2 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    fake.set_extend(ExtendMode::Ok);
    tokio::time::sleep(Duration::from_millis(900)).await;
    assert_eq!(session.keepalive_state(), KeepaliveState::Running);
    assert!(Fake::count(&fake.extends) >= 4);
    session.end().await.expect("end");
}

#[tokio::test]
async fn manual_extend_updates_the_expiry() {
    let fake = Fake::new(5_000);
    let client = control(&fake).await;
    let session = client
        .open_session_with(request(), SessionOptions { keepalive: None })
        .await
        .expect("open");
    let before = session.expires_at_ms();
    tokio::time::sleep(Duration::from_millis(20)).await;
    let expires = session
        .extend(Extend::AdditionalSecs(300))
        .await
        .expect("extend");
    assert!(expires > before);
    assert_eq!(session.expires_at_ms(), expires);
    assert_eq!(
        *fake.last_extend.lock().expect("lock"),
        Some(json!({"additional_secs": 300}))
    );
}

// --- fail closed ---------------------------------------------------------------------------

#[tokio::test]
async fn create_fails_closed() {
    type Check = fn(&Error) -> bool;
    let cases: [(CreateMode, Check, u32); 7] = [
        (
            CreateMode::SuccessFalse,
            |e| matches!(e, Error::InvalidCreateResponse(m) if m == "backend exploded"),
            0,
        ),
        // `success` absent reads as not successful, and nothing is known to release
        (
            CreateMode::NoSuccessField,
            |e| matches!(e, Error::InvalidCreateResponse(_)),
            0,
        ),
        (
            CreateMode::NoProxyUrl,
            |e| matches!(e, Error::InvalidCreateResponse(_)),
            1,
        ),
        (
            CreateMode::EmptySocks,
            |e| matches!(e, Error::InvalidCreateResponse(_)),
            1,
        ),
        (
            CreateMode::BadScheme,
            |e| matches!(e, Error::InvalidCreateResponse(_)),
            1,
        ),
        (
            CreateMode::OverridesDropped,
            |e| matches!(e, Error::UpstreamOverridesMismatch),
            1,
        ),
        (
            CreateMode::OverridesAdded,
            |e| matches!(e, Error::UpstreamOverridesMismatch),
            1,
        ),
    ];
    for (mode, check, deletes) in cases {
        let fake = Fake::new(60_000);
        fake.set_create(mode);
        let client = control(&fake).await;
        // overrides are requested for the "dropped" case, and absent for the "added" case
        let request = if mode == CreateMode::OverridesAdded {
            request()
        } else {
            request().upstream_override("a.internal:80", "http://10.0.0.5:8080")
        };
        let error = client
            .create_session(&request)
            .await
            .expect_err("must refuse");
        assert!(check(&error), "{mode:?}: {error}");
        assert!(
            !error.to_string().contains("password"),
            "{mode:?} leaked a URL: {error}"
        );
        assert_eq!(Fake::count(&fake.deletes), deletes, "{mode:?}");
        // open_session must not hand out a session either, and must not spawn a keepalive
        assert!(client.open_session(request).await.is_err(), "{mode:?}");
        assert_eq!(Fake::count(&fake.extends), 0, "{mode:?}");
    }
}

#[tokio::test]
async fn create_conflict_is_typed() {
    let fake = Fake::new(60_000);
    fake.set_create(CreateMode::Conflict);
    let client = control(&fake).await;
    let error = client
        .create_session(&request())
        .await
        .expect_err("conflict");
    assert!(
        matches!(error, Error::Conflict { ref message } if message.contains("upstream_overrides")),
        "{error}"
    );
    assert_eq!(Fake::count(&fake.deletes), 0);
}

#[tokio::test]
async fn attach_keeps_flag_warning_and_matching_overrides() {
    let fake = Fake::new(60_000);
    fake.set_create(CreateMode::Attached);
    let client = control(&fake).await;
    let created = client
        .create_session(&request().upstream_override("a.internal:80", "http://10.0.0.5:8080"))
        .await
        .expect("attach");
    assert!(created.attached());
    assert!(
        created
            .warning()
            .is_some_and(|w| w.contains("captured_hosts"))
    );
    assert_eq!(created.upstream_overrides().len(), 1);
}

#[tokio::test]
async fn empty_ids_are_not_sent() {
    let fake = Fake::new(60_000);
    let client = control(&fake).await;
    let error = client
        .create_session(&CreateSessionRequest::new("acme", "crawl", ""))
        .await
        .expect_err("refused");
    assert!(matches!(error, Error::InvalidInput(_)));
    assert_eq!(Fake::count(&fake.creates), 0);
}

#[tokio::test]
async fn debug_output_hides_credentials() {
    let fake = Fake::new(60_000);
    let client = control(&fake).await;
    let session = client
        .open_session_with(request(), SessionOptions { keepalive: None })
        .await
        .expect("open");
    for text in [format!("{session:?}"), format!("{:?}", session.created())] {
        assert!(!text.contains("password"), "{text}");
        assert!(!text.contains("127.0.0.1:8443"), "{text}");
        assert!(!text.contains(SESSION_ID), "{text}");
    }
    assert!(!format!("{client:?}").contains(KEY));
}

// --- error mapping -------------------------------------------------------------------------

#[tokio::test]
async fn statuses_map_to_typed_errors() {
    let fake = Fake::new(60_000);
    let client = control(&fake).await;
    for code in [401u16, 403, 404, 409, 400, 422, 429, 500, 502, 503, 499] {
        fake.get_status.store(code, Ordering::SeqCst);
        let error = client
            .get_session(session_id())
            .await
            .expect_err("error status");
        match code {
            401 | 403 => assert!(
                matches!(error, Error::Auth { status, .. } if status == code),
                "{code}: {error}"
            ),
            404 => assert!(matches!(error, Error::NotFound { .. }), "{code}: {error}"),
            409 => assert!(matches!(error, Error::Conflict { .. }), "{code}: {error}"),
            500 | 502 | 503 => {
                assert!(
                    matches!(error, Error::Unavailable { status, .. } if status == code),
                    "{code}: {error}"
                );
                assert!(error.is_retryable());
            }
            429 => {
                assert!(
                    matches!(error, Error::Client { status: 429, retry_after: Some(d), .. } if d == Duration::from_secs(7)),
                    "{error}"
                );
                assert!(error.is_retryable());
            }
            499 => assert!(
                matches!(&error, Error::Client { status: 400, message, .. } if message.contains("plain text")),
                "{error}"
            ),
            _ => {
                assert!(
                    matches!(error, Error::Client { status, .. } if status == code),
                    "{code}: {error}"
                );
                assert!(!error.is_retryable());
            }
        }
    }
}

#[tokio::test]
async fn a_wrong_key_is_an_auth_error() {
    let fake = Fake::new(60_000);
    let addr = serve(control_router(&fake)).await;
    let client = SessionsClient::new(&format!("http://{addr}"), "pxk_wrong").expect("client");
    assert!(matches!(
        client.create_session(&request()).await,
        Err(Error::Auth { status: 401, .. })
    ));
    assert_eq!(Fake::count(&fake.creates), 0);
}

#[tokio::test]
async fn transport_errors_do_not_leak_the_url() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    drop(listener);
    let client = SessionsClient::new(&format!("http://{addr}"), KEY).expect("client");
    let error = client
        .get_session(session_id())
        .await
        .expect_err("nothing listens");
    assert!(matches!(error, Error::Transport(_)));
    assert!(error.is_retryable());
    assert!(!error.to_string().contains(SESSION_ID), "{error}");
}

#[tokio::test]
async fn delete_maps_404_to_false() {
    let fake = Fake::new(60_000);
    let client = control(&fake).await;
    assert!(client.delete_session(session_id()).await.expect("deleted"));
    fake.delete_status.store(404, Ordering::SeqCst);
    assert!(
        !client
            .delete_session(session_id())
            .await
            .expect("already gone")
    );
    fake.delete_status.store(500, Ordering::SeqCst);
    assert!(matches!(
        client.delete_session(session_id()).await,
        Err(Error::Unavailable { .. })
    ));
}

// --- reads ---------------------------------------------------------------------------------

#[tokio::test]
async fn session_config_status_certificate_and_sequence() {
    let fake = Fake::new(60_000);
    let client = control(&fake).await;

    let config = client.get_session(session_id()).await.expect("config");
    assert_eq!(config.org_id, "acme");
    assert_eq!(config.rate_limit.map(|r| r.burst), Some(10));
    let debug = format!("{config:?}");
    assert!(
        !debug.contains("hunter2"),
        "egress password leaked: {debug}"
    );
    assert!(
        !debug.contains("topsecret"),
        "injected header value leaked: {debug}"
    );
    assert!(debug.contains("Authorization"));

    // a state the client does not know decodes as Unknown, not as an error
    let status = client.session_status(session_id()).await.expect("status");
    assert_eq!(status.state, SessionState::Unknown);
    assert!(status.closing_at.is_none());

    assert_eq!(client.certificate().await.expect("certificate"), CA_PEM);

    let sequence = client.sequence("c1", Some("acme")).await.expect("sequence");
    assert_eq!(
        (sequence.cursor.as_deref(), sequence.count),
        (Some("cur1"), 12)
    );
    let query = fake.last_query.lock().expect("lock").clone();
    assert_eq!(query.get("source_id").map(String::as_str), Some("c1"));
    assert_eq!(query.get("org_id").map(String::as_str), Some("acme"));
}

#[tokio::test]
async fn wait_all_processed_polls_until_true() {
    let fake = Fake::new(60_000);
    fake.processed_after.store(3, Ordering::SeqCst);
    let client = control(&fake).await;
    client
        .wait_all_processed(
            "c1",
            Some("acme"),
            Duration::from_secs(5),
            Duration::from_millis(20),
        )
        .await
        .expect("processed");
    assert_eq!(Fake::count(&fake.processed_polls), 3);
    let query = fake.last_query.lock().expect("lock").clone();
    assert_eq!(query.get("source_id").map(String::as_str), Some("c1"));
    assert_eq!(query.get("org_id").map(String::as_str), Some("acme"));
}

#[tokio::test]
async fn wait_all_processed_times_out() {
    let fake = Fake::new(60_000);
    fake.processed_after.store(u32::MAX, Ordering::SeqCst);
    let client = control(&fake).await;
    let started = std::time::Instant::now();
    let error = client
        .wait_all_processed(
            "c1",
            None,
            Duration::from_millis(200),
            Duration::from_millis(50),
        )
        .await
        .expect_err("never processed");
    assert!(matches!(error, Error::Timeout { .. }), "{error}");
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(Fake::count(&fake.processed_polls) >= 2);
}

#[tokio::test]
async fn wait_all_processed_tolerates_5xx_but_not_auth_errors() {
    let fake = Fake::new(60_000);
    fake.processed_status.store(503, Ordering::SeqCst);
    let client = control(&fake).await;
    let error = client
        .wait_all_processed(
            "c1",
            None,
            Duration::from_millis(150),
            Duration::from_millis(30),
        )
        .await
        .expect_err("still down");
    assert!(matches!(error, Error::Timeout { .. }), "{error}");

    fake.processed_status.store(403, Ordering::SeqCst);
    let error = client
        .wait_all_processed(
            "c1",
            None,
            Duration::from_secs(5),
            Duration::from_millis(30),
        )
        .await
        .expect_err("forbidden");
    assert!(matches!(error, Error::Auth { status: 403, .. }), "{error}");
}

#[tokio::test]
async fn traffic_search_count_and_get() {
    let fake = Fake::new(60_000);
    let client = control(&fake).await;

    let mut query = TrafficQuery::new(vec![
        QueryBranch::for_source("c1").status_code(IntFilter::gte(400)),
    ])
    .limit(1)
    .fetch_bodies(0, 1024);
    let first = client.search_requests(&query).await.expect("first page");
    assert_eq!(first.items.len(), 1);
    assert_eq!(first.items[0].status_code, 503);
    assert_eq!(
        first.items[0].response_headers.get("Retry-After"),
        Some("5")
    );
    let sent = fake.last_body.lock().expect("lock").clone().expect("body");
    assert_eq!(
        sent,
        json!({
            "branches": [{"source_id": ["c1"], "status_code": {"op": "gte", "value": 400}}],
            "limit": 1, "order": "asc",
            "request_body_max_fetch_size": 0, "response_body_max_fetch_size": 1024
        })
    );

    // follow the cursor to the end
    query.cursor = first.next_cursor.clone();
    assert_eq!(query.cursor.as_deref(), Some("page2"));
    let second = client.search_requests(&query).await.expect("second page");
    assert!(second.next_cursor.is_none());
    assert_eq!(
        fake.last_body.lock().expect("lock").as_ref().expect("body")["cursor"],
        "page2"
    );

    assert_eq!(client.count_requests(&query).await.expect("count"), 41);

    let capture = client
        .get_capture(
            "ac me",
            Uuid::parse_str("11111111-1111-1111-1111-111111111111").expect("uuid"),
        )
        .await
        .expect("capture");
    assert_eq!(capture.response_body, "full body");
    assert_eq!(
        capture.response_headers.get("content-type"),
        Some("text/plain")
    );

    let ws = WsTrafficQuery::new(vec![WsQueryBranch::for_source("c1")]);
    assert_eq!(client.count_ws(&ws).await.expect("ws count"), 41);
    assert_eq!(
        *fake.last_body.lock().expect("lock"),
        Some(json!({"branches": [{"source_id": "c1"}], "order": "asc"}))
    );

    let empty = TrafficQuery::new(Vec::new());
    assert!(matches!(
        client.search_requests(&empty).await,
        Err(Error::InvalidInput(_))
    ));
}

// --- session helpers and providers ---------------------------------------------------------

#[tokio::test]
async fn proxy_env_and_browser_args_name_the_session() {
    let fake = Fake::new(60_000);
    let client = control(&fake).await;
    let session = client
        .open_session_with(request(), SessionOptions { keepalive: None })
        .await
        .expect("open");

    let args = session.browser_args();
    assert_eq!(args, [format!("--proxy-server={}", session.proxy_url())]);

    // The CA bundle needs the machine's trust roots; skip the file checks where there are none.
    if proxyx_client::env::system_roots_pem().is_err() {
        eprintln!("no system roots on this machine; skipping the bundle checks");
        return;
    }
    let path = {
        let env = session.proxy_env().await.expect("env");
        let map = env.to_map();
        assert_eq!(map["HTTPS_PROXY"], session.proxy_url());
        assert_eq!(map["http_proxy"], session.proxy_url());
        assert_eq!(map["SSL_CERT_FILE"], map["REQUESTS_CA_BUNDLE"]);
        let path = std::path::PathBuf::from(&map["SSL_CERT_FILE"]);
        let bundle = std::fs::read_to_string(&path).expect("bundle file");
        assert!(bundle.starts_with(CA_PEM.trim()));
        assert!(
            bundle.matches("BEGIN CERTIFICATE").count() > 1,
            "system roots missing"
        );
        path
    };
    // same file for the life of the session, removed with it
    assert_eq!(session.ca_bundle().await.expect("bundle"), path);
    drop(session);
    assert!(!path.exists());

    let chosen = std::env::temp_dir().join(format!("proxyx-client-test-{}.pem", Uuid::new_v4()));
    let session = client
        .open_session_with(request(), SessionOptions { keepalive: None })
        .await
        .expect("open");
    let env = session.proxy_env_at(&chosen).await.expect("env at path");
    assert_eq!(env.to_map()["SSL_CERT_FILE"], chosen.to_string_lossy());
    assert!(chosen.exists());
    std::fs::remove_file(&chosen).expect("cleanup");
}

#[tokio::test]
async fn http_client_refuses_an_invalid_session_ca() {
    let fake = Fake::new(60_000);
    let client = control(&fake).await;
    let session = client
        .open_session_with(request(), SessionOptions { keepalive: None })
        .await
        .expect("open");
    // the fake's CA is not a real certificate
    let result = session.http_client();
    assert!(result.is_err(), "{result:?}");
}

#[tokio::test]
async fn sessions_provider_acquires_and_releases() {
    let fake = Fake::new(60_000);
    let client = control(&fake).await;
    let provider = SessionsProvider::new(client).with_options(SessionOptions { keepalive: None });
    let handle = provider.acquire(request()).await.expect("handle");
    assert!(handle.proxy_url().is_some_and(|u| u.contains(SESSION_ID)));
    assert!(handle.proxy_url_socks5().is_some());
    assert_eq!(handle.ca_cert_pem(), Some(CA_PEM));
    assert_eq!(handle.browser_args().len(), 1);
    handle.end().await.expect("end");
    handle.end().await.expect("end again");
    assert_eq!(Fake::count(&fake.deletes), 1);
}

// --- pool control API ----------------------------------------------------------------------

struct PoolFake {
    status: AtomicU16,
    batches: Mutex<Vec<Value>>,
    auth: Mutex<Vec<String>>,
}

async fn block_signals(
    State(fake): State<Arc<PoolFake>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let auth = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    fake.auth.lock().expect("lock").push(auth);
    let count = body.as_array().map_or(0, Vec::len);
    fake.batches.lock().expect("lock").push(body);
    match fake.status.load(Ordering::SeqCst) {
        200 => Json(json!({"accepted": count - 1, "ignored": 1})).into_response(),
        429 => {
            let mut response = (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({"error": "too many failed attempts"})),
            )
                .into_response();
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("42"));
            response
        }
        code => (status_of(code), Json(json!({"error": "nope"}))).into_response(),
    }
}

#[tokio::test]
async fn block_signals_report() {
    let fake = Arc::new(PoolFake {
        status: AtomicU16::new(200),
        batches: Mutex::new(Vec::new()),
        auth: Mutex::new(Vec::new()),
    });
    let router = Router::new()
        .route("/v1/block-signals", post(block_signals))
        .with_state(Arc::clone(&fake));
    let addr = serve(router).await;
    let client = PoolControlClient::new(&format!("http://{addr}"), "org-key-123").expect("client");

    let info = ConnectInfo {
        session: "sess1".into(),
        exit_ip: "203.0.113.9".parse().expect("ip"),
    };
    let signals = vec![
        BlockSignal::at(
            &info,
            "example.com",
            443,
            SignalType::RateLimited,
            1_700_000_000,
        ),
        BlockSignal::at(
            &info,
            "2001:db8::5",
            443,
            SignalType::Challenge,
            1_700_000_001,
        ),
    ];
    let outcome = client.report(&signals).await.expect("report");
    assert_eq!((outcome.accepted, outcome.ignored), (1, 1));

    let sent = fake.batches.lock().expect("lock")[0].clone();
    assert_eq!(
        sent,
        json!([
            {"session": "sess1", "exit_ip": "203.0.113.9", "target": "example.com:443", "type": "rate_limited", "time": 1_700_000_000},
            {"session": "sess1", "exit_ip": "203.0.113.9", "target": "[2001:db8::5]:443", "type": "challenge", "time": 1_700_000_001},
        ])
    );
    let expected = format!("Basic {}", STANDARD.encode("px:org-key-123"));
    assert_eq!(fake.auth.lock().expect("lock")[0], expected);

    // nothing to send, nothing sent; an oversized batch is refused without a request
    let requests = fake.batches.lock().expect("lock").len();
    assert_eq!(client.report(&[]).await.expect("empty").accepted, 0);
    let big = vec![signals[0].clone(); MAX_BATCH + 1];
    assert!(matches!(
        client.report(&big).await,
        Err(Error::InvalidInput(_))
    ));
    assert_eq!(fake.batches.lock().expect("lock").len(), requests);
    let max = vec![signals[0].clone(); MAX_BATCH];
    client.report(&max).await.expect("a full batch");

    fake.status.store(429, Ordering::SeqCst);
    let error = client.report(&signals).await.expect_err("limited");
    assert!(
        matches!(error, Error::Client { status: 429, retry_after: Some(d), .. } if d == Duration::from_secs(42)),
        "{error}"
    );
    fake.status.store(401, Ordering::SeqCst);
    assert!(matches!(
        client.report(&signals).await,
        Err(Error::Auth { status: 401, .. })
    ));
    fake.status.store(503, Ordering::SeqCst);
    assert!(matches!(
        client.report(&signals).await,
        Err(Error::Unavailable { .. })
    ));
}

// --- CONNECT through the pool gateway ------------------------------------------------------

/// A listener that answers one CONNECT with `reply`, then keeps the socket open. Returns the
/// request head it received through the channel.
async fn fake_gateway(reply: &'static [u8]) -> (u16, tokio::sync::oneshot::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            if socket.read(&mut byte).await.expect("read") == 0 {
                return;
            }
            head.push(byte[0]);
        }
        let _ = tx.send(String::from_utf8_lossy(&head).into_owned());
        if !reply.is_empty() {
            socket.write_all(reply).await.expect("write");
        }
        // hold the socket so a reader sees data, not EOF
        tokio::time::sleep(Duration::from_secs(5)).await;
    });
    (port, rx)
}

#[tokio::test]
async fn connect_tunnel_reads_the_head_and_keeps_early_bytes() {
    let reply: &[u8] =
        b"HTTP/1.1 200 Connection established\r\nX-ProxyX-Pool-Session: sess9\r\nX-ProxyX-Exit-IP: 203.0.113.9\r\n\r\nEARLY";
    let (port, head) = fake_gateway(reply).await;
    let gateway = PoolGateway::new("127.0.0.1").connect_port(port);
    let selector = PoolSelector::new().kind(Kind::Rotating).country("fr");
    let (mut stream, info) = gateway
        .connect_tunnel(
            &selector,
            &Secret::new("org key"),
            "example.com",
            443,
            Duration::from_secs(5),
        )
        .await
        .expect("tunnel");
    assert_eq!(info.session, "sess9");
    assert_eq!(info.exit_ip.to_string(), "203.0.113.9");

    // the tunnel's first bytes were not consumed by the handshake
    let mut early = [0u8; 5];
    stream.read_exact(&mut early).await.expect("early bytes");
    assert_eq!(&early, b"EARLY");

    let head = head.await.expect("request head");
    assert!(
        head.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"),
        "{head}"
    );
    assert!(head.contains("Host: example.com:443\r\n"));
    let expected = format!(
        "Proxy-Authorization: Basic {}\r\n",
        STANDARD.encode("px-kind-rotating-cc-fr:org key")
    );
    assert!(head.contains(&expected), "{head}");
}

#[tokio::test]
async fn connect_tunnel_reports_the_refusal_cause() {
    let (port, _head) = fake_gateway(b"HTTP/1.1 503 cache_empty\r\n\r\n").await;
    let gateway = PoolGateway::new("127.0.0.1").connect_port(port);
    let error = gateway
        .connect_tunnel(
            &PoolSelector::new(),
            &Secret::new("k"),
            "example.com",
            443,
            Duration::from_secs(5),
        )
        .await
        .expect_err("refused");
    assert_eq!(error.cause(), Some(Cause::CacheEmpty));
    assert!(error.is_retryable());
    assert!(matches!(error, ConnectError::Refused { status: 503, .. }));
}

#[tokio::test]
async fn connect_tunnel_times_out_and_refuses_bad_input() {
    let (port, _head) = fake_gateway(b"").await;
    let gateway = PoolGateway::new("127.0.0.1").connect_port(port);
    let error = gateway
        .connect_tunnel(
            &PoolSelector::new(),
            &Secret::new("k"),
            "example.com",
            443,
            Duration::from_millis(150),
        )
        .await
        .expect_err("silent gateway");
    assert!(matches!(error, ConnectError::Timeout));

    let error = gateway
        .connect_tunnel(
            &PoolSelector::new(),
            &Secret::new("k"),
            "evil\r\nX: y",
            443,
            Duration::from_secs(1),
        )
        .await
        .expect_err("header injection");
    assert!(matches!(error, ConnectError::InvalidTarget(_)));
    let error = gateway
        .connect_tunnel(
            &PoolSelector::new().sid("A"),
            &Secret::new("k"),
            "example.com",
            443,
            Duration::from_secs(1),
        )
        .await
        .expect_err("bad selector");
    assert!(matches!(error, ConnectError::InvalidTarget(_)));
}
