use std::sync::Arc;

use axum::extract::{MatchedPath, Request};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::{Router, http::StatusCode, routing::get};
use tokio_util::sync::CancellationToken;
use tracing::Instrument as _;

pub mod limits;
pub mod rpc;
pub mod service;
pub mod traffic_graphql;

pub use rpc::AppState;

pub fn router(state: Arc<AppState>) -> Router {
    let rpc_router = rpc::router(state.clone())
        .layer(middleware::from_fn_with_state(
            state.clone(),
            rpc::service_auth::require_service_principal,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            rpc::service_auth::require_internal_cidr,
        ));

    let ready = {
        let state = state.clone();
        move || health_ready(state.clone())
    };
    let broker_probe = {
        let state = state.clone();
        move || health_broker(state.clone())
    };
    let store_probe = {
        let state = state.clone();
        move || health_store(state.clone())
    };
    Router::new()
        .nest("/rpc", rpc_router)
        .route("/rpc/health", get(ready.clone()))
        .nest("/graphql", traffic_graphql::router(state.clone()))
        .route("/health/live", get(health_live))
        .route("/health/ready", get(ready.clone()))
        .route("/health/store", get(store_probe))
        .route("/health/broker", get(broker_probe))
        .route("/health", get(ready))
        .route("/metrics", get(metrics))
        .layer(middleware::from_fn_with_state(
            limits::Limits::new(state.config.http, state.config.auth_mode),
            limits::enforce,
        ))
        .layer(middleware::from_fn(request_metrics))
}

/// Count a request refused by [`limits`].
pub(crate) fn count_refusal(reason: &'static str) {
    common::metrics::API_REFUSALS_TOTAL
        .with_label_values(&[reason])
        .inc();
}

pub async fn serve(
    addr: std::net::SocketAddr,
    state: Arc<AppState>,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    let app = router(state);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "API server listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(cancel.cancelled_owned())
    .await?;
    Ok(())
}

async fn health_live() -> StatusCode {
    StatusCode::OK
}

/// Ready when the database and Redis both answer within [`READY_PROBE_TIMEOUT`].
/// The capture store is not probed (see [`health_store`], `/health/store`):
/// the API serves sessions without it, and a slow analytics store must not
/// take the session API out of rotation.
async fn health_ready(state: Arc<AppState>) -> StatusCode {
    const READY_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
    let database = async { state.db.ping().await.is_ok() };
    let redis = async {
        let mut conn = state.redis.clone();
        redis::cmd("PING")
            .query_async::<String>(&mut conn)
            .await
            .is_ok()
    };
    let probes = async { tokio::join!(database, redis) };
    match tokio::time::timeout(READY_PROBE_TIMEOUT, probes).await {
        Ok((true, true)) => StatusCode::OK,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    }
}

/// Whether the API's captures-log producer has a working broker connection
/// (Kafka, RabbitMQ). Redis Streams cannot tell and always reports `ok`; the
/// session API itself needs Redis, which `/health/ready` covers. Like the
/// store probe it is not part of readiness.
async fn health_broker(state: Arc<AppState>) -> (StatusCode, axum::Json<serde_json::Value>) {
    let broker = state.config.broker_kind.as_str();
    if state.broker_producer.healthy() {
        (
            StatusCode::OK,
            axum::Json(serde_json::json!({ "broker": broker, "status": "ok" })),
        )
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(serde_json::json!({ "broker": broker, "status": "disconnected" })),
        )
    }
}

/// Reachability of the configured capture store, separate from readiness so a
/// slow analytics store never takes the session API out of rotation. `200`
/// with `{"store": ..., "status": "ok"}`, or `503` with the reason.
async fn health_store(state: Arc<AppState>) -> (StatusCode, axum::Json<serde_json::Value>) {
    store_health(state.capture_store.as_ref()).await
}

async fn store_health(
    capture_store: &dyn crate::capture_store::CaptureStore,
) -> (StatusCode, axum::Json<serde_json::Value>) {
    const STORE_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
    let store = capture_store.backend().as_str();
    let probe = tokio::time::timeout(STORE_PROBE_TIMEOUT, capture_store.ping()).await;
    match probe {
        Ok(Ok(())) => (
            StatusCode::OK,
            axum::Json(serde_json::json!({ "store": store, "status": "ok" })),
        ),
        Ok(Err(error)) => {
            tracing::warn!(store, error = %error, "capture store health check failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                axum::Json(serde_json::json!({
                    "store": store,
                    "status": "unreachable",
                    "error": format!("{error:#}"),
                })),
            )
        }
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(serde_json::json!({
                "store": store,
                "status": "timeout",
                "error": format!("no answer within {}s", STORE_PROBE_TIMEOUT.as_secs()),
            })),
        ),
    }
}

async fn metrics() -> ([(&'static str, &'static str); 1], Vec<u8>) {
    (
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        common::metrics::render(),
    )
}

/// Records request count and latency per matched route template, and runs
/// the request inside a server span that joins the caller's trace (W3C
/// `traceparent` header). Probe and scrape routes are skipped so they don't
/// dominate the series or the traces.
async fn request_metrics(req: Request, next: Next) -> Response {
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str().to_owned());
    let route = route.as_deref().unwrap_or("unmatched");
    if route == "/metrics" || route == "/rpc/health" || route.starts_with("/health") {
        return next.run(req).await;
    }
    let span = tracing::info_span!(
        "http.request",
        otel.name = %format!("{} {route}", req.method()),
        otel.kind = "server",
        otel.status_code = tracing::field::Empty,
        http.request.method = %req.method(),
        http.route = route,
        http.response.status_code = tracing::field::Empty,
        trace_id = tracing::field::Empty,
    );
    let traceparent = req
        .headers()
        .get("traceparent")
        .and_then(|v| v.to_str().ok());
    common::telemetry::start_trace(&span, traceparent);
    let start = std::time::Instant::now();
    let response = next.run(req).instrument(span.clone()).await;
    span.record("http.response.status_code", response.status().as_u16());
    if response.status().is_server_error() {
        span.record("otel.status_code", "error");
    }
    common::metrics::API_REQUESTS_TOTAL
        .with_label_values(&[
            route,
            common::metrics::status_class(response.status().as_u16()),
        ])
        .inc();
    common::metrics::API_REQUEST_DURATION_SECONDS
        .with_label_values(&[route])
        .observe(start.elapsed().as_secs_f64());
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_trace;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    const TRACE_ID: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
    const PARENT_SPAN_ID: &str = "00f067aa0ba902b7";

    /// Serve `/items/{id}` (200) and `/boom` (500) behind the request
    /// middleware, send one raw HTTP/1.1 request, return the status line.
    async fn send(path: &str, traceparent: Option<&str>) -> String {
        let app = Router::new()
            .route("/items/{id}", get(|| async { StatusCode::OK }))
            .route("/boom", get(|| async { StatusCode::INTERNAL_SERVER_ERROR }))
            .layer(middleware::from_fn(request_metrics));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await });

        let mut request = format!("GET {path} HTTP/1.1\r\nhost: test\r\nconnection: close\r\n");
        if let Some(traceparent) = traceparent {
            request.push_str(&format!("traceparent: {traceparent}\r\n"));
        }
        request.push_str("\r\n");
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        server.abort();
        response.lines().next().unwrap().to_owned()
    }

    #[tokio::test]
    async fn store_health_reports_reachability_and_the_reason() {
        use crate::capture_store::{OpenSearchConfig, OpenSearchStore};
        let status = Arc::new(std::sync::atomic::AtomicU16::new(200));
        let served = status.clone();
        let app = Router::new().route(
            "/",
            get(move || {
                let code = served.load(std::sync::atomic::Ordering::Relaxed);
                async move { StatusCode::from_u16(code).unwrap() }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await });
        let store = OpenSearchStore::new(&OpenSearchConfig::new(url)).unwrap();

        let (code, body) = store_health(&store).await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(body.0["store"], "opensearch");
        assert_eq!(body.0["status"], "ok");

        status.store(503, std::sync::atomic::Ordering::Relaxed);
        let (code, body) = store_health(&store).await;
        assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body.0["status"], "unreachable");
        assert!(body.0["error"].as_str().unwrap().contains("503"));
        server.abort();
    }

    #[tokio::test]
    async fn request_span_joins_caller_trace() {
        let (spans, _guard) = test_trace::capture();
        let status = send(
            "/items/42",
            Some(&format!("00-{TRACE_ID}-{PARENT_SPAN_ID}-01")),
        )
        .await;
        assert_eq!(status, "HTTP/1.1 200 OK");

        let spans = spans.take();
        assert_eq!(spans.len(), 1);
        let span = &spans[0];
        assert_eq!(span.name, "GET /items/{id}");
        assert_eq!(span.span_kind, opentelemetry::trace::SpanKind::Server);
        assert_eq!(span.span_context.trace_id().to_string(), TRACE_ID);
        assert_eq!(span.parent_span_id.to_string(), PARENT_SPAN_ID);
        assert_eq!(
            test_trace::attr(span, "http.route").as_deref(),
            Some("/items/{id}")
        );
        assert_eq!(
            test_trace::attr(span, "http.response.status_code").as_deref(),
            Some("200")
        );
        assert_eq!(
            test_trace::attr(span, "trace_id").as_deref(),
            Some(TRACE_ID)
        );
    }

    #[tokio::test]
    async fn request_without_traceparent_starts_new_trace() {
        let (spans, _guard) = test_trace::capture();
        send("/items/42", None).await;

        let spans = spans.take();
        assert_eq!(spans.len(), 1);
        assert_eq!(
            spans[0].parent_span_id,
            opentelemetry::trace::SpanId::INVALID
        );
        assert_ne!(
            spans[0].span_context.trace_id(),
            opentelemetry::trace::TraceId::INVALID
        );
    }

    #[tokio::test]
    async fn server_error_marks_span_as_error() {
        let (spans, _guard) = test_trace::capture();
        let status = send("/boom", None).await;
        assert_eq!(status, "HTTP/1.1 500 Internal Server Error");

        let spans = spans.take();
        assert_eq!(spans.len(), 1);
        assert!(matches!(
            spans[0].status,
            opentelemetry::trace::Status::Error { .. }
        ));
    }

    #[tokio::test]
    async fn probe_routes_have_no_span() {
        let (spans, _guard) = test_trace::capture();
        let app = Router::new()
            .route("/health", get(health_live))
            .layer(middleware::from_fn(request_metrics));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await });
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"GET /health HTTP/1.1\r\nhost: test\r\nconnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        server.abort();

        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(spans.take().is_empty());
    }
}
