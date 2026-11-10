//! The ops listener: `/metrics`, `/healthz`, `/readyz`.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::extract::State as AxState;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use tokio::net::TcpListener;

use crate::conn::Shared;
use crate::metrics::CONTENT_TYPE;
use crate::server::Server;

/// Refresh the gauges that are read from live state, then render.
pub fn render_metrics(shared: &Shared) -> String {
    let state = shared.state();
    let m = &shared.metrics;
    for pool in state.all_pools() {
        let name = pool.name();
        let (open, half_open, unhealthy) = pool.states();
        for (label, v) in [
            ("total", pool.len()),
            ("open", open),
            ("half_open", half_open),
            ("unhealthy", unhealthy),
            ("prefixes", pool.prefix_count()),
        ] {
            m.egress_addresses
                .with_label_values(&[name, label])
                .set(v as i64);
        }
    }
    for p in state.parents.all() {
        m.parent_up
            .with_label_values(&[&p.name])
            .set(i64::from(!p.is_down()));
        m.parent_breaker_state
            .with_label_values(&[&p.name])
            .set(p.state().as_i64());
        m.parent_healthy
            .with_label_values(&[&p.name])
            .set(i64::from(p.health.is_healthy()));
    }
    // The writer thread counts what it dropped; the counter follows it.
    let dropped = shared.access_log().dropped();
    let seen = m.access_log_dropped_total.get();
    if dropped > seen {
        m.access_log_dropped_total.inc_by(dropped - seen);
    }
    m.render()
}

async fn metrics(AxState(server): AxState<Arc<Server>>) -> Response {
    let mut r = render_metrics(&server.shared).into_response();
    r.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(CONTENT_TYPE));
    r
}

/// Liveness: the process answers.
async fn healthz() -> &'static str {
    "ok\n"
}

/// Ready when the process is not stopping, a configuration is in force, every
/// configured listener is bound and at least one egress path is healthy.
async fn readyz(AxState(server): AxState<Arc<Server>>) -> Response {
    let r = server.readiness();
    let status = if r.is_ready() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, r.report()).into_response()
}

pub fn router(server: Arc<Server>) -> Router {
    Router::new()
        .route("/metrics", get(metrics))
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .with_state(server)
}

/// Serve until shutdown. Returns the bound address through `bound`.
pub async fn serve(server: Arc<Server>, addr: SocketAddr) -> std::io::Result<SocketAddr> {
    let listener = TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    let app = router(server);
    // Stays up while the proxy drains (`/readyz` answers 503 then) and ends with the process.
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(local)
}
