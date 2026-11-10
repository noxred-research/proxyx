//! Ops server: `/healthz`, `/readyz`, `/metrics` on their own port, so a
//! scrape or a probe never competes with `/v1` traffic or carries its auth.
//!
//! It starts before Postgres and Redis are connected, so liveness never
//! fails while the binary retries its connections: `/healthz` answers 200
//! from the first moment and `/readyz` answers 503 `starting` until
//! [`OpsDeps`] arrive. From the stop request on (see
//! [`OpsState::with_draining`]) `/readyz` answers 503 `draining`, so the
//! Service sends no new traffic, while `/healthz` and `/metrics` keep
//! answering until the caller stops the server: the drain stays observable
//!.
//!
//! The `redis_down` gauge is refreshed by a ping every [`REDIS_CHECK_EVERY`],
//! not only when `/readyz` is probed: a pod nobody probes must not show a
//! Redis outage that ended.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use anyhow::Context as _;
use axum::Router;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use common::metrics::{CONTENT_TYPE, Metrics};
use store::loaded::Loaded;
use store::{Db, Hot};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

/// A Redis ping that takes longer counts as a failure.
const PING_TIMEOUT: Duration = Duration::from_secs(2);
/// `/readyz` turns 503 after this many failed checks in a row, so one lost
/// ping does not take a pod out of rotation.
const READY_FAILURES: u32 = 3;
/// How often the ops server pings Redis to refresh `redis_down`.
const REDIS_CHECK_EVERY: Duration = Duration::from_secs(5);

/// What `/readyz` checks, available once the binary connected.
#[derive(Clone)]
pub struct OpsDeps {
    pub db: Db,
    pub hot: Hot,
    pub loaded: watch::Receiver<Arc<Loaded>>,
}

/// State of the ops routes.
pub struct OpsState {
    metrics: Arc<Metrics>,
    /// `None` until the binary connected to Postgres and Redis and loaded
    /// the first snapshot.
    deps: watch::Receiver<Option<OpsDeps>>,
    failures: AtomicU32,
    redis_check_every: Duration,
    /// Fires when the process was asked to stop; never, until set.
    draining: CancellationToken,
}

impl OpsState {
    pub fn new(metrics: Arc<Metrics>, deps: watch::Receiver<Option<OpsDeps>>) -> Self {
        Self {
            metrics,
            deps,
            failures: AtomicU32::new(0),
            redis_check_every: REDIS_CHECK_EVERY,
            draining: CancellationToken::new(),
        }
    }

    /// `/readyz` answers 503 `draining` once `draining` fires.
    #[must_use]
    pub fn with_draining(mut self, draining: CancellationToken) -> Self {
        self.draining = draining;
        self
    }

    /// Ping Redis this often instead of every [`REDIS_CHECK_EVERY`].
    #[must_use]
    pub fn with_redis_check_every(mut self, every: Duration) -> Self {
        self.redis_check_every = every;
        self
    }

    /// Ping Redis and set `redis_down` from the answer. `None` until the
    /// binary connected.
    async fn check_redis(&self) -> Option<bool> {
        let deps = self.deps.borrow().clone()?;
        let ok = matches!(
            tokio::time::timeout(PING_TIMEOUT, deps.hot.ping()).await,
            Ok(Ok(()))
        );
        self.metrics.redis_down.set(i64::from(!ok));
        Some(ok)
    }

    /// Record one readiness check; true while the pod should stay ready.
    fn record(&self, ok: bool) -> bool {
        if ok {
            self.failures.store(0, Ordering::Relaxed);
            true
        } else {
            self.failures.fetch_add(1, Ordering::Relaxed) + 1 < READY_FAILURES
        }
    }
}

fn ops_router(state: Arc<OpsState>) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .with_state(state)
}

/// Serve the ops routes until `cancel` fires. The caller fires it after the
/// drain, not at the stop request.
pub async fn serve_ops(
    addr: std::net::SocketAddr,
    state: Arc<OpsState>,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind the ops server to {addr}"))?;
    tracing::info!(%addr, "ops server listening");
    serve_ops_on(listener, state, cancel).await
}

/// [`serve_ops`] on a bound listener. It also keeps `redis_down` fresh.
pub async fn serve_ops_on(
    listener: TcpListener,
    state: Arc<OpsState>,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    let refresh = tokio::spawn({
        let (state, cancel) = (Arc::clone(&state), cancel.clone());
        async move {
            let mut tick = tokio::time::interval(state.redis_check_every);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = tick.tick() => { state.check_redis().await; }
                    () = cancel.cancelled() => break,
                }
            }
        }
    });
    let served = axum::serve(listener, ops_router(state))
        .with_graceful_shutdown(cancel.cancelled_owned())
        .await
        .context("ops server failed");
    refresh.abort();
    served
}

/// Liveness: the event loop answers.
async fn healthz() -> &'static str {
    "ok"
}

/// Readiness: not draining, Redis answers and a snapshot is loaded. Postgres
/// is not checked: when it is down the gateway keeps serving the last snapshot.
async fn readyz(State(state): State<Arc<OpsState>>) -> Response {
    if state.draining.is_cancelled() {
        return (StatusCode::SERVICE_UNAVAILABLE, "draining").into_response();
    }
    let Some(redis_ok) = state.check_redis().await else {
        return (StatusCode::SERVICE_UNAVAILABLE, "starting").into_response();
    };
    if state.record(redis_ok) {
        (StatusCode::OK, "ok").into_response()
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "redis unavailable").into_response()
    }
}

async fn metrics(State(state): State<Arc<OpsState>>) -> Response {
    if let Some(deps) = state.deps.borrow().as_ref() {
        state
            .metrics
            .snapshot_age_seconds
            .set(deps.loaded.borrow().loaded_at.elapsed().as_secs_f64());
    }
    (
        [(header::CONTENT_TYPE, CONTENT_TYPE)],
        state.metrics.render(),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> (OpsState, watch::Sender<Option<OpsDeps>>) {
        let (tx, rx) = watch::channel(None);
        (OpsState::new(Arc::new(Metrics::new("test")), rx), tx)
    }

    #[test]
    fn readiness_turns_off_on_the_third_failure_in_a_row_and_a_success_resets() {
        let (s, _tx) = state();
        assert!(s.record(false));
        assert!(s.record(false));
        assert!(s.record(true), "a success resets the count");
        assert!(s.record(false));
        assert!(s.record(false));
        assert!(!s.record(false), "third failure in a row");
        assert!(!s.record(false), "and it stays off");
        assert!(s.record(true), "recovers on the next success");
    }

    async fn get_status(state: Arc<OpsState>, path: &str) -> (u16, String, Option<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let cancel = CancellationToken::new();
        let stop = cancel.clone();
        tokio::spawn(async move {
            axum::serve(listener, ops_router(state))
                .with_graceful_shutdown(stop.cancelled_owned())
                .await
                .expect("serve");
        });
        let resp = reqwest::get(format!("http://{addr}{path}"))
            .await
            .expect("request");
        let status = resp.status().as_u16();
        let ctype = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .map(|v| v.to_str().expect("header").to_owned());
        let body = resp.text().await.expect("body");
        cancel.cancel();
        (status, body, ctype)
    }

    #[tokio::test]
    async fn healthz_answers_before_the_dependencies_connect_and_readyz_says_starting() {
        let (s, _tx) = state();
        let s = Arc::new(s);
        assert_eq!(get_status(s.clone(), "/healthz").await.0, 200);
        let (code, body, _) = get_status(s, "/readyz").await;
        assert_eq!((code, body.as_str()), (503, "starting"));
    }

    #[tokio::test]
    async fn metrics_are_served_as_prometheus_text_with_the_service_label() {
        let (s, _tx) = state();
        s.metrics.tunnels_open.set(3);
        let (code, body, ctype) = get_status(Arc::new(s), "/metrics").await;
        assert_eq!(code, 200);
        assert_eq!(ctype.as_deref(), Some(CONTENT_TYPE));
        assert!(
            body.contains("proxyx_pool_tunnels_open{service=\"test\"} 3"),
            "{body}"
        );
    }

    #[tokio::test]
    async fn after_the_stop_request_readyz_is_503_and_the_rest_keeps_serving_until_the_server_stops()
     {
        let addr = {
            let l = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            l.local_addr().expect("addr")
        };
        let (tx, rx) = watch::channel(None);
        let draining = CancellationToken::new();
        let metrics = Arc::new(Metrics::new("test"));
        metrics.tunnels_open.set(7);
        let state = Arc::new(OpsState::new(metrics, rx).with_draining(draining.clone()));
        let stop = CancellationToken::new();
        let server = tokio::spawn(serve_ops(addr, state, stop.clone()));
        let http = reqwest::Client::new();
        let get = |path: &'static str| {
            let http = http.clone();
            async move {
                for _ in 0..50 {
                    if let Ok(resp) = http.get(format!("http://{addr}{path}")).send().await {
                        let code = resp.status().as_u16();
                        return (code, resp.text().await.expect("body"));
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                panic!("{path} never answered");
            }
        };

        assert_eq!(get("/readyz").await, (503, "starting".to_owned()));
        draining.cancel();
        assert_eq!(get("/readyz").await, (503, "draining".to_owned()));
        assert_eq!(get("/healthz").await.0, 200);
        let (code, body) = get("/metrics").await;
        assert_eq!(code, 200);
        assert!(
            body.contains("proxyx_pool_tunnels_open{service=\"test\"} 7"),
            "{body}"
        );
        assert!(!server.is_finished(), "the stop request alone ends nothing");

        stop.cancel();
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("the server stops when told to")
            .expect("join")
            .expect("serve");
        drop(tx);
    }
}
