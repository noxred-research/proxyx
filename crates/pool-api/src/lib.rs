//! Control API and ops endpoints.
//!
//! `/v1` credentials:
//!
//! * admin bearer: inventory, policies (`PUT /v1/policies`, `DELETE
//!   /v1/policies/{scope}/{name}`), org keys, org blocks, customer upstreams
//!   ([`upstream`]) and `POST /v1/ips/{ip}/block`;
//! * org key (HTTP Basic password): `POST /v1/block-signals`;
//! * prober bearer: `/v1/probe/*` (`POST /v1/probe/token` hands out the
//!   short-lived password of the probe listener, see [`auth`]).
//!
//! Wrong credentials are throttled per source (`429` after 20 in a minute,
//! see `auth`). Admin routes name the person in the optional `X-Operator`
//! header for the audit trail. Errors are `{"error": msg}`, also for an
//! unknown route (`404`), a wrong method (`405`), a bad path segment or an
//! oversized body (`413`); internal causes are logged and never sent. The ops
//! routes live in [`ops`] on their own port.
//!
//! **Who wins between git and the API**: `global` and `route_class`
//! policies belong to git. The API can still write them (an emergency
//! change); that version stays until git changes *that* policy, and then git
//! wins and the audit row of its write names the actor it replaced. Git
//! changes to other policies never touch it.
//! `DELETE` removes an API-written policy (a policy git defines then returns
//! at the next reload, and the check of the set that remains counts git's
//! version); one git wrote is git's to remove.

mod auth;
mod error;
mod inventory;
mod ops;
mod orgs;
mod policies;
mod probe;
mod react;
mod signals;
mod state;
mod upstream;
mod wire;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use axum::Router;
use axum::extract::{ConnectInfo, DefaultBodyLimit, MatchedPath, Request, State};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use common::metrics::Metrics;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tower_service::Service as _;
use tracing::Instrument as _;

use crate::error::ApiError;

pub use ops::{OpsDeps, OpsState, serve_ops, serve_ops_on};
pub use state::{ApiState, TunnelControl};

/// One request, storage calls included, must finish inside this bound; the
/// client gets `504` otherwise.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
/// Largest request body: 10,000 inventory entries at about 400 bytes each.
/// A bigger body answers `413` before any handler runs on it.
const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;
/// A client has this long to send a whole request head, from the connection's
/// accept and again after each response on a kept-alive one.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// Most connections open at once. The callers are the session proxy pods, the prober and
/// operators; the gateway's descriptor check (`2 x max_connections + 512`)
/// leaves room for these.
const MAX_CONNECTIONS: usize = 256;
/// Pause after a failed `accept`, so a descriptor shortage is not a busy loop.
const ACCEPT_RETRY: Duration = Duration::from_millis(100);

/// The `/v1` router.
fn router(state: Arc<ApiState>) -> Router {
    let admin = Router::new()
        .route("/v1/inventory", get(inventory::list))
        .route("/v1/inventory/replacements", get(inventory::replacements))
        .route("/v1/inventory/{provider}", put(inventory::put))
        .route("/v1/ips/{ip}/block", post(signals::operator_block))
        .route("/v1/policies", get(policies::list).put(policies::put))
        .route("/v1/policies/{scope}/{name}", delete(policies::delete))
        .route("/v1/orgs/{org}/cache-policy", put(policies::put_org))
        .route(
            "/v1/orgs/{org}/keys",
            post(orgs::create_key).delete(orgs::disable_keys),
        )
        .route(
            "/v1/orgs/{org}/upstream",
            get(upstream::get)
                .put(upstream::set)
                .delete(upstream::clear),
        )
        .route("/v1/orgs/{org}/upstream/validate", post(upstream::validate))
        .route(
            "/v1/orgs/{org}/upstream/rotate-secret",
            post(upstream::rotate_secret),
        )
        .route(
            "/v1/org-blocks",
            post(orgs::create_block).get(orgs::list_blocks),
        )
        .route("/v1/org-blocks/{id}", delete(orgs::revoke_block))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_admin,
        ));
    let probe = Router::new()
        .route("/v1/probe/targets", get(probe::targets))
        .route("/v1/probe/results", post(probe::results))
        .route("/v1/probe/token", post(auth::probe_token))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_prober,
        ));
    Router::new()
        .route("/v1/block-signals", post(signals::block_signals))
        .merge(admin)
        .merge(probe)
        .fallback(error::route_not_found)
        .method_not_allowed_fallback(error::method_not_allowed)
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state.metrics),
            request,
        ))
        .with_state(state)
}

/// Bound the request, run it inside a server span that joins the caller's
/// trace (W3C `traceparent` header), and count it. The route is the matched
/// template, never the raw path, which can carry an org id or an IP. The
/// `/v1` router has no probe or scrape route; those live on the ops server,
/// which has no span.
async fn request(State(metrics): State<Arc<Metrics>>, req: Request, next: Next) -> Response {
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map_or_else(|| "unmatched".to_owned(), |p| p.as_str().to_owned());
    let span = tracing::info_span!(
        "http.request",
        otel.name = %format!("{} {route}", req.method()),
        otel.kind = "server",
        otel.status_code = tracing::field::Empty,
        http.request.method = %req.method(),
        http.route = %route,
        http.response.status_code = tracing::field::Empty,
        trace_id = tracing::field::Empty,
    );
    let traceparent = req
        .headers()
        .get("traceparent")
        .and_then(|v| v.to_str().ok());
    common::telemetry::start_trace(&span, traceparent);
    let start = Instant::now();
    let response = async {
        match tokio::time::timeout(REQUEST_TIMEOUT, next.run(req)).await {
            Ok(response) => response,
            Err(_) => ApiError::new(axum::http::StatusCode::GATEWAY_TIMEOUT, "request timed out")
                .into_response(),
        }
    }
    .instrument(span.clone())
    .await;
    let status = response.status();
    span.record("http.response.status_code", status.as_u16());
    if status.is_server_error() {
        span.record("otel.status_code", "error");
    }
    metrics
        .api_requests_total
        .with_label_values(&[&route, common::metrics::status_class(status.as_u16())])
        .inc();
    metrics
        .api_request_duration_seconds
        .with_label_values(&[&route])
        .observe(start.elapsed().as_secs_f64());
    response
}

/// Bind `addr` and serve [`router`] until `cancel` fires.
pub async fn serve(
    addr: SocketAddr,
    state: Arc<ApiState>,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind the control API to {addr}"))?;
    tracing::info!(%addr, "control API listening");
    serve_listener(listener, state, cancel).await
}

/// Serve [`router`] on a bound listener until `cancel` fires.
///
/// Not `axum::serve`: its connection builder sets no timer, so hyper's header
/// read timeout never runs and a client that sends its request head one byte
/// at a time holds a connection (and a file descriptor of the process that
/// also serves the tunnels) for as long as it likes. This
/// loop speaks HTTP/1.1 (every caller does, in clear inside the cluster),
/// closes a connection that has not sent a full request head in
/// [`HEADER_READ_TIMEOUT`], and holds at most [`MAX_CONNECTIONS`] open: past
/// that it stops accepting until one closes.
pub async fn serve_listener(
    listener: TcpListener,
    state: Arc<ApiState>,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    serve_app(listener, router(state), cancel, Limits::default()).await
}

/// What bounds a client of [`serve_app`].
#[derive(Clone, Copy)]
struct Limits {
    header_read_timeout: Duration,
    max_connections: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            header_read_timeout: HEADER_READ_TIMEOUT,
            max_connections: MAX_CONNECTIONS,
        }
    }
}

async fn serve_app(
    listener: TcpListener,
    app: Router,
    cancel: CancellationToken,
    limits: Limits,
) -> anyhow::Result<()> {
    let slots = Arc::new(Semaphore::new(limits.max_connections));
    let tracker = TaskTracker::new();
    loop {
        let permit = tokio::select! {
            () = cancel.cancelled() => break,
            permit = Arc::clone(&slots).acquire_owned() => permit.context("connection slots closed")?,
        };
        let (stream, peer) = tokio::select! {
            () = cancel.cancelled() => break,
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                Err(err) => {
                    // out of descriptors or an aborted handshake: retry
                    tracing::warn!(error = %err, "control API accept failed");
                    tokio::time::sleep(ACCEPT_RETRY).await;
                    continue;
                }
            },
        };
        tracker.spawn(serve_connection(
            app.clone(),
            stream,
            peer,
            permit,
            limits.header_read_timeout,
            cancel.clone(),
        ));
    }
    tracker.close();
    tracker.wait().await;
    Ok(())
}

/// One client connection; ends when the client leaves, a request head takes
/// too long, or `cancel` fires (the request in flight finishes first).
async fn serve_connection(
    app: Router,
    stream: TcpStream,
    peer: SocketAddr,
    _permit: OwnedSemaphorePermit,
    header_read_timeout: Duration,
    cancel: CancellationToken,
) {
    let service = hyper::service::service_fn(move |mut req: hyper::Request<Incoming>| {
        req.extensions_mut().insert(ConnectInfo(peer));
        app.clone().call(req)
    });
    let mut conn = std::pin::pin!(
        http1::Builder::new()
            .timer(TokioTimer::new())
            .header_read_timeout(header_read_timeout)
            .serve_connection(TokioIo::new(stream), service)
    );
    let mut stopping = false;
    loop {
        tokio::select! {
            result = conn.as_mut() => {
                if let Err(err) = result {
                    tracing::debug!(%peer, error = %err, "control API connection ended");
                }
                return;
            }
            () = cancel.cancelled(), if !stopping => {
                stopping = true;
                conn.as_mut().graceful_shutdown();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;

    /// Send one raw HTTP/1.1 request through `request` and return the status
    /// line.
    async fn send(metrics: &Arc<Metrics>, path: &str) -> String {
        let app = Router::new()
            .route("/items/{id}", get(|| async { StatusCode::OK }))
            .route("/boom", get(|| async { StatusCode::INTERNAL_SERVER_ERROR }))
            .layer(middleware::from_fn_with_state(Arc::clone(metrics), request));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let req = format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
        stream.write_all(req.as_bytes()).await.expect("write");
        let mut out = String::new();
        stream.read_to_string(&mut out).await.expect("read");
        out.lines().next().unwrap_or_default().to_owned()
    }

    #[tokio::test]
    async fn requests_are_counted_by_route_template_and_status_class() {
        let metrics = Arc::new(Metrics::new("test"));
        assert!(send(&metrics, "/items/secret-org-id").await.contains("200"));
        assert!(send(&metrics, "/boom").await.contains("500"));
        assert!(send(&metrics, "/nowhere/1.2.3.4").await.contains("404"));

        let count = |route: &str, class: &str| {
            metrics
                .api_requests_total
                .with_label_values(&[route, class])
                .get()
        };
        assert_eq!(count("/items/{id}", "2xx"), 1);
        assert_eq!(count("/boom", "5xx"), 1);
        assert_eq!(count("unmatched", "4xx"), 1);
        let text = metrics.render();
        assert!(!text.contains("secret-org-id"), "{text}");
        assert!(!text.contains("1.2.3.4"), "{text}");
        assert_eq!(
            metrics
                .api_request_duration_seconds
                .with_label_values(&["/items/{id}"])
                .get_sample_count(),
            1
        );
    }

    /// A running [`serve_app`] with a router that echoes the peer address.
    async fn serve_echo(limits: Limits) -> (SocketAddr, CancellationToken) {
        let app = Router::new().route(
            "/peer",
            get(|ConnectInfo(peer): ConnectInfo<SocketAddr>| async move { peer.ip().to_string() }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let cancel = CancellationToken::new();
        tokio::spawn(serve_app(listener, app, cancel.clone(), limits));
        (addr, cancel)
    }

    const PEER_REQUEST: &[u8] = b"GET /peer HTTP/1.1\r\nHost: x\r\n\r\n";

    async fn read_some(stream: &mut TcpStream, within: Duration) -> Option<String> {
        let mut buf = vec![0u8; 1024];
        let n = tokio::time::timeout(within, stream.read(&mut buf))
            .await
            .ok()?
            .expect("read");
        Some(String::from_utf8_lossy(&buf[..n]).into_owned())
    }

    /// A client that never finishes its request head is cut
    /// off at the header timeout, and the peer address still reaches handlers.
    #[tokio::test]
    async fn a_slow_request_head_is_closed_at_the_header_timeout() {
        let (addr, cancel) = serve_echo(Limits {
            header_read_timeout: Duration::from_millis(300),
            max_connections: 8,
        })
        .await;

        let mut ok = TcpStream::connect(addr).await.expect("connect");
        ok.write_all(PEER_REQUEST).await.expect("write");
        let reply = read_some(&mut ok, Duration::from_secs(2)).await;
        assert!(
            reply.is_some_and(|r| r.starts_with("HTTP/1.1 200") && r.ends_with("127.0.0.1")),
            "the handler sees the peer"
        );

        let mut slow = TcpStream::connect(addr).await.expect("connect");
        slow.write_all(b"GET /peer HTTP/1.1\r\nHost: x\r\n")
            .await
            .expect("write");
        // the head never ends: the server answers 408 or closes, in time
        let end = read_some(&mut slow, Duration::from_secs(3)).await;
        assert!(
            end.is_some(),
            "still open 3 s after a 300 ms header timeout"
        );
        cancel.cancel();
    }

    /// Past `max_connections` a client waits for a slot.
    #[tokio::test]
    async fn connections_past_the_cap_wait_for_a_free_slot() {
        let (addr, cancel) = serve_echo(Limits {
            header_read_timeout: Duration::from_secs(30),
            max_connections: 2,
        })
        .await;
        let first = TcpStream::connect(addr).await.expect("connect");
        let _second = TcpStream::connect(addr).await.expect("connect");
        // let the accept loop take both slots
        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut third = TcpStream::connect(addr).await.expect("connect");
        third.write_all(PEER_REQUEST).await.expect("write");
        assert!(
            read_some(&mut third, Duration::from_millis(300))
                .await
                .is_none(),
            "served with no slot free"
        );
        drop(first);
        let reply = read_some(&mut third, Duration::from_secs(2)).await;
        assert!(reply.is_some_and(|r| r.starts_with("HTTP/1.1 200")));
        cancel.cancel();
    }
}
