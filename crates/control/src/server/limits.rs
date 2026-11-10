//! Request limits of the control API: a per-request deadline (`504`), a cap on
//! requests served at once (`503` with `Retry-After`), and a token bucket per
//! credential (`429` with `Retry-After`). Health and metrics routes are exempt
//! so probes keep answering under load. Configured by [`HttpLimits`].

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use parking_lot::Mutex;
use sha2::{Digest as _, Sha256};
use tokio::sync::Semaphore;

use crate::config::HttpLimits;

/// Distinct credentials tracked at once; idle ones are forgotten after
/// [`IDLE_FOR`].
const MAX_KEYS: u64 = 100_000;
const IDLE_FOR: Duration = Duration::from_secs(600);

/// Shared state of the limit middleware.
pub struct Limits {
    config: HttpLimits,
    in_flight: Option<Arc<Semaphore>>,
    buckets: moka::sync::Cache<[u8; 32], Arc<Mutex<Bucket>>>,
}

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    at: Instant,
}

impl Limits {
    pub fn new(config: HttpLimits) -> Arc<Self> {
        Arc::new(Self {
            in_flight: (config.max_in_flight > 0)
                .then(|| Arc::new(Semaphore::new(config.max_in_flight))),
            buckets: moka::sync::Cache::builder()
                .max_capacity(MAX_KEYS)
                .time_to_idle(IDLE_FOR)
                .build(),
            config,
        })
    }

    /// Take one token for `key`; `Err(wait)` when the bucket is empty.
    fn take(&self, key: [u8; 32], now: Instant) -> Result<(), Duration> {
        let rate = self.config.per_key_rps;
        if rate <= 0.0 {
            return Ok(());
        }
        let burst = self.config.per_key_burst.max(1.0);
        let bucket = self.buckets.get_with(key, || {
            Arc::new(Mutex::new(Bucket {
                tokens: burst,
                at: now,
            }))
        });
        let mut bucket = bucket.lock();
        let elapsed = now.saturating_duration_since(bucket.at).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * rate).min(burst);
        bucket.at = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            Ok(())
        } else {
            Err(Duration::from_secs_f64((1.0 - bucket.tokens) / rate))
        }
    }
}

fn exempt(path: &str) -> bool {
    path == "/metrics" || path == "/health" || path.starts_with("/health/") || path == "/rpc/health"
}

/// The rate-limit key: the credential the request presents, else its peer
/// address. Hashed so no credential is kept in memory.
fn key_of(request: &Request) -> [u8; 32] {
    let mut hasher = Sha256::new();
    if let Some(auth) = request.headers().get(header::AUTHORIZATION) {
        hasher.update(b"auth:");
        hasher.update(auth.as_bytes());
    } else if let Some(ConnectInfo(peer)) = request.extensions().get::<ConnectInfo<SocketAddr>>() {
        hasher.update(b"peer:");
        hasher.update(peer.ip().to_string().as_bytes());
    } else {
        hasher.update(b"anonymous");
    }
    hasher.finalize().into()
}

fn refuse(status: StatusCode, retry_after: Duration, message: &'static str) -> Response {
    let secs = retry_after.as_secs().max(1);
    let mut response = (
        status,
        [(header::CONTENT_TYPE, "application/json")],
        format!("{{\"error\":\"{message}\"}}"),
    )
        .into_response();
    if let Ok(value) = HeaderValue::from_str(&secs.to_string()) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    response
}

/// The middleware: rate limit, then the in-flight cap, then the deadline.
pub async fn enforce(State(limits): State<Arc<Limits>>, request: Request, next: Next) -> Response {
    if exempt(request.uri().path()) {
        return next.run(request).await;
    }
    if let Err(wait) = limits.take(key_of(&request), Instant::now()) {
        crate::server::count_refusal("rate_limited");
        return refuse(StatusCode::TOO_MANY_REQUESTS, wait, "rate limit exceeded");
    }
    let _permit = match &limits.in_flight {
        Some(semaphore) => match Arc::clone(semaphore).try_acquire_owned() {
            Ok(permit) => Some(permit),
            Err(_) => {
                crate::server::count_refusal("over_capacity");
                return refuse(
                    StatusCode::SERVICE_UNAVAILABLE,
                    Duration::from_secs(1),
                    "too many requests in flight",
                );
            }
        },
        None => None,
    };
    match limits.config.request_timeout_secs {
        0 => next.run(request).await,
        secs => match tokio::time::timeout(Duration::from_secs(secs), next.run(request)).await {
            Ok(response) => response,
            Err(_) => {
                crate::server::count_refusal("timeout");
                refuse(
                    StatusCode::GATEWAY_TIMEOUT,
                    Duration::from_secs(1),
                    "request timed out",
                )
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::routing::get;
    use tower::ServiceExt as _;

    fn app(config: HttpLimits) -> Router {
        let limits = Limits::new(config);
        Router::new()
            .route("/fast", get(|| async { "ok" }))
            .route(
                "/slow",
                get(|| async {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    "late"
                }),
            )
            .route("/health/live", get(|| async { "live" }))
            .layer(axum::middleware::from_fn_with_state(limits, enforce))
    }

    fn get_with(path: &str, auth: &str) -> Request {
        Request::builder()
            .uri(path)
            .header(header::AUTHORIZATION, auth)
            .body(Body::empty())
            .expect("request")
    }

    #[tokio::test]
    async fn a_key_over_its_burst_gets_429_with_retry_after_and_others_are_unaffected() {
        let app = app(HttpLimits {
            per_key_rps: 1.0,
            per_key_burst: 2.0,
            ..HttpLimits::default()
        });
        for _ in 0..2 {
            let ok = app
                .clone()
                .oneshot(get_with("/fast", "Bearer a"))
                .await
                .expect("call");
            assert_eq!(ok.status(), StatusCode::OK);
        }
        let limited = app
            .clone()
            .oneshot(get_with("/fast", "Bearer a"))
            .await
            .expect("call");
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(limited.headers()[header::RETRY_AFTER], "1");
        let other = app
            .clone()
            .oneshot(get_with("/fast", "Bearer b"))
            .await
            .expect("call");
        assert_eq!(other.status(), StatusCode::OK);
        // Probes are never limited.
        let probe = app
            .oneshot(get_with("/health/live", "Bearer a"))
            .await
            .expect("call");
        assert_eq!(probe.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn a_request_past_its_deadline_gets_504() {
        let app = app(HttpLimits {
            request_timeout_secs: 1,
            ..HttpLimits::default()
        });
        let started = Instant::now();
        let late = app
            .oneshot(get_with("/slow", "Bearer a"))
            .await
            .expect("call");
        assert_eq!(late.status(), StatusCode::GATEWAY_TIMEOUT);
        assert!(started.elapsed() < Duration::from_secs(4));
    }

    #[tokio::test]
    async fn requests_over_the_in_flight_cap_get_503() {
        let app = app(HttpLimits {
            max_in_flight: 1,
            request_timeout_secs: 0,
            ..HttpLimits::default()
        });
        let busy = tokio::spawn(app.clone().oneshot(get_with("/slow", "Bearer a")));
        tokio::time::sleep(Duration::from_millis(200)).await;
        let refused = app
            .oneshot(get_with("/fast", "Bearer b"))
            .await
            .expect("call");
        assert_eq!(refused.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(refused.headers()[header::RETRY_AFTER], "1");
        busy.abort();
    }

    #[test]
    fn zero_rate_disables_the_bucket() {
        let limits = Limits::new(HttpLimits {
            per_key_rps: 0.0,
            ..HttpLimits::default()
        });
        let now = Instant::now();
        for _ in 0..10_000 {
            assert!(limits.take([1; 32], now).is_ok());
        }
    }
}
