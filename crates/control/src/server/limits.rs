//! Request limits of the control API: a per-request deadline (`504`), a cap on
//! requests served at once (`503` with `Retry-After`), and independent token
//! buckets per source address and credential (`429` with `Retry-After`). Health
//! and metrics routes are exempt. Configured by [`HttpLimits`].

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

use crate::auth::{Principal, principal_from_headers};
use crate::config::{AuthMode, HttpLimits};

/// Distinct credentials or source addresses tracked in each cache; idle entries
/// are forgotten after [`IDLE_FOR`].
const MAX_KEYS: u64 = 100_000;
const IDLE_FOR: Duration = Duration::from_secs(600);

type Buckets = moka::sync::Cache<[u8; 32], Arc<Mutex<Bucket>>>;

/// Shared state of the limit middleware.
pub struct Limits {
    config: HttpLimits,
    auth_mode: AuthMode,
    in_flight: Option<Arc<Semaphore>>,
    buckets: Buckets,
    sources: Buckets,
}

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    at: Instant,
}

impl Limits {
    pub fn new(config: HttpLimits, auth_mode: AuthMode) -> Arc<Self> {
        let buckets = || {
            Buckets::builder()
                .max_capacity(MAX_KEYS)
                .time_to_idle(IDLE_FOR)
                .build()
        };
        Arc::new(Self {
            in_flight: (config.max_in_flight > 0)
                .then(|| Arc::new(Semaphore::new(config.max_in_flight))),
            buckets: buckets(),
            sources: buckets(),
            config,
            auth_mode,
        })
    }

    /// Take one token for `key`; `Err(wait)` when the bucket is empty.
    fn take(&self, buckets: &Buckets, key: [u8; 32], now: Instant) -> Result<(), Duration> {
        let rate = self.config.per_key_rps;
        if rate <= 0.0 {
            return Ok(());
        }
        let burst = self.config.per_key_burst.max(1.0);
        let bucket = buckets.get_with(key, || {
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

/// Hash the credential using the same normalization as authentication. Ignore
/// headers that do not authenticate in the configured mode.
fn key_of(request: &Request, auth_mode: AuthMode) -> Option<[u8; 32]> {
    let mut hasher = Sha256::new();
    match auth_mode {
        AuthMode::Keys => {
            let token = request
                .headers()
                .get(header::AUTHORIZATION)?
                .to_str()
                .ok()
                .and_then(crate::keys::bearer)?;
            hasher.update(b"bearer:");
            hasher.update(token.as_bytes());
        }
        AuthMode::TrustedHeaders => match principal_from_headers(request.headers()).ok()? {
            Principal::User(user) => {
                hasher.update(b"user:");
                if let Some(org_id) = user.org_id {
                    hasher.update(org_id.as_bytes());
                }
                hasher.update([0]);
                hasher.update(user.user_id.as_bytes());
            }
            Principal::Service(service) => {
                hasher.update(b"service:");
                hasher.update(service.org_id.as_bytes());
                hasher.update([0]);
                hasher.update(service.service_name.as_bytes());
            }
        },
    }
    Some(hasher.finalize().into())
}

/// Only the transport peer identifies a source; forwarded headers are untrusted.
fn source_key(request: &Request) -> [u8; 32] {
    let mut hasher = Sha256::new();
    match request.extensions().get::<ConnectInfo<SocketAddr>>() {
        Some(ConnectInfo(peer)) => match peer.ip() {
            std::net::IpAddr::V4(ip) => hasher.update(ip.octets()),
            std::net::IpAddr::V6(ip) => hasher.update(ip.octets()),
        },
        None => hasher.update(b"unknown-peer"),
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

/// Apply source and credential limits before authentication, then cap in-flight
/// requests and enforce the deadline.
pub async fn enforce(State(limits): State<Arc<Limits>>, request: Request, next: Next) -> Response {
    if exempt(request.uri().path()) {
        return next.run(request).await;
    }
    let now = Instant::now();
    let admission = limits
        .take(&limits.sources, source_key(&request), now)
        .and_then(|()| match key_of(&request, limits.auth_mode) {
            Some(key) => limits.take(&limits.buckets, key, now),
            None => Ok(()),
        });
    if let Err(wait) = admission {
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
        app_with_mode(config, AuthMode::Keys)
    }

    fn app_with_mode(config: HttpLimits, auth_mode: AuthMode) -> Router {
        let limits = Limits::new(config, auth_mode);
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
        get_from(path, auth, "192.0.2.1:1000")
    }

    fn get_from(path: &str, auth: &str, peer: &str) -> Request {
        Request::builder()
            .uri(path)
            .header(header::AUTHORIZATION, auth)
            .extension(ConnectInfo(peer.parse::<SocketAddr>().expect("peer")))
            .body(Body::empty())
            .expect("request")
    }

    #[tokio::test]
    async fn rotating_bearer_tokens_cannot_bypass_the_source_bucket() {
        let app = app(HttpLimits {
            per_key_rps: 0.001,
            per_key_burst: 2.0,
            ..HttpLimits::default()
        });
        for (token, peer, expected) in [
            ("Bearer a", "192.0.2.1:1000", StatusCode::OK),
            ("Bearer b", "192.0.2.1:2000", StatusCode::OK),
            ("Bearer c", "192.0.2.1:3000", StatusCode::TOO_MANY_REQUESTS),
            ("Bearer c", "192.0.2.2:1000", StatusCode::OK),
        ] {
            let response = app
                .clone()
                .oneshot(get_from("/fast", token, peer))
                .await
                .expect("call");
            assert_eq!(response.status(), expected);
        }
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
            .oneshot(get_from("/fast", "Bearer b", "192.0.2.2:1000"))
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
    async fn bearer_spelling_variants_share_a_bucket_across_sources() {
        let app = app(HttpLimits {
            per_key_rps: 0.001,
            per_key_burst: 1.0,
            ..HttpLimits::default()
        });
        for (index, auth) in [
            "Bearer pxk_abc",
            "bearer pxk_abc",
            "bEaReR   pxk_abc ",
            "  BEARER pxk_abc  ",
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(crate::keys::bearer(auth), Some("pxk_abc"));
            let request = get_from("/fast", auth, &format!("192.0.2.{}:1000", index + 1));
            let response = app.clone().oneshot(request).await.expect("call");
            assert_eq!(
                response.status(),
                if index == 0 {
                    StatusCode::OK
                } else {
                    StatusCode::TOO_MANY_REQUESTS
                }
            );
        }
    }

    #[tokio::test]
    async fn trusted_users_share_canonical_identity_but_not_organizations() {
        let app = app_with_mode(
            HttpLimits {
                per_key_rps: 0.001,
                per_key_burst: 1.0,
                ..HttpLimits::default()
            },
            AuthMode::TrustedHeaders,
        );
        for (index, principal_type, user_id, org_id, expected) in [
            (
                1,
                "user",
                "abcdefab-cdef-abcd-efab-cdefabcdefab",
                "org-a",
                StatusCode::OK,
            ),
            (
                2,
                "  SuPeRaDmIn  ",
                "  ABCDEFABCDEFABCDEFABCDEFABCDEFAB  ",
                "  org-a  ",
                StatusCode::TOO_MANY_REQUESTS,
            ),
            (
                3,
                "user",
                "abcdefab-cdef-abcd-efab-cdefabcdefab",
                "org-b",
                StatusCode::OK,
            ),
        ] {
            let mut request = get_from(
                "/fast",
                &format!("Bearer ignored-{index}"),
                &format!("192.0.2.{index}:1000"),
            );
            let headers = request.headers_mut();
            for (name, value) in [
                (crate::auth::PRINCIPAL_TYPE_HEADER, principal_type),
                (crate::auth::USER_ID_HEADER, user_id),
                (crate::auth::ORG_ID_HEADER, org_id),
            ] {
                headers.insert(name, HeaderValue::from_str(value).expect("header"));
            }
            let response = app.clone().oneshot(request).await.expect("call");
            assert_eq!(response.status(), expected);
        }
    }

    #[test]
    fn trusted_services_use_organization_and_name_not_authorization() {
        let service_request = |org: &str, name: &str, auth: &str| {
            let mut request = get_with("/fast", auth);
            for (header, value) in [
                (crate::auth::PRINCIPAL_TYPE_HEADER, "  SERVICE  "),
                (crate::auth::ORG_ID_HEADER, org),
                (crate::auth::SERVICE_NAME_HEADER, name),
            ] {
                request
                    .headers_mut()
                    .insert(header, HeaderValue::from_str(value).expect("header"));
            }
            request
        };
        let key = key_of(
            &service_request("org-a", "worker", "Bearer ignored-a"),
            AuthMode::TrustedHeaders,
        )
        .expect("service key");
        assert_eq!(
            Some(key),
            key_of(
                &service_request("  org-a  ", "  worker  ", "Bearer ignored-b"),
                AuthMode::TrustedHeaders,
            )
        );
        for request in [
            service_request("org-b", "worker", "Bearer ignored-a"),
            service_request("org-a", "other", "Bearer ignored-a"),
        ] {
            assert_ne!(Some(key), key_of(&request, AuthMode::TrustedHeaders));
        }
        assert_eq!(
            key_of(&get_with("/fast", "Basic ignored"), AuthMode::Keys),
            None
        );
        assert_eq!(
            key_of(
                &get_with("/fast", "Bearer ignored"),
                AuthMode::TrustedHeaders
            ),
            None
        );
    }

    #[tokio::test]
    async fn source_bucket_limits_attempts_before_authentication() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let attempts = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&attempts);
        let limits = Limits::new(
            HttpLimits {
                per_key_rps: 0.001,
                per_key_burst: 2.0,
                ..HttpLimits::default()
            },
            AuthMode::TrustedHeaders,
        );
        let app = Router::new()
            .route(
                "/fast",
                get(move |request: Request| {
                    let attempts = Arc::clone(&observed);
                    async move {
                        attempts.fetch_add(1, Ordering::SeqCst);
                        match principal_from_headers(request.headers()) {
                            Ok(_) => StatusCode::OK,
                            Err(_) => StatusCode::UNAUTHORIZED,
                        }
                    }
                }),
            )
            .layer(axum::middleware::from_fn_with_state(limits, enforce));
        for (index, principal_type, peer, expected) in [
            (1, "invalid-a", "192.0.2.1:1000", StatusCode::UNAUTHORIZED),
            (2, "invalid-b", "192.0.2.1:2000", StatusCode::UNAUTHORIZED),
            (
                3,
                "service",
                "192.0.2.1:3000",
                StatusCode::TOO_MANY_REQUESTS,
            ),
            (4, "service", "192.0.2.2:1000", StatusCode::OK),
        ] {
            let mut request = get_from("/fast", &format!("Bearer rotating-{index}"), peer);
            for (name, value) in [
                (crate::auth::PRINCIPAL_TYPE_HEADER, principal_type),
                (crate::auth::ORG_ID_HEADER, "org-a"),
                (crate::auth::SERVICE_NAME_HEADER, "worker"),
                ("x-forwarded-for", &format!("198.51.100.{index}")),
            ] {
                request
                    .headers_mut()
                    .insert(name, HeaderValue::from_str(value).expect("header"));
            }
            let response = app.clone().oneshot(request).await.expect("call");
            assert_eq!(response.status(), expected);
            if expected == StatusCode::TOO_MANY_REQUESTS {
                assert!(response.headers().contains_key(header::RETRY_AFTER));
                assert_eq!(attempts.load(Ordering::SeqCst), 2);
            }
        }
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
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
        let limits = Limits::new(
            HttpLimits {
                per_key_rps: 0.0,
                ..HttpLimits::default()
            },
            AuthMode::Keys,
        );
        let now = Instant::now();
        for _ in 0..10_000 {
            assert!(limits.take(&limits.buckets, [1; 32], now).is_ok());
            assert!(limits.take(&limits.sources, [1; 32], now).is_ok());
        }
    }
}
