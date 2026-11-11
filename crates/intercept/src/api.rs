use std::sync::Arc;

use axum::{
    Router,
    extract::State,
    http::{StatusCode, header},
    response::IntoResponse,
    routing::get,
};
use tokio_util::sync::CancellationToken;

use crate::health::Readiness;
use crate::profiling::{self, Profiler};

pub async fn serve(
    addr: std::net::SocketAddr,
    cancel: CancellationToken,
    readiness: Arc<Readiness>,
    profiler: Option<Arc<Profiler>>,
) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "API server listening");
    axum::serve(listener, router(readiness, profiler))
        .with_graceful_shutdown(cancel.cancelled_owned())
        .await?;
    Ok(())
}

fn router(readiness: Arc<Readiness>, profiler: Option<Arc<Profiler>>) -> Router {
    let app = Router::new()
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        // Alias of `/health/ready`, for probes configured before the split.
        .route("/health", get(ready))
        .route("/metrics", get(metrics))
        .with_state(readiness);
    match profiler {
        Some(profiler) => app.merge(profiling::router(profiler)),
        None => app,
    }
}

async fn live() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "application/json")],
        r#"{"status":"live"}"#,
    )
}

/// `200` with the report while ready, `503` with the same body otherwise.
async fn ready(State(readiness): State<Arc<Readiness>>) -> impl IntoResponse {
    let report = readiness.report();
    let status = if report.ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    let body = serde_json::to_vec(&report).unwrap_or_default();
    (status, [(header::CONTENT_TYPE, "application/json")], body)
}

async fn metrics() -> ([(&'static str, &'static str); 1], Vec<u8>) {
    (
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        common::metrics::render(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Serve `router` on an ephemeral port and return (status, body) of `GET path`.
    async fn get_path(app: Router, path: &str) -> (u16, Vec<u8>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await });
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let request = format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await.unwrap();
        let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
        let head = String::from_utf8_lossy(&raw[..split]);
        let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
        let mut body = raw[split + 4..].to_vec();
        if head
            .to_ascii_lowercase()
            .contains("transfer-encoding: chunked")
        {
            body = dechunk(&body);
        }
        (status, body)
    }

    fn dechunk(mut raw: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let eol = raw.windows(2).position(|w| w == b"\r\n").unwrap();
            let size =
                usize::from_str_radix(std::str::from_utf8(&raw[..eol]).unwrap(), 16).unwrap();
            if size == 0 {
                return out;
            }
            out.extend_from_slice(&raw[eol + 2..eol + 2 + size]);
            raw = &raw[eol + 4 + size..];
        }
    }

    fn healthy() -> Arc<Readiness> {
        let readiness = Arc::new(Readiness::new());
        readiness
            .register_listener("connect")
            .store(true, std::sync::atomic::Ordering::Release);
        readiness
    }

    #[tokio::test]
    async fn live_and_ready_routes_answer_while_healthy() {
        let readiness = healthy();
        let (status, body) = get_path(router(readiness.clone(), None), "/health/live").await;
        assert_eq!(status, 200);
        assert_eq!(body, br#"{"status":"live"}"#);
        for path in ["/health/ready", "/health"] {
            let (status, body) = get_path(router(readiness.clone(), None), path).await;
            assert_eq!(status, 200, "{path}");
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(json["ready"], true);
            assert_eq!(json["draining"], false);
            for check in ["redis", "capture_pipeline", "listeners"] {
                assert_eq!(json["checks"][check]["ok"], true, "{path} {check}");
            }
        }
    }

    #[tokio::test]
    async fn ready_is_503_while_draining_but_live_stays_200() {
        let readiness = healthy();
        readiness.set_draining();
        for path in ["/health/ready", "/health"] {
            let (status, body) = get_path(router(readiness.clone(), None), path).await;
            assert_eq!(status, 503, "{path}");
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(json["ready"], false);
            assert_eq!(json["draining"], true);
        }
        let (status, _) = get_path(router(readiness, None), "/health/live").await;
        assert_eq!(status, 200);
    }

    #[tokio::test]
    async fn ready_is_503_when_a_listener_is_down() {
        let readiness = healthy();
        let down = readiness.register_listener("socks5");
        let (status, body) = get_path(router(readiness.clone(), None), "/health/ready").await;
        assert_eq!(status, 503);
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["checks"]["listeners"]["ok"], false);
        assert_eq!(
            json["checks"]["listeners"]["detail"],
            "not accepting: socks5"
        );
        down.store(true, std::sync::atomic::Ordering::Release);
        let (status, _) = get_path(router(readiness, None), "/health/ready").await;
        assert_eq!(status, 200);
    }

    #[tokio::test]
    async fn debug_routes_404_when_profiling_off() {
        for path in ["/debug/stalls", "/debug/pprof/profile?seconds=1"] {
            let (status, _) = get_path(router(healthy(), None), path).await;
            assert_eq!(status, 404, "{path}");
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn stalls_json_shape() {
        let profiler = Profiler::start(CancellationToken::new());
        let (status, body) = get_path(router(healthy(), Some(profiler)), "/debug/stalls").await;
        assert_eq!(status, 200);
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["threshold_ms"], 50);
        assert_eq!(json["interval_ms"], 10);
        assert!(json["events"].is_array());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn cpu_profile_returns_protobuf_and_rejects_concurrent() {
        use pprof::protos::Message as _;

        let profiler = Profiler::start(CancellationToken::new());
        let app = router(healthy(), Some(profiler));
        let first = tokio::spawn(get_path(app.clone(), "/debug/pprof/profile?seconds=1"));
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let (second, _) = get_path(app.clone(), "/debug/pprof/profile?seconds=1").await;
        assert_eq!(second, 409);

        let (status, body) = first.await.unwrap();
        assert_eq!(status, 200);
        let profile = pprof::protos::Profile::decode(body.as_slice()).unwrap();
        assert!(!profile.sample_type.is_empty());

        let (bad, _) = get_path(app, "/debug/pprof/profile?seconds=0").await;
        assert_eq!(bad, 400);
    }

    fn fast_health() -> crate::config::HealthConfig {
        crate::config::HealthConfig {
            check_interval_ms: 50,
            redis_timeout_ms: 300,
            redis_failure_threshold: 2,
            capture_stall_fraction: 0.5,
            capture_stall_window_ms: 200,
            capture_publish_stale_ms: 400,
            drain_notice_ms: 0,
        }
    }

    /// Poll `/health/ready` until it answers `want`; returns the JSON body.
    async fn poll_ready(
        readiness: &Arc<Readiness>,
        want: u16,
        within: std::time::Duration,
    ) -> serde_json::Value {
        let deadline = std::time::Instant::now() + within;
        loop {
            let (status, body) = get_path(router(readiness.clone(), None), "/health/ready").await;
            if status == want {
                return serde_json::from_slice(&body).unwrap();
            }
            assert!(
                std::time::Instant::now() < deadline,
                "/health/ready kept answering {status}, wanted {want}: {}",
                String::from_utf8_lossy(&body)
            );
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }

    async fn redis_manager(url: &str) -> redis::aio::ConnectionManager {
        redis::aio::ConnectionManager::new(redis::Client::open(url).unwrap())
            .await
            .unwrap()
    }

    fn writer_with(
        producer: crate::health::testkit::GatedProducer,
        capacity: usize,
    ) -> Arc<crate::pipeline::RequestLogWriter> {
        Arc::new(crate::pipeline::RequestLogWriter::new(
            crate::pipeline::RequestLogConfig {
                channel_capacity: capacity,
                ..crate::pipeline::RequestLogConfig::default()
            },
            Box::new(producer),
        ))
    }

    /// Run the readiness monitor against `redis_url` through a forwarder that
    /// is stopped and restarted: not ready while the port is closed, ready
    /// again once it is back.
    async fn redis_outage_cycle(target: &str, db: u32) {
        use crate::health::testkit::{Forwarder, GatedProducer};

        let mut forwarder = Forwarder::start(target).await;
        let url = format!("redis://127.0.0.1:{}/{db}", forwarder.port);
        let redis = redis_manager(&url).await;
        let (producer, _gate) = GatedProducer::new(true);
        let readiness = healthy();
        let cancel = CancellationToken::new();
        let monitor = crate::health::spawn_monitor(
            readiness.clone(),
            redis,
            writer_with(producer, 8),
            fast_health(),
            cancel.clone(),
        );

        let ok = poll_ready(&readiness, 200, std::time::Duration::from_secs(5)).await;
        assert_eq!(ok["checks"]["redis"]["ok"], true);

        forwarder.stop().await;
        let down = poll_ready(&readiness, 503, std::time::Duration::from_secs(10)).await;
        assert_eq!(down["ready"], false);
        assert_eq!(down["checks"]["redis"]["ok"], false);
        assert!(
            down["checks"]["redis"]["detail"]
                .as_str()
                .unwrap()
                .contains("PING"),
            "{down}"
        );
        assert_eq!(down["checks"]["listeners"]["ok"], true);
        let (live, _) = get_path(router(readiness.clone(), None), "/health/live").await;
        assert_eq!(live, 200, "liveness does not depend on Redis");
        let (alias, _) = get_path(router(readiness.clone(), None), "/health").await;
        assert_eq!(alias, 503, "/health follows readiness");

        forwarder.restart().await;
        let back = poll_ready(&readiness, 200, std::time::Duration::from_secs(30)).await;
        assert_eq!(back["checks"]["redis"]["ok"], true);

        cancel.cancel();
        monitor.await.unwrap();
        forwarder.stop().await;
    }

    #[tokio::test]
    async fn ready_flips_503_when_redis_is_unreachable_and_recovers() {
        let fake = crate::health::testkit::fake_redis().await;
        let target = fake
            .strip_prefix("redis://")
            .unwrap()
            .trim_end_matches('/')
            .to_string();
        redis_outage_cycle(&target, 0).await;
    }

    /// Same cycle against a real Valkey: `PROXYX_TEST_REDIS_URL`, db 11.
    #[tokio::test]
    async fn ready_follows_a_real_valkey_outage() {
        let Ok(base) = std::env::var("PROXYX_TEST_REDIS_URL") else {
            eprintln!("SKIP: PROXYX_TEST_REDIS_URL is not set");
            return;
        };
        let target = base
            .trim_start_matches("redis://")
            .split('/')
            .next()
            .unwrap()
            .to_string();
        redis_outage_cycle(&target, 11).await;
    }

    #[tokio::test]
    async fn ready_is_503_when_the_capture_pipeline_stalls_and_recovers() {
        use crate::health::testkit::{GatedProducer, fake_redis};

        let redis = redis_manager(&fake_redis().await).await;
        let (producer, gate) = GatedProducer::new(false);
        let writer = writer_with(producer, 4);
        let readiness = healthy();
        let cancel = CancellationToken::new();
        let monitor = crate::health::spawn_monitor(
            readiness.clone(),
            redis,
            writer.clone(),
            fast_health(),
            cancel.clone(),
        );
        poll_ready(&readiness, 200, std::time::Duration::from_secs(5)).await;

        // One capture goes in flight and the producer never answers.
        writer.send(crate::pipeline::test_event("stall-a")).await;
        let stalled = poll_ready(&readiness, 503, std::time::Duration::from_secs(5)).await;
        assert_eq!(stalled["checks"]["capture_pipeline"]["ok"], false);
        assert!(
            stalled["checks"]["capture_pipeline"]["detail"]
                .as_str()
                .unwrap()
                .contains("no capture published"),
            "{stalled}"
        );
        assert_eq!(stalled["checks"]["redis"]["ok"], true);
        let (live, _) = get_path(router(readiness.clone(), None), "/health/live").await;
        assert_eq!(live, 200);

        // The broker comes back: the queue empties and readiness returns.
        gate.send(true).unwrap();
        poll_ready(&readiness, 200, std::time::Duration::from_secs(5)).await;

        cancel.cancel();
        monitor.await.unwrap();
    }

    #[tokio::test]
    async fn ready_is_503_when_the_capture_queue_stays_full() {
        use crate::health::testkit::{GatedProducer, fake_redis};

        let redis = redis_manager(&fake_redis().await).await;
        let (producer, gate) = GatedProducer::new(false);
        let writer = writer_with(producer, 4);
        let readiness = healthy();
        let cancel = CancellationToken::new();
        let monitor = crate::health::spawn_monitor(
            readiness.clone(),
            redis,
            writer.clone(),
            fast_health(),
            cancel.clone(),
        );

        writer.send(crate::pipeline::test_event("full-a")).await;
        // Let the drain task take it in flight, then fill the queue past half.
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        for i in 0..3 {
            writer
                .send(crate::pipeline::test_event(&format!("full-{i}")))
                .await;
        }
        let stalled = poll_ready(&readiness, 503, std::time::Duration::from_secs(5)).await;
        assert!(
            stalled["checks"]["capture_pipeline"]["detail"]
                .as_str()
                .unwrap()
                .contains("capture queue at 3/4"),
            "{stalled}"
        );

        gate.send(true).unwrap();
        poll_ready(&readiness, 200, std::time::Duration::from_secs(5)).await;
        cancel.cancel();
        monitor.await.unwrap();
    }
}
