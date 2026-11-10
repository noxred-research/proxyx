//! End-to-end smoke tests of the load tool.
//!
//! The first test needs nothing outside the process: a TLS origin and a CONNECT
//! proxy stub run in it. The second drives the real `proxyx-intercept` and
//! needs `PROXYX_BENCH_INTERCEPT` (path to the binary) and
//! `PROXYX_TEST_REDIS_URL`; without them it prints a skip line, as the other
//! suites do. `ci/bench-smoke.sh` sets both.

use std::sync::Arc;
use std::time::Duration;

use proxyx_bench::cli::{CommonArgs, SessionArgs, SessionMode};
use proxyx_bench::report::{Report, Sweep, run_sweep};
use proxyx_bench::session::{self, ORIGIN_HOST, Plan, SessionConnector};
use proxyx_bench::stubs;
use proxyx_bench::tls::{self, Ca};
use uuid::Uuid;

fn sweep(levels: Vec<usize>, duration: Duration) -> Sweep {
    Sweep {
        levels,
        duration: Some(duration),
        requests: None,
        keepalive: true,
        timeout: Duration::from_secs(10),
        warmup: Duration::ZERO,
        pid: Some(std::process::id()),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn passthrough_load_against_a_local_stub_has_no_errors() {
    let origin_ca = Ca::generate("smoke origin ca").expect("ca");
    let (cert, key) = origin_ca.issue_server(ORIGIN_HOST).expect("leaf");
    let origin = stubs::http_origin(512, Some(tls::server_config(cert, &key).expect("server")))
        .await
        .expect("origin");
    let proxy = stubs::connect_proxy().await.expect("proxy stub");

    let connector = SessionConnector::new(&Plan {
        proxy: proxy.addr,
        session_id: Uuid::new_v4(),
        origin_port: origin.addr.port(),
        trust_der: origin_ca.cert_der(),
        payload_bytes: 512,
    })
    .expect("connector");
    session::preflight(&connector).await.expect("preflight");

    let runs = run_sweep(Arc::new(connector), &sweep(vec![4], Duration::from_secs(1)))
        .await
        .expect("sweep");
    let run = &runs[0];
    assert_eq!(run.concurrency, 4);
    assert_eq!(run.result.errors, 0, "{:?}", run.result.error_examples);
    assert!(run.result.requests > 0);
    assert!(run.result.requests_per_sec > 0.0);
    assert!(run.result.latency.p99_us >= run.result.latency.p50_us);
    // keep-alive: four tunnels carried every request (plus the preflight's)
    assert_eq!(proxy.accepted(), 4 + 1);
    // 512 bytes each way per request
    assert_eq!(run.result.bytes, run.result.requests * 1024);
    let usage = run.target.expect("the process was sampled");
    assert!(usage.peak_rss_kb > 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn without_keepalive_every_request_opens_a_tunnel() {
    let origin_ca = Ca::generate("smoke origin ca").expect("ca");
    let (cert, key) = origin_ca.issue_server(ORIGIN_HOST).expect("leaf");
    let origin = stubs::http_origin(64, Some(tls::server_config(cert, &key).expect("server")))
        .await
        .expect("origin");
    let proxy = stubs::connect_proxy().await.expect("proxy stub");
    let connector = Arc::new(
        SessionConnector::new(&Plan {
            proxy: proxy.addr,
            session_id: Uuid::new_v4(),
            origin_port: origin.addr.port(),
            trust_der: origin_ca.cert_der(),
            payload_bytes: 64,
        })
        .expect("connector"),
    );
    let sweep = Sweep {
        keepalive: false,
        requests: Some(40),
        duration: None,
        ..sweep(vec![2], Duration::from_secs(1))
    };
    let runs = run_sweep(connector, &sweep).await.expect("sweep");
    assert_eq!(runs[0].result.requests, 40);
    assert_eq!(runs[0].result.errors, 0);
    assert_eq!(proxy.accepted(), 40);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_real_session_proxy_serves_passthrough_and_mitm() {
    let (Some(binary), Ok(redis_url)) = (
        std::env::var_os("PROXYX_BENCH_INTERCEPT"),
        std::env::var("PROXYX_TEST_REDIS_URL"),
    ) else {
        eprintln!("SKIP: PROXYX_BENCH_INTERCEPT and PROXYX_TEST_REDIS_URL must be set");
        return;
    };
    let args = |mode: SessionMode| SessionArgs {
        common: CommonArgs {
            concurrency: vec![4],
            duration: Some(Duration::from_secs(1)),
            requests: None,
            payload_bytes: 256,
            keepalive: true,
            timeout: Duration::from_secs(10),
            warmup: Duration::ZERO,
            json: false,
            spawn: Some(binary.clone().into()),
            pid: None,
            workdir: None,
        },
        mode,
        redis_url: redis_url.clone(),
        redis_prefix: format!("proxyx_bench_test_{}", Uuid::new_v4().simple()),
        proxy: None,
        ca_der: None,
    };
    for mode in [SessionMode::Passthrough, SessionMode::Mitm] {
        let report: Report = session::run(&args(mode)).await.expect("run");
        assert_eq!(report.total_errors(), 0, "{mode:?}: {}", report.to_table());
        assert!(report.total_requests() > 0, "{mode:?}");
        assert!(
            report.runs[0]
                .target
                .is_some_and(|u| u.cpu_seconds >= 0.0 && u.peak_rss_kb > 0)
        );
    }
}
