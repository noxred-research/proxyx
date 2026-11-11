//! Sentry against a local ingest stub: the layers installed by
//! `telemetry::init` and the options `sentry::init` builds from `SentryConfig`.
//! One test function, because the tracing subscriber and the Sentry hub are
//! process-global.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

use proxyx_pool_common::secret::Secret;
use proxyx_pool_common::sentry::{SentryConfig, init};
use proxyx_pool_common::telemetry;

type Bodies = Arc<Mutex<Vec<String>>>;

/// Read one HTTP request, store its body, answer `200 {}`.
fn serve(mut stream: TcpStream, bodies: &Bodies) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    let (head_end, length) = loop {
        let n = stream.read(&mut chunk).expect("read request");
        assert!(n > 0, "connection closed before the request head ended");
        buf.extend_from_slice(&chunk[..n]);
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
            let length = head
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .map(|value| value.trim().parse::<usize>().expect("content-length"))
                .expect("the ingest request has a content-length");
            break (end + 4, length);
        }
    };
    while buf.len() < head_end + length {
        let n = stream.read(&mut chunk).expect("read body");
        assert!(n > 0, "connection closed before the request body ended");
        buf.extend_from_slice(&chunk[..n]);
    }
    let body = String::from_utf8_lossy(&buf[head_end..head_end + length]).into_owned();
    bodies.lock().expect("bodies lock").push(body);
    stream
        .write_all(b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}")
        .expect("write response");
}

fn config(port: u16, sample_rate: f32, traces_sample_rate: f32) -> SentryConfig {
    SentryConfig {
        dsn: Some(Secret::new(format!("http://publickey@127.0.0.1:{port}/1"))),
        environment: Some("staging".into()),
        release: Some("9.9.9".into()),
        sample_rate,
        traces_sample_rate,
    }
}

/// Run `emit` under a client built from the given rates and return what the
/// stub received once the guard has flushed.
fn run(
    port: u16,
    bodies: &Bodies,
    sample_rate: f32,
    traces_sample_rate: f32,
    emit: impl FnOnce(),
) -> String {
    bodies.lock().expect("bodies lock").clear();
    let guard = init(&config(port, sample_rate, traces_sample_rate), "stub-svc")
        .expect("a DSN starts the client");
    emit();
    drop(guard);
    bodies.lock().expect("bodies lock").join("\n")
}

fn emit_records() {
    tracing::warn!("crumb-warn");
    tracing::info!("crumb-info");
    tracing::debug!("crumb-debug");
    let span = tracing::info_span!("work-span");
    let _entered = span.enter();
    tracing::error!("the-error");
}

#[test]
fn events_breadcrumbs_and_sample_rates_reach_the_ingest() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
    let port = listener.local_addr().expect("stub address").port();
    let bodies: Bodies = Arc::default();
    let served = Arc::clone(&bodies);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let served = Arc::clone(&served);
            thread::spawn(move || serve(stream.expect("accept"), &served));
        }
    });

    // The subscriber is global; the client behind it changes per scenario.
    let _otel = telemetry::init("stub-svc", false);

    // Error events and breadcrumbs, release, environment, service tag, traces.
    let all = run(port, &bodies, 1.0, 1.0, emit_records);
    assert!(all.contains("the-error"), "ERROR is an event: {all}");
    assert!(
        all.contains("crumb-warn") && all.contains("crumb-info"),
        "WARN and INFO are breadcrumbs on the event: {all}"
    );
    assert!(!all.contains("crumb-debug"), "DEBUG is ignored: {all}");
    assert!(all.contains("\"release\":\"9.9.9\""), "release: {all}");
    assert!(
        all.contains("\"environment\":\"staging\""),
        "environment: {all}"
    );
    assert!(all.contains("\"service\":\"stub-svc\""), "tag: {all}");
    assert!(
        all.contains("\"type\":\"transaction\""),
        "traces_sample_rate 1.0 sends the span as a transaction: {all}"
    );
    // WARN and INFO alone never become events: only the one ERROR does.
    assert_eq!(all.matches("\"type\":\"event\"").count(), 1, "{all}");

    // Traces off (the default): the error still arrives, no transaction.
    let errors_only = run(port, &bodies, 1.0, 0.0, emit_records);
    assert!(errors_only.contains("the-error"), "{errors_only}");
    assert!(
        !errors_only.contains("\"type\":\"transaction\""),
        "traces_sample_rate 0.0 sends no transaction: {errors_only}"
    );

    // Error sample rate 0.0 drops the event; breadcrumbs alone send nothing.
    let none = run(port, &bodies, 0.0, 0.0, emit_records);
    assert!(
        !none.contains("the-error") && !none.contains("crumb-warn"),
        "sample_rate 0.0 sends no event: {none}"
    );
}
