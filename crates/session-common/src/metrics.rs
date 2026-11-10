//! Process-wide Prometheus metrics for ProxyX.
//!
//! One shared [`Registry`] carries a constant `service` label read from the
//! `SERVICE_NAME` environment variable (injected by the Helm chart). Call
//! [`render`] from a `/metrics` HTTP handler — it does no I/O.

use std::collections::HashMap;
use std::sync::LazyLock;

use prometheus::{
    Counter, CounterVec, Encoder, Histogram, HistogramOpts, HistogramVec, IntGauge, IntGaugeVec,
    Opts, Registry, TextEncoder,
};

/// Shared registry.  Every metric below is registered here.
pub static REGISTRY: LazyLock<Registry> = LazyLock::new(|| {
    let service = std::env::var("SERVICE_NAME").unwrap_or_else(|_| "unknown".into());
    Registry::new_custom(None, Some(HashMap::from([("service".into(), service)])))
        .expect("prometheus registry")
});

// ---------------------------------------------------------------------------
// Proxy
// ---------------------------------------------------------------------------

/// Proxy connections completed, by `outcome` (ok | rejected |
/// backend_unavailable | upstream_error | upstream_timeout | upstream_unavailable | error) and `listener`
/// (connect | http | socks5). `error` means the handler returned an error;
/// the other non-`ok` values mean it sent the client an error reply.
pub static PROXY_CONNECTIONS_TOTAL: LazyLock<CounterVec> = LazyLock::new(|| {
    let c = CounterVec::new(
        Opts::new(
            "proxyx_intercept_connections_total",
            "Proxy connections handled",
        ),
        &["outcome", "listener"],
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

/// Proxied MITM requests, by `protocol` (http | https | websocket) and
/// `status_class` (1xx..5xx from the upstream response, or `error` when no
/// upstream response arrived). Raw tunnels are not counted.
pub static PROXY_REQUESTS_TOTAL: LazyLock<CounterVec> = LazyLock::new(|| {
    let c = CounterVec::new(
        Opts::new("proxyx_intercept_requests_total", "Proxied MITM requests"),
        &["protocol", "status_class"],
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

/// Time from forwarding a MITM request upstream to receiving the upstream
/// response headers (seconds), by `protocol`.
pub static PROXY_UPSTREAM_DURATION_SECONDS: LazyLock<HistogramVec> = LazyLock::new(|| {
    let h = HistogramVec::new(
        HistogramOpts::new(
            "proxyx_intercept_upstream_duration_seconds",
            "Upstream time to response headers",
        )
        .buckets(vec![
            0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0,
        ]),
        &["protocol"],
    )
    .unwrap();
    REGISTRY.register(Box::new(h.clone())).unwrap();
    h
});

/// Tokio scheduler lag measured by the proxy's profiling probe: how late a
/// 10 ms interval tick fired (seconds). Only registered when proxy profiling
/// is on, so it is deliberately not forced in [`render`].
pub static PROXY_SCHEDULER_LAG_SECONDS: LazyLock<Histogram> = LazyLock::new(|| {
    let h = Histogram::with_opts(
        HistogramOpts::new(
            "proxyx_intercept_scheduler_lag_seconds",
            "Lateness of the proxy's 10 ms runtime probe tick",
        )
        .buckets(vec![
            0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0,
        ]),
    )
    .unwrap();
    REGISTRY.register(Box::new(h.clone())).unwrap();
    h
});

/// Captures queued in the request log writer's channel, waiting to be
/// published.
pub static PROXY_CAPTURE_BUFFER_DEPTH: LazyLock<IntGauge> = LazyLock::new(|| {
    let g = IntGauge::new(
        "proxyx_intercept_capture_buffer_depth",
        "Captures queued for publishing",
    )
    .unwrap();
    REGISTRY.register(Box::new(g.clone())).unwrap();
    g
});

/// Time the proxy itself adds to a MITM exchange (seconds), by `protocol`
/// (http | https | websocket) and `phase` (request | response | lock_wait |
/// ratelimit_wait | capture_wait). Body streaming is not included.
pub static PROXY_OVERHEAD_SECONDS: LazyLock<HistogramVec> = LazyLock::new(|| {
    let h = HistogramVec::new(
        HistogramOpts::new(
            "proxyx_intercept_overhead_seconds",
            "Proxy-added time per MITM exchange phase",
        )
        .buckets(vec![
            0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 10.0,
        ]),
        &["protocol", "phase"],
    )
    .unwrap();
    REGISTRY.register(Box::new(h.clone())).unwrap();
    h
});

/// Successful MITM TLS handshakes (seconds), by `side` (client | upstream).
pub static PROXY_TLS_HANDSHAKE_SECONDS: LazyLock<HistogramVec> = LazyLock::new(|| {
    let h = HistogramVec::new(
        HistogramOpts::new(
            "proxyx_intercept_tls_handshake_seconds",
            "MITM TLS handshake duration",
        )
        .buckets(vec![
            0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
        ]),
        &["side"],
    )
    .unwrap();
    REGISTRY.register(Box::new(h.clone())).unwrap();
    h
});

/// Captures successfully published to the broker.
pub static PROXY_CAPTURES_PUBLISHED_TOTAL: LazyLock<Counter> = LazyLock::new(|| {
    let c = Counter::new(
        "proxyx_intercept_captures_published_total",
        "Captures published to the broker",
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

/// Captures permanently dropped after publish retries exhausted.
pub static PROXY_CAPTURES_DROPPED_TOTAL: LazyLock<Counter> = LazyLock::new(|| {
    let c = Counter::new(
        "proxyx_intercept_captures_dropped_total",
        "Captures dropped after publish retries exhausted",
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

/// Worst upstream circuit-breaker state among the tracked targets of one
/// `target_kind` (egress_proxy | private_override | origin): 0 closed, 1 open,
/// 2 half_open. Open wins over half_open.
pub static PROXY_UPSTREAM_BREAKER_STATE: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    let g = IntGaugeVec::new(
        Opts::new(
            "proxyx_intercept_upstream_breaker_state",
            "Worst upstream breaker state per target kind: 0 closed, 1 open, 2 half_open",
        ),
        &["target_kind"],
    )
    .unwrap();
    REGISTRY.register(Box::new(g.clone())).unwrap();
    g
});

/// Upstream breaker state changes, by `target_kind` and the state entered
/// (`to`: open | half_open | closed).
pub static PROXY_UPSTREAM_BREAKER_TRANSITIONS_TOTAL: LazyLock<CounterVec> = LazyLock::new(|| {
    let c = CounterVec::new(
        Opts::new(
            "proxyx_intercept_upstream_breaker_transitions_total",
            "Upstream breaker state transitions",
        ),
        &["target_kind", "to"],
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

/// Upstream dials refused without connecting because the target's breaker was
/// open (or half-open with every probe slot taken), by `target_kind`.
pub static PROXY_UPSTREAM_BREAKER_REJECTED_TOTAL: LazyLock<CounterVec> = LazyLock::new(|| {
    let c = CounterVec::new(
        Opts::new(
            "proxyx_intercept_upstream_breaker_rejected_total",
            "Upstream dials failed fast by an open breaker",
        ),
        &["target_kind"],
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

/// 1 while the proxy reports itself ready on `/health/ready`, else 0.
pub static PROXY_READY: LazyLock<IntGauge> = LazyLock::new(|| {
    let g = IntGauge::new(
        "proxyx_intercept_ready",
        "1 while the session proxy is ready for traffic",
    )
    .unwrap();
    REGISTRY.register(Box::new(g.clone())).unwrap();
    g
});

/// Result of one readiness check, by `check` (redis | capture_pipeline |
/// listeners): 1 ok, 0 failing.
pub static PROXY_READINESS_CHECK: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    let g = IntGaugeVec::new(
        Opts::new(
            "proxyx_intercept_readiness_check",
            "Readiness check result: 1 ok, 0 failing",
        ),
        &["check"],
    )
    .unwrap();
    REGISTRY.register(Box::new(g.clone())).unwrap();
    g
});

/// 1 once the proxy received a shutdown signal and is draining.
pub static PROXY_DRAINING: LazyLock<IntGauge> = LazyLock::new(|| {
    let g = IntGauge::new(
        "proxyx_intercept_draining",
        "1 while the session proxy drains for shutdown",
    )
    .unwrap();
    REGISTRY.register(Box::new(g.clone())).unwrap();
    g
});

/// Client connections currently open on all listeners.
pub static PROXY_CONNECTIONS_ACTIVE: LazyLock<IntGauge> = LazyLock::new(|| {
    let g = IntGauge::new(
        "proxyx_intercept_connections_active",
        "Client connections currently open",
    )
    .unwrap();
    REGISTRY.register(Box::new(g.clone())).unwrap();
    g
});

/// Client connections closed at accept time because `tuning.max_connections`
/// was reached.
pub static PROXY_CONNECTION_LIMIT_REFUSALS_TOTAL: LazyLock<Counter> = LazyLock::new(|| {
    let c = Counter::new(
        "proxyx_intercept_connection_limit_refusals_total",
        "Connections refused at accept time by the connection limit",
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

/// Rate-limit backend calls that failed, by `backend` (redis | limiter).
pub static PROXY_RATELIMIT_BACKEND_ERRORS_TOTAL: LazyLock<CounterVec> = LazyLock::new(|| {
    let c = CounterVec::new(
        Opts::new(
            "proxyx_intercept_ratelimit_backend_errors_total",
            "Rate-limit backend calls that failed",
        ),
        &["backend"],
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

/// Requests the rate limiter let through because its backend failed and the
/// fail-open policy granted tokens, by `backend` (redis | limiter).
pub static PROXY_RATELIMIT_FAILOPEN_TOTAL: LazyLock<CounterVec> = LazyLock::new(|| {
    let c = CounterVec::new(
        Opts::new(
            "proxyx_intercept_ratelimit_failopen_total",
            "Requests admitted by the rate-limit fail-open policy",
        ),
        &["backend"],
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

// ---------------------------------------------------------------------------
// Ingester
// ---------------------------------------------------------------------------

/// Messages consumed from the broker, by `outcome` (ok | error).
pub static INGESTER_MESSAGES_TOTAL: LazyLock<CounterVec> = LazyLock::new(|| {
    let c = CounterVec::new(
        Opts::new(
            "proxyx_ingester_messages_total",
            "Messages consumed from the captures log",
        ),
        &["outcome"],
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

/// Duration of ClickHouse batch flushes (seconds), by `table`
/// (http_captures | ws_messages) and `outcome` (ok | error).
pub static INGESTER_FLUSH_DURATION_SECONDS: LazyLock<HistogramVec> = LazyLock::new(|| {
    let h = HistogramVec::new(
        HistogramOpts::new(
            "proxyx_ingester_flush_duration_seconds",
            "ClickHouse batch flush duration",
        )
        .buckets(vec![
            0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0,
        ]),
        &["table", "outcome"],
    )
    .unwrap();
    REGISTRY.register(Box::new(h.clone())).unwrap();
    h
});

/// Rows dropped from a ClickHouse batch because they could not be written,
/// by `table` (http_captures | ws_messages). The broker redelivers them, so a
/// steady rate means a poison message loops.
pub static INGESTER_ROWS_DROPPED_TOTAL: LazyLock<CounterVec> = LazyLock::new(|| {
    let c = CounterVec::new(
        Opts::new(
            "proxyx_ingester_rows_dropped_total",
            "Rows dropped from a ClickHouse batch after a write error",
        ),
        &["table"],
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

/// `_bulk` writes of the OpenSearch store that were retried in place after a
/// transient failure (transport error, timeout, `429` or `5xx`), by `table`.
/// Each count is one retry round of one request, not one document.
pub static INGESTER_STORE_RETRIES_TOTAL: LazyLock<CounterVec> = LazyLock::new(|| {
    let c = CounterVec::new(
        Opts::new(
            "proxyx_ingester_store_retries_total",
            "In-place retries of capture store writes after a transient failure",
        ),
        &["table"],
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

/// Records handed to the broker by a producer, by `broker` (redis_stream |
/// kafka | rabbitmq) and `outcome` (published | failed | not_sent).
pub static BROKER_PUBLISH_RECORDS_TOTAL: LazyLock<CounterVec> = LazyLock::new(|| {
    let c = CounterVec::new(
        Opts::new(
            "proxyx_broker_publish_records_total",
            "Records published to the captures log broker",
        ),
        &["broker", "outcome"],
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

/// Duration of one producer batch publish (seconds), by `broker`.
pub static BROKER_PUBLISH_DURATION_SECONDS: LazyLock<HistogramVec> = LazyLock::new(|| {
    let h = HistogramVec::new(
        HistogramOpts::new(
            "proxyx_broker_publish_duration_seconds",
            "Duration of one batch publish to the captures log broker",
        )
        .buckets(vec![
            0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
        ]),
        &["broker"],
    )
    .unwrap();
    REGISTRY.register(Box::new(h.clone())).unwrap();
    h
});

/// Messages a consumer received from the broker, by `broker`.
pub static BROKER_CONSUMED_TOTAL: LazyLock<CounterVec> = LazyLock::new(|| {
    let c = CounterVec::new(
        Opts::new(
            "proxyx_broker_consumed_total",
            "Messages received from the captures log broker",
        ),
        &["broker"],
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

/// Consumer acknowledgements, by `broker` and `outcome` (ok | error |
/// rejected).
pub static BROKER_ACKS_TOTAL: LazyLock<CounterVec> = LazyLock::new(|| {
    let c = CounterVec::new(
        Opts::new(
            "proxyx_broker_acks_total",
            "Acknowledgements of captures log messages",
        ),
        &["broker", "outcome"],
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

/// Broker connections re-established after a loss, by `broker` and `role`
/// (producer | consumer).
pub static BROKER_RECONNECTS_TOTAL: LazyLock<CounterVec> = LazyLock::new(|| {
    let c = CounterVec::new(
        Opts::new(
            "proxyx_broker_reconnects_total",
            "Captures log broker connections re-established after a loss",
        ),
        &["broker", "role"],
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

/// 1 while the producer or consumer has a working broker connection, by
/// `broker` (kafka | rabbitmq) and `role` (producer | consumer).
pub static BROKER_CONNECTED: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    let g = IntGaugeVec::new(
        Opts::new(
            "proxyx_broker_connected",
            "Captures log broker connection up (1) or down (0)",
        ),
        &["broker", "role"],
    )
    .unwrap();
    REGISTRY.register(Box::new(g.clone())).unwrap();
    g
});

/// 1 while a capture store flusher's circuit breaker is open, by `table`.
pub static INGESTER_CIRCUIT_OPEN: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    let g = IntGaugeVec::new(
        Opts::new(
            "proxyx_ingester_circuit_open",
            "Capture store flusher circuit breaker open (1) or closed (0)",
        ),
        &["table"],
    )
    .unwrap();
    REGISTRY.register(Box::new(g.clone())).unwrap();
    g
});

/// Time from a capture completing at the proxy to its ClickHouse insert
/// committing (seconds), by `table` (http_captures | ws_messages).
pub static CAPTURE_COMMIT_LAG_SECONDS: LazyLock<HistogramVec> = LazyLock::new(|| {
    let h = HistogramVec::new(
        HistogramOpts::new(
            "proxyx_capture_commit_lag_seconds",
            "Capture completion to ClickHouse commit lag",
        )
        .buckets(vec![
            0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0,
        ]),
        &["table"],
    )
    .unwrap();
    REGISTRY.register(Box::new(h.clone())).unwrap();
    h
});

// ---------------------------------------------------------------------------
// API
// ---------------------------------------------------------------------------

/// API HTTP requests completed, by `route` (matched route template, or
/// `unmatched`) and `status_class` (1xx..5xx).
pub static API_REQUESTS_TOTAL: LazyLock<CounterVec> = LazyLock::new(|| {
    let c = CounterVec::new(
        Opts::new(
            "proxyx_control_api_requests_total",
            "API HTTP requests handled",
        ),
        &["route", "status_class"],
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

/// API requests refused by the request limits, by `reason` (`rate_limited`,
/// `over_capacity`, `timeout`).
pub static API_REFUSALS_TOTAL: LazyLock<CounterVec> = LazyLock::new(|| {
    let c = CounterVec::new(
        Opts::new(
            "proxyx_control_api_refusals_total",
            "API requests refused by the request limits",
        ),
        &["reason"],
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

/// API HTTP request duration (seconds), by `route`.
pub static API_REQUEST_DURATION_SECONDS: LazyLock<HistogramVec> = LazyLock::new(|| {
    let h = HistogramVec::new(
        HistogramOpts::new(
            "proxyx_control_api_request_duration_seconds",
            "API HTTP request duration",
        )
        .buckets(vec![
            0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
        ]),
        &["route"],
    )
    .unwrap();
    REGISTRY.register(Box::new(h.clone())).unwrap();
    h
});

/// HTTP status class label: `1xx`..`5xx`. Codes outside 100..=599 map to
/// `5xx`.
pub fn status_class(status: u16) -> &'static str {
    match status {
        100..=199 => "1xx",
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        _ => "5xx",
    }
}

// ---------------------------------------------------------------------------
// Render
// ---------------------------------------------------------------------------

/// Encode all registered metrics as Prometheus text exposition format.
/// No I/O — safe to call from an HTTP handler.
///
/// Forces every metric first, so a counter that has not fired yet (for
/// example dropped captures) is still scraped as 0 and alerts can see it.
pub fn render() -> Vec<u8> {
    LazyLock::force(&PROXY_CONNECTIONS_TOTAL);
    LazyLock::force(&PROXY_REQUESTS_TOTAL);
    LazyLock::force(&PROXY_UPSTREAM_DURATION_SECONDS);
    LazyLock::force(&PROXY_CAPTURE_BUFFER_DEPTH);
    LazyLock::force(&PROXY_OVERHEAD_SECONDS);
    LazyLock::force(&PROXY_TLS_HANDSHAKE_SECONDS);
    LazyLock::force(&PROXY_CAPTURES_PUBLISHED_TOTAL);
    LazyLock::force(&PROXY_CAPTURES_DROPPED_TOTAL);
    LazyLock::force(&PROXY_UPSTREAM_BREAKER_STATE);
    LazyLock::force(&PROXY_UPSTREAM_BREAKER_TRANSITIONS_TOTAL);
    LazyLock::force(&PROXY_UPSTREAM_BREAKER_REJECTED_TOTAL);
    LazyLock::force(&PROXY_READY);
    LazyLock::force(&PROXY_READINESS_CHECK);
    LazyLock::force(&PROXY_DRAINING);
    LazyLock::force(&PROXY_CONNECTIONS_ACTIVE);
    LazyLock::force(&PROXY_CONNECTION_LIMIT_REFUSALS_TOTAL);
    LazyLock::force(&PROXY_RATELIMIT_BACKEND_ERRORS_TOTAL);
    LazyLock::force(&PROXY_RATELIMIT_FAILOPEN_TOTAL);
    // Closed label sets, so a scrape shows 0 before the first event.
    for kind in ["egress_proxy", "private_override", "origin"] {
        PROXY_UPSTREAM_BREAKER_STATE.with_label_values(&[kind]);
        PROXY_UPSTREAM_BREAKER_REJECTED_TOTAL.with_label_values(&[kind]);
        for to in ["open", "half_open", "closed"] {
            PROXY_UPSTREAM_BREAKER_TRANSITIONS_TOTAL.with_label_values(&[kind, to]);
        }
    }
    for check in ["redis", "capture_pipeline", "listeners"] {
        PROXY_READINESS_CHECK.with_label_values(&[check]);
    }
    for backend in ["redis", "limiter"] {
        PROXY_RATELIMIT_BACKEND_ERRORS_TOTAL.with_label_values(&[backend]);
        PROXY_RATELIMIT_FAILOPEN_TOTAL.with_label_values(&[backend]);
    }
    LazyLock::force(&INGESTER_MESSAGES_TOTAL);
    LazyLock::force(&INGESTER_FLUSH_DURATION_SECONDS);
    LazyLock::force(&INGESTER_ROWS_DROPPED_TOTAL);
    LazyLock::force(&INGESTER_CIRCUIT_OPEN);
    LazyLock::force(&BROKER_PUBLISH_RECORDS_TOTAL);
    LazyLock::force(&BROKER_PUBLISH_DURATION_SECONDS);
    LazyLock::force(&BROKER_CONSUMED_TOTAL);
    LazyLock::force(&BROKER_ACKS_TOTAL);
    LazyLock::force(&BROKER_RECONNECTS_TOTAL);
    LazyLock::force(&BROKER_CONNECTED);
    LazyLock::force(&INGESTER_STORE_RETRIES_TOTAL);
    LazyLock::force(&CAPTURE_COMMIT_LAG_SECONDS);
    LazyLock::force(&API_REQUESTS_TOTAL);
    LazyLock::force(&API_REQUEST_DURATION_SECONDS);
    let encoder = TextEncoder::new();
    let families = REGISTRY.gather();
    let mut buf = Vec::with_capacity(4096);
    encoder.encode(&families, &mut buf).expect("encode metrics");
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_includes_unfired_counters() {
        let out = String::from_utf8(render()).unwrap();
        assert!(
            out.lines()
                .any(|l| l.starts_with("proxyx_intercept_captures_dropped_total{")),
            "a counter that never fired must still render a sample line",
        );
    }

    #[test]
    fn status_class_maps_codes() {
        assert_eq!(status_class(101), "1xx");
        assert_eq!(status_class(204), "2xx");
        assert_eq!(status_class(304), "3xx");
        assert_eq!(status_class(404), "4xx");
        assert_eq!(status_class(503), "5xx");
        assert_eq!(status_class(999), "5xx");
    }

    #[test]
    fn render_includes_new_metric_labels() {
        PROXY_REQUESTS_TOTAL
            .with_label_values(&["https", "2xx"])
            .inc();
        PROXY_UPSTREAM_DURATION_SECONDS
            .with_label_values(&["https"])
            .observe(0.2);
        PROXY_CAPTURE_BUFFER_DEPTH.set(3);
        INGESTER_FLUSH_DURATION_SECONDS
            .with_label_values(&["ws_messages", "ok"])
            .observe(0.1);
        INGESTER_CIRCUIT_OPEN
            .with_label_values(&["ws_messages"])
            .set(1);
        API_REQUESTS_TOTAL
            .with_label_values(&["/rpc/sessions", "2xx"])
            .inc();
        API_REQUEST_DURATION_SECONDS
            .with_label_values(&["/rpc/sessions"])
            .observe(0.01);
        PROXY_OVERHEAD_SECONDS
            .with_label_values(&["http", "lock_wait"])
            .observe(0.002);
        PROXY_TLS_HANDSHAKE_SECONDS
            .with_label_values(&["client"])
            .observe(0.03);
        CAPTURE_COMMIT_LAG_SECONDS
            .with_label_values(&["http_captures"])
            .observe(1.5);

        let out = String::from_utf8(render()).unwrap();
        let has = |name: &str, labels: &[&str]| {
            out.lines().any(|l| {
                l.starts_with(&format!("{name}{{")) && labels.iter().all(|lb| l.contains(lb))
            })
        };
        assert!(has(
            "proxyx_intercept_requests_total",
            &[r#"protocol="https""#, r#"status_class="2xx""#],
        ));
        assert!(has(
            "proxyx_intercept_upstream_duration_seconds_count",
            &[r#"protocol="https""#],
        ));
        assert!(has("proxyx_intercept_capture_buffer_depth", &[]));
        assert!(has(
            "proxyx_ingester_flush_duration_seconds_count",
            &[r#"table="ws_messages""#, r#"outcome="ok""#],
        ));
        assert!(has(
            "proxyx_ingester_circuit_open",
            &[r#"table="ws_messages""#],
        ));
        assert!(has(
            "proxyx_control_api_requests_total",
            &[r#"route="/rpc/sessions""#, r#"status_class="2xx""#],
        ));
        assert!(has(
            "proxyx_control_api_request_duration_seconds_count",
            &[r#"route="/rpc/sessions""#],
        ));
        assert!(has(
            "proxyx_intercept_overhead_seconds_count",
            &[r#"protocol="http""#, r#"phase="lock_wait""#],
        ));
        assert!(has(
            "proxyx_intercept_tls_handshake_seconds_count",
            &[r#"side="client""#],
        ));
        assert!(has(
            "proxyx_capture_commit_lag_seconds_count",
            &[r#"table="http_captures""#],
        ));
    }

    #[test]
    fn render_includes_ops_metrics_before_first_event() {
        PROXY_UPSTREAM_BREAKER_TRANSITIONS_TOTAL
            .with_label_values(&["origin", "open"])
            .inc();
        PROXY_READY.set(1);
        PROXY_DRAINING.set(0);
        PROXY_CONNECTIONS_ACTIVE.set(2);

        let out = String::from_utf8(render()).unwrap();
        let has = |name: &str, labels: &[&str]| {
            out.lines().any(|l| {
                l.starts_with(&format!("{name}{{")) && labels.iter().all(|lb| l.contains(lb))
            })
        };
        for kind in ["egress_proxy", "private_override", "origin"] {
            let kind_label = format!(r#"target_kind="{kind}""#);
            assert!(has(
                "proxyx_intercept_upstream_breaker_state",
                &[&kind_label]
            ));
            assert!(has(
                "proxyx_intercept_upstream_breaker_rejected_total",
                &[&kind_label],
            ));
            for to in ["open", "half_open", "closed"] {
                let to_label = format!(r#"to="{to}""#);
                assert!(has(
                    "proxyx_intercept_upstream_breaker_transitions_total",
                    &[&kind_label, &to_label],
                ));
            }
        }
        for check in ["redis", "capture_pipeline", "listeners"] {
            let label = format!(r#"check="{check}""#);
            assert!(has("proxyx_intercept_readiness_check", &[&label]));
        }
        for backend in ["redis", "limiter"] {
            let label = format!(r#"backend="{backend}""#);
            assert!(has(
                "proxyx_intercept_ratelimit_backend_errors_total",
                &[&label]
            ));
            assert!(has("proxyx_intercept_ratelimit_failopen_total", &[&label]));
        }
        for name in [
            "proxyx_intercept_ready",
            "proxyx_intercept_draining",
            "proxyx_intercept_connections_active",
            "proxyx_intercept_connection_limit_refusals_total",
        ] {
            assert!(
                out.lines().any(|l| l.starts_with(&format!("{name}{{"))),
                "{name} missing from the exposition",
            );
        }
    }
}
