//! Prometheus metrics of `proxyx edge`: `proxyx_edge_<noun>_<unit>`.
//! Labels are closed sets (configured names and fixed words): never client
//! addresses, users, hosts, session ids or egress addresses. The families are
//! documented in `docs/metrics/edge.md`, and a test keeps the two in step.

use std::collections::HashMap;

use crate::breaker::Transitions;
use prometheus::core::Collector as _;
use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGaugeVec, Opts, Registry,
    TextEncoder,
};

const NS: &str = "proxyx_edge";

/// The constant `service` label of every series, like the other roles.
const SERVICE: &str = "proxyx-edge";

/// `Content-Type` of `/metrics`.
pub const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// Activity read from existing metric series, without creating new series.
#[derive(Debug, Default, Clone, Copy, serde::Serialize)]
pub(crate) struct Activity {
    pub active: u64,
    pub total_connections: u64,
    pub failures: u64,
    pub latency_seconds: Option<f64>,
}

#[derive(Debug, Default)]
pub(crate) struct ActivitySnapshot {
    pub listeners: HashMap<String, Activity>,
    pub pools: HashMap<String, Activity>,
}

pub struct Metrics {
    registry: Registry,
    /// Client connections by listener and outcome.
    pub connections_total: IntCounterVec,
    /// Client connections open now, by listener.
    pub connections_open: IntGaugeVec,
    /// Requests (HTTP requests, CONNECT, SOCKS commands) by listener, protocol and result.
    pub requests_total: IntCounterVec,
    /// Payload bytes by listener and direction (`up` client to target, `down` target to client).
    pub bytes_total: IntCounterVec,
    /// Refused logins by listener and reason.
    pub auth_failures_total: IntCounterVec,
    /// Access rule decisions.
    pub acl_decisions_total: IntCounterVec,
    /// Requests refused because the destination is private or internal.
    pub destination_denied_total: IntCounter,
    /// Requests or connections refused by a limit.
    pub limit_rejections_total: IntCounterVec,
    /// Connections to targets by egress pool and outcome.
    pub egress_connections_total: IntCounterVec,
    /// Time to connect to a target or parent, by egress pool.
    pub connect_duration_seconds: HistogramVec,
    /// Addresses of an egress pool by state (`total`, `open`, `half_open`, `unhealthy`, `prefixes`).
    pub egress_addresses: IntGaugeVec,
    /// Requests through a parent by parent and outcome.
    pub parent_requests_total: IntCounterVec,
    /// 1 while a parent is in use, 0 while it is down.
    pub parent_up: IntGaugeVec,
    /// Name lookups by result.
    pub dns_lookups_total: IntCounterVec,
    /// Configuration reloads by result.
    pub config_reloads_total: IntCounterVec,
    /// Access log lines dropped because the writer fell behind.
    pub access_log_dropped_total: IntCounter,
    /// SOCKS5 UDP associations open now.
    pub udp_associations_open: IntGaugeVec,
    /// Circuit breaker transitions by kind (`parent`, `egress`) and the state entered.
    pub breaker_transitions_total: IntCounterVec,
    /// Breaker of each parent: 0 closed, 1 half open, 2 open.
    pub parent_breaker_state: IntGaugeVec,
    /// 1 while a parent passes its active health probes.
    pub parent_healthy: IntGaugeVec,
    /// Active health probes by kind (`parent`, `egress`) and result.
    pub health_checks_total: IntCounterVec,
    /// Requests to HTTP parents by whether an idle connection was reused.
    pub parent_conn_reuse_total: IntCounterVec,
}

fn counter_vec(r: &Registry, name: &str, help: &str, labels: &[&str]) -> IntCounterVec {
    let c = IntCounterVec::new(Opts::new(name, help).namespace(NS), labels).expect("valid metric");
    r.register(Box::new(c.clone())).expect("register metric");
    c
}

fn gauge_vec(r: &Registry, name: &str, help: &str, labels: &[&str]) -> IntGaugeVec {
    let g = IntGaugeVec::new(Opts::new(name, help).namespace(NS), labels).expect("valid metric");
    r.register(Box::new(g.clone())).expect("register metric");
    g
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    pub fn new() -> Self {
        let registry = Registry::new_custom(
            None,
            Some(std::collections::HashMap::from([(
                "service".to_owned(),
                SERVICE.to_owned(),
            )])),
        )
        .expect("valid registry");
        let r = &registry;
        let connect = HistogramVec::new(
            HistogramOpts::new(
                "connect_duration_seconds",
                "Time to connect to a target or parent, by egress pool.",
            )
            .namespace(NS)
            .buckets(vec![
                0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
            ]),
            &["pool"],
        )
        .expect("valid metric");
        r.register(Box::new(connect.clone()))
            .expect("register metric");
        let destination_denied = IntCounter::with_opts(
            Opts::new(
                "destination_denied_total",
                "Requests refused because the destination is private or internal.",
            )
            .namespace(NS),
        )
        .expect("valid metric");
        r.register(Box::new(destination_denied.clone()))
            .expect("register metric");
        let dropped = IntCounter::with_opts(
            Opts::new(
                "access_log_dropped_total",
                "Access log lines dropped because the writer fell behind.",
            )
            .namespace(NS),
        )
        .expect("valid metric");
        r.register(Box::new(dropped.clone()))
            .expect("register metric");
        Self {
            connections_total: counter_vec(
                r,
                "connections_total",
                "Client connections by listener and outcome.",
                &["listener", "outcome"],
            ),
            connections_open: gauge_vec(
                r,
                "connections_open",
                "Client connections open now.",
                &["listener"],
            ),
            requests_total: counter_vec(
                r,
                "requests_total",
                "Requests by listener, protocol and result.",
                &["listener", "protocol", "result"],
            ),
            bytes_total: counter_vec(
                r,
                "bytes_total",
                "Payload bytes by listener and direction.",
                &["listener", "direction"],
            ),
            auth_failures_total: counter_vec(
                r,
                "auth_failures_total",
                "Refused logins by listener and reason.",
                &["listener", "reason"],
            ),
            acl_decisions_total: counter_vec(
                r,
                "acl_decisions_total",
                "Access rule decisions.",
                &["action"],
            ),
            destination_denied_total: destination_denied,
            limit_rejections_total: counter_vec(
                r,
                "limit_rejections_total",
                "Requests or connections refused by a limit.",
                &["kind"],
            ),
            egress_connections_total: counter_vec(
                r,
                "egress_connections_total",
                "Connections to targets by egress pool and outcome.",
                &["pool", "outcome"],
            ),
            connect_duration_seconds: connect,
            egress_addresses: gauge_vec(
                r,
                "egress_addresses",
                "Addresses of an egress pool by state.",
                &["pool", "state"],
            ),
            parent_requests_total: counter_vec(
                r,
                "parent_requests_total",
                "Requests through a parent by parent and outcome.",
                &["parent", "outcome"],
            ),
            parent_up: gauge_vec(
                r,
                "parent_up",
                "1 while a parent is in use, 0 while it is down.",
                &["parent"],
            ),
            dns_lookups_total: counter_vec(
                r,
                "dns_lookups_total",
                "Name lookups by result.",
                &["result"],
            ),
            config_reloads_total: counter_vec(
                r,
                "config_reloads_total",
                "Configuration reloads by result.",
                &["result"],
            ),
            access_log_dropped_total: dropped,
            udp_associations_open: gauge_vec(
                r,
                "udp_associations_open",
                "SOCKS5 UDP associations open now.",
                &["listener"],
            ),
            breaker_transitions_total: counter_vec(
                r,
                "breaker_transitions_total",
                "Circuit breaker transitions by kind and the state entered.",
                &["kind", "state"],
            ),
            parent_breaker_state: gauge_vec(
                r,
                "parent_breaker_state",
                "Breaker of each parent: 0 closed, 1 half open, 2 open.",
                &["parent"],
            ),
            parent_healthy: gauge_vec(
                r,
                "parent_healthy",
                "1 while a parent passes its active health probes.",
                &["parent"],
            ),
            health_checks_total: counter_vec(
                r,
                "health_checks_total",
                "Active health probes by kind and result.",
                &["kind", "result"],
            ),
            parent_conn_reuse_total: counter_vec(
                r,
                "parent_conn_reuse_total",
                "Requests to HTTP parents by whether an idle connection was reused.",
                &["outcome"],
            ),
            registry,
        }
    }

    /// The transition counters of one kind of breaker (`parent` or `egress`).
    pub fn transitions(&self, kind: &str) -> Transitions {
        let c = |state: &str| {
            self.breaker_transitions_total
                .with_label_values(&[kind, state])
        };
        Transitions {
            closed: c("closed"),
            half_open: c("half_open"),
            open: c("open"),
        }
    }

    /// Read the same samples exposed by Prometheus. Missing series remain absent.
    pub(crate) fn activity_snapshot(&self) -> ActivitySnapshot {
        let mut snapshot = ActivitySnapshot::default();
        for family in [
            self.connections_total.collect(),
            self.connections_open.collect(),
            self.requests_total.collect(),
            self.egress_connections_total.collect(),
            self.connect_duration_seconds.collect(),
        ]
        .into_iter()
        .flatten()
        {
            let (entries, key) = match family.get_name() {
                "proxyx_edge_connections_total"
                | "proxyx_edge_connections_open"
                | "proxyx_edge_requests_total" => (&mut snapshot.listeners, "listener"),
                "proxyx_edge_egress_connections_total" | "proxyx_edge_connect_duration_seconds" => {
                    (&mut snapshot.pools, "pool")
                }
                _ => continue,
            };
            for metric in family.get_metric() {
                let label = |name| {
                    metric
                        .get_label()
                        .iter()
                        .find(|label| label.get_name() == name)
                        .map(|label| label.get_value())
                };
                let Some(name) = label(key) else {
                    continue;
                };
                let activity = entries.entry(name.to_owned()).or_default();
                let count = metric.get_counter().get_value() as u64;
                match family.get_name() {
                    "proxyx_edge_connections_total" => {
                        activity.total_connections =
                            activity.total_connections.saturating_add(count);
                        if label("outcome") != Some("accepted") {
                            activity.failures = activity.failures.saturating_add(count);
                        }
                    }
                    "proxyx_edge_connections_open" => {
                        activity.active =
                            u64::try_from(metric.get_gauge().get_value() as i64).unwrap_or(0);
                    }
                    "proxyx_edge_requests_total" => {
                        if label("result") != Some("ok") {
                            activity.failures = activity.failures.saturating_add(count);
                        }
                    }
                    "proxyx_edge_egress_connections_total" => {
                        activity.total_connections =
                            activity.total_connections.saturating_add(count);
                        if label("outcome") != Some("ok") {
                            activity.failures = activity.failures.saturating_add(count);
                        }
                    }
                    "proxyx_edge_connect_duration_seconds" => {
                        let histogram = metric.get_histogram();
                        let count = histogram.get_sample_count();
                        if count != 0 {
                            activity.latency_seconds =
                                Some(histogram.get_sample_sum() / count as f64);
                        }
                    }
                    _ => {}
                }
            }
        }
        snapshot
    }

    /// Text exposition for `/metrics`; serve it as [`CONTENT_TYPE`]. No I/O.
    pub fn render(&self) -> String {
        let mut buf = Vec::with_capacity(4096);
        TextEncoder::new()
            .encode(&self.registry.gather(), &mut buf)
            .expect("encode metrics");
        String::from_utf8(buf).expect("metrics text is UTF-8")
    }

    #[cfg(test)]
    pub(crate) fn registry(&self) -> &Registry {
        &self.registry
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;

    /// Touch every labelled family once so it shows in `gather()`.
    fn populate(m: &Metrics) {
        m.connections_total
            .with_label_values(&["l", "accepted"])
            .inc();
        m.connections_open.with_label_values(&["l"]).set(1);
        m.requests_total
            .with_label_values(&["l", "http", "ok"])
            .inc();
        m.bytes_total.with_label_values(&["l", "up"]).inc();
        m.auth_failures_total
            .with_label_values(&["l", "invalid"])
            .inc();
        m.acl_decisions_total.with_label_values(&["allow"]).inc();
        m.destination_denied_total.inc();
        m.limit_rejections_total
            .with_label_values(&["global"])
            .inc();
        m.egress_connections_total
            .with_label_values(&["p", "ok"])
            .inc();
        m.connect_duration_seconds
            .with_label_values(&["p"])
            .observe(0.1);
        m.egress_addresses.with_label_values(&["p", "total"]).set(1);
        m.parent_requests_total
            .with_label_values(&["x", "ok"])
            .inc();
        m.parent_up.with_label_values(&["x"]).set(1);
        m.dns_lookups_total.with_label_values(&["ok"]).inc();
        m.config_reloads_total.with_label_values(&["ok"]).inc();
        m.access_log_dropped_total.inc();
        m.udp_associations_open.with_label_values(&["l"]).set(1);
        m.breaker_transitions_total
            .with_label_values(&["parent", "open"])
            .inc();
        m.parent_breaker_state.with_label_values(&["x"]).set(0);
        m.parent_healthy.with_label_values(&["x"]).set(1);
        m.health_checks_total
            .with_label_values(&["parent", "ok"])
            .inc();
        m.parent_conn_reuse_total
            .with_label_values(&["reused"])
            .inc();
    }

    fn documented() -> BTreeMap<String, BTreeSet<String>> {
        let text = include_str!("../../../docs/metrics/edge.md");
        let mut docs = BTreeMap::new();
        let mut current: Option<String> = None;
        for line in text.lines() {
            if let Some(name) = line
                .strip_prefix("### `")
                .and_then(|rest| rest.strip_suffix('`'))
            {
                current = Some(name.to_owned());
                docs.insert(name.to_owned(), BTreeSet::new());
            } else if let (Some(labels), Some(name)) =
                (line.strip_prefix("- **Labels:**"), current.as_ref())
            {
                let words = labels.split('`').skip(1).step_by(2);
                docs.insert(name.clone(), words.map(str::to_owned).collect());
            }
        }
        docs
    }

    #[test]
    fn metrics_md_matches_the_registry_and_forbids_identity_labels() {
        let m = Metrics::new();
        populate(&m);
        let registered: BTreeMap<String, BTreeSet<String>> = m
            .registry()
            .gather()
            .iter()
            .map(|f| {
                let labels = f
                    .get_metric()
                    .iter()
                    .flat_map(|metric| metric.get_label())
                    .map(|p| p.get_name().to_owned())
                    .filter(|name| name != "service")
                    .collect();
                (f.get_name().to_owned(), labels)
            })
            .collect();
        let defined = include_str!("metrics.rs")
            .split("pub struct Metrics {")
            .nth(1)
            .and_then(|rest| rest.split("\n}").next())
            .unwrap_or_default()
            .matches("\n    pub ")
            .count();
        assert_eq!(registered.len(), defined, "populate() misses a family");
        assert_eq!(
            registered,
            documented(),
            "docs/metrics/edge.md and the registry differ"
        );
        for (name, labels) in &registered {
            for forbidden in [
                "user", "host", "ip", "address", "target", "session", "url", "client",
            ] {
                assert!(!labels.contains(forbidden), "{name} has label {forbidden}");
            }
        }
    }

    #[test]
    fn activity_snapshot_aggregates_existing_samples_without_registering_series() {
        let m = Metrics::new();
        m.connections_total
            .with_label_values(&["busy", "accepted"])
            .inc_by(2);
        m.connections_total
            .with_label_values(&["busy", "over_limit"])
            .inc_by(3);
        m.connections_open.with_label_values(&["busy"]).set(2);
        m.requests_total
            .with_label_values(&["busy", "http", "ok"])
            .inc_by(4);
        m.requests_total
            .with_label_values(&["busy", "socks5", "connect_error"])
            .inc_by(5);
        for (outcome, count) in [("ok", 3), ("failed", 2), ("no_address", 1)] {
            m.egress_connections_total
                .with_label_values(&["local", outcome])
                .inc_by(count);
        }
        let latency = m.connect_duration_seconds.with_label_values(&["local"]);
        latency.observe(0.1);
        latency.observe(0.3);
        let before = m.render();
        let snapshot = m.activity_snapshot();
        let listener = &snapshot.listeners["busy"];
        assert_eq!(listener.active, 2);
        assert_eq!(listener.total_connections, 5);
        assert_eq!(listener.failures, 8);
        assert!(listener.latency_seconds.is_none());
        let pool = &snapshot.pools["local"];
        assert_eq!(pool.total_connections, 6);
        assert_eq!(pool.failures, 3);
        assert!((pool.latency_seconds.unwrap_or_default() - 0.2).abs() < f64::EPSILON);
        assert_eq!(m.render(), before);
    }

    #[test]
    fn render_is_prometheus_text() {
        let m = Metrics::new();
        populate(&m);
        let text = m.render();
        assert!(
            text.contains("proxyx_edge_connections_total{listener=\"l\",outcome=\"accepted\",service=\"proxyx-edge\"} 1")
        );
        assert!(text.contains("# TYPE proxyx_edge_connect_duration_seconds histogram"));
    }
}
