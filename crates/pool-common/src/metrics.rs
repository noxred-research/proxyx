//! Prometheus metrics. Names follow `proxyx_pool_<noun>_<unit>`.
//! Labels are closed sets: never org, host, IP or session id.

use std::collections::{BTreeSet, HashMap};

use prometheus::core::Collector;
use prometheus::{
    Encoder, Gauge, GaugeVec, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge,
    IntGaugeVec, Opts, Registry, TextEncoder,
};

const NS: &str = "proxyx_pool";

/// `Content-Type` of the `/metrics` response.
pub const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// Every metric family ProxyX exports. Build once per process and share
/// behind an `Arc`.
pub struct Metrics {
    registry: Registry,
    /// Tunnels by listener (`connect`, `socks`, `probe`), outcome (`ok` or a
    /// cause code) and the provider that served them (`none` when none did).
    pub connections_total: IntCounterVec,
    /// Logins refused because the org key is unknown (`unknown_key`), or
    /// because the source caused too many unknown-key lookups
    /// (`source_limited`, ).
    pub auth_failures_total: IntCounterVec,
    /// Open tunnels now.
    pub tunnels_open: IntGauge,
    /// Upstream dial time by provider and stage (`dns`, `tcp`, `handshake`, `first_byte`).
    pub dial_duration_seconds: HistogramVec,
    /// Refusals because of `max_tunnels_per_org`.
    pub org_capacity_refusals_total: IntCounter,
    /// Refusals because of `limits.org_max_gb_per_day`.
    pub org_budget_refusals_total: IntCounter,
    /// Leasable units per kind, provider and tier (`normal`, `degraded`).
    pub cache_ready: IntGaugeVec,
    /// Effective `min_ready` per kind and provider, for the low-watermark alert.
    pub cache_min_ready: IntGaugeVec,
    /// Effective `capacity.low_watermark` per kind and provider, for the cache-low alert.
    pub cache_low_watermark: IntGaugeVec,
    /// 1 when the leasable units have been below the low watermark for the
    /// policy's `low_for`, per kind, provider and tier: `all` counts both
    /// tiers (the cache-low alert fires on it), `normal` the normal tier alone.
    pub cache_low: IntGaugeVec,
    /// Rotating sessions by kind and state.
    pub cache_sessions: IntGaugeVec,
    /// Lease attempts by kind, outcome (`hit`, `shared`, `created`, or a cause
    /// code) and the provider that served the tunnel (`none` for a failed walk).
    pub cache_leases_total: IntCounterVec,
    /// Leases that broke a soft limit (`rest`, `orgs_hard`, `max_conns`,
    /// `fair_use`) because no unit was left within the limits, by provider.
    pub lease_limit_broken_total: IntCounterVec,
    /// Evictions by cause (`ready_ttl`, `max_age`, `keepalive`, `ip_changed`,
    /// `stability`, `reputation`, `quality`, `block`, `duplicate`, `retired`).
    pub cache_evictions_total: IntCounterVec,
    /// Static IPs by provider and state.
    pub inventory_ips: IntGaugeVec,
    /// Smallest number of rental days left per provider.
    pub inventory_rental_days_left: GaugeVec,
    /// SIM box resets by provider and outcome (`changed`, `unchanged`, `timeout`, `error`).
    pub rotate_total: IntCounterVec,
    /// Block signals by source, type and resulting scope (`target`, `ip`, `pool_guard`, `route_class`).
    pub block_signals_total: IntCounterVec,
    /// Events of a session proxy block-signal batch that were not applied (too old,
    /// unknown session, session of another org, or another exit IP).
    pub block_signals_ignored_total: IntCounter,
    /// Warmer and on-demand session creates by provider and outcome (`ok`,
    /// `failed`, `budget`, `breaker`).
    pub warm_creates_total: IntCounterVec,
    /// Route classes the gateway skipped on a tunnel request because their
    /// breaker is open, per provider. The request goes on to the next
    /// partition.
    pub breaker_skips_total: IntCounterVec,
    /// Breaker per provider: 0 closed, 1 half-open, 2 open.
    pub provider_breaker_state: IntGaugeVec,
    /// Stuck state the sweeper reclaimed, by kind (`session`, `reservation`, `lease`).
    pub sweeper_reclaimed_total: IntCounterVec,
    /// 1 when the last reload of a source (`policies`, `inventory`, `adapters`, `probe_targets`) failed.
    pub config_reload_failed: IntGaugeVec,
    /// Share of the cost budget used in the current window, per provider,
    /// never above 1. Set it through [`Metrics::set_cost_used_ratio`].
    pub cost_used_ratio: GaugeVec,
    /// Replacement report events emitted, per provider.
    pub replace_reports_total: IntCounterVec,
    /// Static IPs that reached `fair_use_gb_per_ip_month` (stopped for new
    /// leases until the month resets), per provider.
    pub fair_use_exceeded_total: IntCounterVec,
    /// Failed calls to IP-check and reputation services, by `check` (the
    /// service name; not `service`, which is the constant process label).
    pub check_failures_total: IntCounterVec,
    /// 1 while the last Redis ping failed.
    pub redis_down: IntGauge,
    /// 1 while the last Postgres query failed.
    pub postgres_down: IntGauge,
    /// Seconds since the policy and inventory snapshot was loaded.
    pub snapshot_age_seconds: Gauge,
    /// Control API requests by `route` (matched template, or `unmatched`) and
    /// `status_class` (`1xx` to `5xx`, `other`).
    pub api_requests_total: IntCounterVec,
    /// Control API request duration by `route`.
    pub api_request_duration_seconds: HistogramVec,
}

fn opts(name: &str, help: &str) -> Opts {
    Opts::new(name, help).namespace(NS)
}

fn reg<M: Collector + Clone + 'static>(r: &Registry, metric: prometheus::Result<M>) -> M {
    let m = metric.expect("static metric definition is valid");
    r.register(Box::new(m.clone()))
        .expect("metric names are unique");
    m
}

fn counter(r: &Registry, name: &str, help: &str) -> IntCounter {
    reg(r, IntCounter::with_opts(opts(name, help)))
}

fn int_gauge(r: &Registry, name: &str, help: &str) -> IntGauge {
    reg(r, IntGauge::with_opts(opts(name, help)))
}

fn gauge(r: &Registry, name: &str, help: &str) -> Gauge {
    reg(r, Gauge::with_opts(opts(name, help)))
}

fn starting_down(gauge: IntGauge) -> IntGauge {
    gauge.set(1);
    gauge
}

fn counter_vec(r: &Registry, name: &str, help: &str, labels: &[&str]) -> IntCounterVec {
    reg(r, IntCounterVec::new(opts(name, help), labels))
}

fn int_gauge_vec(r: &Registry, name: &str, help: &str, labels: &[&str]) -> IntGaugeVec {
    reg(r, IntGaugeVec::new(opts(name, help), labels))
}

fn gauge_vec(r: &Registry, name: &str, help: &str, labels: &[&str]) -> GaugeVec {
    reg(r, GaugeVec::new(opts(name, help), labels))
}

fn histogram_vec(
    r: &Registry,
    name: &str,
    help: &str,
    buckets: Vec<f64>,
    labels: &[&str],
) -> HistogramVec {
    let opts = HistogramOpts::new(name, help)
        .namespace(NS)
        .buckets(buckets);
    reg(r, HistogramVec::new(opts, labels))
}

impl Metrics {
    /// Build and register every family. Every series carries the constant
    /// label `service` (the process role, from `SERVICE_NAME` in `main`).
    pub fn new(service: &str) -> Self {
        let r = Registry::new_custom(
            None,
            Some(HashMap::from([("service".to_owned(), service.to_owned())])),
        )
        .expect("static registry definition is valid");
        let kind_provider = &["kind", "provider"];
        let kind_provider_tier = &["kind", "provider", "tier"];
        Self {
            connections_total: counter_vec(
                &r,
                "connections_total",
                "Tunnels by listener, outcome and provider",
                &["listener", "outcome", "provider"],
            ),
            auth_failures_total: counter_vec(
                &r,
                "auth_failures_total",
                "Org key logins refused as wrong key or by the per-source limit",
                &["reason"],
            ),
            tunnels_open: int_gauge(&r, "tunnels_open", "Open tunnels"),
            dial_duration_seconds: histogram_vec(
                &r,
                "dial_duration_seconds",
                "Upstream dial time by stage",
                vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 4.0, 8.0],
                &["provider", "stage"],
            ),
            org_capacity_refusals_total: counter(
                &r,
                "org_capacity_refusals_total",
                "Tunnels refused by max_tunnels_per_org",
            ),
            org_budget_refusals_total: counter(
                &r,
                "org_budget_refusals_total",
                "Tunnels refused by limits.org_max_gb_per_day",
            ),
            cache_ready: int_gauge_vec(
                &r,
                "cache_ready",
                "Leasable units by tier",
                kind_provider_tier,
            ),
            cache_min_ready: int_gauge_vec(
                &r,
                "cache_min_ready",
                "Effective min_ready",
                kind_provider,
            ),
            cache_low_watermark: int_gauge_vec(
                &r,
                "cache_low_watermark",
                "Effective low_watermark",
                kind_provider,
            ),
            cache_low: int_gauge_vec(
                &r,
                "cache_low",
                "1 when ready stayed below low_watermark for low_for",
                kind_provider_tier,
            ),
            cache_sessions: int_gauge_vec(
                &r,
                "cache_sessions",
                "Rotating sessions by state",
                &["kind", "state"],
            ),
            cache_leases_total: counter_vec(
                &r,
                "cache_leases_total",
                "Lease attempts by outcome and provider",
                &["kind", "outcome", "provider"],
            ),
            lease_limit_broken_total: counter_vec(
                &r,
                "lease_limit_broken_total",
                "Leases that broke a soft limit because no unit was left within the limits",
                &["limit", "provider"],
            ),
            cache_evictions_total: counter_vec(
                &r,
                "cache_evictions_total",
                "Evictions by cause",
                &["cause"],
            ),
            inventory_ips: int_gauge_vec(
                &r,
                "inventory_ips",
                "Static IPs by state",
                &["provider", "state"],
            ),
            inventory_rental_days_left: gauge_vec(
                &r,
                "inventory_rental_days_left",
                "Fewest rental days left",
                &["provider"],
            ),
            rotate_total: counter_vec(
                &r,
                "rotate_total",
                "SIM box resets by outcome",
                &["provider", "outcome"],
            ),
            block_signals_total: counter_vec(
                &r,
                "block_signals_total",
                "Block signals by source, type and scope",
                &["source", "type", "scope"],
            ),
            block_signals_ignored_total: counter(
                &r,
                "block_signals_ignored_total",
                "the session proxy block-signal events that were not applied",
            ),
            warm_creates_total: counter_vec(
                &r,
                "warm_creates_total",
                "Warmer creates by outcome",
                &["provider", "outcome"],
            ),
            breaker_skips_total: counter_vec(
                &r,
                "breaker_skips_total",
                "Route classes skipped for an open breaker",
                &["provider"],
            ),
            provider_breaker_state: int_gauge_vec(
                &r,
                "provider_breaker_state",
                "0 closed, 1 half-open, 2 open",
                &["provider"],
            ),
            sweeper_reclaimed_total: counter_vec(
                &r,
                "sweeper_reclaimed_total",
                "Stuck state reclaimed",
                &["kind"],
            ),
            config_reload_failed: int_gauge_vec(
                &r,
                "config_reload_failed",
                "1 when the last reload failed",
                &["source"],
            ),
            cost_used_ratio: gauge_vec(
                &r,
                "cost_used_ratio",
                "Share of the cost budget used",
                &["provider"],
            ),
            replace_reports_total: counter_vec(
                &r,
                "replace_reports_total",
                "Replacement report events",
                &["provider"],
            ),
            fair_use_exceeded_total: counter_vec(
                &r,
                "fair_use_exceeded_total",
                "Static IPs that reached their monthly fair-use traffic",
                &["provider"],
            ),
            check_failures_total: counter_vec(
                &r,
                "check_failures_total",
                "Failed check-service calls",
                &["check"],
            ),
            // 1 until the first successful call: a pod that starts while
            // Redis or Postgres is down must read as down, not as healthy.
            redis_down: starting_down(int_gauge(&r, "redis_down", "1 while Redis fails")),
            postgres_down: starting_down(int_gauge(&r, "postgres_down", "1 while Postgres fails")),
            snapshot_age_seconds: gauge(&r, "snapshot_age_seconds", "Age of the loaded snapshot"),
            api_requests_total: counter_vec(
                &r,
                "api_requests_total",
                "Control API requests handled",
                &["route", "status_class"],
            ),
            api_request_duration_seconds: histogram_vec(
                &r,
                "api_request_duration_seconds",
                "Control API request duration",
                vec![
                    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
                ],
                &["route"],
            ),
            registry: r,
        }
    }

    /// Text exposition for `/metrics`; serve it as [`CONTENT_TYPE`]. No I/O.
    /// An encode failure is a bug: it must not scrape as a healthy empty body.
    pub fn render(&self) -> String {
        let mut buf = Vec::with_capacity(4096);
        TextEncoder::new()
            .encode(&self.registry.gather(), &mut buf)
            .expect("encode metrics");
        String::from_utf8(buf).expect("metrics text is UTF-8")
    }

    /// Set `cost_used_ratio` of `provider`: the meter's ratio capped at 1
    /// (a window that spent past its limit is still "all used", and the
    /// docs and runbook 054 promise a value of at most 1).
    pub fn set_cost_used_ratio(&self, provider: &str, ratio: f64) {
        self.cost_used_ratio
            .with_label_values(&[provider])
            .set(ratio.clamp(0.0, 1.0));
    }

    /// Remove the `provider_breaker_state` and `cost_used_ratio` series of
    /// providers that are not in `breakers` / `costs` any more: a provider
    /// that left the policy or the inventory must not keep its last value (an
    /// open breaker or a spent budget would keep alerting).
    pub fn forget_providers(&self, breakers: &BTreeSet<String>, costs: &BTreeSet<String>) {
        for provider in providers_of(&self.provider_breaker_state) {
            if !breakers.contains(&provider) {
                let _ = self
                    .provider_breaker_state
                    .remove_label_values(&[provider.as_str()]);
            }
        }
        for provider in providers_of(&self.cost_used_ratio) {
            if !costs.contains(&provider) {
                let _ = self
                    .cost_used_ratio
                    .remove_label_values(&[provider.as_str()]);
            }
        }
    }
}

/// The `provider` label values of the series a metric vector holds now.
fn providers_of(vec: &dyn Collector) -> Vec<String> {
    vec.collect()
        .iter()
        .flat_map(|family| family.get_metric())
        .filter_map(|metric| {
            metric
                .get_label()
                .iter()
                .find(|label| label.get_name() == "provider")
                .map(|label| label.get_value().to_owned())
        })
        .collect()
}

/// Label of `api_requests_total`: `1xx` to `5xx`, `other` for a code outside
/// 100..=599.
pub fn status_class(status: u16) -> &'static str {
    match status {
        100..=199 => "1xx",
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        500..=599 => "5xx",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::{Metrics, status_class};

    #[test]
    fn every_series_carries_the_service_label() {
        let m = Metrics::new("gateway");
        m.connections_total
            .with_label_values(&["connect", "ok", "p"])
            .inc();
        let text = m.render();
        assert!(
            text.contains(
                "proxyx_pool_connections_total{listener=\"connect\",outcome=\"ok\",provider=\"p\",service=\"gateway\"} 1"
            ),
            "{text}"
        );
        assert!(
            text.contains("proxyx_pool_tunnels_open{service=\"gateway\"} 0"),
            "{text}"
        );
    }

    #[test]
    fn no_family_labels_collide_with_the_service_label() {
        let m = Metrics::new("warmer");
        m.check_failures_total
            .with_label_values(&["fraud_score"])
            .inc();
        let text = m.render();
        let line = text
            .lines()
            .find(|l| l.starts_with("proxyx_pool_check_failures_total{"))
            .expect("sample line");
        assert_eq!(line.matches("service=").count(), 1, "{line}");
    }

    /// Touch one series of every family so the registry reports it.
    fn populate(m: &Metrics) {
        m.org_budget_refusals_total.inc();
        m.auth_failures_total
            .with_label_values(&["unknown_key"])
            .inc();
        m.connections_total
            .with_label_values(&["connect", "ok", "p"])
            .inc();
        m.dial_duration_seconds
            .with_label_values(&["p", "tcp"])
            .observe(0.1);
        m.cache_ready
            .with_label_values(&["static", "p", "normal"])
            .set(1);
        m.cache_min_ready.with_label_values(&["static", "p"]).set(1);
        m.cache_low_watermark
            .with_label_values(&["static", "p"])
            .set(1);
        m.cache_low
            .with_label_values(&["static", "p", "all"])
            .set(1);
        m.cache_sessions
            .with_label_values(&["rotating", "ready"])
            .set(1);
        m.cache_leases_total
            .with_label_values(&["static", "hit", "p"])
            .inc();
        m.lease_limit_broken_total
            .with_label_values(&["rest", "p"])
            .inc();
        m.cache_evictions_total.with_label_values(&["block"]).inc();
        m.inventory_ips
            .with_label_values(&["p", "available"])
            .set(1);
        m.inventory_rental_days_left
            .with_label_values(&["p"])
            .set(1.0);
        m.rotate_total.with_label_values(&["p", "changed"]).inc();
        m.block_signals_total
            .with_label_values(&["probe", "forbidden", "ip"])
            .inc();
        m.block_signals_ignored_total.inc();
        m.warm_creates_total.with_label_values(&["p", "ok"]).inc();
        m.breaker_skips_total.with_label_values(&["p"]).inc();
        m.provider_breaker_state.with_label_values(&["p"]).set(0);
        m.sweeper_reclaimed_total
            .with_label_values(&["lease"])
            .inc();
        m.config_reload_failed
            .with_label_values(&["policies"])
            .set(0);
        m.set_cost_used_ratio("p", 0.5);
        m.replace_reports_total.with_label_values(&["p"]).inc();
        m.fair_use_exceeded_total.with_label_values(&["p"]).inc();
        m.check_failures_total
            .with_label_values(&["fraud_score"])
            .inc();
        m.api_requests_total
            .with_label_values(&["/v1/orgs", "2xx"])
            .inc();
        m.api_request_duration_seconds
            .with_label_values(&["/v1/orgs"])
            .observe(0.01);
    }
    #[test]
    fn cost_used_ratio_is_capped_at_one() {
        let m = Metrics::new("warmer");
        for (given, shown) in [(0.25, 0.25), (1.0, 1.0), (31.9, 1.0), (-0.1, 0.0)] {
            m.set_cost_used_ratio("p", given);
            let got = m.cost_used_ratio.with_label_values(&["p"]).get();
            assert!((got - shown).abs() < 1e-9, "{given} shown as {got}");
        }
    }

    #[test]
    fn status_class_groups_codes_and_names_anything_else_other() {
        for (status, class) in [
            (100, "1xx"),
            (204, "2xx"),
            (302, "3xx"),
            (404, "4xx"),
            (599, "5xx"),
            (99, "other"),
            (600, "other"),
            (0, "other"),
        ] {
            assert_eq!(status_class(status), class, "{status}");
        }
    }

    /// Documented families of `METRICS.md`: name -> label names from the
    /// backticked words of the `**Labels:**` line. The `## Prober` section at
    /// the end describes another process (Python) and is not in this registry.
    fn documented() -> BTreeMap<String, BTreeSet<String>> {
        let mut docs = BTreeMap::new();
        let mut current = None;
        for line in include_str!("../../../docs/metrics/pool.md")
            .lines()
            .take_while(|line| !line.starts_with("## Prober"))
        {
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
    fn metrics_md_matches_the_registered_families_and_forbids_identity_labels() {
        let m = Metrics::new("gateway");
        populate(&m);
        let registered: BTreeMap<String, BTreeSet<String>> = m
            .registry
            .gather()
            .iter()
            .map(|family| {
                let labels = family
                    .get_metric()
                    .iter()
                    .flat_map(|metric| metric.get_label())
                    .map(|pair| pair.get_name().to_owned())
                    .filter(|name| name != "service")
                    .collect();
                (family.get_name().to_owned(), labels)
            })
            .collect();

        // Guards `populate`: a new family must be touched there to be checked.
        let defined = include_str!("metrics.rs")
            .split("pub struct Metrics {")
            .nth(1)
            .and_then(|rest| rest.split("\n}").next())
            .unwrap_or_default()
            .matches("\n    pub ")
            .count();
        assert_eq!(registered.len(), defined, "populate() misses a family");

        let documented = documented();
        assert_eq!(
            registered, documented,
            "METRICS.md and the registry differ (name or labels)"
        );
        for (name, labels) in &registered {
            for forbidden in ["org", "host", "ip", "target", "session", "url"] {
                assert!(!labels.contains(forbidden), "{name} has label {forbidden}");
            }
        }
    }
}
