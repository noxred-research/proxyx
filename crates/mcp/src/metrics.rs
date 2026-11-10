//! Prometheus text parsing, the documented metric catalogue, summaries and counter deltas.
//!
//! The catalogue mirrors `docs/metrics/*.md`; a test parses those documents and fails when a
//! family, its type or its label names drift. Only catalogued families are summarized: they
//! are the public contract (closed label sets, never an org, host, IP or session id).

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::backend::{Backends, Role};

/// Most bytes read from one `/metrics` scrape.
pub const MAX_SCRAPE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Counter,
    Gauge,
    Histogram,
}

impl Kind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Kind::Counter => "counter",
            Kind::Gauge => "gauge",
            Kind::Histogram => "histogram",
        }
    }
}

/// One documented metric family.
#[derive(Debug, Clone, Copy)]
pub struct Family {
    pub name: &'static str,
    pub kind: Kind,
    pub labels: &'static [&'static str],
    pub summary: &'static str,
}

const fn fam(
    name: &'static str,
    kind: Kind,
    labels: &'static [&'static str],
    summary: &'static str,
) -> Family {
    Family {
        name,
        kind,
        labels,
        summary,
    }
}

use Kind::{Counter, Gauge, Histogram};

/// Every documented family of the pool gateway, warmer, session proxy, ingester and control
/// API, in document order.
pub const CATALOG: &[Family] = &[
    fam(
        "proxyx_pool_connections_total",
        Counter,
        &["listener", "outcome", "provider"],
        "Gateway connections by listener and outcome; a cause code outcome is the refusal the client saw.",
    ),
    fam(
        "proxyx_pool_auth_failures_total",
        Counter,
        &["reason"],
        "Logins refused for their key: unknown_key or source_limited.",
    ),
    fam(
        "proxyx_pool_tunnels_open",
        Gauge,
        &[],
        "Tunnels open now in this pod.",
    ),
    fam(
        "proxyx_pool_dial_duration_seconds",
        Histogram,
        &["provider", "stage"],
        "Upstream dial time per stage (dns, tcp, handshake, first_byte).",
    ),
    fam(
        "proxyx_pool_org_capacity_refusals_total",
        Counter,
        &[],
        "Tunnels refused with org_capacity.",
    ),
    fam(
        "proxyx_pool_org_budget_refusals_total",
        Counter,
        &[],
        "Tunnels refused with org_budget.",
    ),
    fam(
        "proxyx_pool_api_requests_total",
        Counter,
        &["route", "status_class"],
        "Pool control API requests by route template and status class.",
    ),
    fam(
        "proxyx_pool_api_request_duration_seconds",
        Histogram,
        &["route"],
        "Pool control API request duration by route.",
    ),
    fam(
        "proxyx_pool_cache_ready",
        Gauge,
        &["kind", "provider", "tier"],
        "Units that can be leased now, by tier (normal, degraded).",
    ),
    fam(
        "proxyx_pool_cache_min_ready",
        Gauge,
        &["kind", "provider"],
        "Effective min_ready of the provider.",
    ),
    fam(
        "proxyx_pool_cache_low_watermark",
        Gauge,
        &["kind", "provider"],
        "Level below which the provider's cache counts as low.",
    ),
    fam(
        "proxyx_pool_cache_low",
        Gauge,
        &["kind", "provider", "tier"],
        "1 when ready units stayed below the low watermark for the policy's low_for.",
    ),
    fam(
        "proxyx_pool_cache_sessions",
        Gauge,
        &["kind", "state"],
        "Rotating sessions by lifecycle state (creating, ready, leased, draining).",
    ),
    fam(
        "proxyx_pool_cache_leases_total",
        Counter,
        &["kind", "outcome", "provider"],
        "Lease attempts: hit, shared, created or the cause code of a failed walk.",
    ),
    fam(
        "proxyx_pool_lease_limit_broken_total",
        Counter,
        &["limit", "provider"],
        "Last-resort leases that broke a soft limit (rest, orgs_hard, max_conns, fair_use).",
    ),
    fam(
        "proxyx_pool_cache_evictions_total",
        Counter,
        &["cause"],
        "Why units were removed from rotation.",
    ),
    fam(
        "proxyx_pool_sweeper_reclaimed_total",
        Counter,
        &["kind"],
        "Stuck state reclaimed after a crash or a lost message.",
    ),
    fam(
        "proxyx_pool_inventory_ips",
        Gauge,
        &["provider", "state"],
        "Static IPs by state.",
    ),
    fam(
        "proxyx_pool_inventory_rental_days_left",
        Gauge,
        &["provider"],
        "Fewest rental days left among the provider's IPs.",
    ),
    fam(
        "proxyx_pool_rotate_total",
        Counter,
        &["provider", "outcome"],
        "SIM box resets by result.",
    ),
    fam(
        "proxyx_pool_replace_reports_total",
        Counter,
        &["provider"],
        "IPs the operator should ask the provider to replace.",
    ),
    fam(
        "proxyx_pool_fair_use_exceeded_total",
        Counter,
        &["provider"],
        "Static IPs that used up their monthly fair-use traffic.",
    ),
    fam(
        "proxyx_pool_block_signals_total",
        Counter,
        &["source", "type", "scope"],
        "Block signals received, with the scope they resulted in.",
    ),
    fam(
        "proxyx_pool_block_signals_ignored_total",
        Counter,
        &[],
        "Block-signal events that were dropped (stale, unknown session, other org, other exit IP).",
    ),
    fam(
        "proxyx_pool_check_failures_total",
        Counter,
        &["check"],
        "Failed calls to IP-check and reputation services.",
    ),
    fam(
        "proxyx_pool_warm_creates_total",
        Counter,
        &["provider", "outcome"],
        "Session creates tried or skipped for budget or an open breaker.",
    ),
    fam(
        "proxyx_pool_breaker_skips_total",
        Counter,
        &["provider"],
        "Route classes skipped on a tunnel request because their breaker is open.",
    ),
    fam(
        "proxyx_pool_provider_breaker_state",
        Gauge,
        &["provider"],
        "Worst breaker state of the provider's route classes: 0 closed, 1 half-open, 2 open.",
    ),
    fam(
        "proxyx_pool_cost_used_ratio",
        Gauge,
        &["provider"],
        "Share of the cost budget used in the current window, capped at 1.",
    ),
    fam(
        "proxyx_pool_redis_down",
        Gauge,
        &[],
        "1 while the last Redis ping or call failed.",
    ),
    fam(
        "proxyx_pool_postgres_down",
        Gauge,
        &[],
        "1 while the last Postgres query failed.",
    ),
    fam(
        "proxyx_pool_config_reload_failed",
        Gauge,
        &["source"],
        "1 when the last reload of that source failed and the previous version is in use.",
    ),
    fam(
        "proxyx_pool_snapshot_age_seconds",
        Gauge,
        &[],
        "Seconds since the policy and inventory snapshot was loaded.",
    ),
    fam(
        "proxyx_intercept_connections_total",
        Counter,
        &["outcome", "listener"],
        "Session proxy client connections by outcome.",
    ),
    fam(
        "proxyx_intercept_requests_total",
        Counter,
        &["protocol", "status_class"],
        "Requests the session proxy forwarded upstream.",
    ),
    fam(
        "proxyx_intercept_upstream_duration_seconds",
        Histogram,
        &["protocol"],
        "Time until the upstream response headers arrive.",
    ),
    fam(
        "proxyx_intercept_capture_buffer_depth",
        Gauge,
        &[],
        "Captures waiting in the request log writer channel.",
    ),
    fam(
        "proxyx_intercept_overhead_seconds",
        Histogram,
        &["protocol", "phase"],
        "Time the proxy itself adds to one intercepted exchange.",
    ),
    fam(
        "proxyx_intercept_tls_handshake_seconds",
        Histogram,
        &["side"],
        "Duration of intercepted TLS handshakes.",
    ),
    fam(
        "proxyx_intercept_captures_published_total",
        Counter,
        &[],
        "Captures published to the broker.",
    ),
    fam(
        "proxyx_intercept_captures_dropped_total",
        Counter,
        &[],
        "Captures lost after every publish attempt failed.",
    ),
    fam(
        "proxyx_intercept_upstream_breaker_state",
        Gauge,
        &["target_kind"],
        "Worst circuit breaker state among tracked upstream targets of a kind: 0 closed, 1 open, 2 half_open.",
    ),
    fam(
        "proxyx_intercept_upstream_breaker_transitions_total",
        Counter,
        &["target_kind", "to"],
        "Upstream breaker state changes, by the state entered.",
    ),
    fam(
        "proxyx_intercept_upstream_breaker_rejected_total",
        Counter,
        &["target_kind"],
        "Dials refused without connecting because the target's breaker was open or its probe slots were taken.",
    ),
    fam(
        "proxyx_intercept_ready",
        Gauge,
        &[],
        "1 while the session proxy's readiness answers 200.",
    ),
    fam(
        "proxyx_intercept_readiness_check",
        Gauge,
        &["check"],
        "Result of one readiness check (redis, capture_pipeline, listeners): 1 passing, 0 failing.",
    ),
    fam(
        "proxyx_intercept_draining",
        Gauge,
        &[],
        "1 from the shutdown signal until the process exits.",
    ),
    fam(
        "proxyx_intercept_connections_active",
        Gauge,
        &[],
        "Client connections holding a connection slot.",
    ),
    fam(
        "proxyx_intercept_connection_limit_refusals_total",
        Counter,
        &[],
        "Connections closed right after accept because every connection slot was taken.",
    ),
    fam(
        "proxyx_intercept_ratelimit_backend_errors_total",
        Counter,
        &["backend"],
        "Failed calls to the rate-limit backend (redis, limiter).",
    ),
    fam(
        "proxyx_intercept_ratelimit_failopen_total",
        Counter,
        &["backend"],
        "Requests admitted without a rate-limit verdict because the backend failed and the policy fails open.",
    ),
    fam(
        "proxyx_ingester_messages_total",
        Counter,
        &["outcome"],
        "Messages consumed from the captures log.",
    ),
    fam(
        "proxyx_ingester_flush_duration_seconds",
        Histogram,
        &["table", "outcome"],
        "Duration of one ClickHouse batch insert.",
    ),
    fam(
        "proxyx_ingester_rows_dropped_total",
        Counter,
        &["table"],
        "Rows dropped from a batch because writing them failed.",
    ),
    fam(
        "proxyx_ingester_store_retries_total",
        Counter,
        &["table"],
        "In-place retries of a bulk write to the capture store after a transient failure.",
    ),
    fam(
        "proxyx_broker_publish_records_total",
        Counter,
        &["broker", "outcome"],
        "Records handed to the captures log broker, by published, failed or not sent.",
    ),
    fam(
        "proxyx_broker_publish_duration_seconds",
        Histogram,
        &["broker"],
        "Duration of one batch publish to the captures log broker.",
    ),
    fam(
        "proxyx_broker_consumed_total",
        Counter,
        &["broker"],
        "Messages the ingester received from the captures log broker.",
    ),
    fam(
        "proxyx_broker_acks_total",
        Counter,
        &["broker", "outcome"],
        "Acknowledgements of captures log messages, by ok, error or rejected.",
    ),
    fam(
        "proxyx_broker_connected",
        Gauge,
        &["broker", "role"],
        "1 while the Kafka or RabbitMQ producer or consumer connection works.",
    ),
    fam(
        "proxyx_broker_reconnects_total",
        Counter,
        &["broker", "role"],
        "Broker connections that came back after a loss.",
    ),
    fam(
        "proxyx_ingester_circuit_open",
        Gauge,
        &["table"],
        "1 once consecutive flush failures open the ingester's circuit breaker.",
    ),
    fam(
        "proxyx_capture_commit_lag_seconds",
        Histogram,
        &["table"],
        "Delay from a capture completing at the proxy to its row committing.",
    ),
    fam(
        "proxyx_control_api_requests_total",
        Counter,
        &["route", "status_class"],
        "Control API requests by route template and status class.",
    ),
    fam(
        "proxyx_control_api_request_duration_seconds",
        Histogram,
        &["route"],
        "Control API request duration by route.",
    ),
    fam(
        "proxyx_control_api_refusals_total",
        Counter,
        &["reason"],
        "Control API requests refused by the request limits (rate_limited, over_capacity, timeout).",
    ),
];

/// The catalogued family named `name`.
pub fn family(name: &str) -> Option<&'static Family> {
    CATALOG.iter().find(|family| family.name == name)
}

/// One scraped series.
#[derive(Debug, Clone, PartialEq)]
pub struct Sample {
    pub name: String,
    pub labels: Vec<(String, String)>,
    pub value: f64,
}

impl Sample {
    pub fn label(&self, name: &str) -> Option<&str> {
        self.labels
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    /// The labels as a map, without the constant `service` label.
    pub fn label_map(&self) -> BTreeMap<String, String> {
        self.labels
            .iter()
            .filter(|(key, _)| key != "service")
            .cloned()
            .collect()
    }
}

/// Parse the Prometheus text exposition format. Lines that do not parse are skipped.
pub fn parse_exposition(text: &str) -> Vec<Sample> {
    text.lines().filter_map(parse_line).collect()
}

fn parse_line(line: &str) -> Option<Sample> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let (name, rest) = {
        let at = line.find(['{', ' '])?;
        line.split_at(at)
    };
    let (labels, rest) = if let Some(body) = rest.strip_prefix('{') {
        let (labels, after) = parse_labels(body)?;
        (labels, after)
    } else {
        (Vec::new(), rest)
    };
    let value_text = rest.split_whitespace().next()?;
    let value = match value_text {
        "+Inf" | "Inf" => f64::INFINITY,
        "-Inf" => f64::NEG_INFINITY,
        "NaN" => f64::NAN,
        other => other.parse().ok()?,
    };
    Some(Sample {
        name: name.to_owned(),
        labels,
        value,
    })
}

/// Parse `a="x",b="y"}` followed by the value part. Returns the labels and the text after `}`.
fn parse_labels(body: &str) -> Option<(Vec<(String, String)>, &str)> {
    let mut labels = Vec::new();
    let mut rest = body;
    loop {
        rest = rest.trim_start();
        if let Some(after) = rest.strip_prefix('}') {
            return Some((labels, after));
        }
        let eq = rest.find('=')?;
        let key = rest[..eq].trim().to_owned();
        let after = rest[eq + 1..].strip_prefix('"')?;
        let mut value = String::new();
        let mut chars = after.char_indices();
        let end = loop {
            let (at, c) = chars.next()?;
            match c {
                '\\' => match chars.next()?.1 {
                    'n' => value.push('\n'),
                    other => value.push(other),
                },
                '"' => break at + 1,
                other => value.push(other),
            }
        };
        labels.push((key, value));
        rest = after[end..].trim_start();
        if let Some(next) = rest.strip_prefix(',') {
            rest = next;
        }
    }
}

/// One scrape of one role.
#[derive(Debug, Clone)]
pub struct Scrape {
    pub role: String,
    pub samples: Vec<Sample>,
}

/// A role that could not be scraped.
#[derive(Debug, Clone)]
pub struct ScrapeError {
    pub role: String,
    pub message: String,
}

/// Scrape every role (or the named one) concurrently.
pub async fn scrape(backends: &Backends, only: Option<&str>) -> (Vec<Scrape>, Vec<ScrapeError>) {
    let mut tasks = tokio::task::JoinSet::new();
    for role in backends
        .roles
        .iter()
        .filter(|role| only.is_none_or(|name| role.name == name))
    {
        let role: Role = role.clone();
        tasks.spawn(async move {
            let reply = role.api.get_raw(role.paths.metrics, MAX_SCRAPE_BYTES).await;
            (role.name, reply)
        });
    }
    let mut scrapes = Vec::new();
    let mut errors = Vec::new();
    while let Some(joined) = tasks.join_next().await {
        let Ok((role, reply)) = joined else { continue };
        match reply {
            Ok(reply) if reply.status == 200 => scrapes.push(Scrape {
                role,
                samples: parse_exposition(&reply.text),
            }),
            Ok(reply) => errors.push(ScrapeError {
                role,
                message: format!("/metrics answered {}", reply.status),
            }),
            Err(error) => errors.push(ScrapeError {
                role,
                message: error.message,
            }),
        }
    }
    scrapes.sort_by(|a, b| a.role.cmp(&b.role));
    errors.sort_by(|a, b| a.role.cmp(&b.role));
    (scrapes, errors)
}

/// Samples of the family `name` (and, for a histogram, its `_bucket`, `_sum`, `_count`) across
/// all scrapes, tagged with the role they came from.
pub fn samples_of<'a>(
    scrapes: &'a [Scrape],
    name: &'a str,
) -> impl Iterator<Item = (&'a str, &'a Sample)> + 'a {
    scrapes.iter().flat_map(move |scrape| {
        scrape
            .samples
            .iter()
            .filter(move |sample| sample.name == name)
            .map(move |sample| (scrape.role.as_str(), sample))
    })
}

/// Sum of the samples of `name` whose labels contain every `(key, value)` of `filter`.
pub fn sum(scrapes: &[Scrape], name: &str, filter: &[(&str, &str)]) -> f64 {
    samples_of(scrapes, name)
        .filter(|(_, sample)| {
            filter
                .iter()
                .all(|(key, value)| sample.label(key) == Some(*value))
        })
        .map(|(_, sample)| sample.value)
        .sum()
}

/// Estimate quantile `q` of a histogram from its cumulative buckets.
pub fn quantile(buckets: &[(f64, f64)], q: f64) -> Option<f64> {
    let total = buckets.last()?.1;
    if total <= 0.0 {
        return None;
    }
    let target = total * q;
    let mut previous = (0.0_f64, 0.0_f64);
    for &(bound, count) in buckets {
        if count >= target {
            if bound.is_infinite() {
                return Some(previous.0);
            }
            let span = count - previous.1;
            if span <= 0.0 {
                return Some(bound);
            }
            return Some(previous.0 + (bound - previous.0) * ((target - previous.1) / span));
        }
        previous = (bound, count);
    }
    None
}

/// Summarize catalogued families found in `scrapes`.
///
/// `family_filter` keeps families whose name contains the text; `max_series` bounds each
/// family's series list (largest first).
pub fn summarize(scrapes: &[Scrape], family_filter: Option<&str>, max_series: usize) -> Vec<Value> {
    let mut out = Vec::new();
    for family in CATALOG {
        if family_filter.is_some_and(|text| !family.name.contains(text)) {
            continue;
        }
        let value = match family.kind {
            Kind::Histogram => summarize_histogram(scrapes, family, max_series),
            _ => summarize_scalar(scrapes, family, max_series),
        };
        if let Some(value) = value {
            out.push(value);
        }
    }
    out
}

fn round(value: f64) -> f64 {
    if value.is_finite() {
        (value * 1000.0).round() / 1000.0
    } else {
        value
    }
}

fn summarize_scalar(scrapes: &[Scrape], family: &Family, max_series: usize) -> Option<Value> {
    let mut grouped: BTreeMap<BTreeMap<String, String>, f64> = BTreeMap::new();
    let mut roles: Vec<&str> = Vec::new();
    for (role, sample) in samples_of(scrapes, family.name) {
        if !roles.contains(&role) {
            roles.push(role);
        }
        *grouped.entry(sample.label_map()).or_insert(0.0) += sample.value;
    }
    if grouped.is_empty() {
        return None;
    }
    let total: f64 = grouped.values().sum();
    let mut series: Vec<(BTreeMap<String, String>, f64)> = grouped.into_iter().collect();
    series.sort_by(|a, b| b.1.total_cmp(&a.1));
    let truncated = series.len() > max_series;
    series.truncate(max_series);
    Some(json!({
        "family": family.name,
        "type": family.kind.as_str(),
        "meaning": family.summary,
        "roles": roles,
        "total": round(total),
        "series": series
            .into_iter()
            .map(|(labels, value)| json!({"labels": labels, "value": round(value)}))
            .collect::<Vec<_>>(),
        "series_truncated": truncated,
    }))
}

fn summarize_histogram(scrapes: &[Scrape], family: &Family, max_series: usize) -> Option<Value> {
    type Key = BTreeMap<String, String>;
    let mut counts: BTreeMap<Key, f64> = BTreeMap::new();
    let mut sums: BTreeMap<Key, f64> = BTreeMap::new();
    let mut buckets: BTreeMap<Key, BTreeMap<u64, (f64, f64)>> = BTreeMap::new();
    let count_name = format!("{}_count", family.name);
    let sum_name = format!("{}_sum", family.name);
    let bucket_name = format!("{}_bucket", family.name);
    let mut roles: Vec<&str> = Vec::new();
    for scrape in scrapes {
        for sample in &scrape.samples {
            let mut key = sample.label_map();
            if sample.name == count_name {
                *counts.entry(key).or_insert(0.0) += sample.value;
            } else if sample.name == sum_name {
                *sums.entry(key).or_insert(0.0) += sample.value;
            } else if sample.name == bucket_name {
                let Some(le) = key.remove("le") else { continue };
                let bound = match le.as_str() {
                    "+Inf" | "Inf" => f64::INFINITY,
                    other => other.parse().unwrap_or(f64::NAN),
                };
                if bound.is_nan() {
                    continue;
                }
                let slot = buckets
                    .entry(key)
                    .or_default()
                    .entry(bound.to_bits())
                    .or_insert((bound, 0.0));
                slot.1 += sample.value;
            } else {
                continue;
            }
            if !roles.contains(&scrape.role.as_str()) {
                roles.push(scrape.role.as_str());
            }
        }
    }
    if counts.is_empty() {
        return None;
    }
    let mut series: Vec<(Key, f64)> = counts.iter().map(|(k, v)| (k.clone(), *v)).collect();
    series.sort_by(|a, b| b.1.total_cmp(&a.1));
    let truncated = series.len() > max_series;
    series.truncate(max_series);
    let total: f64 = counts.values().sum();
    let items: Vec<Value> = series
        .into_iter()
        .map(|(labels, count)| {
            let sum = sums.get(&labels).copied().unwrap_or(0.0);
            let mut ordered: Vec<(f64, f64)> = buckets
                .get(&labels)
                .map(|map| map.values().copied().collect())
                .unwrap_or_default();
            ordered.sort_by(|a, b| a.0.total_cmp(&b.0));
            json!({
                "labels": labels,
                "count": round(count),
                "mean": if count > 0.0 { json!(round(sum / count)) } else { Value::Null },
                "p50": quantile(&ordered, 0.5).map(round),
                "p95": quantile(&ordered, 0.95).map(round),
            })
        })
        .collect();
    Some(json!({
        "family": family.name,
        "type": "histogram",
        "meaning": family.summary,
        "roles": roles,
        "observations": round(total),
        "series": items,
        "series_truncated": truncated,
    }))
}

/// A series identity for delta tracking.
type SeriesKey = (String, String);

fn series_key(sample: &Sample) -> SeriesKey {
    let labels: BTreeMap<String, String> = sample.label_map();
    (
        sample.name.clone(),
        labels
            .into_iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(","),
    )
}

#[derive(Debug, Clone)]
struct Snapshot {
    at: Instant,
    counters: HashMap<SeriesKey, f64>,
}

/// What changed in counters since a baseline.
#[derive(Debug, Clone)]
pub struct Delta {
    /// Seconds between the baseline and now.
    pub seconds: f64,
    /// Increase per series. A counter that went down (a restart) counts from zero.
    pub increase: HashMap<SeriesKey, f64>,
}

impl Delta {
    /// The increase of the series of `name` whose labels contain `filter`.
    pub fn sum(&self, name: &str, filter: &[(&str, &str)]) -> f64 {
        self.increase
            .iter()
            .filter(|((series, labels), _)| {
                series == name
                    && filter.iter().all(|(key, value)| {
                        labels
                            .split(',')
                            .any(|pair| pair == format!("{key}={value}"))
                    })
            })
            .map(|(_, value)| value)
            .sum()
    }

    /// Increase per value of label `label` for series of `name`.
    pub fn by_label(&self, name: &str, label: &str) -> BTreeMap<String, f64> {
        let prefix = format!("{label}=");
        let mut out = BTreeMap::new();
        for ((series, labels), value) in &self.increase {
            if series != name {
                continue;
            }
            let key = labels
                .split(',')
                .find_map(|pair| pair.strip_prefix(&prefix))
                .unwrap_or("")
                .to_owned();
            *out.entry(key).or_insert(0.0) += value;
        }
        out
    }
}

/// Keeps the last scrapes' counters per role so a tool can report rates, not just totals.
#[derive(Debug)]
pub struct Sampler {
    capacity: usize,
    history: Mutex<HashMap<String, VecDeque<Snapshot>>>,
}

impl Sampler {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(2),
            history: Mutex::new(HashMap::new()),
        }
    }

    fn counters(samples: &[Sample]) -> HashMap<SeriesKey, f64> {
        samples
            .iter()
            .filter(|sample| {
                family(&sample.name).is_some_and(|family| family.kind == Kind::Counter)
            })
            .map(|sample| (series_key(sample), sample.value))
            .collect()
    }

    /// Remember the counters of `scrape`.
    pub fn record(&self, scrape: &Scrape) {
        let snapshot = Snapshot {
            at: Instant::now(),
            counters: Self::counters(&scrape.samples),
        };
        let mut history = self
            .history
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let queue = history.entry(scrape.role.clone()).or_default();
        queue.push_back(snapshot);
        while queue.len() > self.capacity {
            queue.pop_front();
        }
    }

    /// The change since the remembered scrape of `role` closest to `window` ago, relative to
    /// `current`. `None` when nothing older than a second is remembered.
    pub fn delta(&self, current: &Scrape, window: Duration) -> Option<Delta> {
        let history = self
            .history
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let queue = history.get(&current.role)?;
        let now = Instant::now();
        let baseline = queue
            .iter()
            .filter(|snapshot| now.duration_since(snapshot.at) >= Duration::from_secs(1))
            .min_by_key(|snapshot| {
                let age = now.duration_since(snapshot.at);
                age.abs_diff(window)
            })?;
        let now_counters = Self::counters(&current.samples);
        let mut increase = HashMap::new();
        for (key, value) in now_counters {
            let before = baseline.counters.get(&key).copied().unwrap_or(0.0);
            let change = if value >= before {
                value - before
            } else {
                value
            };
            if change > 0.0 {
                increase.insert(key, change);
            }
        }
        Some(Delta {
            seconds: now.duration_since(baseline.at).as_secs_f64(),
            increase,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"# HELP proxyx_pool_connections_total Connections
# TYPE proxyx_pool_connections_total counter
proxyx_pool_connections_total{listener="connect",outcome="ok",provider="p1",service="proxyx-gateway"} 40
proxyx_pool_connections_total{listener="connect",outcome="cache_empty",provider="none",service="proxyx-gateway"} 7
proxyx_pool_cache_ready{kind="rotating",provider="p1",tier="normal",service="proxyx-warmer"} 3
proxyx_pool_dial_duration_seconds_bucket{provider="p1",stage="tcp",le="0.1",service="x"} 5
proxyx_pool_dial_duration_seconds_bucket{provider="p1",stage="tcp",le="1",service="x"} 9
proxyx_pool_dial_duration_seconds_bucket{provider="p1",stage="tcp",le="+Inf",service="x"} 10
proxyx_pool_dial_duration_seconds_sum{provider="p1",stage="tcp",service="x"} 4.5
proxyx_pool_dial_duration_seconds_count{provider="p1",stage="tcp",service="x"} 10
weird{a="q\"uote\\n"} 1.5 1700000000
"#;

    #[test]
    fn parses_the_text_format() {
        let samples = parse_exposition(SAMPLE);
        assert_eq!(samples.len(), 9);
        assert_eq!(samples[0].label("outcome"), Some("ok"));
        assert!((samples[0].value - 40.0).abs() < f64::EPSILON);
        let weird = samples.last().expect("last sample");
        assert_eq!(weird.label("a"), Some("q\"uote\\n"));
        assert!((weird.value - 1.5).abs() < f64::EPSILON);
    }

    #[test]
    fn summarizes_scalars_and_histograms() {
        let scrapes = vec![Scrape {
            role: "gateway".into(),
            samples: parse_exposition(SAMPLE),
        }];
        let summary = summarize(&scrapes, None, 10);
        let conn = summary
            .iter()
            .find(|v| v["family"] == "proxyx_pool_connections_total")
            .expect("connections family");
        assert_eq!(conn["total"], 47.0);
        assert_eq!(conn["series"][0]["labels"]["outcome"], "ok");
        let dial = summary
            .iter()
            .find(|v| v["family"] == "proxyx_pool_dial_duration_seconds")
            .expect("dial family");
        assert_eq!(dial["series"][0]["count"], 10.0);
        let p95 = dial["series"][0]["p95"].as_f64().expect("p95");
        assert!(p95 > 0.1 && p95 <= 1.0, "p95 {p95}");
    }

    #[test]
    fn sampler_reports_counter_increase_and_restarts() {
        let sampler = Sampler::new(4);
        let first = Scrape {
            role: "gateway".into(),
            samples: parse_exposition(SAMPLE),
        };
        // an old baseline: pretend it is two seconds old by recording and sleeping
        sampler.record(&first);
        std::thread::sleep(Duration::from_millis(1100));
        let later = Scrape {
            role: "gateway".into(),
            samples: parse_exposition(&SAMPLE.replace("} 7\n", "} 12\n")),
        };
        let delta = sampler
            .delta(&later, Duration::from_secs(60))
            .expect("delta");
        assert!(delta.seconds >= 1.0);
        assert!(
            (delta.sum(
                "proxyx_pool_connections_total",
                &[("outcome", "cache_empty")]
            ) - 5.0)
                .abs()
                < 1e-9
        );
        let by = delta.by_label("proxyx_pool_connections_total", "outcome");
        assert_eq!(by.get("ok"), None);
        // a counter that went down is a restart: it counts from zero
        let restarted = Scrape {
            role: "gateway".into(),
            samples: parse_exposition(&SAMPLE.replace("} 40\n", "} 3\n")),
        };
        let delta = sampler
            .delta(&restarted, Duration::from_secs(60))
            .expect("delta");
        assert!(
            (delta.sum("proxyx_pool_connections_total", &[("outcome", "ok")]) - 3.0).abs() < 1e-9
        );
    }

    #[test]
    fn catalogue_matches_the_documents() {
        for (doc, prober_cut) in [
            (include_str!("../../../docs/metrics/pool.md"), true),
            (
                include_str!("../../../docs/metrics/session-proxy.md"),
                false,
            ),
        ] {
            let doc = if prober_cut {
                doc.split("## Prober").next().unwrap_or(doc)
            } else {
                doc
            };
            let mut documented = 0;
            for section in doc.split("\n### `").skip(1) {
                let name = section.split('`').next().expect("family name");
                let family = family(name).unwrap_or_else(|| panic!("{name} is not in CATALOG"));
                let kind = section
                    .lines()
                    .find_map(|line| line.strip_prefix("- **Type:** "))
                    .expect("type line");
                assert!(
                    kind.starts_with(family.kind.as_str()),
                    "{name}: documented {kind}, catalogued {}",
                    family.kind.as_str()
                );
                let labels_line = section
                    .lines()
                    .find_map(|line| line.strip_prefix("- **Labels:** "))
                    .expect("labels line");
                let mut documented_labels = Vec::new();
                if labels_line.trim() != "none" {
                    let mut depth = 0;
                    let mut item = String::new();
                    let mut items = Vec::new();
                    for c in labels_line.chars() {
                        match c {
                            '(' => depth += 1,
                            ')' => depth -= 1,
                            ',' if depth == 0 => {
                                items.push(std::mem::take(&mut item));
                                continue;
                            }
                            _ => {}
                        }
                        item.push(c);
                    }
                    items.push(item);
                    for item in items {
                        let label = item.trim().trim_start_matches('`');
                        documented_labels.push(label.split('`').next().expect("label").to_owned());
                    }
                }
                let catalogued: Vec<String> = family
                    .labels
                    .iter()
                    .map(|label| (*label).to_owned())
                    .collect();
                let mut expected = documented_labels.clone();
                // the documents list `requests_total` and `unmatched` as detail, not as labels
                expected.retain(|label| label != "requests_total" && label != "unmatched");
                assert_eq!(catalogued, expected, "{name}: label names differ");
                documented += 1;
            }
            assert!(documented > 10);
        }
        // and the other way: nothing is catalogued that the documents do not describe
        let documents = format!(
            "{}{}",
            include_str!("../../../docs/metrics/pool.md")
                .split("## Prober")
                .next()
                .unwrap_or(""),
            include_str!("../../../docs/metrics/session-proxy.md")
        );
        for family in CATALOG {
            assert!(
                documents.contains(&format!("### `{}`", family.name)),
                "{} is catalogued but not documented",
                family.name
            );
        }
    }
}
