//! `assess` (pass/warn/fail findings with remediation and runbook references), the generic
//! discovery of breaker gauges, and `effective_config` (timeouts and keepalive in force).
//!
//! Everything here is read-only and works from the roles' unauthenticated ops ports and the
//! stored policies. Breakers of roles whose code this crate does not know (session-proxy
//! upstream breakers, edge parent breakers) are found by metric name, so they show up as soon
//! as a role exposes them.

use std::collections::BTreeMap;
use std::time::Duration;

use common::Cause;
use serde_json::{Value, json};

use super::Ctx;
use super::monitor::{
    self, Rates, breaker_name, by_label, capacity_rows, gather, rate_note, round,
};
use super::policy_tools::policy_set_from_listing;
use super::util::{Args, ToolError, ToolResult};
use crate::metrics::{self, Scrape, sum};

const RUNBOOKS: &str = "docs/runbooks/";

fn runbook(file: &str) -> String {
    format!("{RUNBOOKS}{file}")
}

const RB_REDIS: &str = "001-redis-down.md";
const RB_POSTGRES: &str = "002-postgres-down.md";
const RB_CACHE_LOW: &str = "003-cache-below-low-watermark.md";
const RB_BREAKER: &str = "004-provider-breaker-open.md";
const RB_BUDGET: &str = "005-provider-budget-at-90-percent.md";
const RB_RENTAL: &str = "006-static-ip-rental-ending.md";
const RB_RELOAD: &str = "007-config-reload-rejected.md";
const RB_SWEEPER: &str = "008-sweeper-reclaim-rate-rising.md";
const RB_REPLACE: &str = "009-ip-replace-requested.md";
const RB_COOLED: &str = "010-pool-cooled.md";
const RB_DROPPED: &str = "011-block-signals-dropped.md";
const RB_LEASE_LIMIT: &str = "013-lease-limit-broken.md";
const RB_OPERATIONS: &str = "docs/operations.md";

/// Share of connections (percent) answered with a server-side cause before it warns or fails.
const REFUSAL_WARN: f64 = 2.0;
const REFUSAL_FAIL: f64 = 10.0;
/// Fewest connections that make a refusal share meaningful.
const MIN_CONNECTIONS: f64 = 20.0;
/// Fewest histogram observations that make a quantile meaningful.
const MIN_OBSERVATIONS: f64 = 20.0;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Status {
    Pass,
    Warn,
    Fail,
}

impl Status {
    fn name(self) -> &'static str {
        match self {
            Status::Pass => "pass",
            Status::Warn => "warn",
            Status::Fail => "fail",
        }
    }
}

struct Findings {
    rows: Vec<(Status, Value)>,
    not_assessed: Vec<Value>,
}

impl Findings {
    #[allow(clippy::too_many_arguments)]
    fn add(
        &mut self,
        status: Status,
        area: &str,
        id: &str,
        summary: impl Into<String>,
        evidence: Value,
        remediation: &[&str],
        runbook_file: Option<&str>,
    ) {
        let runbook = runbook_file.map(|file| {
            if file.starts_with("docs/") {
                file.to_owned()
            } else {
                runbook(file)
            }
        });
        self.rows.push((
            status,
            json!({
                "status": status.name(),
                "area": area,
                "check": id,
                "summary": summary.into(),
                "evidence": evidence,
                "remediation": if status == Status::Pass { json!([]) } else { json!(remediation) },
                "runbook": if status == Status::Pass { Value::Null } else { json!(runbook) },
            }),
        ));
    }

    fn skip(&mut self, check: &str, reason: impl Into<String>) {
        self.not_assessed
            .push(json!({"check": check, "reason": reason.into()}));
    }
}

/// Counter readings: the increase over the window when a baseline exists, else the totals.
struct Counts<'a> {
    scrapes: &'a [Scrape],
    rates: Option<&'a Rates>,
}

impl Counts<'_> {
    fn basis(&self) -> &'static str {
        if self.rates.is_some() {
            "window"
        } else {
            "since_start"
        }
    }

    fn inc(&self, name: &str, filter: &[(&str, &str)]) -> f64 {
        match self.rates {
            Some(rates) => rates.delta.sum(name, filter),
            None => sum(self.scrapes, name, filter),
        }
    }

    fn by_label(&self, name: &str, label: &str) -> BTreeMap<String, f64> {
        match self.rates {
            Some(rates) => rates.delta.by_label(name, label),
            None => by_label(self.scrapes, name, label),
        }
    }

    fn present(&self, name: &str) -> bool {
        metrics::samples_of(self.scrapes, name).next().is_some()
    }
}

/// One histogram series: its labels, observations and estimated p95.
struct Series {
    labels: BTreeMap<String, String>,
    count: f64,
    p95: Option<f64>,
}

fn histogram(scrapes: &[Scrape], name: &str) -> Vec<Series> {
    type Key = BTreeMap<String, String>;
    let mut counts: BTreeMap<Key, f64> = BTreeMap::new();
    let mut buckets: BTreeMap<Key, BTreeMap<u64, (f64, f64)>> = BTreeMap::new();
    let (count_name, bucket_name) = (format!("{name}_count"), format!("{name}_bucket"));
    for scrape in scrapes {
        for sample in &scrape.samples {
            let mut key = sample.label_map();
            if sample.name == count_name {
                *counts.entry(key).or_insert(0.0) += sample.value;
            } else if sample.name == bucket_name {
                let Some(le) = key.remove("le") else { continue };
                let bound = if le == "+Inf" {
                    f64::INFINITY
                } else {
                    le.parse().unwrap_or(f64::NAN)
                };
                if bound.is_nan() {
                    continue;
                }
                buckets
                    .entry(key)
                    .or_default()
                    .entry(bound.to_bits())
                    .or_insert((bound, 0.0))
                    .1 += sample.value;
            }
        }
    }
    counts
        .into_iter()
        .map(|(labels, count)| {
            let mut ordered: Vec<(f64, f64)> = buckets
                .get(&labels)
                .map(|map| map.values().copied().collect())
                .unwrap_or_default();
            ordered.sort_by(|a, b| a.0.total_cmp(&b.0));
            Series {
                p95: metrics::quantile(&ordered, 0.95),
                labels,
                count,
            }
        })
        .collect()
}

// --- breaker discovery ----------------------------------------------------------------------------

/// Breaker series in the scrapes that are not the pool route-class families.
pub fn other_breakers(scrapes: &[Scrape]) -> Vec<Value> {
    let mut rows = Vec::new();
    for scrape in scrapes {
        for sample in &scrape.samples {
            let name = sample.name.as_str();
            if !name.contains("breaker")
                || name == "proxyx_pool_provider_breaker_state"
                || name == "proxyx_pool_breaker_skips_total"
                || name.ends_with("_bucket")
                || name.ends_with("_sum")
                || name.ends_with("_count")
            {
                continue;
            }
            let labels = sample.label_map();
            let counter = name.ends_with("_total");
            let state = if counter {
                None
            } else if name.ends_with("_open") || name.ends_with("_is_open") {
                Some(if sample.value >= 1.0 {
                    "open"
                } else {
                    "closed"
                })
            } else if name.starts_with("proxyx_intercept_") {
                // the session proxy numbers its states 0 closed, 1 open, 2 half_open
                Some(match sample.value.round() as i64 {
                    0 => "closed",
                    1 => "open",
                    _ => "half_open",
                })
            } else {
                Some(breaker_name(sample.value))
            };
            rows.push(json!({
                "role": scrape.role,
                "metric": name,
                "labels": labels,
                "kind": if counter { "counter" } else { "gauge" },
                "value": sample.value,
                "state": state,
            }));
        }
    }
    rows
}

// --- assess ---------------------------------------------------------------------------------------------

fn cause_runbook(code: &str) -> Option<&'static str> {
    match Cause::from_code(code)? {
        Cause::CacheEmpty | Cause::NoHealthyIp | Cause::LeaseTimeout => Some(RB_CACHE_LOW),
        Cause::ProviderUnavailable
        | Cause::ProviderAuth
        | Cause::ProviderTimeout
        | Cause::UpstreamError => Some(RB_BREAKER),
        Cause::CacheUnavailable => Some(RB_REDIS),
        Cause::OrgBudget => Some(RB_BUDGET),
        _ => None,
    }
}

fn health_findings(f: &mut Findings, health: &Value) {
    for row in health["roles"].as_array().into_iter().flatten() {
        let role = row["role"].as_str().unwrap_or("?");
        let verdict = row["verdict"].as_str().unwrap_or("down");
        let detail = row["ready"]["detail"]
            .as_str()
            .or(row["live"]["detail"].as_str())
            .unwrap_or("");
        let evidence = json!({"role": role, "live": row["live"], "ready": row["ready"]});
        let lower = detail.to_lowercase();
        let rb = if lower.contains("redis") {
            Some(RB_REDIS)
        } else if lower.contains("postgres") {
            Some(RB_POSTGRES)
        } else {
            None
        };
        match verdict {
            "healthy" => f.add(Status::Pass, "health", &format!("role.{role}"), format!("{role} is live and ready"), evidence, &[], None),
            "not_ready" => f.add(
                Status::Warn,
                "health",
                &format!("role.{role}"),
                format!("{role} is live but not ready{}", if detail.is_empty() { String::new() } else { format!(": {detail}") }),
                evidence,
                &["read the reason /readyz gives: starting and draining are transient, a dependency reason is not", "check every replica, not only the one behind the load balancer"],
                Some(rb.unwrap_or(RB_OPERATIONS)),
            ),
            _ => f.add(
                Status::Fail,
                "health",
                &format!("role.{role}"),
                format!("{role} is {verdict}: its liveness probe did not succeed"),
                evidence,
                &["check the process or pod, its logs and its dependencies", "confirm the role's URL in endpoints.roles"],
                Some(rb.unwrap_or(RB_OPERATIONS)),
            ),
        }
    }
}

fn dependency_findings(f: &mut Findings, c: &Counts<'_>) {
    for (metric, label, rb, what) in [
        (
            "proxyx_pool_redis_down",
            "redis",
            RB_REDIS,
            "new leases are refused with cache_unavailable; open tunnels continue",
        ),
        (
            "proxyx_pool_postgres_down",
            "postgres",
            RB_POSTGRES,
            "processes keep the last good snapshot; key lookups and control writes fail",
        ),
    ] {
        if !c.present(metric) {
            continue;
        }
        if sum(c.scrapes, metric, &[]) >= 1.0 {
            f.add(
                Status::Fail,
                "dependencies",
                label,
                format!("{label} is reported down ({metric} = 1): {what}"),
                json!({"metric": metric}),
                &[
                    "restore the datastore first",
                    "then confirm /readyz recovers on every replica",
                ],
                Some(rb),
            );
        } else {
            f.add(
                Status::Pass,
                "dependencies",
                label,
                format!("{label} is reachable"),
                json!({"metric": metric}),
                &[],
                None,
            );
        }
    }
    let failing: Vec<String> = metrics::samples_of(c.scrapes, "proxyx_pool_config_reload_failed")
        .filter(|(_, s)| s.value >= 1.0)
        .filter_map(|(_, s)| s.label("source").map(str::to_owned))
        .collect();
    if c.present("proxyx_pool_config_reload_failed") {
        if failing.is_empty() {
            f.add(
                Status::Pass,
                "config",
                "reload",
                "the last reload of every config source succeeded",
                Value::Null,
                &[],
                None,
            );
        } else {
            f.add(
                Status::Fail,
                "config",
                "reload",
                format!(
                    "the last reload failed for: {}; the previous version stays in use",
                    failing.join(", ")
                ),
                json!({"sources": failing}),
                &[
                    "read the gateway log for the file and rule that failed",
                    "fix the policy, inventory, adapter or probe-target source",
                    "validate_policy checks a policy draft without writing it",
                ],
                Some(RB_RELOAD),
            );
        }
    }
    let age = metrics::samples_of(c.scrapes, "proxyx_pool_snapshot_age_seconds")
        .map(|(_, s)| s.value)
        .fold(0.0, f64::max);
    if c.present("proxyx_pool_snapshot_age_seconds") && age > 300.0 {
        f.add(
            Status::Warn,
            "config",
            "snapshot_age",
            format!("the policy and inventory snapshot is {age:.0}s old (reload every 30s)"),
            json!({"seconds": age}),
            &["reloads are stuck: check proxyx_pool_postgres_down and the reload log"],
            Some(RB_RELOAD),
        );
    }
}

fn capacity_findings(f: &mut Findings, scrapes: &[Scrape]) {
    let capacity = capacity_rows(scrapes, None);
    if capacity.rows.is_empty() {
        f.skip(
            "capacity",
            "no cache_ready / cache_min_ready series: configure the warmer role in endpoints.roles",
        );
        return;
    }
    for row in &capacity.rows {
        let provider = row["provider"].as_str().unwrap_or("?");
        let kind = row["kind"].as_str().unwrap_or("?");
        let id = format!("{kind}.{provider}");
        let summary = format!(
            "{kind} provider {provider}: {} ready ({} degraded) against min_ready {} and low watermark {}",
            row["ready"], row["ready_degraded"], row["min_ready"], row["low_watermark"]
        );
        match row["verdict"].as_str().unwrap_or("ok") {
            "ok" => f.add(Status::Pass, "capacity", &id, summary, row.clone(), &[], None),
            "degraded_only" => f.add(Status::Warn, "capacity", &id, format!("{summary}: only degraded units are left, so leases are slow"), row.clone(), &["check the quality criteria and the probe results", "the warmer replaces degraded units; check breaker and cost state"], Some(RB_CACHE_LOW)),
            "below_min" => f.add(Status::Warn, "capacity", &id, format!("{summary}: below min_ready"), row.clone(), &["pool_capacity and breaker_states show whether the provider or the warmer is the limit", "static kind: list_inventory for cooldown, quarantined and offline IPs"], Some(RB_CACHE_LOW)),
            verdict => f.add(Status::Fail, "capacity", &id, format!("{summary}: {verdict}, the cache-low alert condition"), row.clone(), &["find lost units: breakers, cost budget, rentals, a stopped warmer", "tunnels may already be refused with cache_empty or no_healthy_ip"], Some(RB_CACHE_LOW)),
        }
        if let Some(ratio) = row["cost_used_ratio"].as_f64() {
            let (status, text) = if ratio >= 1.0 {
                (
                    Status::Fail,
                    format!(
                        "provider {provider} spent its whole cost budget: new creates are stopped"
                    ),
                )
            } else if ratio >= 0.9 {
                (
                    Status::Fail,
                    format!(
                        "provider {provider} used {:.0}% of its cost budget",
                        ratio * 100.0
                    ),
                )
            } else if ratio >= 0.8 {
                (
                    Status::Warn,
                    format!(
                        "provider {provider} used {:.0}% of its cost budget",
                        ratio * 100.0
                    ),
                )
            } else {
                (
                    Status::Pass,
                    format!(
                        "provider {provider} used {:.0}% of its cost budget",
                        ratio * 100.0
                    ),
                )
            };
            f.add(status, "budget", &format!("cost.{provider}"), text, json!({"cost_used_ratio": ratio}), &["diagnose session churn (creates, evictions) before touching the approved cost limit", "demand may simply have grown: review the policy's cost and limits"], Some(RB_BUDGET));
        }
        if let Some(days) = row["rental_days_left"].as_f64() {
            let status = if days < 3.0 {
                Status::Fail
            } else if days < 14.0 {
                Status::Warn
            } else {
                Status::Pass
            };
            f.add(
                status,
                "inventory",
                &format!("rental.{provider}"),
                format!("provider {provider}: fewest rental days left is {days:.0}"),
                json!({"days": days}),
                &[
                    "renew or replace the rentals that end first",
                    "put_inventory (capability inventory) after the new IPs exist",
                ],
                Some(RB_RENTAL),
            );
        }
    }
    let replace = sum(
        scrapes,
        "proxyx_pool_inventory_ips",
        &[("state", "replace_requested")],
    );
    if replace > 0.0 {
        f.add(
            Status::Warn,
            "inventory",
            "replace_requested",
            format!("{replace:.0} static IP(s) are in replace_requested"),
            json!({"ips": replace}),
            &[
                "inventory_replacements lists them with scores and block counts",
                "ask the provider for a replacement, then put_inventory",
            ],
            Some(RB_REPLACE),
        );
    }
}

fn breaker_findings(f: &mut Findings, c: &Counts<'_>) {
    let states = by_label(c.scrapes, "proxyx_pool_provider_breaker_state", "provider");
    for (provider, state) in &states {
        let name = breaker_name(*state);
        let status = match name {
            "open" => Status::Fail,
            "half_open" => Status::Warn,
            _ => Status::Pass,
        };
        let skips = c.inc("proxyx_pool_breaker_skips_total", &[("provider", provider)]);
        f.add(status, "breakers", &format!("pool.{provider}"), format!("pool breaker of provider {provider} is {name}"), json!({"state": name, "tunnel_skips": skips, "basis": c.basis()}), &["open: the provider cannot create sessions; tunnels use the next provider or fail with provider_unavailable", "half_open: a probe is in flight; watch whether it closes", "breaker_states shows creates by outcome"], Some(RB_BREAKER));
    }
    for row in other_breakers(c.scrapes) {
        let Some(state) = row["state"].as_str() else {
            continue;
        };
        let status = match state {
            "open" => Status::Fail,
            "half_open" => Status::Warn,
            _ => Status::Pass,
        };
        let label = row["labels"]
            .as_object()
            .map(|m| {
                m.values()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join("/")
            })
            .unwrap_or_default();
        f.add(status, "breakers", &format!("{}:{}", row["role"].as_str().unwrap_or("?"), label), format!("{} {} is {state}", row["metric"].as_str().unwrap_or(""), label), row.clone(), &["an open upstream or parent breaker stops traffic to that hop: check the hop's health and credentials", "read the role's metric documentation for the breaker's thresholds"], Some(RB_BREAKER));
    }
    if states.is_empty() && other_breakers(c.scrapes).is_empty() {
        f.skip(
            "breakers",
            "no breaker gauge was found in the scraped roles",
        );
    }
}

fn refusal_findings(f: &mut Findings, c: &Counts<'_>) {
    let by_outcome = c.by_label("proxyx_pool_connections_total", "outcome");
    if by_outcome.is_empty() {
        f.skip("refusals", "no proxyx_pool_connections_total series: configure the gateway role in endpoints.roles");
        return;
    }
    let total: f64 = by_outcome.values().sum();
    let mut server: Vec<(String, f64)> = Vec::new();
    let mut client = 0.0;
    for (outcome, count) in &by_outcome {
        if outcome == "ok" || *count <= 0.0 {
            continue;
        }
        match Cause::from_code(outcome) {
            Some(cause) if cause.status() >= 500 => server.push((outcome.clone(), *count)),
            _ => client += count,
        }
    }
    server.sort_by(|a, b| b.1.total_cmp(&a.1));
    let server_total: f64 = server.iter().map(|(_, n)| n).sum();
    let evidence = json!({"connections": total, "server_side": server, "basis": c.basis()});
    if total < MIN_CONNECTIONS {
        f.add(
            Status::Pass,
            "refusals",
            "server_side",
            format!(
                "only {total:.0} connections in the {} basis: too few to judge a refusal rate",
                c.basis()
            ),
            evidence,
            &[],
            None,
        );
    } else {
        let share = server_total / total * 100.0;
        let top = server.first().map(|(code, _)| code.clone());
        let rb = top
            .as_deref()
            .and_then(cause_runbook)
            .unwrap_or(RB_CACHE_LOW);
        let summary = format!(
            "{share:.1}% of connections were refused with a pool-side cause (503, 502, 504){}",
            top.as_deref()
                .map(|code| format!("; the main cause is {code}"))
                .unwrap_or_default()
        );
        let status = if share >= REFUSAL_FAIL {
            Status::Fail
        } else if share >= REFUSAL_WARN {
            Status::Warn
        } else {
            Status::Pass
        };
        f.add(status, "refusals", "server_side", summary, evidence, &["recent_refusals lists causes with meaning and next steps; explain_refusal explains one", "pool-side causes mean the pool could not serve: check capacity, breakers and dependencies"], Some(rb));
        let client_share = client / total * 100.0;
        let status = if client_share >= REFUSAL_FAIL {
            Status::Warn
        } else {
            Status::Pass
        };
        f.add(status, "refusals", "client_side", format!("{client_share:.1}% of connections were refused for a client-side cause (auth, options, org limits, bad requests)"), json!({"share_percent": round(client_share)}), &["explain_refusal for the dominant code", "explain_selector checks a username against the grammar and the org policy"], Some("docs/gateway.md#cause-codes"));
    }
}

fn signal_findings(f: &mut Findings, c: &Counts<'_>) {
    if !c.present("proxyx_pool_block_signals_total")
        && !c.present("proxyx_pool_block_signals_ignored_total")
    {
        f.skip("block_signals", "no block-signal series scraped");
        return;
    }
    let ignored = c.inc("proxyx_pool_block_signals_ignored_total", &[]);
    let applied: f64 = c
        .by_label("proxyx_pool_block_signals_total", "scope")
        .values()
        .sum();
    if ignored > 0.0 && ignored >= applied.max(5.0) {
        f.add(Status::Warn, "block_signals", "ignored", format!("{ignored:.0} block signals were dropped against {applied:.0} applied: clients and gateway disagree about sessions or exit IPs"), json!({"ignored": ignored, "applied": applied, "basis": c.basis()}), &["stale reports, unknown sessions and exit-IP mismatches are dropped; blocked IPs stay in leasing", "clients must send X-ProxyX-Pool-Session and X-ProxyX-Exit-IP of the same tunnel"], Some(RB_DROPPED));
    } else {
        f.add(
            Status::Pass,
            "block_signals",
            "ignored",
            format!("{ignored:.0} block signals dropped, {applied:.0} applied"),
            json!({"basis": c.basis()}),
            &[],
            None,
        );
    }
    let wide = c.inc("proxyx_pool_block_signals_total", &[("scope", "ip")])
        + c.inc(
            "proxyx_pool_block_signals_total",
            &[("scope", "pool_guard")],
        )
        + c.inc(
            "proxyx_pool_block_signals_total",
            &[("scope", "route_class")],
        );
    if wide > 0.0 {
        f.add(Status::Warn, "block_signals", "wide_scope", format!("{wide:.0} block signal(s) escalated beyond one target (ip, pool_guard or route_class)"), json!({"count": wide, "basis": c.basis()}), &["block_signal_rates shows source, type and scope", "distinguish a real block, a bad target and a provider-wide outage"], Some(RB_COOLED));
    }
}

fn pressure_findings(f: &mut Findings, c: &Counts<'_>) {
    let broken = c.inc(
        "proxyx_pool_lease_limit_broken_total",
        &[("limit", "max_conns")],
    ) + c.inc(
        "proxyx_pool_lease_limit_broken_total",
        &[("limit", "fair_use")],
    );
    if c.present("proxyx_pool_lease_limit_broken_total") {
        if broken >= 10.0 {
            f.add(
                Status::Warn,
                "capacity",
                "lease_limits",
                format!("{broken:.0} last-resort leases broke max_conns or fair_use"),
                json!({"count": broken, "basis": c.basis()}),
                &["the pool is too small for its load: add capacity or lower concurrency"],
                Some(RB_LEASE_LIMIT),
            );
        } else {
            f.add(
                Status::Pass,
                "capacity",
                "lease_limits",
                "no sustained last-resort leases",
                json!({"count": broken}),
                &[],
                None,
            );
        }
    }
    let swept = c.inc("proxyx_pool_sweeper_reclaimed_total", &[]);
    if c.present("proxyx_pool_sweeper_reclaimed_total") && c.rates.is_some() {
        if swept > 0.0 {
            f.add(Status::Warn, "state", "sweeper", format!("the sweeper reclaimed {swept:.0} abandoned item(s) in the window: something crashes or leaks"), json!({"count": swept}), &["find crashes or unfinished work behind the cleanup (by kind label)"], Some(RB_SWEEPER));
        } else {
            f.add(
                Status::Pass,
                "state",
                "sweeper",
                "the sweeper reclaimed nothing in the window",
                Value::Null,
                &[],
                None,
            );
        }
    }
    let checks = c.inc("proxyx_pool_check_failures_total", &[]);
    if checks > 0.0 {
        f.add(Status::Warn, "verification", "check_failures", format!("{checks:.0} IP-check or reputation calls failed"), json!({"by_check": c.by_label("proxyx_pool_check_failures_total", "check"), "basis": c.basis()}), &["a failing reputation scorer is skipped per on_score_unavailable; check its key and quota"], Some(RB_OPERATIONS));
    }
}

fn latency_findings(f: &mut Findings, scrapes: &[Scrape]) {
    let mut any = false;
    // (family, per-stage warn, per-stage fail, label list)
    let checks: [(&str, f64, f64, &str); 3] = [
        (
            "proxyx_pool_dial_duration_seconds",
            2.0,
            5.0,
            "provider/stage",
        ),
        (
            "proxyx_control_api_request_duration_seconds",
            1.0,
            5.0,
            "route",
        ),
        (
            "proxyx_pool_api_request_duration_seconds",
            1.0,
            5.0,
            "route",
        ),
    ];
    for (name, warn, fail, _) in checks {
        let series: Vec<Series> = histogram(scrapes, name)
            .into_iter()
            .filter(|s| s.count >= MIN_OBSERVATIONS)
            .collect();
        if series.is_empty() {
            continue;
        }
        any = true;
        let worst = series
            .iter()
            .filter(|s| {
                s.labels
                    .get("stage")
                    .is_none_or(|stage| stage != "first_byte")
            })
            .filter_map(|s| s.p95.map(|p| (p, s)))
            .max_by(|a, b| a.0.total_cmp(&b.0));
        let Some((p95, series)) = worst else { continue };
        let status = if p95 >= fail {
            Status::Fail
        } else if p95 >= warn {
            Status::Warn
        } else {
            Status::Pass
        };
        let rb = if name.contains("dial") {
            RB_BREAKER
        } else {
            RB_OPERATIONS
        };
        f.add(status, "latency", name.trim_start_matches("proxyx_"), format!("worst p95 of {name} is {p95:.2}s ({:?})", series.labels), json!({"p95_seconds": round(p95), "labels": series.labels, "observations": series.count, "basis": "since process start (cumulative histogram)"}), &["a slow handshake stage points at the provider, slow API routes at Postgres or Redis", "metrics_snapshot with this family shows every series"], Some(rb));
    }
    for (name, warn, fail) in [("proxyx_capture_commit_lag_seconds", 30.0, 300.0)] {
        let series: Vec<Series> = histogram(scrapes, name)
            .into_iter()
            .filter(|s| s.count >= MIN_OBSERVATIONS)
            .collect();
        let Some(worst) = series
            .iter()
            .filter_map(|s| s.p95.map(|p| (p, s)))
            .max_by(|a, b| a.0.total_cmp(&b.0))
        else {
            continue;
        };
        any = true;
        let status = if worst.0 >= fail {
            Status::Fail
        } else if worst.0 >= warn {
            Status::Warn
        } else {
            Status::Pass
        };
        f.add(
            status,
            "latency",
            "capture_commit_lag",
            format!("capture commit lag p95 is {:.1}s", worst.0),
            json!({"p95_seconds": round(worst.0), "labels": worst.1.labels}),
            &["captures reach ClickHouse late: check the ingester, the broker and ClickHouse"],
            Some("docs/capture-pipeline.md"),
        );
    }
    if !any {
        f.skip("latency", "no histogram has enough observations yet");
    }
}

fn pipeline_findings(f: &mut Findings, c: &Counts<'_>) {
    if c.present("proxyx_ingester_circuit_open") {
        let open: Vec<String> = metrics::samples_of(c.scrapes, "proxyx_ingester_circuit_open")
            .filter(|(_, s)| s.value >= 1.0)
            .filter_map(|(_, s)| s.label("table").map(str::to_owned))
            .collect();
        if open.is_empty() {
            f.add(
                Status::Pass,
                "capture_pipeline",
                "ingester_circuit",
                "the ingester's circuit breakers are closed",
                Value::Null,
                &[],
                None,
            );
        } else {
            f.add(
                Status::Fail,
                "capture_pipeline",
                "ingester_circuit",
                format!(
                    "the ingester's circuit is open for: {}; captures are not reaching ClickHouse",
                    open.join(", ")
                ),
                json!({"tables": open}),
                &["check ClickHouse availability and the ingester log"],
                Some("docs/capture-pipeline.md"),
            );
        }
    }
    if c.present("proxyx_intercept_captures_dropped_total") {
        let dropped = c.inc("proxyx_intercept_captures_dropped_total", &[]);
        if dropped > 0.0 {
            f.add(
                Status::Fail,
                "capture_pipeline",
                "captures_dropped",
                format!("{dropped:.0} capture(s) were lost after every publish attempt failed"),
                json!({"dropped": dropped, "basis": c.basis()}),
                &[
                    "a broker outage longer than the retry window loses captures",
                    "check the broker and proxyx_intercept_capture_buffer_depth",
                ],
                Some("docs/capture-pipeline.md"),
            );
        } else {
            f.add(
                Status::Pass,
                "capture_pipeline",
                "captures_dropped",
                "no captures were dropped",
                Value::Null,
                &[],
                None,
            );
        }
    }
    let rows = c.inc("proxyx_ingester_rows_dropped_total", &[]);
    if rows > 0.0 {
        f.add(
            Status::Warn,
            "capture_pipeline",
            "rows_dropped",
            format!("{rows:.0} row(s) were dropped from batches because writing them failed"),
            json!({"rows": rows}),
            &["inspect the ingester log for the failing rows"],
            Some("docs/capture-pipeline.md"),
        );
    }
}

pub async fn assess(ctx: &Ctx, args: &Args) -> ToolResult {
    let window = Duration::from_secs(args.u64("window_secs").unwrap_or(300));
    let include_passes = args.bool("include_passes").unwrap_or(true);
    let mut f = Findings {
        rows: Vec::new(),
        not_assessed: Vec::new(),
    };

    let health = monitor::health(ctx, &Args::default()).await?;
    health_findings(&mut f, &health);

    let mut rate_info = Value::Null;
    match gather(ctx, None, window).await {
        Ok((scrapes, errors, rates)) => {
            for error in errors {
                f.skip("metrics", format!("{}: {}", error["role"], error["error"]));
            }
            let counts = Counts {
                scrapes: &scrapes,
                rates: rates.as_ref(),
            };
            rate_info = rate_note(rates.as_ref());
            dependency_findings(&mut f, &counts);
            capacity_findings(&mut f, &scrapes);
            breaker_findings(&mut f, &counts);
            refusal_findings(&mut f, &counts);
            signal_findings(&mut f, &counts);
            pressure_findings(&mut f, &counts);
            latency_findings(&mut f, &scrapes);
            pipeline_findings(&mut f, &counts);
        }
        Err(error) => f.skip("metrics", error.message),
    }

    let worst = f
        .rows
        .iter()
        .map(|(status, _)| *status)
        .max()
        .unwrap_or(Status::Pass);
    let count = |status: Status| f.rows.iter().filter(|(s, _)| *s == status).count();
    let (fails, warns, passes) = (
        count(Status::Fail),
        count(Status::Warn),
        count(Status::Pass),
    );
    f.rows.sort_by_key(|row| std::cmp::Reverse(row.0));
    let findings: Vec<Value> = f
        .rows
        .into_iter()
        .filter(|(status, _)| include_passes || *status != Status::Pass)
        .map(|(_, value)| value)
        .collect();
    let mut runbooks: Vec<&str> = findings
        .iter()
        .filter(|finding| finding["status"] != "pass")
        .filter_map(|finding| finding["runbook"].as_str())
        .collect();
    runbooks.sort_unstable();
    runbooks.dedup();
    Ok(json!({
        "overall": worst.name(),
        "counts": {"fail": fails, "warn": warns, "pass": passes},
        "summary": match worst {
            Status::Pass => "every check that could run passed".to_owned(),
            Status::Warn => format!("{warns} warning(s) to look at"),
            Status::Fail => format!("{fails} failing check(s) need action now, {warns} warning(s)"),
        },
        "findings": findings,
        "runbooks_to_follow": runbooks,
        "not_assessed": f.not_assessed,
        "rates": rate_info,
        "note": "Thresholds: refusal share warn 2% and fail 10% of at least 20 connections; latency p95 dial warn 2s fail 5s, API warn 1s fail 5s; cost warn 80% fail 90%; rental warn 14 days fail 3 days. Histograms are cumulative since process start. Findings are evidence for a person; confirm with the named tools before changing anything.",
    }))
}

// --- effective_config -------------------------------------------------------------------------------

fn secs(duration: Duration) -> u64 {
    duration.as_secs()
}

fn builtin(name: &str, value: &str, configurable: &str, source: &str) -> Value {
    json!({"name": name, "value": value, "configurable": configurable, "source": source})
}

/// Gateway timings that are fixed in code or default-valued, from `docs/gateway.md`.
fn gateway_builtins() -> Vec<Value> {
    let g = "docs/gateway.md";
    vec![
        builtin(
            "client first byte",
            "3s",
            "no",
            &format!("{g}#pre-auth-timeouts"),
        ),
        builtin(
            "client request head or SOCKS5 negotiation",
            "10s after the first byte",
            "no",
            &format!("{g}#pre-auth-timeouts"),
        ),
        builtin(
            "client reply write without progress",
            "5s",
            "no",
            &format!("{g}#pre-auth-timeouts"),
        ),
        builtin(
            "client TCP keepalive",
            "idle 60s, 4 probes 15s apart",
            "no",
            &format!("{g}#pre-auth-timeouts"),
        ),
        builtin(
            "open budget (lease, create, exit check, dial, retries)",
            "8s",
            "no",
            &format!("{g}#the-open-pipeline"),
        ),
        builtin(
            "dial DNS stage",
            "1s",
            "no",
            &format!("{g}#dial-retries-and-the-breaker"),
        ),
        builtin(
            "dial TCP connect stage",
            "2s over all addresses",
            "no",
            &format!("{g}#dial-retries-and-the-breaker"),
        ),
        builtin(
            "dial handshake stage",
            "3s",
            "no",
            &format!("{g}#dial-retries-and-the-breaker"),
        ),
        builtin(
            "dial attempts",
            "3, waits 100ms and 200ms",
            "no",
            &format!("{g}#dial-retries-and-the-breaker"),
        ),
        builtin(
            "tunnel idle timeout",
            "10m",
            "yes: tunnel_idle_timeout (PROXYX_POOL_TUNNEL_IDLE_TIMEOUT)",
            "docs/configuration.md",
        ),
        builtin(
            "graceful drain",
            "300s",
            "yes: drain_timeout (PROXYX_POOL_DRAIN_TIMEOUT)",
            &format!("{g}#graceful-drain"),
        ),
        builtin(
            "keeper tick (counters, lease renewal, org blocks)",
            "5s",
            "no",
            &format!("{g}#relay-idle-timeout-and-the-keeper"),
        ),
        builtin(
            "session record refresh",
            "every third of its 10-minute life while a tunnel is open",
            "no",
            &format!("{g}#relay-idle-timeout-and-the-keeper"),
        ),
        builtin(
            "verified org key trusted without a lookup",
            "30s (stale entry served up to 1h)",
            "no",
            &format!("{g}#key-cache"),
        ),
        builtin(
            "policy and inventory snapshot reload",
            "30s",
            "yes: reload_every (PROXYX_POOL_RELOAD_EVERY)",
            "docs/configuration.md",
        ),
        builtin(
            "control API request",
            "15s, header read 10s, body 4 MiB",
            "no",
            &format!("{g}#conventions"),
        ),
    ]
}

pub async fn effective_config(ctx: &Ctx, args: &Args) -> ToolResult {
    let org = match args.str("org") {
        Some(_) => Some(ctx.org(args)?),
        None => None,
    };
    let provider = args.str("provider");
    let mut out = json!({
        "gateway_builtin": gateway_builtins(),
        "builtin_note": "Documented defaults and constants, not read from the running roles: a deployment can override the configurable ones through its environment, which the roles do not expose. Compare with the role's own configuration when it matters.",
        "mcp_server": {
            "backend_request_timeout_secs": ctx.cfg.limits.request_timeout_secs,
            "backend_connect_timeout_secs": 5,
            "llm_timeout_secs": ctx.cfg.llm.as_ref().map(|llm| llm.timeout_secs),
            "approval_ttl_secs": ctx.cfg.safety.approval_ttl_secs,
            "metrics_sample_interval_secs": ctx.cfg.metrics.sample_interval_secs,
            "max_session_ttl_secs": ctx.cfg.limits.max_session_ttl_secs,
            "http_max_body_bytes": ctx.cfg.http.max_body_bytes,
        },
        "policy": Value::Null,
    });
    let Some(pool) = ctx.backends.pool.as_ref() else {
        out["policy"] = json!({"available": false, "reason": "endpoints.pool is not configured, so the stored policies cannot be read"});
        return Ok(out);
    };
    let listing = pool.api.get(&["v1", "policies"], &[]).await?;
    let set = policy_set_from_listing(&listing).map_err(ToolError::internal)?;
    let provider_id = provider
        .map(|p| {
            p.parse::<common::types::ProviderId>()
                .map_err(|e| ToolError::invalid(e.to_string()))
        })
        .transpose()?;
    let effective = match org.as_deref() {
        Some(org) => {
            let id = org
                .parse::<common::types::OrgId>()
                .map_err(|e| ToolError::invalid(e.to_string()))?;
            set.effective(&id, provider_id.as_ref())
        }
        None => set.effective_default(provider_id.as_ref()),
    };
    out["policy"] = json!({
        "available": true,
        "org": org,
        "provider": provider,
        "lease": {
            "lease_ttl_secs": secs(effective.lease_ttl),
            "lease_wait_secs": secs(effective.lease_wait),
            "create_deadline_secs": secs(effective.create_deadline),
            "rest_after_release_secs": secs(effective.rest_after_release),
            "sticky_scope": format!("{:?}", effective.sticky_scope).to_lowercase(),
        },
        "rotating": {
            "keepalive_secs": secs(effective.rotating.keepalive),
            "keepalive_interval_in_force_secs": secs(effective.keepalive_interval()),
            "keepalive_interval_rule": "min(rotating.keepalive, lease_ttl / 2), so a session never idles while a lease lives",
            "ready_ttl_secs": secs(effective.rotating.ready_ttl),
            "max_age_secs": effective.rotating.max_age.map(secs),
            "max_age_rule": "unset means 80% of the provider's maximum session life",
            "min_remaining_secs": secs(effective.rotating.min_remaining),
            "recheck_every_secs": secs(effective.rotating.recheck_every),
        },
        "static": {
            "cooldown_secs": secs(effective.static_ips.cooldown),
            "retest_every_secs": secs(effective.static_ips.retest_every),
            "recheck_every_secs": secs(effective.static_ips.recheck_every),
            "replace_quarantine_for_secs": secs(effective.static_ips.replace_quarantine_for),
        },
        "block_rules": {
            "target_cooldown_secs": secs(effective.block.target_cooldown),
            "signal_window_secs": secs(effective.block.signal_window),
            "escalate_targets": effective.block.escalate_targets,
            "escalate_signals": effective.block.escalate_signals,
            "max_cooldown_share": effective.block.max_cooldown_share,
        },
        "quality_criteria": {
            "max_ttfb_ms": effective.criteria.max_ttfb_ms,
            "max_load_ms": effective.criteria.max_load_ms,
            "min_success": effective.criteria.min_success,
            "verdict_max_age_secs": secs(effective.criteria.verdict_max_age),
        },
        "limits": {
            "max_tunnels_per_org": effective.max_tunnels_per_org,
            "org_max_gb_per_day": effective.limits.org_max_gb_per_day,
        },
    });
    Ok(out)
}
