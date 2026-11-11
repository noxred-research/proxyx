//! Monitoring tools: health, metrics summaries, capacity, breakers, block signals, refusals and
//! the evidence-gathering `diagnose`.
//!
//! All of them read the roles' unauthenticated ops ports (`/healthz`, `/readyz`, `/metrics`),
//! so they work with nothing but role URLs configured. Rates come from the background sampler's
//! counter history: a counter's total says little about now, its increase over a window does.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use common::Cause;
use serde_json::{Value, json};

use super::Ctx;
use super::util::{Args, ToolError, ToolResult};
use crate::explain::{self, CodeSource};
use crate::metrics::{self, Delta, Scrape, sum};

pub(super) fn round(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

/// Scrape the roles (or one), refresh the sampler and return the scrapes with rates ready.
pub(super) async fn gather(
    ctx: &Ctx,
    role: Option<&str>,
    window: Duration,
) -> Result<(Vec<Scrape>, Vec<Value>, Option<Rates>), ToolError> {
    if let Some(name) = role
        && ctx.backends.role_named(name).is_none()
    {
        let known: Vec<&str> = ctx.backends.roles.iter().map(|r| r.name.as_str()).collect();
        return Err(ToolError::invalid(format!(
            "no role named {name:?}; configured roles: {known:?}"
        )));
    }
    let (scrapes, errors) = metrics::scrape(&ctx.backends, role).await;
    let errors: Vec<Value> = errors
        .into_iter()
        .map(|error| json!({"role": error.role, "error": error.message}))
        .collect();
    if scrapes.is_empty() {
        return Err(ToolError::new(
            super::util::FailKind::Backend,
            format!("no role answered /metrics: {errors:?}"),
        ));
    }
    let deltas: Vec<Delta> = scrapes
        .iter()
        .filter_map(|scrape| ctx.sampler.delta(scrape, window))
        .collect();
    for scrape in &scrapes {
        ctx.sampler.record(scrape);
    }
    let rates = Rates::merge(deltas);
    Ok((scrapes, errors, rates))
}

/// Counter increases merged across roles.
pub(super) struct Rates {
    pub(super) seconds: f64,
    pub(super) delta: Delta,
}

impl Rates {
    fn merge(deltas: Vec<Delta>) -> Option<Self> {
        if deltas.is_empty() {
            return None;
        }
        let seconds = deltas.iter().map(|d| d.seconds).sum::<f64>() / deltas.len() as f64;
        let mut increase = std::collections::HashMap::new();
        for delta in deltas {
            for (key, value) in delta.increase {
                *increase.entry(key).or_insert(0.0) += value;
            }
        }
        Some(Self {
            seconds,
            delta: Delta { seconds, increase },
        })
    }

    pub(super) fn per_min(&self, increase: f64) -> f64 {
        round(increase / self.seconds.max(1.0) * 60.0)
    }
}

pub(super) fn rate_note(rates: Option<&Rates>) -> Value {
    match rates {
        Some(rates) => json!({"window_secs": rates.seconds.round()}),
        None => json!({
            "window_secs": null,
            "note": "no earlier scrape is remembered yet, so only totals are shown; call again in a while (the server scrapes in the background every metrics.sample_interval_secs)",
        }),
    }
}

// --- health -----------------------------------------------------------------------------------

pub async fn health(ctx: &Ctx, args: &Args) -> ToolResult {
    let filter = args.str("role");
    let roles: Vec<_> = ctx
        .backends
        .roles
        .iter()
        .filter(|role| filter.is_none_or(|name| role.name == name))
        .cloned()
        .collect();
    if roles.is_empty() {
        return Err(ToolError::invalid(format!(
            "no role named {filter:?} is configured"
        )));
    }
    let mut tasks = tokio::task::JoinSet::new();
    for role in roles {
        tasks.spawn(async move {
            let live = probe(&role, role.paths.live).await;
            let ready = match role.paths.ready {
                Some(path) => Some(probe(&role, path).await),
                None => None,
            };
            (role.name.clone(), role.kind, live, ready)
        });
    }
    let mut rows = Vec::new();
    while let Some(joined) = tasks.join_next().await {
        let Ok((name, kind, live, ready)) = joined else {
            continue;
        };
        let live_ok = live["ok"] == true;
        let ready_ok = ready.as_ref().is_none_or(|probe| probe["ok"] == true);
        let verdict = match (live_ok, ready_ok) {
            (true, true) => "healthy",
            (true, false) => "not_ready",
            (false, _) if live["status"].is_null() => "down",
            (false, _) => "unhealthy",
        };
        rows.push(json!({
            "role": name,
            "kind": kind,
            "verdict": verdict,
            "live": live,
            "ready": ready,
        }));
    }
    rows.sort_by(|a, b| a["role"].as_str().cmp(&b["role"].as_str()));
    let overall = if rows.iter().all(|row| row["verdict"] == "healthy") {
        "ok"
    } else if rows
        .iter()
        .any(|row| row["verdict"] == "down" || row["verdict"] == "unhealthy")
    {
        "down"
    } else {
        "degraded"
    };
    Ok(json!({
        "overall": overall,
        "roles": rows,
        "hint": if overall == "ok" { Value::Null } else {
            json!("A role that is not_ready answers /readyz with its reason (starting, draining, redis unavailable). Use explain_refusal on the cause codes clients see, and recent_refusals for what is failing now.")
        },
    }))
}

async fn probe(role: &crate::backend::Role, path: &str) -> Value {
    match role.api.get_raw(path, 4096).await {
        Ok(reply) => {
            let ok = reply.status == 200;
            let body: String = reply.text.trim().chars().take(120).collect();
            json!({
                "path": path,
                "ok": ok,
                "status": reply.status,
                "latency_ms": u64::try_from(reply.elapsed.as_millis()).unwrap_or(u64::MAX),
                "detail": if ok || body.is_empty() { Value::Null } else { json!(body) },
            })
        }
        Err(error) => json!({"path": path, "ok": false, "status": null, "error": error.message}),
    }
}

// --- metrics ----------------------------------------------------------------------------------

pub async fn metrics_snapshot(ctx: &Ctx, args: &Args) -> ToolResult {
    let (scrapes, errors, _) = gather(ctx, args.str("role"), Duration::from_secs(300)).await?;
    let max_series = ctx.rows(args.u64("max_series").or(Some(20)));
    let families = metrics::summarize(&scrapes, args.str("family"), max_series);
    Ok(json!({
        "roles": scrapes.iter().map(|s| s.role.as_str()).collect::<Vec<_>>(),
        "scrape_errors": errors,
        "families": families,
        "note": "Only documented families are summarized (docs/metrics). Counters are cumulative since the process started; use recent_refusals, block_signal_rates or breaker_states for rates.",
    }))
}

// --- capacity ---------------------------------------------------------------------------------

pub(super) fn by_label(scrapes: &[Scrape], name: &str, label: &str) -> BTreeMap<String, f64> {
    let mut out = BTreeMap::new();
    for (_, sample) in metrics::samples_of(scrapes, name) {
        let key = sample.label(label).unwrap_or("").to_owned();
        *out.entry(key).or_insert(0.0) += sample.value;
    }
    out
}

pub(super) fn breaker_name(state: f64) -> &'static str {
    match state.round() as i64 {
        0 => "closed",
        1 => "half_open",
        _ => "open",
    }
}

pub(super) struct Capacity {
    pub(super) rows: Vec<Value>,
    pub(super) worst: &'static str,
}

pub(super) fn capacity_rows(scrapes: &[Scrape], provider_filter: Option<&str>) -> Capacity {
    let mut keys: BTreeSet<(String, String)> = BTreeSet::new();
    for name in [
        "proxyx_pool_cache_ready",
        "proxyx_pool_cache_min_ready",
        "proxyx_pool_cache_low_watermark",
    ] {
        for (_, sample) in metrics::samples_of(scrapes, name) {
            if let (Some(kind), Some(provider)) = (sample.label("kind"), sample.label("provider")) {
                keys.insert((kind.to_owned(), provider.to_owned()));
            }
        }
    }
    let costs = by_label(scrapes, "proxyx_pool_cost_used_ratio", "provider");
    let breakers = by_label(scrapes, "proxyx_pool_provider_breaker_state", "provider");
    let rentals = by_label(
        scrapes,
        "proxyx_pool_inventory_rental_days_left",
        "provider",
    );
    let mut rows = Vec::new();
    let mut worst = 0_u8;
    for (kind, provider) in keys {
        if provider_filter.is_some_and(|wanted| wanted != provider) {
            continue;
        }
        let filter = [("kind", kind.as_str()), ("provider", provider.as_str())];
        let normal = sum(
            scrapes,
            "proxyx_pool_cache_ready",
            &[filter[0], filter[1], ("tier", "normal")],
        );
        let degraded = sum(
            scrapes,
            "proxyx_pool_cache_ready",
            &[filter[0], filter[1], ("tier", "degraded")],
        );
        let ready = normal + degraded;
        let min_ready = sum(scrapes, "proxyx_pool_cache_min_ready", &filter);
        let watermark = sum(scrapes, "proxyx_pool_cache_low_watermark", &filter);
        let low_all = sum(
            scrapes,
            "proxyx_pool_cache_low",
            &[filter[0], filter[1], ("tier", "all")],
        ) >= 1.0;
        let low_normal = sum(
            scrapes,
            "proxyx_pool_cache_low",
            &[filter[0], filter[1], ("tier", "normal")],
        ) >= 1.0;
        let (verdict, rank) = if ready <= 0.0 && min_ready > 0.0 {
            ("empty", 4)
        } else if low_all || (watermark > 0.0 && ready < watermark) {
            ("below_watermark", 3)
        } else if ready < min_ready {
            ("below_min", 2)
        } else if normal <= 0.0 && degraded > 0.0 {
            ("degraded_only", 1)
        } else {
            ("ok", 0)
        };
        worst = worst.max(rank);
        rows.push(json!({
            "kind": kind,
            "provider": provider,
            "verdict": verdict,
            "ready": ready,
            "ready_normal": normal,
            "ready_degraded": degraded,
            "min_ready": min_ready,
            "low_watermark": watermark,
            "shortfall": (min_ready - ready).max(0.0),
            "cache_low_alert_condition": low_all,
            "cache_low_normal_tier": low_normal,
            "cost_used_ratio": costs.get(&provider),
            "breaker": breakers.get(&provider).map(|state| breaker_name(*state)),
            "rental_days_left": rentals.get(&provider),
        }));
    }
    Capacity {
        rows,
        worst: [
            "ok",
            "degraded_only",
            "below_min",
            "below_watermark",
            "empty",
        ][usize::from(worst)],
    }
}

pub async fn pool_capacity(ctx: &Ctx, args: &Args) -> ToolResult {
    let (scrapes, errors, _) = gather(ctx, None, Duration::from_secs(300)).await?;
    let capacity = capacity_rows(&scrapes, args.str("provider"));
    let sessions = by_label(&scrapes, "proxyx_pool_cache_sessions", "state");
    let inventory: BTreeMap<String, BTreeMap<String, f64>> = {
        let mut out: BTreeMap<String, BTreeMap<String, f64>> = BTreeMap::new();
        for (_, sample) in metrics::samples_of(&scrapes, "proxyx_pool_inventory_ips") {
            if let (Some(provider), Some(state)) = (sample.label("provider"), sample.label("state"))
            {
                *out.entry(provider.to_owned())
                    .or_default()
                    .entry(state.to_owned())
                    .or_insert(0.0) += sample.value;
            }
        }
        out
    };
    let flags: Vec<Value> = ["proxyx_pool_redis_down", "proxyx_pool_postgres_down"]
        .iter()
        .map(|name| json!({"metric": name, "down": sum(&scrapes, name, &[]) >= 1.0}))
        .collect();
    let failing_reloads: Vec<String> =
        metrics::samples_of(&scrapes, "proxyx_pool_config_reload_failed")
            .filter(|(_, sample)| sample.value >= 1.0)
            .filter_map(|(_, sample)| sample.label("source").map(str::to_owned))
            .collect();
    let mut notes = Vec::new();
    if capacity.rows.is_empty() {
        notes.push("no cache_ready, cache_min_ready or cache_low_watermark series were found: the warmer exposes them, so configure the warmer role (endpoints.roles) and make sure it runs".to_owned());
    }
    Ok(json!({
        "status": capacity.worst,
        "providers": capacity.rows,
        "rotating_sessions_by_state": sessions,
        "inventory_by_provider_and_state": inventory,
        "dependencies": flags,
        "config_reload_failing": failing_reloads,
        "snapshot_age_seconds": metrics::samples_of(&scrapes, "proxyx_pool_snapshot_age_seconds").map(|(_, s)| s.value).fold(None, |acc: Option<f64>, v| Some(acc.map_or(v, |a| a.max(v)))),
        "scrape_errors": errors,
        "notes": notes,
    }))
}

// --- breakers, blocks, refusals ------------------------------------------------------------------

pub async fn breaker_states(ctx: &Ctx, args: &Args) -> ToolResult {
    let window = Duration::from_secs(args.u64("window_secs").unwrap_or(300));
    let (scrapes, errors, rates) = gather(ctx, None, window).await?;
    let states = by_label(&scrapes, "proxyx_pool_provider_breaker_state", "provider");
    let skips = by_label(&scrapes, "proxyx_pool_breaker_skips_total", "provider");
    let mut providers = BTreeSet::new();
    providers.extend(states.keys().cloned());
    providers.extend(skips.keys().cloned());
    let rows: Vec<Value> = providers
        .into_iter()
        .map(|provider| {
            let creates: BTreeMap<String, f64> = {
                let mut out = BTreeMap::new();
                for (_, sample) in metrics::samples_of(&scrapes, "proxyx_pool_warm_creates_total") {
                    if sample.label("provider") == Some(provider.as_str()) {
                        *out.entry(sample.label("outcome").unwrap_or("").to_owned())
                            .or_insert(0.0) += sample.value;
                    }
                }
                out
            };
            let recent_skips = rates.as_ref().map(|r| {
                r.delta.sum(
                    "proxyx_pool_breaker_skips_total",
                    &[("provider", provider.as_str())],
                )
            });
            json!({
                "provider": provider,
                "state": states.get(&provider).map(|state| breaker_name(*state)),
                "tunnel_skips_total": skips.get(&provider),
                "tunnel_skips_recent": recent_skips,
                "session_creates_total_by_outcome": creates,
            })
        })
        .collect();
    let open: Vec<&str> = rows
        .iter()
        .filter(|row| row["state"] == "open")
        .filter_map(|row| row["provider"].as_str())
        .collect();
    Ok(json!({
        "open_providers": open,
        "providers": rows,
        "other_breakers": super::assess::other_breakers(&scrapes),
        "other_breakers_note": "Every gauge or counter whose name contains `breaker` and is not a pool route-class family, read from the roles' /metrics (session-proxy upstream breakers, edge parent breakers). State is read as 0 closed, 1 half-open, 2 open for `*_state` gauges and 1 open for `*_open` gauges; check the role's metric documentation when a name follows another convention.",
        "rates": rate_note(rates.as_ref()),
        "scrape_errors": errors,
        "reading": "open for more than 5 minutes means the provider cannot create sessions; tunnels then skip it and use the next provider in the policy, or fail with provider_unavailable when every candidate is open",
    }))
}

pub async fn block_signal_rates(ctx: &Ctx, args: &Args) -> ToolResult {
    let window = Duration::from_secs(args.u64("window_secs").unwrap_or(300));
    let (scrapes, errors, rates) = gather(ctx, None, window).await?;
    let mut groups: BTreeMap<(String, String, String), f64> = BTreeMap::new();
    for (_, sample) in metrics::samples_of(&scrapes, "proxyx_pool_block_signals_total") {
        let key = (
            sample.label("source").unwrap_or("").to_owned(),
            sample.label("type").unwrap_or("").to_owned(),
            sample.label("scope").unwrap_or("").to_owned(),
        );
        *groups.entry(key).or_insert(0.0) += sample.value;
    }
    let mut rows: Vec<Value> = groups
        .into_iter()
        .map(|((source, kind, scope), total)| {
            let recent = rates.as_ref().map(|r| {
                r.delta.sum(
                    "proxyx_pool_block_signals_total",
                    &[
                        ("source", source.as_str()),
                        ("type", kind.as_str()),
                        ("scope", scope.as_str()),
                    ],
                )
            });
            json!({
                "source": source,
                "type": kind,
                "scope": scope,
                "total": total,
                "recent": recent,
                "per_minute": recent.zip(rates.as_ref()).map(|(inc, r)| r.per_min(inc)),
            })
        })
        .collect();
    rows.sort_by(|a, b| {
        let key = |v: &Value| v["recent"].as_f64().or(v["total"].as_f64()).unwrap_or(0.0);
        key(b).total_cmp(&key(a))
    });
    let ignored_total = sum(&scrapes, "proxyx_pool_block_signals_ignored_total", &[]);
    let ignored_recent = rates
        .as_ref()
        .map(|r| r.delta.sum("proxyx_pool_block_signals_ignored_total", &[]));
    Ok(json!({
        "signals": rows,
        "ignored": {"total": ignored_total, "recent": ignored_recent},
        "signal_types": explain::signal_types(),
        "rates": rate_note(rates.as_ref()),
        "scrape_errors": errors,
        "reading": "scope target: cooled for that host only; ip: taken out of leasing for every target; pool_guard: escalation stopped because the cooled share of the partition was reached; route_class: a canary or probe found the whole route blocked. A steady ignored rate means clients and gateway disagree about sessions or exit IPs, and blocked IPs stay in leasing.",
    }))
}

pub async fn recent_refusals(ctx: &Ctx, args: &Args) -> ToolResult {
    let window = Duration::from_secs(args.u64("window_secs").unwrap_or(300));
    let top = usize::try_from(args.u64("top").unwrap_or(10)).unwrap_or(10);
    let (scrapes, errors, rates) = gather(ctx, None, window).await?;
    let totals = by_label(&scrapes, "proxyx_pool_connections_total", "outcome");
    let recent = rates
        .as_ref()
        .map(|r| r.delta.by_label("proxyx_pool_connections_total", "outcome"));
    let all_total: f64 = totals.values().sum();
    let all_recent: Option<f64> = recent.as_ref().map(|m| m.values().sum());
    let mut rows: Vec<Value> = Vec::new();
    for (outcome, total) in &totals {
        if outcome == "ok" || *total <= 0.0 {
            continue;
        }
        let cause = Cause::from_code(outcome);
        let recent_n = recent
            .as_ref()
            .map(|m| m.get(outcome).copied().unwrap_or(0.0));
        let explanation = cause.map(|cause| explain::explain(CodeSource::Gateway(cause)));
        rows.push(json!({
            "outcome": outcome,
            "kind": if cause.is_some() { "cause" } else { "connection_level" },
            "http_status": cause.map(Cause::status),
            "total": total,
            "recent": recent_n,
            "per_minute": recent_n.zip(rates.as_ref()).map(|(n, r)| r.per_min(n)),
            "share_of_connections": if all_total > 0.0 { json!(round(total / all_total * 100.0)) } else { Value::Null },
            "meaning": explanation.as_ref().map(|e| e["meaning"].clone()),
            "next_steps": explanation.as_ref().map(|e| e["next_steps"].clone()),
        }));
    }
    rows.sort_by(|a, b| {
        let key = |v: &Value| {
            v["recent"]
                .as_f64()
                .unwrap_or_else(|| v["total"].as_f64().unwrap_or(0.0))
        };
        key(b).total_cmp(&key(a))
    });
    rows.truncate(top);
    let session_proxy = by_label(&scrapes, "proxyx_intercept_connections_total", "outcome");
    Ok(json!({
        "connections_total": all_total,
        "connections_recent": all_recent,
        "ok_total": totals.get("ok"),
        "refusals": rows,
        "session_proxy_outcomes": if session_proxy.is_empty() { Value::Null } else { json!(session_proxy) },
        "rates": rate_note(rates.as_ref()),
        "scrape_errors": errors,
        "note": "outcomes that are not cause codes (bad_request, over_limit) are connection-level: a malformed or silent client, or a full pod. Ask explain_refusal about any cause code.",
    }))
}

// --- diagnose -----------------------------------------------------------------------------------

fn finding(severity: &str, finding: impl Into<String>, evidence: Value, next: &[&str]) -> Value {
    json!({"severity": severity, "finding": finding.into(), "evidence": evidence, "next_tools": next})
}

pub async fn diagnose(ctx: &Ctx, args: &Args) -> ToolResult {
    let window = Duration::from_secs(args.u64("window_secs").unwrap_or(300));
    let org = match args.str("org") {
        Some(_) => Some(ctx.org(args)?),
        None => ctx
            .backends
            .control
            .as_ref()
            .map(|c| c.org.clone())
            .filter(|org| ctx.gate.check_org(org).is_ok()),
    };
    let mut findings: Vec<Value> = Vec::new();
    let mut checked: Vec<&str> = Vec::new();
    let mut skipped: Vec<Value> = Vec::new();

    // refusals and capacity from metrics
    if ctx.backends.roles.is_empty() {
        skipped.push(json!({"check": "metrics", "reason": "no role endpoints configured"}));
    } else {
        match gather(ctx, None, window).await {
            Ok((got, errors, rates)) => {
                checked.push("metrics");
                let scrapes = got;
                for error in errors {
                    skipped.push(json!({"check": "metrics", "reason": error}));
                }
                let totals = by_label(&scrapes, "proxyx_pool_connections_total", "outcome");
                let recent = rates
                    .as_ref()
                    .map(|r| r.delta.by_label("proxyx_pool_connections_total", "outcome"));
                let mut causes: Vec<(String, f64)> = totals
                    .iter()
                    .filter(|(outcome, _)| Cause::from_code(outcome).is_some())
                    .map(|(outcome, total)| {
                        let count = recent
                            .as_ref()
                            .map_or(*total, |m| m.get(outcome).copied().unwrap_or(0.0));
                        (outcome.clone(), count)
                    })
                    .filter(|(_, count)| *count > 0.0)
                    .collect();
                causes.sort_by(|a, b| b.1.total_cmp(&a.1));
                for (code, count) in causes.into_iter().take(3) {
                    let Some(cause) = Cause::from_code(&code) else {
                        continue;
                    };
                    let advice = explain::explain(CodeSource::Gateway(cause));
                    findings.push(finding(
                        "warning",
                        format!(
                            "{count} tunnels were refused with `{code}` {}",
                            if recent.is_some() {
                                "in the window"
                            } else {
                                "since the gateway started"
                            }
                        ),
                        json!({"meaning": advice["meaning"], "next_steps": advice["next_steps"]}),
                        &["explain_refusal", "recent_refusals"],
                    ));
                }
                let capacity = capacity_rows(&scrapes, None);
                for row in &capacity.rows {
                    let verdict = row["verdict"].as_str().unwrap_or("ok");
                    if verdict != "ok" {
                        findings.push(finding(
                            if matches!(verdict, "empty" | "below_watermark") {
                                "critical"
                            } else {
                                "warning"
                            },
                            format!(
                                "{} provider {} is {verdict}: {} ready, min_ready {}",
                                row["kind"].as_str().unwrap_or(""),
                                row["provider"].as_str().unwrap_or(""),
                                row["ready"],
                                row["min_ready"]
                            ),
                            row.clone(),
                            &["pool_capacity", "breaker_states"],
                        ));
                    }
                    if row["breaker"] == "open" {
                        findings.push(finding(
                            "critical",
                            format!(
                                "the breaker of provider {} is open: it cannot create sessions",
                                row["provider"].as_str().unwrap_or("")
                            ),
                            json!({"provider": row["provider"]}),
                            &["breaker_states", "explain_refusal"],
                        ));
                    }
                }
                for name in ["proxyx_pool_redis_down", "proxyx_pool_postgres_down"] {
                    if sum(&scrapes, name, &[]) >= 1.0 {
                        findings.push(finding(
                            "critical",
                            format!(
                                "{} is 1: new leases are refused with cache_unavailable",
                                name.trim_start_matches("proxyx_pool_")
                            ),
                            json!({"metric": name}),
                            &["health"],
                        ));
                    }
                }
            }
            Err(error) => skipped.push(json!({"check": "metrics", "reason": error.message})),
        }
    }

    // org blocks, policy
    if let (Some(pool), Some(org)) = (ctx.backends.pool.as_ref(), org.as_deref()) {
        match pool
            .api
            .get(&["v1", "org-blocks"], &[("org", org.to_owned())])
            .await
        {
            Ok(body) => {
                checked.push("org_blocks");
                let items = body["items"].as_array().cloned().unwrap_or_default();
                if !items.is_empty() {
                    findings.push(finding(
                        "critical",
                        format!("org {org} has {} active block(s): matching tunnels are refused with org_blocked", items.len()),
                        json!(items),
                        &["list_org_blocks", "explain_refusal"],
                    ));
                }
            }
            Err(error) => skipped.push(json!({"check": "org_blocks", "reason": error.message})),
        }
        match pool.api.get(&["v1", "policies"], &[]).await {
            Ok(body) => {
                checked.push("policy");
                if let Ok(set) = super::policy_tools::policy_set_from_listing(&body)
                    && let Ok(org_id) = org.parse::<common::types::OrgId>()
                {
                    let effective = set.effective(&org_id, None);
                    findings.push(finding(
                            "info",
                            format!(
                                "org {org} may use kinds {:?}, providers {:?}, regions {:?}; lease_ttl {}s, max_tunnels_per_org {:?}",
                                effective.kinds.iter().map(ToString::to_string).collect::<Vec<_>>(),
                                effective.providers.iter().map(ToString::to_string).collect::<Vec<_>>(),
                                effective.regions.iter().map(ToString::to_string).collect::<Vec<_>>(),
                                effective.lease_ttl.as_secs(),
                                effective.max_tunnels_per_org,
                            ),
                            json!({"org": org}),
                            &["list_policies", "explain_selector"],
                        ));
                }
            }
            Err(error) => skipped.push(json!({"check": "policy", "reason": error.message})),
        }
    } else {
        skipped.push(
            json!({"check": "org_blocks and policy", "reason": "needs endpoints.pool and an org"}),
        );
    }

    // rate limit bucket
    if let (Some(control), Some(org)) = (ctx.backends.control.as_ref(), org.as_deref()) {
        match control
            .api
            .get(&["rpc", "orgs", org, "rate-limit-state"], &[])
            .await
        {
            Ok(state) => {
                checked.push("rate_limit");
                let tokens = state["tokens"].as_f64();
                if state["exists"] == true && tokens.is_some_and(|t| t < 1.0) {
                    findings.push(finding(
                        "warning",
                        format!("org {org}'s session-proxy rate-limit bucket is empty: requests wait for refill"),
                        state,
                        &["get_org", "set_org_rate_limit"],
                    ));
                }
            }
            Err(error) => skipped.push(json!({"check": "rate_limit", "reason": error.message})),
        }
    }

    let rank = |severity: &str| match severity {
        "critical" => 0,
        "warning" => 1,
        _ => 2,
    };
    findings.sort_by_key(|f| rank(f["severity"].as_str().unwrap_or("info")));
    let problems = findings.iter().filter(|f| f["severity"] != "info").count();
    Ok(json!({
        "org": org,
        "summary": if problems == 0 { "no problem found by the checks that ran".to_owned() } else { format!("{problems} finding(s) need attention") },
        "findings": findings,
        "checked": checked,
        "skipped": skipped,
        "note": "Findings are evidence, not verdicts. Confirm with the named tools before changing anything.",
    }))
}
