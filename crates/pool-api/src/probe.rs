//! The prober's side of the control API (contract:
//! `services/proxyx/prober/src/proxyx_prober/contract.py`).
//!
//! `GET /v1/probe/targets` says what to test: every route class once per
//! interval (the hourly canary) and the browser samples the warmer queued.
//! `POST /v1/probe/results` takes the raw measurements; this module applies the
//! policy criteria (`max_ttfb_ms`, `max_load_ms`, `min_success`):
//!
//! * a **sample** result becomes a verdict under its job id and the job is
//!   no longer listed;
//! * a **canary** result becomes a verdict under `canary:<provider>:<region>`.
//!   A canary that failed on blocks or errors drains the route class (every
//!   ready unit leaves the ready set, static IPs go to Cooldown) and pauses
//!   warming. One that only found slow pages (`Verdict::slow`: no block, no
//!   error) moves the class's units to the degraded tier and keeps leasing; a
//!   passing one lifts the pause and returns the degraded units to normal.
//!
//! The pages the prober loads are `loaded.probe_targets`
//! (`data_dir/probe-targets.toml`, see [`store::loaded::ProbeTargets`]).

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::extract::State;
use common::types::{IpState, Partition, ProviderId, Region, SignalSource, SignalType, Tier};
use policy::Criteria;
use serde::Deserialize;
use serde_json::{Value, json};
use store::{Transition, Verdict};
use time::OffsetDateTime;

use crate::error::{ApiError, ApiJson};
use crate::react::try_transition;
use crate::state::ApiState;
use crate::wire::{MAX_ID_LEN, plain_id};

/// A failed canary pauses warming this long; the next canary (one interval
/// later) lifts or renews it.
const PAUSE_TTL: Duration = Duration::from_secs(2 * 3_600);
/// Verdicts are read soon after they are written; a day covers any lag.
const VERDICT_TTL: Duration = Duration::from_secs(24 * 3_600);
const MAX_RUNS: usize = 1_000;
/// Most page URLs the prober accepts for one region or sample.
const MAX_TARGETS: usize = 100;
/// Longest page URL the prober accepts.
const MAX_TARGET_LEN: usize = 2_048;

/// The prober builds usernames from provider and country, and `-` separates
/// options there.
fn option_safe(provider: &ProviderId) -> bool {
    !provider.as_str().contains('-')
}

/// `GET /v1/probe/targets`
pub(crate) async fn targets(State(state): State<Arc<ApiState>>) -> Result<Json<Value>, ApiError> {
    let loaded = state.loaded.borrow().clone();

    // A route class is a route-class policy; a provider without one is a class
    // of its own, so every provider gets a canary.
    let mut classes: Vec<(String, ProviderId)> = Vec::new();
    for record in state.db.current_policies().await? {
        if record.scope == "route_class"
            && let Some(provider) = record.target.as_deref().and_then(|t| t.parse().ok())
        {
            classes.push((record.name, provider));
        }
    }
    for adapter in loaded.adapters.iter() {
        if !classes.iter().any(|(_, p)| p == adapter.id()) {
            classes.push((adapter.id().to_string(), adapter.id().clone()));
        }
    }

    let mut route_classes = Vec::new();
    for (name, provider) in classes {
        if !option_safe(&provider) {
            tracing::warn!(%provider, "provider id has a dash, the prober cannot test it");
            continue;
        }
        let policy = loaded.policies.effective(&state.probe_org, Some(&provider));
        let regions: Vec<Value> = policy
            .regions
            .iter()
            .filter_map(|region| {
                let urls: Vec<String> = loaded
                    .probe_targets
                    .for_region(region)
                    .into_iter()
                    .map(String::from)
                    .filter(|u| u.len() <= MAX_TARGET_LEN)
                    .take(MAX_TARGETS)
                    .collect();
                (!urls.is_empty()).then(
                    || json!({ "region": region, "country": region.country(), "targets": urls }),
                )
            })
            .collect();
        if !regions.is_empty() {
            route_classes.push(json!({
                "route_class": name,
                "provider": provider,
                "regions": regions,
            }));
        }
    }

    let samples: Vec<Value> = state
        .hot
        .sample_pending()
        .await?
        .into_iter()
        .filter(|job| option_safe(&job.provider))
        .map(|job| {
            json!({
                "job_id": job.job_id,
                "route_class": job.route_class,
                "provider": job.provider,
                "region": job.region,
                "country": job.region.country(),
                "sid": job.sid,
                "targets": &job.targets[..job.targets.len().min(MAX_TARGETS)],
            })
        })
        .collect();
    Ok(Json(
        json!({ "route_classes": route_classes, "samples": samples }),
    ))
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Kind {
    Canary,
    Sample,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Outcome {
    Ok,
    Blocked,
    Timeout,
    Error,
}

/// One page load. Times are milliseconds from navigation start.
#[derive(Debug, Deserialize)]
pub(crate) struct Run {
    outcome: Outcome,
    status: Option<u16>,
    ttfb_ms: Option<f64>,
    load_ms: Option<f64>,
    block_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Results {
    job_id: Option<String>,
    kind: Kind,
    provider: ProviderId,
    region: Region,
    results: Vec<Run>,
}

/// Judge a result against the criteria: a run is good when it loaded and
/// stayed within the time limits; the verdict passes when the share of good
/// runs reaches `min_success`. It is `slow` when it fails only for speed: no
/// run was blocked or ended in an error, and the share of runs that loaded,
/// however slowly, reaches `min_success` (a timeout is slowness).
fn evaluate(runs: &[Run], c: &Criteria, now: OffsetDateTime) -> Verdict {
    let within = |v: Option<f64>, max: u32| v.is_none_or(|ms| ms <= f64::from(max));
    let good = runs
        .iter()
        .filter(|r| {
            r.outcome == Outcome::Ok
                && within(r.ttfb_ms, c.max_ttfb_ms)
                && within(r.load_ms, c.max_load_ms)
        })
        .count();
    let bad = runs
        .iter()
        .filter(|r| matches!(r.outcome, Outcome::Blocked | Outcome::Error))
        .count();
    let blocked = runs
        .iter()
        .filter(|r| r.outcome == Outcome::Blocked)
        .count();
    let loaded = runs.iter().filter(|r| r.outcome == Outcome::Ok).count();
    let n = runs.len().max(1) as f64;
    let ratio = good as f64 / n;
    let ok = ratio >= c.min_success;
    Verdict {
        ok,
        success_ratio: ratio,
        checked_at: now.unix_timestamp(),
        detail: if ok {
            String::new()
        } else {
            format!(
                "{good} of {} runs good, {} needed; {blocked} blocked",
                runs.len(),
                c.min_success
            )
        },
        slow: !ok && bad == 0 && loaded as f64 / n >= c.min_success,
    }
}

fn blocked_type(run: &Run) -> SignalType {
    let reason = run
        .block_reason
        .as_deref()
        .unwrap_or("")
        .to_ascii_lowercase();
    let challenge = ["captcha", "challenge", "sorry"]
        .iter()
        .any(|m| reason.contains(m));
    match run.status {
        Some(429) => SignalType::RateLimited,
        Some(403) if !challenge => SignalType::Forbidden,
        _ => SignalType::Challenge,
    }
}

/// `POST /v1/probe/results`
pub(crate) async fn results(
    State(state): State<Arc<ApiState>>,
    ApiJson(body): ApiJson<Results>,
) -> Result<Json<Value>, ApiError> {
    if body.results.is_empty() || body.results.len() > MAX_RUNS {
        return Err(ApiError::bad_request(format!(
            "send between 1 and {MAX_RUNS} runs"
        )));
    }
    let job_id = match (body.kind, body.job_id) {
        (Kind::Sample, Some(id)) if plain_id(&id) => Some(id),
        (Kind::Sample, _) => {
            return Err(ApiError::bad_request(format!(
                "a sample result needs a job_id of 1 to {MAX_ID_LEN} of [A-Za-z0-9_-]"
            )));
        }
        (Kind::Canary, _) => None,
    };
    let partition = Partition {
        provider: body.provider,
        region: body.region,
    };
    let loaded = state.loaded.borrow().clone();
    let policy = loaded
        .policies
        .effective(&state.probe_org, Some(&partition.provider));
    // Anything else would write a verdict, a warm pause or a drain for a
    // route class that does not exist.
    let route_class_policy = state.db.current_policies().await?.into_iter().any(|r| {
        r.scope == "route_class" && r.target.as_deref() == Some(partition.provider.as_str())
    });
    if loaded.adapters.get(&partition.provider).is_none() && !route_class_policy {
        return Err(ApiError::not_found("unknown provider"));
    }
    if !policy
        .regions
        .iter()
        .any(|r| partition.region.satisfies(r) || r.satisfies(&partition.region))
    {
        return Err(ApiError::bad_request(
            "the region is not one of the provider's policy regions",
        ));
    }
    let verdict = evaluate(&body.results, &policy.criteria, OffsetDateTime::now_utc());

    let source = if body.kind == Kind::Canary {
        SignalSource::Canary
    } else {
        SignalSource::Probe
    };
    for run in body
        .results
        .iter()
        .filter(|r| r.outcome == Outcome::Blocked)
    {
        state
            .metrics
            .block_signals_total
            .with_label_values(&[source.as_str(), blocked_type(run).as_str(), "route_class"])
            .inc();
    }

    let mut drained = 0;
    let mut degraded = 0;
    let mut promoted = 0;
    if let Some(job_id) = job_id {
        state
            .hot
            .verdict_put(&job_id, &verdict, VERDICT_TTL)
            .await?;
        state.hot.sample_done(&job_id).await?;
    } else {
        // Only a class this check degraded comes back with it: an IP the
        // warmer found slow on its own is the warmer's to return.
        let key = format!("canary:{}", partition.tag());
        let was_slow = state.hot.verdict_get(&key).await?.is_some_and(|v| v.slow);
        if verdict.ok {
            resume_route_class(&state, &partition).await?;
            if was_slow {
                promoted = promote_route_class(&state, &partition).await?;
            }
        } else if verdict.slow {
            resume_route_class(&state, &partition).await?;
            degraded = demote_route_class(&state, &partition).await?;
            tracing::warn!(
                partition = %partition,
                success_ratio = verdict.success_ratio,
                degraded,
                "canary found the route class slow, units moved to the degraded tier"
            );
        } else {
            drained = drain_route_class(&state, &partition, policy.static_ips.cooldown).await?;
            tracing::warn!(
                partition = %partition,
                success_ratio = verdict.success_ratio,
                drained,
                "canary failed, route class drained and warming paused"
            );
        }
        // Written last: a call that failed above is retried by the prober,
        // and the retry must still see the verdict that made it promote.
        state.hot.verdict_put(&key, &verdict, VERDICT_TTL).await?;
    }
    Ok(Json(
        json!({ "verdict": verdict, "drained": drained, "degraded": degraded, "promoted": promoted }),
    ))
}

/// The partitions a canary of `partition` speaks for: itself, and the
/// partitions of the provider's inventory whose region it covers.
async fn route_partitions(
    state: &ApiState,
    partition: &Partition,
) -> Result<(Vec<store::InventoryRow>, BTreeSet<Partition>), ApiError> {
    let rows: Vec<_> = state
        .db
        .list_inventory(Some(&partition.provider), None)
        .await?
        .into_iter()
        .filter(|r| r.entry.region.satisfies(&partition.region))
        .collect();
    let mut partitions: BTreeSet<Partition> =
        rows.iter().map(store::InventoryRow::partition).collect();
    partitions.insert(partition.clone());
    Ok((rows, partitions))
}

async fn resume_route_class(state: &ApiState, partition: &Partition) -> Result<(), ApiError> {
    let (_, partitions) = route_partitions(state, partition).await?;
    for p in &partitions {
        state.hot.warm_resume(p).await?;
    }
    Ok(())
}

/// Take every ready unit of the route class out of leasing (open tunnels
/// end on their own), cool its static IPs and pause warming. Returns how
/// many units left the ready set.
async fn drain_route_class(
    state: &ApiState,
    partition: &Partition,
    cooldown: Duration,
) -> Result<usize, ApiError> {
    let (rows, partitions) = route_partitions(state, partition).await?;
    let until = OffsetDateTime::now_utc() + cooldown;
    for row in rows.iter().filter(|r| r.state.is_leasable()) {
        let change = Transition::to(IpState::Cooldown, "canary failed").cooldown_until(until);
        try_transition(state, row.entry.ip, &change, "canary").await?;
    }
    let mut drained = 0;
    for p in &partitions {
        for id in state.hot.ready_ids(p).await? {
            if state.hot.ready_take(p, &id).await? {
                drained += 1;
            }
        }
        state.hot.warm_pause(p, PAUSE_TTL).await?;
    }
    Ok(drained)
}

/// Move the units of the route class to the degraded tier: static IPs to
/// `Degraded`, every other ready unit (rotating sessions) by its tier field.
/// Customer upstreams are left alone. Returns how many units were demoted.
async fn demote_route_class(state: &ApiState, partition: &Partition) -> Result<usize, ApiError> {
    let (rows, partitions) = route_partitions(state, partition).await?;
    let owned: BTreeSet<String> = rows
        .iter()
        .filter(|r| r.owner.is_some())
        .map(|r| r.entry.ip.to_string())
        .collect();
    for row in rows
        .iter()
        .filter(|r| r.owner.is_none() && matches!(r.state, IpState::Available | IpState::Leased))
    {
        let change = Transition::to(IpState::Degraded, "canary slow");
        try_transition(state, row.entry.ip, &change, "canary").await?;
    }
    let mut degraded = 0;
    for p in &partitions {
        for id in state.hot.ready_ids(p).await? {
            if !owned.contains(&id) && state.hot.set_tier(p, &id, Tier::Degraded).await? {
                degraded += 1;
            }
        }
    }
    Ok(degraded)
}

/// The reverse of [`demote_route_class`]: a canary that passed at full speed
/// returns the static IPs it degraded to `Available` and the degraded ready
/// units to the normal tier. An IP the warmer degraded on its own (its last
/// move was not the canary's) is left to the warmer, and so are customer
/// upstreams. A rotating session carries no record of who made it slow, so a
/// passing canary returns them all: the class is at full speed now. Returns
/// how many units were promoted. The moves and tier changes can be repeated,
/// so a retried call finishes what a failed one left.
async fn promote_route_class(state: &ApiState, partition: &Partition) -> Result<usize, ApiError> {
    let (rows, partitions) = route_partitions(state, partition).await?;
    let mut kept: BTreeSet<String> = rows
        .iter()
        .filter(|r| r.owner.is_some())
        .map(|r| r.entry.ip.to_string())
        .collect();
    for row in rows
        .iter()
        .filter(|r| r.owner.is_none() && r.state == IpState::Degraded)
    {
        let key = row.entry.ip.to_string();
        let by_canary =
            state.db.last_transition(&key).await?.is_some_and(|t| {
                t.actor == "canary" && t.detail["to"] == IpState::Degraded.as_str()
            });
        if by_canary {
            let change = Transition::to(IpState::Available, "canary passed");
            try_transition(state, row.entry.ip, &change, "canary").await?;
        } else {
            kept.insert(key);
        }
    }
    let mut promoted = 0;
    for p in &partitions {
        for id in state.hot.ready_ids(p).await? {
            if !kept.contains(&id)
                && state.hot.tier(p, &id).await? == Tier::Degraded
                && state.hot.set_tier(p, &id, Tier::Normal).await?
            {
                promoted += 1;
            }
        }
    }
    Ok(promoted)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn criteria() -> Criteria {
        Criteria {
            max_risk: 75,
            max_ttfb_ms: 3_000,
            max_load_ms: 10_000,
            min_success: 0.66,
            browser_sample: 0.05,
            verdict_max_age: Duration::from_secs(86_400),
        }
    }

    fn run(outcome: Outcome, ttfb: Option<f64>, load: Option<f64>) -> Run {
        Run {
            outcome,
            status: None,
            ttfb_ms: ttfb,
            load_ms: load,
            block_reason: None,
        }
    }

    #[test]
    fn a_slow_page_is_not_a_success_and_the_share_is_judged_at_min_success() {
        let now = OffsetDateTime::now_utc();
        let c = criteria();
        let ok = || run(Outcome::Ok, Some(200.0), Some(900.0));
        // 2 of 3 good = 0.666..: passes 0.66
        let v = evaluate(&[ok(), ok(), run(Outcome::Blocked, None, None)], &c, now);
        assert!(v.ok, "{v:?}");
        // 1 of 3 good: fails
        let v = evaluate(
            &[
                ok(),
                run(Outcome::Timeout, None, None),
                run(Outcome::Error, None, None),
            ],
            &c,
            now,
        );
        assert!(!v.ok && v.detail.contains("1 of 3"), "{v:?}");
        // an ok page over the load limit counts as a failure
        let slow = run(Outcome::Ok, Some(200.0), Some(10_001.0));
        let v = evaluate(&[ok(), slow], &c, now);
        assert!(!v.ok, "{v:?}");
        // at the limit it still passes
        let edge = run(Outcome::Ok, Some(3_000.0), Some(10_000.0));
        assert!(evaluate(&[edge], &c, now).ok);
    }

    #[test]
    fn a_verdict_is_slow_only_when_nothing_was_blocked_or_failed_and_enough_pages_loaded() {
        let now = OffsetDateTime::now_utc();
        let c = criteria();
        let fast = || run(Outcome::Ok, Some(200.0), Some(900.0));
        let slow = || run(Outcome::Ok, Some(200.0), Some(10_001.0));
        let slow_verdict = |runs: &[Run]| {
            let v = evaluate(runs, &c, now);
            (v.ok, v.slow)
        };
        assert_eq!(slow_verdict(&[slow(), slow(), slow()]), (false, true));
        assert_eq!(
            slow_verdict(&[fast(), fast(), slow()]),
            (true, false),
            "a pass is not slow"
        );
        // two loaded, one timeout: 2 of 3 still reach min_success, and a
        // timeout is slowness
        let timeout = || run(Outcome::Timeout, None, None);
        assert_eq!(slow_verdict(&[slow(), slow(), timeout()]), (false, true));
        // a block or an error is bad however many pages loaded
        let blocked = || run(Outcome::Blocked, None, None);
        let error = || run(Outcome::Error, None, None);
        assert_eq!(slow_verdict(&[slow(), slow(), blocked()]), (false, false));
        assert_eq!(slow_verdict(&[slow(), slow(), error()]), (false, false));
        assert_eq!(
            slow_verdict(&[slow(), timeout(), timeout()]),
            (false, false),
            "too few loaded pages"
        );
    }

    #[test]
    fn blocked_runs_map_to_a_signal_type() {
        let mut r = run(Outcome::Blocked, None, None);
        r.status = Some(429);
        assert_eq!(blocked_type(&r), SignalType::RateLimited);
        r.status = Some(403);
        assert_eq!(blocked_type(&r), SignalType::Forbidden);
        r.block_reason = Some("Captcha form".into());
        assert_eq!(blocked_type(&r), SignalType::Challenge);
        r.status = None;
        assert_eq!(blocked_type(&r), SignalType::Challenge);
    }
}
