//! The findings: facts in, `OK` / `WARN` / `CRIT` out. Every threshold is a
//! field of [`Thresholds`] with the default documented in `docs/doctor.md`.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::time::Duration;

use common::types::IpState;
use serde::Serialize;
use serde_json::{Value, json};
use time::OffsetDateTime;

use super::facts::{Breaker, Kind, PartitionFacts, PoolFacts, ProviderFacts, StaticFacts};

pub const SCHEMA_VERSION: u32 = 1;

/// Exit codes, as `proxyx doctor`: 0 all OK, 1 a CRIT (or a WARN under `--strict`), 2 only WARNs.
pub const EXIT_OK: i32 = 0;
pub const EXIT_CRIT: i32 = 1;
pub const EXIT_WARN: i32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Ok,
    Warn,
    Crit,
}

impl Level {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::Warn => "WARN",
            Self::Crit => "CRIT",
        }
    }
}

/// One judged fact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub level: Level,
    /// What it is about: a partition, a provider, `pool`.
    pub subject: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Section {
    pub name: &'static str,
    pub findings: Vec<Finding>,
}

/// The result of one assessment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assessment {
    /// Unix seconds of the assessment.
    pub generated_at: i64,
    pub sections: Vec<Section>,
}

/// Every threshold of the assessment.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Thresholds {
    /// Lease use (`leased / (leased + free)`) of a partition: WARN, CRIT.
    pub utilization_warn: f64,
    pub utilization_crit: f64,
    /// A static IP is stale when its last check is older than this many
    /// `static.recheck_every`.
    pub stale_factor: u32,
    /// Share of a provider's IPs that are stale (or unhealthy, or over the risk
    /// limit) at which the finding is CRIT instead of WARN.
    pub stale_crit_share: f64,
    pub unhealthy_warn_share: f64,
    pub unhealthy_crit_share: f64,
    pub risky_warn_share: f64,
    pub risky_crit_share: f64,
    /// Share of the static IPs that got a block signal inside the window.
    pub blocked_warn_share: f64,
    pub blocked_crit_share: f64,
    /// Days left of a static IP rental: WARN below `rental_warn_days`, CRIT below `rental_crit_days`.
    pub rental_warn_days: i64,
    pub rental_crit_days: i64,
    /// Budget use (the larger of the traffic and create shares): WARN, CRIT.
    pub budget_warn: f64,
    pub budget_crit: f64,
    /// The gateway's snapshot is stale beyond this many reload intervals.
    pub snapshot_age_factor: f64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            utilization_warn: 0.8,
            utilization_crit: 0.95,
            stale_factor: 3,
            stale_crit_share: 0.5,
            unhealthy_warn_share: 0.2,
            unhealthy_crit_share: 0.5,
            risky_warn_share: 0.1,
            risky_crit_share: 0.3,
            blocked_warn_share: 0.2,
            blocked_crit_share: 0.5,
            rental_warn_days: 30,
            rental_crit_days: 14,
            budget_warn: 0.8,
            budget_crit: 0.9,
            snapshot_age_factor: 5.0,
        }
    }
}

fn finding(level: Level, subject: impl Into<String>, message: impl Into<String>) -> Finding {
    Finding {
        level,
        subject: subject.into(),
        message: message.into(),
    }
}

fn share_level(share: f64, warn: f64, crit: f64) -> Level {
    if share >= crit {
        Level::Crit
    } else if share >= warn {
        Level::Warn
    } else {
        Level::Ok
    }
}

fn pct(share: f64) -> String {
    format!("{:.0}%", share * 100.0)
}

fn ratio(n: usize, of: usize) -> f64 {
    if of == 0 { 0.0 } else { n as f64 / of as f64 }
}

fn human(d: Duration) -> String {
    let s = d.as_secs();
    // A round figure keeps its unit (a one hour window is `1h`, not `60m`).
    for (unit, size) in [("d", 86_400), ("h", 3_600), ("m", 60)] {
        if s >= size && s.is_multiple_of(size) {
            return format!("{}{unit}", s / size);
        }
    }
    match s {
        0..=119 => format!("{s}s"),
        120..=7199 => format!("{}m", s / 60),
        7200..=172_799 => format!("{}h", s / 3600),
        _ => format!("{}d", s / 86_400),
    }
}

/// Judge `facts`.
pub fn evaluate(facts: &PoolFacts, th: &Thresholds) -> Assessment {
    let sections = vec![
        Section {
            name: "capacity",
            findings: capacity(facts),
        },
        Section {
            name: "leases",
            findings: leases(facts, th),
        },
        Section {
            name: "breakers",
            findings: breakers(facts),
        },
        Section {
            name: "checks",
            findings: checks(facts, th),
        },
        Section {
            name: "inventory",
            findings: inventory(facts, th),
        },
        Section {
            name: "reputation",
            findings: reputation(facts, th),
        },
        Section {
            name: "blocks",
            findings: blocks(facts, th),
        },
        Section {
            name: "rentals",
            findings: rentals(facts, th),
        },
        Section {
            name: "budget",
            findings: budget(facts, th),
        },
        Section {
            name: "gateway",
            findings: gateway(facts, th),
        },
    ];
    Assessment {
        generated_at: facts.now.unix_timestamp(),
        sections,
    }
}

fn name(p: &PartitionFacts) -> String {
    format!("{}@{} ({})", p.provider, p.region, p.kind.name())
}

fn capacity(facts: &PoolFacts) -> Vec<Finding> {
    let mut out = Vec::new();
    for p in &facts.partitions {
        let (subject, ready) = (name(p), p.ready);
        let level = if p.min_ready == 0 {
            Level::Ok
        } else if ready == 0 || ready < u64::from(p.low_watermark) {
            Level::Crit
        } else if ready < u64::from(p.min_ready) {
            Level::Warn
        } else {
            Level::Ok
        };
        let mut message = format!(
            "{ready} ready, min_ready {}, low watermark {}",
            p.min_ready, p.low_watermark
        );
        if p.degraded_free > 0 {
            let _ = write!(message, " ({} on the degraded tier)", p.degraded_free);
        }
        if p.creating > 0 {
            let _ = write!(message, ", {} being created", p.creating);
        }
        out.push(finding(level, subject.clone(), message));
        if p.paused {
            out.push(finding(
                Level::Warn,
                subject,
                "warming is paused (a canary failed): no new unit is started until the pause is lifted",
            ));
        }
    }
    if out.is_empty() {
        out.push(finding(Level::Ok, "pool", "no partition is configured"));
    }
    out
}

fn leases(facts: &PoolFacts, th: &Thresholds) -> Vec<Finding> {
    let mut out = Vec::new();
    for p in &facts.partitions {
        // Rotating `ready` counts only the free units; a static partition counts every leasable IP.
        let total = match p.kind {
            Kind::Rotating => p.leased.saturating_add(p.ready),
            Kind::Static => p.ready.max(p.leased),
        };
        if total == 0 {
            continue;
        }
        let used = p.leased as f64 / total as f64;
        out.push(finding(
            share_level(used, th.utilization_warn, th.utilization_crit),
            name(p),
            format!("{} of {total} units leased ({})", p.leased, pct(used)),
        ));
        if let Some(b) = &p.busiest {
            let level = if b.tunnels >= u64::from(b.limit) * 2 {
                Level::Crit
            } else if b.tunnels >= u64::from(b.limit) {
                Level::Warn
            } else {
                Level::Ok
            };
            out.push(finding(
                level,
                name(p),
                format!(
                    "busiest IP {} carries {} tunnels, the limit is {} per IP",
                    b.ip, b.tunnels, b.limit
                ),
            ));
        }
    }
    if out.is_empty() {
        out.push(finding(Level::Ok, "pool", "no leasable unit"));
    }
    out
}

fn breakers(facts: &PoolFacts) -> Vec<Finding> {
    let mut out: Vec<Finding> = facts
        .providers
        .iter()
        .map(|p| match p.breaker {
            Breaker::Closed => finding(Level::Ok, &p.provider, "breaker closed"),
            Breaker::HalfOpen => finding(
                Level::Warn,
                &p.provider,
                "breaker half-open: probing the provider after failures",
            ),
            Breaker::Open => finding(
                Level::Warn,
                &p.provider,
                "breaker open: the provider failed repeatedly and is skipped",
            ),
        })
        .collect();
    if out.is_empty() {
        out.push(finding(Level::Ok, "pool", "no provider"));
    }
    out
}

fn provider_of<'a>(facts: &'a PoolFacts, name: &str) -> Option<&'a ProviderFacts> {
    facts.providers.iter().find(|p| p.provider == name)
}

fn by_provider(facts: &PoolFacts) -> BTreeMap<&str, Vec<&StaticFacts>> {
    let mut map: BTreeMap<&str, Vec<&StaticFacts>> = BTreeMap::new();
    for s in &facts.statics {
        map.entry(s.provider.as_str()).or_default().push(s);
    }
    map
}

/// Whether a static IP is expected to be re-checked on a schedule.
fn is_checked(state: IpState) -> bool {
    !matches!(
        state,
        IpState::Retired | IpState::Offline | IpState::ReplaceRequested
    )
}

fn checks(facts: &PoolFacts, th: &Thresholds) -> Vec<Finding> {
    let mut out = Vec::new();
    for (provider, rows) in by_provider(facts) {
        let Some(policy) = provider_of(facts, provider) else {
            continue;
        };
        let limit = policy.recheck_every * th.stale_factor;
        let rows: Vec<_> = rows.into_iter().filter(|r| is_checked(r.state)).collect();
        if rows.is_empty() {
            continue;
        }
        // An IP never checked counts from the moment it entered its state.
        let age = |r: &StaticFacts| {
            let since = r.last_check_at.unwrap_or(r.state_since);
            (facts.now - since).try_into().unwrap_or(Duration::ZERO)
        };
        let stale: Vec<&&StaticFacts> = rows.iter().filter(|r| age(r) > limit).collect();
        let oldest = rows.iter().map(|r| age(r)).max().unwrap_or(Duration::ZERO);
        if stale.is_empty() {
            out.push(finding(
                Level::Ok,
                provider,
                format!(
                    "all {} IPs checked within {} (oldest {} ago)",
                    rows.len(),
                    human(limit),
                    human(oldest)
                ),
            ));
        } else {
            let share = ratio(stale.len(), rows.len());
            out.push(finding(
                if share >= th.stale_crit_share { Level::Crit } else { Level::Warn },
                provider,
                format!(
                    "{} of {} IPs not checked for over {} (re-check every {}, oldest {} ago): is the warmer running?",
                    stale.len(),
                    rows.len(),
                    human(limit),
                    human(policy.recheck_every),
                    human(oldest)
                ),
            ));
        }
    }
    if out.is_empty() {
        out.push(finding(Level::Ok, "pool", "no static IP to check"));
    }
    out
}

fn inventory(facts: &PoolFacts, th: &Thresholds) -> Vec<Finding> {
    let mut out = Vec::new();
    for (provider, rows) in by_provider(facts) {
        let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
        for r in &rows {
            *counts.entry(r.state.as_str()).or_default() += 1;
        }
        let live = rows.iter().filter(|r| r.state != IpState::Retired).count();
        let unhealthy = rows
            .iter()
            .filter(|r| {
                matches!(
                    r.state,
                    IpState::Cooldown
                        | IpState::Quarantined
                        | IpState::Offline
                        | IpState::ReplaceRequested
                )
            })
            .count();
        let replace = counts
            .get(IpState::ReplaceRequested.as_str())
            .copied()
            .unwrap_or(0);
        let share = ratio(unhealthy, live);
        let mut level = share_level(share, th.unhealthy_warn_share, th.unhealthy_crit_share);
        if replace > 0 {
            level = level.max(Level::Warn);
        }
        let states: Vec<String> = counts.iter().map(|(s, n)| format!("{n} {s}")).collect();
        let mut message = format!("{live} IPs: {}", states.join(", "));
        if unhealthy > 0 {
            let _ = write!(message, "; {} ({}) out of rotation", unhealthy, pct(share));
        }
        if replace > 0 {
            message
                .push_str("; replacement requested: see docs/runbooks/009-ip-replace-requested.md");
        }
        out.push(finding(level, provider, message));
    }
    if out.is_empty() {
        out.push(finding(Level::Ok, "pool", "no static IP in the inventory"));
    }
    out
}

/// Nearest-rank percentile of a sorted slice.
fn percentile(sorted: &[u8], p: f64) -> u8 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = (p * sorted.len() as f64).ceil().max(1.0) as usize;
    sorted[rank.min(sorted.len()) - 1]
}

fn reputation(facts: &PoolFacts, th: &Thresholds) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut all = facts.risks.clone();
    all.sort_unstable();
    if all.is_empty() {
        out.push(finding(
            Level::Ok,
            "pool",
            "no reputation score recorded yet",
        ));
    } else {
        out.push(finding(
            Level::Ok,
            "pool",
            format!(
                "{} scored IPs: median risk {}, p90 {}, worst {}",
                all.len(),
                percentile(&all, 0.5),
                percentile(&all, 0.9),
                all[all.len() - 1]
            ),
        ));
    }
    for (provider, rows) in by_provider(facts) {
        let Some(policy) = provider_of(facts, provider) else {
            continue;
        };
        let scored: Vec<u8> = rows
            .iter()
            .filter(|r| r.state != IpState::Retired)
            .filter_map(|r| r.risk)
            .collect();
        if scored.is_empty() {
            continue;
        }
        let risky = scored.iter().filter(|r| **r > policy.max_risk).count();
        let share = ratio(risky, scored.len());
        out.push(finding(
            share_level(share, th.risky_warn_share, th.risky_crit_share),
            provider,
            format!(
                "{risky} of {} scored IPs are above the risk limit {} ({})",
                scored.len(),
                policy.max_risk,
                pct(share)
            ),
        ));
    }
    out
}

fn blocks(facts: &PoolFacts, th: &Thresholds) -> Vec<Finding> {
    let window = human(facts.window);
    let b = &facts.blocks;
    let live = facts
        .statics
        .iter()
        .filter(|s| s.state != IpState::Retired)
        .count();
    if b.signals == 0 {
        return vec![finding(
            Level::Ok,
            "pool",
            format!("no block signal in the last {window}"),
        )];
    }
    let types: Vec<String> = b.by_type.iter().map(|(t, n)| format!("{n} {t}")).collect();
    let mut message = format!(
        "{} block signals on {} IPs in the last {window} ({})",
        b.signals,
        b.ips,
        types.join(", ")
    );
    let level = if live == 0 {
        Level::Ok
    } else {
        let share = ratio(usize::try_from(b.ips).unwrap_or(usize::MAX), live);
        let _ = write!(
            message,
            "; {} of the {live} static IPs",
            pct(share.min(1.0))
        );
        share_level(share, th.blocked_warn_share, th.blocked_crit_share)
    };
    vec![finding(level, "pool", message)]
}

fn rentals(facts: &PoolFacts, th: &Thresholds) -> Vec<Finding> {
    let today = facts.now.date();
    let mut out = Vec::new();
    for (provider, rows) in by_provider(facts) {
        let mut dated: Vec<(i64, &StaticFacts)> = rows
            .iter()
            .filter(|r| r.state != IpState::Retired)
            .filter_map(|r| r.rental_end.map(|end| ((end - today).whole_days(), *r)))
            .collect();
        if dated.is_empty() {
            continue;
        }
        dated.sort_by_key(|(days, r)| (*days, r.ip));
        let fewest = dated[0].0;
        let level = if fewest < th.rental_crit_days {
            Level::Crit
        } else if fewest < th.rental_warn_days {
            Level::Warn
        } else {
            Level::Ok
        };
        let soonest: Vec<String> = dated
            .iter()
            .take(3)
            .map(|(days, r)| {
                format!(
                    "{} ({})",
                    r.ip,
                    if *days < 0 {
                        format!("ended {} days ago", -days)
                    } else {
                        format!("{days} days")
                    }
                )
            })
            .collect();
        out.push(finding(
            level,
            provider,
            format!(
                "fewest days left: {fewest}; soonest: {}",
                soonest.join(", ")
            ),
        ));
    }
    if out.is_empty() {
        out.push(finding(
            Level::Ok,
            "pool",
            "no static IP has a rental end date",
        ));
    }
    out
}

fn budget(facts: &PoolFacts, th: &Thresholds) -> Vec<Finding> {
    let mut out = Vec::new();
    for p in &facts.providers {
        let Some(c) = p.cost else { continue };
        let bytes_limit = c.max_gb_per_day * common::session::BYTES_PER_GB;
        let share = |used: f64, limit: f64| if limit <= 0.0 { 1.0 } else { used / limit };
        let traffic = share(c.bytes_today as f64, bytes_limit);
        let creates = share(
            c.creates_this_hour as f64,
            f64::from(c.max_creates_per_hour),
        );
        let used = traffic.max(creates);
        let level = share_level(used, th.budget_warn, th.budget_crit);
        let mut message = format!(
            "{} used: traffic {:.2} of {} GB today ({}), creates {} of {} this hour ({})",
            pct(used.min(1.0)),
            c.bytes_today as f64 / common::session::BYTES_PER_GB,
            c.max_gb_per_day,
            pct(traffic),
            c.creates_this_hour,
            c.max_creates_per_hour,
            pct(creates)
        );
        if used >= 1.0 {
            message.push_str("; no new session is created until the window resets");
        } else if used >= 0.8 {
            message.push_str("; the warmer only keeps min_ready");
        }
        out.push(finding(level, &p.provider, message));
    }
    if out.is_empty() {
        out.push(finding(
            Level::Ok,
            "pool",
            "no rotating provider meters a budget",
        ));
    }
    out
}

fn gateway(facts: &PoolFacts, th: &Thresholds) -> Vec<Finding> {
    let Some(g) = &facts.gateway else {
        return vec![finding(Level::Ok, "gateway", "not asked (--no-gateway)")];
    };
    let mut out = Vec::new();
    match &g.ready {
        Ok((200, _)) => out.push(finding(Level::Ok, &g.url, "/readyz answers 200")),
        Ok((status, body)) => out.push(finding(
            Level::Crit,
            &g.url,
            format!("/readyz answers {status}: {}", body.trim()),
        )),
        Err(error) => out.push(finding(
            Level::Warn,
            &g.url,
            format!("the gateway ops server cannot be reached from here: {error}"),
        )),
    }
    if let Some(gauges) = &g.gauges {
        if gauges.postgres_down.is_some_and(|v| v > 0.0) {
            out.push(finding(
                Level::Crit,
                &g.url,
                "the gateway reports Postgres down",
            ));
        }
        if gauges.redis_down.is_some_and(|v| v > 0.0) {
            out.push(finding(
                Level::Crit,
                &g.url,
                "the gateway reports Redis down",
            ));
        }
        if !gauges.reload_failed.is_empty() {
            out.push(finding(
                Level::Warn,
                &g.url,
                format!(
                    "the last configuration reload was rejected ({}): the gateway serves the previous one",
                    gauges.reload_failed.join(", ")
                ),
            ));
        }
        if let Some(age) = gauges.snapshot_age_seconds {
            let limit = g.reload_every.as_secs_f64() * th.snapshot_age_factor;
            if age > limit {
                out.push(finding(
                    Level::Warn,
                    &g.url,
                    format!(
                        "the gateway's snapshot is {age:.0} s old (reload every {} s)",
                        g.reload_every.as_secs()
                    ),
                ));
            }
        }
    }
    out
}

impl Assessment {
    pub fn summary(&self) -> BTreeMap<Level, usize> {
        let mut m = BTreeMap::from([(Level::Ok, 0), (Level::Warn, 0), (Level::Crit, 0)]);
        for f in self.sections.iter().flat_map(|s| &s.findings) {
            *m.entry(f.level).or_default() += 1;
        }
        m
    }

    /// The worst level; with `strict` a WARN counts as CRIT.
    pub fn overall(&self, strict: bool) -> Level {
        let worst = self
            .sections
            .iter()
            .flat_map(|s| &s.findings)
            .map(|f| f.level)
            .max()
            .unwrap_or(Level::Ok);
        if strict && worst == Level::Warn {
            Level::Crit
        } else {
            worst
        }
    }

    pub fn exit_code(&self, strict: bool) -> i32 {
        match self.overall(strict) {
            Level::Crit => EXIT_CRIT,
            Level::Warn => EXIT_WARN,
            Level::Ok => EXIT_OK,
        }
    }

    /// Schema 1:
    ///
    /// ```json
    /// {"schema":1,"target":"pool","generated_at":1800000000,"strict":false,
    ///  "overall":"warn","exit_code":2,"summary":{"ok":9,"warn":1,"crit":0},
    ///  "sections":[{"name":"capacity","findings":[{"level":"ok","subject":"p@fr (rotating)","message":"..."}]}]}
    /// ```
    pub fn to_json(&self, strict: bool) -> Value {
        let s = self.summary();
        json!({
            "schema": SCHEMA_VERSION,
            "target": "pool",
            "generated_at": self.generated_at,
            "strict": strict,
            "overall": self.overall(strict),
            "exit_code": self.exit_code(strict),
            "summary": { "ok": s[&Level::Ok], "warn": s[&Level::Warn], "crit": s[&Level::Crit] },
            "sections": self.sections,
        })
    }

    pub fn render(&self, strict: bool) -> String {
        let mut out = String::new();
        let at = OffsetDateTime::from_unix_timestamp(self.generated_at)
            .map_or_else(|_| self.generated_at.to_string(), |t| t.to_string());
        let _ = writeln!(out, "proxyx assess pool ({at})");
        for section in &self.sections {
            let _ = writeln!(out, "\n== {} ==", section.name);
            let width = section
                .findings
                .iter()
                .map(|f| f.subject.len())
                .max()
                .unwrap_or(0);
            for f in &section.findings {
                let _ = writeln!(
                    out,
                    "{:<4}  {:<width$}  {}",
                    f.level.label(),
                    f.subject,
                    f.message
                );
            }
        }
        let s = self.summary();
        let _ = writeln!(
            out,
            "\n{} ok, {} warn, {} crit: {} (exit {})",
            s[&Level::Ok],
            s[&Level::Warn],
            s[&Level::Crit],
            self.overall(strict).label(),
            self.exit_code(strict)
        );
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assess::facts::{BusyUnit, CostFacts, GatewayFacts, GatewayGauges};
    use store::BlockSummary;
    use time::Duration as TimeDuration;

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("time")
    }

    fn partition(provider: &str, kind: Kind, ready: u64, min_ready: u32) -> PartitionFacts {
        PartitionFacts {
            provider: provider.to_owned(),
            region: "fr".to_owned(),
            kind,
            ready,
            leased: 0,
            degraded_free: 0,
            creating: 0,
            min_ready,
            low_watermark: min_ready / 2,
            paused: false,
            busiest: None,
        }
    }

    fn provider(name: &str) -> ProviderFacts {
        ProviderFacts {
            provider: name.to_owned(),
            breaker: Breaker::Closed,
            cost: None,
            recheck_every: Duration::from_secs(3600),
            max_risk: 75,
        }
    }

    fn static_ip(provider: &str, n: u8, state: IpState) -> StaticFacts {
        StaticFacts {
            provider: provider.to_owned(),
            ip: std::net::IpAddr::from([203, 0, 113, n]),
            state,
            state_since: now() - TimeDuration::days(2),
            last_check_at: Some(now() - TimeDuration::minutes(10)),
            rental_end: None,
            risk: Some(10),
        }
    }

    fn healthy() -> PoolFacts {
        PoolFacts {
            now: now(),
            window: Duration::from_secs(3600),
            partitions: vec![
                partition("rot", Kind::Rotating, 12, 10),
                partition("isp", Kind::Static, 10, 8),
            ],
            providers: vec![provider("rot"), provider("isp")],
            statics: (1..=10)
                .map(|n| static_ip("isp", n, IpState::Available))
                .collect(),
            risks: vec![5, 10, 10, 20],
            blocks: BlockSummary::default(),
            gateway: None,
        }
    }

    fn level(a: &Assessment, section: &str, subject: &str) -> Level {
        let s = a
            .sections
            .iter()
            .find(|s| s.name == section)
            .expect("section");
        s.findings
            .iter()
            .find(|f| f.subject.contains(subject))
            .unwrap_or_else(|| panic!("no finding for {subject} in {s:#?}"))
            .level
    }

    fn assess(facts: &PoolFacts) -> Assessment {
        evaluate(facts, &Thresholds::default())
    }

    #[test]
    fn a_healthy_pool_is_all_ok() {
        let a = assess(&healthy());
        assert_eq!(a.overall(false), Level::Ok, "{a:#?}");
        assert_eq!(a.exit_code(false), EXIT_OK);
        assert_eq!(a.summary()[&Level::Crit], 0);
    }

    #[test]
    fn capacity_is_crit_under_the_low_watermark_and_warn_under_min_ready() {
        let mut f = healthy();
        f.partitions[0].ready = 4; // watermark 5, min_ready 10
        assert_eq!(level(&assess(&f), "capacity", "rot@fr"), Level::Crit);
        f.partitions[0].ready = 5;
        assert_eq!(level(&assess(&f), "capacity", "rot@fr"), Level::Warn);
        f.partitions[0].ready = 10;
        assert_eq!(level(&assess(&f), "capacity", "rot@fr"), Level::Ok);
        f.partitions[0].ready = 0;
        f.partitions[0].low_watermark = 0;
        assert_eq!(
            level(&assess(&f), "capacity", "rot@fr"),
            Level::Crit,
            "empty is critical even with no watermark"
        );
        f.partitions[0].min_ready = 0;
        assert_eq!(
            level(&assess(&f), "capacity", "rot@fr"),
            Level::Ok,
            "no target, nothing to miss"
        );
        assert_eq!(assess(&f).exit_code(false), EXIT_OK);
    }

    #[test]
    fn a_paused_partition_warns() {
        let mut f = healthy();
        f.partitions[0].paused = true;
        let a = assess(&f);
        assert_eq!(a.overall(false), Level::Warn);
        assert_eq!(a.exit_code(false), EXIT_WARN);
        assert_eq!(a.exit_code(true), EXIT_CRIT);
    }

    #[test]
    fn lease_use_and_the_busiest_unit_are_judged() {
        let mut f = healthy();
        f.partitions[0].leased = 40;
        f.partitions[0].ready = 10; // 80%
        assert_eq!(level(&assess(&f), "leases", "rot@fr"), Level::Warn);
        f.partitions[0].leased = 190;
        f.partitions[0].ready = 10; // 95%
        assert_eq!(level(&assess(&f), "leases", "rot@fr"), Level::Crit);
        f.partitions[0].leased = 0;
        f.partitions[1].leased = 3;
        f.partitions[1].busiest = Some(BusyUnit {
            ip: [203, 0, 113, 1].into(),
            tunnels: 40,
            limit: 40,
        });
        let busiest = |f: &PoolFacts| {
            assess(f).sections[1]
                .findings
                .iter()
                .find(|x| x.message.contains("busiest"))
                .expect("busiest")
                .level
        };
        assert_eq!(busiest(&f), Level::Warn);
        f.partitions[1].busiest = Some(BusyUnit {
            ip: [203, 0, 113, 1].into(),
            tunnels: 39,
            limit: 40,
        });
        assert_eq!(busiest(&f), Level::Ok);
        f.partitions[1].busiest = Some(BusyUnit {
            ip: [203, 0, 113, 1].into(),
            tunnels: 80,
            limit: 40,
        });
        assert_eq!(busiest(&f), Level::Crit);
    }

    #[test]
    fn an_open_or_half_open_breaker_warns() {
        let mut f = healthy();
        f.providers[0].breaker = Breaker::Open;
        let a = assess(&f);
        assert_eq!(level(&a, "breakers", "rot"), Level::Warn);
        assert_eq!(level(&a, "breakers", "isp"), Level::Ok);
        assert_eq!(a.overall(false), Level::Warn);
        f.providers[0].breaker = Breaker::HalfOpen;
        assert_eq!(level(&assess(&f), "breakers", "rot"), Level::Warn);
    }

    #[test]
    fn stale_checks_warn_and_a_mostly_stale_provider_is_critical() {
        let mut f = healthy();
        // limit = 3 x 1h
        f.statics[0].last_check_at = Some(now() - TimeDuration::hours(4));
        assert_eq!(level(&assess(&f), "checks", "isp"), Level::Warn);
        for s in &mut f.statics[..6] {
            s.last_check_at = Some(now() - TimeDuration::hours(5));
        }
        assert_eq!(level(&assess(&f), "checks", "isp"), Level::Crit);
        // exactly at the limit is still fresh; never checked counts from the state change
        let mut f = healthy();
        f.statics[0].last_check_at = Some(now() - TimeDuration::hours(3));
        assert_eq!(level(&assess(&f), "checks", "isp"), Level::Ok);
        f.statics[1].last_check_at = None;
        assert_eq!(
            level(&assess(&f), "checks", "isp"),
            Level::Warn,
            "state_since is two days old"
        );
        // retired and offline rows are not expected to be checked
        f.statics[1].state = IpState::Retired;
        assert_eq!(level(&assess(&f), "checks", "isp"), Level::Ok);
    }

    #[test]
    fn unhealthy_inventory_states_are_counted() {
        let mut f = healthy();
        f.statics[0].state = IpState::Quarantined;
        f.statics[1].state = IpState::Quarantined;
        assert_eq!(
            level(&assess(&f), "inventory", "isp"),
            Level::Warn,
            "20% out of rotation"
        );
        for s in &mut f.statics[..5] {
            s.state = IpState::Cooldown;
        }
        assert_eq!(level(&assess(&f), "inventory", "isp"), Level::Crit);
        let mut f = healthy();
        f.statics[0].state = IpState::ReplaceRequested;
        let a = assess(&f);
        assert_eq!(level(&a, "inventory", "isp"), Level::Warn);
        assert!(
            a.sections[4].findings[0]
                .message
                .contains("009-ip-replace-requested")
        );
    }

    #[test]
    fn reputation_compares_scores_with_the_risk_limit() {
        let mut f = healthy();
        assert_eq!(level(&assess(&f), "reputation", "isp"), Level::Ok);
        f.statics[0].risk = Some(90);
        assert_eq!(
            level(&assess(&f), "reputation", "isp"),
            Level::Warn,
            "10% above 75"
        );
        for s in &mut f.statics[..3] {
            s.risk = Some(76);
        }
        assert_eq!(level(&assess(&f), "reputation", "isp"), Level::Crit, "30%");
        let a = assess(&f);
        let pool = &a.sections[5].findings[0].message;
        assert!(
            pool.contains("4 scored IPs")
                && pool.contains("median risk 10")
                && pool.contains("worst 20"),
            "{pool}"
        );
        // unscored IPs are left out
        let mut f = healthy();
        for s in &mut f.statics {
            s.risk = None;
        }
        assert_eq!(assess(&f).sections[5].findings.len(), 1);
    }

    #[test]
    fn block_signals_are_a_share_of_the_static_pool() {
        let mut f = healthy();
        f.blocks = BlockSummary {
            signals: 3,
            ips: 2,
            by_type: vec![("challenge".into(), 3)],
        };
        let a = assess(&f);
        assert_eq!(level(&a, "blocks", "pool"), Level::Warn, "2 of 10 IPs");
        assert!(a.sections[6].findings[0].message.contains("3 challenge"));
        f.blocks.ips = 5;
        assert_eq!(level(&assess(&f), "blocks", "pool"), Level::Crit);
        f.blocks.ips = 1;
        assert_eq!(level(&assess(&f), "blocks", "pool"), Level::Ok);
        f.blocks = BlockSummary::default();
        assert!(
            assess(&f).sections[6].findings[0]
                .message
                .contains("no block signal in the last 1h")
        );
    }

    #[test]
    fn rentals_warn_at_30_days_and_are_critical_under_14_or_past() {
        let mut f = healthy();
        let end = |days: i64| Some((now() + TimeDuration::days(days)).date());
        f.statics[0].rental_end = end(60);
        assert_eq!(level(&assess(&f), "rentals", "isp"), Level::Ok);
        f.statics[0].rental_end = end(29);
        assert_eq!(level(&assess(&f), "rentals", "isp"), Level::Warn);
        f.statics[0].rental_end = end(30);
        assert_eq!(level(&assess(&f), "rentals", "isp"), Level::Ok);
        f.statics[0].rental_end = end(13);
        assert_eq!(level(&assess(&f), "rentals", "isp"), Level::Crit);
        f.statics[0].rental_end = end(-2);
        let a = assess(&f);
        assert_eq!(level(&a, "rentals", "isp"), Level::Crit);
        assert!(
            a.sections[7].findings[0]
                .message
                .contains("ended 2 days ago")
        );
        f.statics[0].state = IpState::Retired;
        assert_eq!(
            level(&assess(&f), "rentals", "pool"),
            Level::Ok,
            "retired rentals do not count"
        );
    }

    #[test]
    fn the_budget_is_the_larger_of_traffic_and_creates() {
        let mut f = healthy();
        let cost = |bytes_gb: f64, creates: u64| CostFacts {
            bytes_today: (bytes_gb * 1e9) as u64,
            creates_this_hour: creates,
            max_gb_per_day: 10.0,
            max_creates_per_hour: 100,
        };
        f.providers[0].cost = Some(cost(1.0, 10));
        assert_eq!(level(&assess(&f), "budget", "rot"), Level::Ok);
        f.providers[0].cost = Some(cost(8.0, 10));
        assert_eq!(level(&assess(&f), "budget", "rot"), Level::Warn);
        f.providers[0].cost = Some(cost(1.0, 90));
        assert_eq!(level(&assess(&f), "budget", "rot"), Level::Crit);
        f.providers[0].cost = Some(cost(1.0, 100));
        assert!(
            assess(&f).sections[8].findings[0]
                .message
                .contains("until the window resets")
        );
        f.providers[0].cost = Some(CostFacts {
            bytes_today: 0,
            creates_this_hour: 0,
            max_gb_per_day: 0.0,
            max_creates_per_hour: 100,
        });
        assert_eq!(
            level(&assess(&f), "budget", "rot"),
            Level::Crit,
            "a limit of zero is used up"
        );
    }

    #[test]
    fn the_gateway_is_judged_by_readyz_and_its_gauges() {
        let mut f = healthy();
        let gw =
            |ready: Result<(u16, String), String>, gauges: Option<GatewayGauges>| GatewayFacts {
                url: "http://127.0.0.1:8888".into(),
                ready,
                gauges,
                reload_every: Duration::from_secs(30),
            };
        f.gateway = Some(gw(Ok((200, "ok".into())), None));
        assert_eq!(level(&assess(&f), "gateway", "8888"), Level::Ok);
        f.gateway = Some(gw(Ok((503, "redis unavailable\n".into())), None));
        let a = assess(&f);
        assert_eq!(level(&a, "gateway", "8888"), Level::Crit);
        assert!(
            a.sections[9].findings[0]
                .message
                .contains("redis unavailable")
        );
        f.gateway = Some(gw(Err("connection failed".into()), None));
        assert_eq!(level(&assess(&f), "gateway", "8888"), Level::Warn);
        f.gateway = Some(gw(
            Ok((200, "ok".into())),
            Some(GatewayGauges {
                postgres_down: Some(1.0),
                redis_down: Some(0.0),
                reload_failed: vec!["inventory".into()],
                snapshot_age_seconds: Some(400.0),
            }),
        ));
        let a = assess(&f);
        let g = &a.sections[9].findings;
        assert!(
            g.iter()
                .any(|x| x.level == Level::Crit && x.message.contains("Postgres down"))
        );
        assert!(
            g.iter()
                .any(|x| x.level == Level::Warn && x.message.contains("inventory"))
        );
        assert!(
            g.iter()
                .any(|x| x.level == Level::Warn && x.message.contains("400 s old"))
        );
        assert!(!g.iter().any(|x| x.message.contains("Redis down")));
    }

    #[test]
    fn percentiles_use_the_nearest_rank() {
        let v = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        assert_eq!(percentile(&v, 0.5), 5);
        assert_eq!(percentile(&v, 0.9), 9);
        assert_eq!(percentile(&v, 1.0), 10);
        assert_eq!(percentile(&[], 0.5), 0);
    }

    #[test]
    fn the_json_schema_is_stable() {
        let mut f = healthy();
        f.partitions.truncate(1);
        f.providers.truncate(1);
        f.statics.clear();
        f.risks.clear();
        f.partitions[0].ready = 4;
        let json = assess(&f).to_json(false);
        assert_eq!(json["schema"], 1);
        assert_eq!(json["target"], "pool");
        assert_eq!(json["generated_at"], 1_800_000_000);
        assert_eq!(json["strict"], false);
        assert_eq!(json["overall"], "crit");
        assert_eq!(json["exit_code"], 1);
        assert_eq!(json["summary"], json!({"ok": 9, "warn": 0, "crit": 1}));
        let names: Vec<&str> = json["sections"]
            .as_array()
            .expect("sections")
            .iter()
            .map(|s| s["name"].as_str().expect("name"))
            .collect();
        assert_eq!(
            names,
            [
                "capacity",
                "leases",
                "breakers",
                "checks",
                "inventory",
                "reputation",
                "blocks",
                "rentals",
                "budget",
                "gateway"
            ]
        );
        assert_eq!(
            json["sections"][0]["findings"][0],
            json!({
                "level": "crit",
                "subject": "rot@fr (rotating)",
                "message": "4 ready, min_ready 10, low watermark 5"
            })
        );
    }

    #[test]
    fn the_table_has_sections_levels_and_the_exit_code() {
        let mut f = healthy();
        f.providers[0].breaker = Breaker::Open;
        let text = assess(&f).render(false);
        assert!(text.starts_with("proxyx assess pool (2027-01-15"), "{text}");
        assert!(text.contains("\n== breakers ==\n"), "{text}");
        assert!(text.contains("WARN  rot  breaker open"), "{text}");
        assert!(text.contains("OK    isp  breaker closed"), "{text}");
        assert!(text.ends_with("WARN (exit 2)\n"), "{text}");
    }
}
