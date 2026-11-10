//! A merged policy with every default applied and every rule checked.

use std::collections::BTreeMap;
use std::fmt::Display;
use std::time::Duration;

use common::types::{Kind, ProviderId, Region, StickyScope};

use crate::doc::{AfterRelease, OnEmpty, OnScoreUnavailable, PolicyDoc, Pool};
use crate::error::PolicyError;

const SECS_PER_MIN: u64 = 60;
const SECS_PER_HOUR: u64 = 3_600;

/// Ready target of one region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadyTarget {
    pub min_ready: u32,
    pub max_ready: u32,
    pub low_watermark: u32,
}

/// Ready sessions (static: healthy IPs) per region.
#[derive(Debug, Clone, PartialEq)]
pub struct Capacity {
    pub min_ready: u32,
    /// Unset: twice the region's `min_ready`.
    pub max_ready: Option<u32>,
    /// Unset: half the region's `min_ready`.
    pub low_watermark: Option<u32>,
    /// How long ready must stay below the low watermark before the warmer
    /// sets `cache_low`, which the cache-low alert fires on (default 2m).
    pub low_for: Duration,
    pub min_ready_by_region: BTreeMap<Region, u32>,
}

impl Capacity {
    /// The `min_ready` of `region`: an override for the exact region, else for
    /// its country, else the policy value.
    fn min_ready_for(&self, region: &Region) -> u32 {
        self.min_ready_by_region
            .get(region)
            .or_else(|| {
                let country = Region::new(region.country(), None).ok()?;
                self.min_ready_by_region.get(&country)
            })
            .copied()
            .unwrap_or(self.min_ready)
    }

    pub fn target(&self, region: &Region) -> ReadyTarget {
        let min_ready = self.min_ready_for(region);
        ReadyTarget {
            min_ready,
            max_ready: self
                .max_ready
                .unwrap_or_else(|| min_ready.saturating_mul(2)),
            low_watermark: self.low_watermark.unwrap_or(min_ready / 2),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Criteria {
    pub max_risk: u8,
    pub max_ttfb_ms: u32,
    pub max_load_ms: u32,
    pub min_success: f64,
    pub browser_sample: f64,
    pub verdict_max_age: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OnEmptyByKind {
    pub static_ips: OnEmpty,
    pub rotating: OnEmpty,
}

impl OnEmptyByKind {
    pub fn for_kind(&self, kind: Kind) -> OnEmpty {
        match kind {
            Kind::Static => self.static_ips,
            Kind::Rotating => self.rotating,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct BlockRules {
    pub target_cooldown: Duration,
    pub escalate_targets: u32,
    pub escalate_signals: u32,
    pub signal_window: Duration,
    pub max_cooldown_share: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StaticRules {
    pub cooldown: Duration,
    pub quarantine_after: u32,
    pub retest_every: Duration,
    pub recheck_every: Duration,
    pub replace_after_checks: u32,
    pub replace_min_sources: u32,
    pub replace_blocked_share: f64,
    pub replace_quarantine_for: Duration,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MobileBoxRules {
    pub rotate_attempts: u32,
    pub rotate_timeout: Duration,
    pub rotate_min_interval: Duration,
    pub rotate_per_hour: u32,
    pub drain_wait: Duration,
    pub offline_after: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stability {
    pub changes_per_hour: u32,
    pub drops_per_hour: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RotatingRules {
    pub ready_ttl: Duration,
    /// Unset: 80% of the provider maximum, see [`RotatingRules::max_age_for`].
    pub max_age: Option<Duration>,
    pub min_remaining: Duration,
    pub after_release: AfterRelease,
    pub refill_concurrency: u32,
    pub refill_rate: u32,
    pub headroom: u32,
    /// Add the extra target the measured lease rate and create latency ask
    /// for; `headroom` is the floor.
    pub headroom_auto: bool,
    pub keepalive: Duration,
    pub recheck_every: Duration,
    pub stability: Stability,
}

impl RotatingRules {
    /// Total life of a session of a provider that allows `provider_max`: the
    /// configured `max_age` or 80% of the maximum, never more than the
    /// provider keeps the session.
    pub fn max_age_for(&self, provider_max: Duration) -> Duration {
        self.max_age
            .unwrap_or_else(|| provider_max.mul_f64(0.8))
            .min(provider_max)
    }

    /// A session must stay leasable for part of its life: `min_remaining`
    /// has to be below the shortest life a new session gets (the warmer
    /// shortens it by up to 20%), or the lease skips every session. The
    /// check cannot be made without the provider's maximum, so it runs where
    /// policies meet adapters, not in [`resolve`].
    pub fn check_life(&self, provider_max: Duration) -> Result<(), String> {
        let shortest = self.max_age_for(provider_max).mul_f64(0.8);
        if self.min_remaining >= shortest {
            return Err(format!(
                "rotating.min_remaining {}s is not below the shortest life {}s of a session \
                 (80% of max_age {}s); no session could ever be leased",
                self.min_remaining.as_secs(),
                shortest.as_secs(),
                self.max_age_for(provider_max).as_secs(),
            ));
        }
        Ok(())
    }
}

/// Spend. Already at or below the `limits` ceilings.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Cost {
    pub max_gb_per_day: f64,
    pub max_creates_per_hour: u32,
    pub fair_use_gb_per_ip_month: f64,
}

/// Ceilings that no scope can raise. `None`: no ceiling.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Limits {
    pub max_gb_per_day: Option<f64>,
    pub max_creates_per_hour: Option<u32>,
    pub fair_use_gb_per_ip_month: Option<f64>,
    /// Traffic one org may use per UTC day. `None`: no budget.
    pub org_max_gb_per_day: Option<f64>,
}

/// The policy that applies to one org on one provider.
#[derive(Debug, Clone, PartialEq)]
pub struct EffectivePolicy {
    pub kinds: Vec<Kind>,
    /// Provider order. Empty: every configured provider.
    pub providers: Vec<ProviderId>,
    pub regions: Vec<Region>,
    pub pool: Pool,
    pub capacity: Capacity,
    pub criteria: Criteria,
    pub on_score_unavailable: OnScoreUnavailable,
    pub lease_ttl: Duration,
    pub on_empty: OnEmptyByKind,
    pub lease_wait: Duration,
    pub create_deadline: Duration,
    /// Cap on orgs per IP or session. `None`: no cap. A soft limit: broken
    /// (after `rest_after_release`, before `max_conns_per_ip`) when no unit is
    /// left within the limits.
    pub orgs_hard: Option<u32>,
    /// Tunnels per IP. `None`: 80% of the provider limit, see [`Self::conns_per_ip`].
    /// A soft limit: broken (third) when no unit is left within the limits,
    /// up to twice the limit per IP; past that the IP is not leased.
    pub max_conns_per_ip: Option<u32>,
    /// Rest of a unit between two orgs. A soft limit: the first one broken
    /// when no unit is left within the limits.
    pub rest_after_release: Duration,
    /// Cap on open tunnels per org. `None`: no cap.
    pub max_tunnels_per_org: Option<u32>,
    pub sticky_scope: StickyScope,
    pub block: BlockRules,
    pub static_ips: StaticRules,
    pub mobile_box: MobileBoxRules,
    pub rotating: RotatingRules,
    pub cost: Cost,
    pub limits: Limits,
}

impl EffectivePolicy {
    /// How often a ready rotating session gets a keepalive:
    /// `min(rotating.keepalive, lease_ttl / 2)`, so it never idles as long as
    /// a lease lives. The warmer and every creator of a session job share it.
    pub fn keepalive_interval(&self) -> Duration {
        self.rotating.keepalive.min(self.lease_ttl / 2)
    }

    /// Tunnels per IP for a provider that allows `provider_limit`.
    pub fn conns_per_ip(&self, provider_limit: u32) -> u32 {
        self.max_conns_per_ip.unwrap_or_else(|| {
            let eighty_percent = u64::from(provider_limit) * 4 / 5;
            u32::try_from(eighty_percent).unwrap_or(u32::MAX).max(1)
        })
    }
}

/// Error builder for one merged combination.
struct Check<'a>(&'a str);

impl Check<'_> {
    fn invalid(&self, field: &'static str, reason: impl Into<String>) -> PolicyError {
        PolicyError::Invalid {
            context: self.0.to_owned(),
            field,
            reason: reason.into(),
        }
    }

    fn positive(&self, field: &'static str, d: Duration) -> Result<Duration, PolicyError> {
        if d.is_zero() {
            Err(self.invalid(field, "must be above 0"))
        } else {
            Ok(d)
        }
    }

    /// `v` or `default_secs`, above 0.
    fn dur(
        &self,
        field: &'static str,
        v: Option<Duration>,
        default_secs: u64,
    ) -> Result<Duration, PolicyError> {
        self.positive(field, v.unwrap_or(secs(default_secs)))
    }

    fn at_least_one(&self, field: &'static str, n: u32) -> Result<u32, PolicyError> {
        if n == 0 {
            Err(self.invalid(field, "must be at least 1"))
        } else {
            Ok(n)
        }
    }

    /// `v` or `default`, at least 1.
    fn count(&self, field: &'static str, v: Option<u32>, default: u32) -> Result<u32, PolicyError> {
        self.at_least_one(field, v.unwrap_or(default))
    }

    /// A share in `[0, 1]`, or in `(0, 1]` when `open_low`.
    fn share(&self, field: &'static str, v: f64, open_low: bool) -> Result<f64, PolicyError> {
        if v.is_finite() && v <= 1.0 && (if open_low { v > 0.0 } else { v >= 0.0 }) {
            Ok(v)
        } else {
            let range = if open_low {
                "above 0 up to 1"
            } else {
                "0 to 1"
            };
            Err(self.invalid(field, format!("{v} is not {range}")))
        }
    }

    /// A set size must be finite and at least 0; unset passes.
    fn gb(&self, field: &'static str, v: Option<f64>) -> Result<(), PolicyError> {
        match v {
            Some(v) if !(v.is_finite() && v >= 0.0) => {
                Err(self.invalid(field, format!("{v} is not a finite size of at least 0")))
            }
            _ => Ok(()),
        }
    }

    fn distinct<T: PartialEq + Display>(
        &self,
        field: &'static str,
        items: &[T],
    ) -> Result<(), PolicyError> {
        for (i, a) in items.iter().enumerate() {
            if items[..i].contains(a) {
                return Err(self.invalid(field, format!("{a} is listed twice")));
            }
        }
        Ok(())
    }

    fn ceiling<T: PartialOrd + Copy + Display>(
        &self,
        field: &'static str,
        value: Option<T>,
        ceiling: Option<T>,
        default: T,
    ) -> Result<T, PolicyError> {
        match (value, ceiling) {
            (Some(v), Some(c)) if v > c => Err(PolicyError::AboveCeiling {
                context: self.0.to_owned(),
                field,
                value: v.to_string(),
                ceiling: c.to_string(),
            }),
            (Some(v), _) => Ok(v),
            (None, Some(c)) if c < default => Ok(c),
            (None, _) => Ok(default),
        }
    }
}

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

/// Apply defaults to a merged document and check it. `context` names the
/// policies that were merged, for error messages.
pub(crate) fn resolve(doc: &PolicyDoc, context: &str) -> Result<EffectivePolicy, PolicyError> {
    let c = Check(context);

    let kinds = doc
        .kinds
        .clone()
        .unwrap_or_else(|| vec![Kind::Static, Kind::Rotating]);
    if kinds.is_empty() {
        return Err(c.invalid("kinds", "must not be empty"));
    }
    c.distinct("kinds", &kinds)?;

    let providers = doc.providers.clone().unwrap_or_default();
    if doc.providers.as_ref().is_some_and(Vec::is_empty) {
        return Err(c.invalid(
            "providers",
            "must not be empty; leave it unset for all providers",
        ));
    }
    c.distinct("providers", &providers)?;

    let regions = doc.regions.clone().unwrap_or_default();
    if regions.is_empty() {
        return Err(c.invalid("regions", "required and must not be empty"));
    }
    c.distinct("regions", &regions)?;

    // A partition has no org dimension, so a private pool of the shared
    // partitions cannot be honoured. An org's own upstream is an org-owned
    // unit (a `customer` adapter), which only that org may lease.
    if doc.pool == Some(Pool::Private) {
        return Err(c.invalid(
            "pool",
            "\"private\" is not supported: use an org-owned customer upstream for a unit one org alone may use",
        ));
    }

    let capacity = Capacity {
        min_ready: doc.min_ready.unwrap_or(10),
        max_ready: doc.max_ready,
        low_watermark: doc.low_watermark,
        low_for: doc.low_for.unwrap_or(secs(2 * SECS_PER_MIN)),
        min_ready_by_region: doc.min_ready_by_region.clone(),
    };
    for min in std::iter::once(&capacity.min_ready).chain(capacity.min_ready_by_region.values()) {
        if let Some(max) = capacity.max_ready
            && *min > max
        {
            return Err(c.invalid("min_ready", format!("{min} is above max_ready {max}")));
        }
        if let Some(low) = capacity.low_watermark
            && low > *min
        {
            return Err(c.invalid("low_watermark", format!("{low} is above min_ready {min}")));
        }
    }

    let cr = &doc.criteria;
    let criteria = Criteria {
        max_risk: cr.max_risk.unwrap_or(75),
        max_ttfb_ms: cr.max_ttfb_ms.unwrap_or(3_000),
        max_load_ms: cr.max_load_ms.unwrap_or(10_000),
        min_success: c.share(
            "criteria.min_success",
            cr.min_success.unwrap_or(0.66),
            false,
        )?,
        browser_sample: c.share(
            "criteria.browser_sample",
            cr.browser_sample.unwrap_or(0.05),
            false,
        )?,
        verdict_max_age: c.dur(
            "criteria.verdict_max_age",
            cr.verdict_max_age,
            24 * SECS_PER_HOUR,
        )?,
    };
    if criteria.max_risk > 100 {
        return Err(c.invalid("criteria.max_risk", "must be 0 to 100"));
    }
    c.at_least_one("criteria.max_ttfb_ms", criteria.max_ttfb_ms)?;
    c.at_least_one("criteria.max_load_ms", criteria.max_load_ms)?;

    let on_empty = OnEmptyByKind {
        static_ips: doc.on_empty.static_ips.unwrap_or(OnEmpty::Wait),
        rotating: doc.on_empty.rotating.unwrap_or(OnEmpty::Create),
    };
    if on_empty.static_ips == OnEmpty::Create {
        return Err(c.invalid(
            "on_empty.static",
            "static IPs cannot be created; use wait or fail",
        ));
    }

    for (field, v) in [
        ("orgs_hard", doc.orgs_hard),
        ("max_conns_per_ip", doc.max_conns_per_ip),
        ("max_tunnels_per_org", doc.max_tunnels_per_org),
    ] {
        if let Some(n) = v {
            c.at_least_one(field, n)?;
        }
    }

    let b = &doc.block;
    let block = BlockRules {
        target_cooldown: c.dur(
            "block.target_cooldown",
            b.target_cooldown,
            30 * SECS_PER_MIN,
        )?,
        escalate_targets: c.count("block.escalate_targets", b.escalate_targets, 3)?,
        escalate_signals: c.count("block.escalate_signals", b.escalate_signals, 5)?,
        signal_window: c.dur("block.signal_window", b.signal_window, 30 * SECS_PER_MIN)?,
        max_cooldown_share: c.share(
            "block.max_cooldown_share",
            b.max_cooldown_share.unwrap_or(0.5),
            true,
        )?,
    };

    let s = &doc.static_ips;
    let static_ips = StaticRules {
        cooldown: c.dur("static.cooldown", s.cooldown, 15 * SECS_PER_MIN)?,
        quarantine_after: c.count("static.quarantine_after", s.quarantine_after, 3)?,
        retest_every: c.dur("static.retest_every", s.retest_every, 6 * SECS_PER_HOUR)?,
        recheck_every: c.dur("static.recheck_every", s.recheck_every, 30 * SECS_PER_MIN)?,
        replace_after_checks: c.count("static.replace_after_checks", s.replace_after_checks, 3)?,
        replace_min_sources: c.count("static.replace_min_sources", s.replace_min_sources, 2)?,
        replace_blocked_share: c.share(
            "static.replace_blocked_share",
            s.replace_blocked_share.unwrap_or(0.6),
            true,
        )?,
        replace_quarantine_for: c.dur(
            "static.replace_quarantine_for",
            s.replace_quarantine_for,
            24 * SECS_PER_HOUR,
        )?,
    };

    let m = &doc.mobile_box;
    let mobile_box = MobileBoxRules {
        rotate_attempts: c.count("mobile_box.rotate_attempts", m.rotate_attempts, 3)?,
        rotate_timeout: c.dur("mobile_box.rotate_timeout", m.rotate_timeout, 120)?,
        rotate_min_interval: m.rotate_min_interval.unwrap_or(secs(60)),
        rotate_per_hour: c.count("mobile_box.rotate_per_hour", m.rotate_per_hour, 6)?,
        drain_wait: m.drain_wait.unwrap_or(secs(60)),
        offline_after: c.dur("mobile_box.offline_after", m.offline_after, 60)?,
    };

    let r = &doc.rotating;
    let rotating = RotatingRules {
        ready_ttl: c.dur("rotating.ready_ttl", r.ready_ttl, 30 * SECS_PER_MIN)?,
        max_age: r
            .max_age
            .map(|d| c.positive("rotating.max_age", d))
            .transpose()?,
        min_remaining: c.dur("rotating.min_remaining", r.min_remaining, 5 * SECS_PER_MIN)?,
        after_release: r.after_release.unwrap_or_default(),
        refill_concurrency: c.count("rotating.refill_concurrency", r.refill_concurrency, 2)?,
        refill_rate: c.count("rotating.refill_rate", r.refill_rate, 10)?,
        headroom: r.headroom.unwrap_or(0),
        headroom_auto: r.headroom_auto.unwrap_or(false),
        keepalive: c.dur("rotating.keepalive", r.keepalive, 30)?,
        recheck_every: c.dur("rotating.recheck_every", r.recheck_every, 5 * SECS_PER_MIN)?,
        stability: Stability {
            changes_per_hour: c.count(
                "rotating.stability.changes_per_hour",
                r.stability.changes_per_hour,
                2,
            )?,
            drops_per_hour: c.count(
                "rotating.stability.drops_per_hour",
                r.stability.drops_per_hour,
                3,
            )?,
        },
    };
    if rotating
        .max_age
        .is_some_and(|max| rotating.min_remaining >= max)
    {
        return Err(c.invalid("rotating.min_remaining", "must be below rotating.max_age"));
    }

    let (l, k) = (&doc.limits, &doc.cost);
    c.gb("limits.max_gb_per_day", l.max_gb_per_day)?;
    c.gb(
        "limits.fair_use_gb_per_ip_month",
        l.fair_use_gb_per_ip_month,
    )?;
    c.gb("limits.org_max_gb_per_day", l.org_max_gb_per_day)?;
    c.gb("cost.max_gb_per_day", k.max_gb_per_day)?;
    c.gb("cost.fair_use_gb_per_ip_month", k.fair_use_gb_per_ip_month)?;
    let limits = Limits {
        max_gb_per_day: l.max_gb_per_day,
        max_creates_per_hour: l.max_creates_per_hour,
        fair_use_gb_per_ip_month: l.fair_use_gb_per_ip_month,
        org_max_gb_per_day: l.org_max_gb_per_day,
    };
    let cost = Cost {
        max_gb_per_day: c.ceiling(
            "cost.max_gb_per_day",
            k.max_gb_per_day,
            l.max_gb_per_day,
            5.0,
        )?,
        max_creates_per_hour: c.ceiling(
            "cost.max_creates_per_hour",
            k.max_creates_per_hour,
            l.max_creates_per_hour,
            600,
        )?,
        fair_use_gb_per_ip_month: c.ceiling(
            "cost.fair_use_gb_per_ip_month",
            k.fair_use_gb_per_ip_month,
            l.fair_use_gb_per_ip_month,
            80.0,
        )?,
    };

    Ok(EffectivePolicy {
        kinds,
        providers,
        regions,
        pool: doc.pool.unwrap_or_default(),
        capacity,
        criteria,
        on_score_unavailable: doc.on_score_unavailable.unwrap_or_default(),
        lease_ttl: c.dur("lease_ttl", doc.lease_ttl, 10 * SECS_PER_MIN)?,
        on_empty,
        lease_wait: doc.lease_wait.unwrap_or(secs(3)),
        create_deadline: c.dur("create_deadline", doc.create_deadline, 6)?,
        orgs_hard: doc.orgs_hard,
        max_conns_per_ip: doc.max_conns_per_ip,
        rest_after_release: doc.rest_after_release.unwrap_or(secs(30)),
        max_tunnels_per_org: doc.max_tunnels_per_org,
        sticky_scope: doc.sticky_scope.unwrap_or_default(),
        block,
        static_ips,
        mobile_box,
        rotating,
        cost,
        limits,
    })
}
