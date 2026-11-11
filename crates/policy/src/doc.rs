//! The policy file schema: every field optional, unknown fields refused.
//!
//! A document is one `[[policy]]` table. Several documents combine field by
//! field in [`PolicyDoc::overlay`]; defaults and validation live in
//! `effective`.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use common::types::{Kind, ProviderId, Region, StickyScope};
use serde::{Deserialize, Serialize};

use crate::error::PolicyError;

/// What a policy covers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    /// Every org and provider.
    #[default]
    Global,
    /// One provider (`match` is the provider id).
    RouteClass,
    /// One org (`match` is the org id).
    Org,
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Scope::Global => "global",
            Scope::RouteClass => "route_class",
            Scope::Org => "org",
        })
    }
}

/// Whether a partition serves several orgs. Only `shared` is a valid policy
/// value: `pool = "private"` is refused at load, because partitions have no
/// org dimension (a unit one org alone may lease is an org-owned customer
/// unit). `Private` stays as an org-block scope (`pool:private`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Pool {
    #[default]
    Shared,
    Private,
}

/// What the gateway does when no unit can be leased.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnEmpty {
    /// Open a new session inside `create_deadline` (rotating only).
    Create,
    /// Wait up to `lease_wait` for a free or shareable unit.
    Wait,
    /// Refuse at once.
    Fail,
}

/// What to do when every reputation scorer is down and no cached score exists.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnScoreUnavailable {
    /// Treat the IP as clean and raise an alert.
    #[default]
    Allow,
    /// Treat the IP as unverified: it is not leased.
    Deny,
}

/// What happens to a rotating session when its lease ends.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AfterRelease {
    #[default]
    Drain,
    ReuseSameOrg,
}

mod opt_secs {
    use std::time::Duration;

    use common::config::humantime_secs;
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serializer};

    /// Longest policy duration. A larger value is a typo, and callers add
    /// these to a clock time (`OffsetDateTime + Duration` panics out of range).
    const MAX: Duration = Duration::from_secs(366 * 86_400);

    #[derive(Deserialize)]
    #[serde(transparent)]
    struct Secs(#[serde(with = "humantime_secs")] Duration);

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Duration>, D::Error> {
        match Option::<Secs>::deserialize(d)? {
            Some(Secs(v)) if v > MAX => Err(D::Error::custom(format!(
                "duration {}s is above the limit of 366 days",
                v.as_secs()
            ))),
            other => Ok(other.map(|s| s.0)),
        }
    }

    pub fn serialize<S: Serializer>(v: &Option<Duration>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(d) => s.serialize_u64(d.as_secs()),
            None => s.serialize_none(),
        }
    }
}

/// Reputation and quality thresholds for a candidate IP or session.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CriteriaDoc {
    /// Highest accepted reputation risk, 0 to 100 (`rotate_at`).
    pub max_risk: Option<u8>,
    pub max_ttfb_ms: Option<u32>,
    pub max_load_ms: Option<u32>,
    /// Lowest accepted share of successful probe requests, 0 to 1.
    pub min_success: Option<f64>,
    /// Share of candidates that also get a browser test, 0 to 1.
    pub browser_sample: Option<f64>,
    #[serde(default, with = "opt_secs")]
    pub verdict_max_age: Option<Duration>,
}

/// `on_empty` per kind. Static default `wait`, rotating default `create`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OnEmptyDoc {
    #[serde(rename = "static")]
    pub static_ips: Option<OnEmpty>,
    pub rotating: Option<OnEmpty>,
}

/// Block rules.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockDoc {
    #[serde(default, with = "opt_secs")]
    pub target_cooldown: Option<Duration>,
    /// Distinct targets that block an IP for all targets.
    pub escalate_targets: Option<u32>,
    /// Signals that block an IP for all targets.
    pub escalate_signals: Option<u32>,
    #[serde(default, with = "opt_secs")]
    pub signal_window: Option<Duration>,
    /// Share of a partition that may be cooled before escalation stops, above 0 up to 1.
    pub max_cooldown_share: Option<f64>,
}

/// Static IP care and replacement rule.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticDoc {
    #[serde(default, with = "opt_secs")]
    pub cooldown: Option<Duration>,
    /// IP-wide blocks within 1 h that quarantine an IP.
    pub quarantine_after: Option<u32>,
    #[serde(default, with = "opt_secs")]
    pub retest_every: Option<Duration>,
    #[serde(default, with = "opt_secs")]
    pub recheck_every: Option<Duration>,
    pub replace_after_checks: Option<u32>,
    pub replace_min_sources: Option<u32>,
    /// Share of test targets that block an IP before replacement, above 0 up to 1.
    pub replace_blocked_share: Option<f64>,
    #[serde(default, with = "opt_secs")]
    pub replace_quarantine_for: Option<Duration>,
}

/// SIM box reset and health limits.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MobileBoxDoc {
    pub rotate_attempts: Option<u32>,
    #[serde(default, with = "opt_secs")]
    pub rotate_timeout: Option<Duration>,
    #[serde(default, with = "opt_secs")]
    pub rotate_min_interval: Option<Duration>,
    pub rotate_per_hour: Option<u32>,
    #[serde(default, with = "opt_secs")]
    pub drain_wait: Option<Duration>,
    #[serde(default, with = "opt_secs")]
    pub offline_after: Option<Duration>,
}

/// IP changes and drops per hour before a rotating session drains.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StabilityDoc {
    pub changes_per_hour: Option<u32>,
    pub drops_per_hour: Option<u32>,
}

/// Rotating session life, refill and keepalive.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotatingDoc {
    #[serde(default, with = "opt_secs")]
    pub ready_ttl: Option<Duration>,
    /// Total life. Unset: 80% of the provider maximum.
    #[serde(default, with = "opt_secs")]
    pub max_age: Option<Duration>,
    #[serde(default, with = "opt_secs")]
    pub min_remaining: Option<Duration>,
    pub after_release: Option<AfterRelease>,
    pub refill_concurrency: Option<u32>,
    pub refill_rate: Option<u32>,
    pub headroom: Option<u32>,
    /// Derive the extra target from the measured lease rate and create
    /// latency; `headroom` stays the floor.
    pub headroom_auto: Option<bool>,
    /// Interval of the neutral keepalive request.
    #[serde(default, with = "opt_secs")]
    pub keepalive: Option<Duration>,
    #[serde(default, with = "opt_secs")]
    pub recheck_every: Option<Duration>,
    #[serde(default)]
    pub stability: StabilityDoc,
}

/// Spend of the policy. Checked against `limits`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CostDoc {
    /// Rotating: traffic per day.
    pub max_gb_per_day: Option<f64>,
    /// Rotating: session creates per hour.
    pub max_creates_per_hour: Option<u32>,
    /// Static: fair-use traffic per IP and month.
    pub fair_use_gb_per_ip_month: Option<f64>,
}

/// Ceilings for `cost`. They only tighten from `global` to `org`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsDoc {
    pub max_gb_per_day: Option<f64>,
    pub max_creates_per_hour: Option<u32>,
    pub fair_use_gb_per_ip_month: Option<f64>,
    /// Traffic one org may use per UTC day across all providers. Unset: no
    /// budget.
    pub org_max_gb_per_day: Option<f64>,
}

/// Upstream dial concurrency.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DialDoc {
    /// Concurrent candidate dials, from 1 through 16.
    pub race: Option<u32>,
}

/// One `[[policy]]` table.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDoc {
    /// Unique across the file set. Used in errors and audit.
    pub name: String,
    #[serde(default)]
    pub scope: Scope,
    /// Provider id for `route_class`, org id for `org`; absent for `global`.
    #[serde(default, rename = "match")]
    pub target: Option<String>,

    /// Kinds in preference order.
    pub kinds: Option<Vec<Kind>>,
    /// Provider order. Unset: every configured provider.
    pub providers: Option<Vec<ProviderId>>,
    /// Regions in fallback order. Required after merging.
    pub regions: Option<Vec<Region>>,
    pub pool: Option<Pool>,

    pub min_ready: Option<u32>,
    pub max_ready: Option<u32>,
    pub low_watermark: Option<u32>,
    /// Time below `low_watermark` before the cache counts as low (`cache_low`).
    #[serde(default, with = "opt_secs")]
    pub low_for: Option<Duration>,
    /// `min_ready` overrides per region (`fr`, `fr/paris`).
    #[serde(default)]
    pub min_ready_by_region: BTreeMap<Region, u32>,

    #[serde(default)]
    pub criteria: CriteriaDoc,
    pub on_score_unavailable: Option<OnScoreUnavailable>,

    #[serde(default, with = "opt_secs")]
    pub lease_ttl: Option<Duration>,
    #[serde(default)]
    pub on_empty: OnEmptyDoc,
    #[serde(default, with = "opt_secs")]
    pub lease_wait: Option<Duration>,
    #[serde(default, with = "opt_secs")]
    pub create_deadline: Option<Duration>,
    pub orgs_hard: Option<u32>,
    pub max_conns_per_ip: Option<u32>,
    #[serde(default, with = "opt_secs")]
    pub rest_after_release: Option<Duration>,
    pub max_tunnels_per_org: Option<u32>,
    /// Sticky entries per org. Unset: no cap; scopes can only tighten it.
    pub max_sticky_entries_per_org: Option<u32>,
    pub sticky_scope: Option<StickyScope>,

    #[serde(default)]
    pub dial: DialDoc,
    #[serde(default)]
    pub block: BlockDoc,
    #[serde(default, rename = "static")]
    pub static_ips: StaticDoc,
    #[serde(default)]
    pub mobile_box: MobileBoxDoc,
    #[serde(default)]
    pub rotating: RotatingDoc,
    #[serde(default)]
    pub cost: CostDoc,
    #[serde(default)]
    pub limits: LimitsDoc,
}

/// A policy file: a list of `[[policy]]` tables.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyFile {
    #[serde(default, rename = "policy")]
    pub policies: Vec<PolicyDoc>,
}

impl PolicyFile {
    /// Parse a TOML policy file; bad syntax, an unknown field and a wrong type
    /// are refused.
    pub fn parse(text: &str) -> Result<Self, PolicyError> {
        toml::from_str(text).map_err(PolicyError::Toml)
    }
}

/// Copy each listed field of `$top` over `$dst` when `$top` sets it.
macro_rules! overlay_fields {
    ($dst:expr, $top:expr; $($f:ident),+ $(,)?) => {
        $( if $top.$f.is_some() { $dst.$f.clone_from(&$top.$f); } )+
    };
}

/// The smaller of two optional ceilings.
fn tighter<T: PartialOrd + Copy>(a: Option<T>, b: Option<T>) -> Option<T> {
    match (a, b) {
        (Some(x), Some(y)) => Some(if y < x { y } else { x }),
        (x, None) => x,
        (None, y) => y,
    }
}

impl PolicyDoc {
    /// Apply `top` over `self`, field by field: a field `top` sets wins, a
    /// field it leaves unset keeps `self`'s value. `min_ready_by_region`
    /// merges per region. `limits` and `max_sticky_entries_per_org` keep the
    /// tighter ceiling, so a lower scope can lower a ceiling but never raise it.
    pub fn overlay(&mut self, top: &PolicyDoc) {
        overlay_fields!(self, top;
            kinds, providers, regions, pool, min_ready, max_ready, low_watermark, low_for,
            on_score_unavailable, lease_ttl, lease_wait, create_deadline, orgs_hard,
            max_conns_per_ip, rest_after_release, max_tunnels_per_org, sticky_scope);
        self.min_ready_by_region
            .extend(top.min_ready_by_region.iter().map(|(r, n)| (r.clone(), *n)));
        self.max_sticky_entries_per_org = tighter(
            self.max_sticky_entries_per_org,
            top.max_sticky_entries_per_org,
        );

        overlay_fields!(self.criteria, top.criteria;
            max_risk, max_ttfb_ms, max_load_ms, min_success, browser_sample, verdict_max_age);
        overlay_fields!(self.on_empty, top.on_empty; static_ips, rotating);
        overlay_fields!(self.dial, top.dial; race);
        overlay_fields!(self.block, top.block;
            target_cooldown, escalate_targets, escalate_signals, signal_window, max_cooldown_share);
        overlay_fields!(self.static_ips, top.static_ips;
            cooldown, quarantine_after, retest_every, recheck_every, replace_after_checks,
            replace_min_sources, replace_blocked_share, replace_quarantine_for);
        overlay_fields!(self.mobile_box, top.mobile_box;
            rotate_attempts, rotate_timeout, rotate_min_interval, rotate_per_hour, drain_wait,
            offline_after);
        overlay_fields!(self.rotating, top.rotating;
            ready_ttl, max_age, min_remaining, after_release, refill_concurrency, refill_rate,
            headroom, headroom_auto, keepalive, recheck_every);
        overlay_fields!(self.rotating.stability, top.rotating.stability;
            changes_per_hour, drops_per_hour);
        overlay_fields!(self.cost, top.cost;
            max_gb_per_day, max_creates_per_hour, fair_use_gb_per_ip_month);

        let (l, t) = (&mut self.limits, &top.limits);
        l.max_gb_per_day = tighter(l.max_gb_per_day, t.max_gb_per_day);
        l.max_creates_per_hour = tighter(l.max_creates_per_hour, t.max_creates_per_hour);
        l.fair_use_gb_per_ip_month =
            tighter(l.fair_use_gb_per_ip_month, t.fair_use_gb_per_ip_month);
        l.org_max_gb_per_day = tighter(l.org_max_gb_per_day, t.org_max_gb_per_day);
    }
}
