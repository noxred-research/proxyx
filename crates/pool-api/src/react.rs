//! The reaction to one block signal, narrow to wide:
//!
//! 1. **Target:** the IP is cooled for that target (`cool:{ip}:{target}`).
//! 2. **IP-wide:** `escalate_targets` distinct targets or `escalate_signals`
//!    signals inside `signal_window` take the IP out of leasing for all
//!    targets. Rotating: the session leaves the ready set (open tunnels end
//!    on their own). Static: Cooldown, or Quarantined after
//!    `quarantine_after` IP-wide blocks in an hour. A SIM box also gets an
//!    `ip.rotate_requested` audit row; the warmer rotates boxes that rest in
//!    Cooldown or Quarantined. A customer's own upstream is only cooled (the
//!    warmer retests it after the cooldown): nobody rotates or replaces it,
//!    and it is no part of the shared pool the guard below measures.
//! 3. **Pool guard:** when `max_cooldown_share` of the static partition is
//!    already cooled, escalation stops (a hostile target that fakes block
//!    pages can then only cool its own target) and a warning is logged.
//!    Rotating sessions need no guard: a drained session is replaced inside
//!    the warmer's own create budget.

use std::net::IpAddr;
use std::time::Duration;

use common::types::{IpState, Kind, OrgId, Partition, SignalSource, SignalType, Subtype, Target};
use policy::BlockRules;
use store::{InventoryRow, StoreError, Transition};
use time::OffsetDateTime;

use crate::error::ApiError;
use crate::state::ApiState;

/// Window of the `quarantine_after` rule.
const QUARANTINE_WINDOW: Duration = Duration::from_secs(3_600);

/// The unit a signal is about.
#[derive(Debug, Clone)]
pub(crate) struct Subject {
    pub partition: Partition,
    /// The exit IP the tunnel used: what blocks and target cooldowns are
    /// keyed by, and what the unit record carries.
    pub ip: IpAddr,
    /// Static: the key of the inventory row (the IP as text, which is not
    /// the exit IP for a SIM box or a customer upstream). Rotating: the
    /// session id.
    pub unit: String,
    pub kind: Kind,
}

/// How far the reaction went; also the `scope` label of `block_signals_total`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reaction {
    Target,
    Ip,
    PoolGuard,
}

impl Reaction {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Target => "target",
            Self::Ip => "ip",
            Self::PoolGuard => "pool_guard",
        }
    }
}

/// Distinct targets or signals inside the window that block the IP for all
/// targets.
fn escalates(distinct_targets: i64, signals: i64, rules: &BlockRules) -> bool {
    distinct_targets >= i64::from(rules.escalate_targets)
        || signals >= i64::from(rules.escalate_signals)
}

/// True when `cooled` of `total` units already reach the share.
fn pool_guard_holds(cooled: usize, total: usize, max_share: f64) -> bool {
    total > 0 && cooled as f64 / total as f64 >= max_share
}

/// Apply one signal. `policy_org` picks the policy whose block rules apply.
pub(crate) async fn react(
    state: &ApiState,
    policy_org: &OrgId,
    subject: &Subject,
    source: SignalSource,
    ty: SignalType,
    target: Option<&str>,
) -> Result<Reaction, ApiError> {
    let loaded = state.loaded.borrow().clone();
    let policy = loaded
        .policies
        .effective(policy_org, Some(&subject.partition.provider));
    let reaction = apply(state, policy, subject, source, ty, target).await?;
    state
        .metrics
        .block_signals_total
        .with_label_values(&[source.as_str(), ty.as_str(), reaction.label()])
        .inc();
    Ok(reaction)
}

async fn apply(
    state: &ApiState,
    policy: &policy::EffectivePolicy,
    subject: &Subject,
    source: SignalSource,
    ty: SignalType,
    target: Option<&str>,
) -> Result<Reaction, ApiError> {
    let rules = &policy.block;
    let now = OffsetDateTime::now_utc();
    if let Some(host) = target {
        state
            .db
            .record_block(
                subject.ip,
                Some(host),
                source,
                ty,
                Some(now + rules.target_cooldown),
            )
            .await?;
        let cooled = Target {
            host: host.to_owned(),
            port: 0,
        };
        state
            .hot
            .cool_target(
                &subject.partition,
                subject.ip,
                &cooled,
                rules.target_cooldown,
            )
            .await?;
        let since = now - rules.signal_window;
        let distinct = state.db.blocked_targets_since(subject.ip, since).await?;
        let signals = state.db.blocks_since(subject.ip, since).await?.len();
        let signals = i64::try_from(signals).unwrap_or(i64::MAX);
        if !escalates(distinct, signals, rules) {
            return Ok(Reaction::Target);
        }
    }
    match subject.kind {
        Kind::Rotating => drain_session(state, subject, source, ty).await,
        Kind::Static => cool_static_ip(state, policy, subject, source, ty, now).await,
    }
}

async fn drain_session(
    state: &ApiState,
    subject: &Subject,
    source: SignalSource,
    ty: SignalType,
) -> Result<Reaction, ApiError> {
    if state
        .hot
        .ready_take(&subject.partition, &subject.unit)
        .await?
    {
        state
            .db
            .record_block(subject.ip, None, source, ty, None)
            .await?;
        state
            .metrics
            .cache_evictions_total
            .with_label_values(&["block"])
            .inc();
    }
    Ok(Reaction::Ip)
}

async fn cool_static_ip(
    state: &ApiState,
    policy: &policy::EffectivePolicy,
    subject: &Subject,
    source: SignalSource,
    ty: SignalType,
    now: OffsetDateTime,
) -> Result<Reaction, ApiError> {
    // The row is found by the unit (its key); `subject.ip` is the exit IP the
    // tunnel used, which is what blocks and cooldowns are keyed by and
    // differs from the key for a SIM box and a customer upstream.
    let row = match subject.unit.parse::<IpAddr>() {
        Ok(key) => state.db.inventory_row(key).await?,
        Err(_) => None,
    };
    let Some(row) = row else {
        tracing::warn!(partition = %subject.partition, "block signal for an ip outside the inventory");
        return Ok(Reaction::Target);
    };
    if !matches!(
        row.state,
        IpState::Available | IpState::Leased | IpState::Degraded | IpState::Candidate
    ) {
        // Already out of leasing: repeated signals from tunnels that opened
        // earlier must not count towards quarantine.
        return Ok(Reaction::Ip);
    }
    // A customer's own upstream is no part of the shared pool: its cooldown
    // does not depend on how many shared IPs rest.
    if row.owner.is_none()
        && pool_guard_tripped(state, &row, policy.block.max_cooldown_share).await?
    {
        tracing::warn!(
            partition = %subject.partition,
            max_cooldown_share = policy.block.max_cooldown_share,
            "pool guard holds, not cooling the ip for all targets"
        );
        return Ok(Reaction::PoolGuard);
    }

    state
        .db
        .record_block(subject.ip, None, source, ty, None)
        .await?;
    let rules = &policy.static_ips;
    let recent = state
        .db
        .ip_wide_blocks_since(subject.ip, now - QUARANTINE_WINDOW)
        .await?;
    let actor = format!("signal:{}", source.as_str());
    let reason = format!("{} signal {}", source.as_str(), ty.as_str());
    if row.entry.subtype == Subtype::MobileBox {
        state
            .db
            .audit(
                &actor,
                "ip.rotate_requested",
                &row.entry.ip.to_string(),
                serde_json::json!({ "reason": reason }),
            )
            .await?;
    }
    let key = row.entry.ip;
    if row.state.is_leasable() {
        let cooldown =
            Transition::to(IpState::Cooldown, &reason).cooldown_until(now + rules.cooldown);
        try_transition(state, key, &cooldown, &actor).await?;
    }
    // A customer IP is never quarantined: nobody replaces or rotates it, and
    // only a passed validation of its owner brings a quarantined unit back.
    // It rests in cooldown, which the warmer retests.
    if row.owner.is_none() && recent >= i64::from(rules.quarantine_after) {
        let quarantine =
            Transition::to(IpState::Quarantined, &reason).retest_at(now + rules.retest_every);
        try_transition(state, key, &quarantine, &actor).await?;
    }
    state
        .hot
        .ready_take(&subject.partition, &subject.unit)
        .await?;
    Ok(Reaction::Ip)
}

/// A move the state machine refuses means a parallel signal already moved
/// the IP; that is not an error.
pub(crate) async fn try_transition(
    state: &ApiState,
    ip: IpAddr,
    change: &Transition,
    actor: &str,
) -> Result<(), ApiError> {
    match state.db.transition_ip(ip, change, actor).await {
        Ok(_) | Err(StoreError::InvalidTransition { .. }) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

async fn pool_guard_tripped(
    state: &ApiState,
    row: &InventoryRow,
    max_share: f64,
) -> Result<bool, ApiError> {
    let rows = state
        .db
        .list_inventory(Some(&row.entry.provider), None)
        .await?;
    let in_partition = rows
        .iter()
        .filter(|r| r.owner.is_none() && r.entry.region == row.entry.region);
    let (mut cooled, mut total) = (0, 0);
    for r in in_partition {
        match r.state {
            IpState::Cooldown | IpState::Quarantined => {
                cooled += 1;
                total += 1;
            }
            IpState::Available | IpState::Leased | IpState::Degraded => total += 1,
            _ => {}
        }
    }
    Ok(pool_guard_holds(cooled, total, max_share))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules() -> BlockRules {
        BlockRules {
            target_cooldown: Duration::from_secs(1_800),
            escalate_targets: 3,
            escalate_signals: 5,
            signal_window: Duration::from_secs(1_800),
            max_cooldown_share: 0.5,
        }
    }

    #[test]
    fn escalation_needs_enough_targets_or_signals() {
        let r = rules();
        assert!(!escalates(2, 4, &r), "below both thresholds");
        assert!(escalates(3, 3, &r), "three distinct targets");
        assert!(escalates(1, 5, &r), "five signals on one target");
    }

    #[test]
    fn pool_guard_holds_at_the_share_not_only_above_it() {
        assert!(!pool_guard_holds(0, 4, 0.5));
        assert!(!pool_guard_holds(1, 4, 0.5));
        assert!(pool_guard_holds(2, 4, 0.5), "half cooled stops escalation");
        assert!(pool_guard_holds(3, 4, 0.5));
        assert!(
            !pool_guard_holds(0, 0, 0.5),
            "an empty partition has no share"
        );
    }
}
