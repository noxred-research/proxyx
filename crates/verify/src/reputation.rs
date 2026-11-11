//! Reputation rule, 6 h cache and per-scorer daily budget.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use common::metrics::Metrics;
use parking_lot::Mutex;
use policy::OnScoreUnavailable;
use reqwest::Client;

use crate::http::{ClientError, direct_client};
use crate::score::{Score, Scorer, ScorerKind};

const DAY_SECS: u64 = 86_400;

/// What to do with an exit IP after a lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Below `warn_at`: keep.
    Keep,
    /// From `warn_at` up to `rotate_at`: check again soon. Twice in a row
    /// (see [`Verdict::escalate`]) means drain.
    Recheck,
    /// Above `rotate_at`, or a `tor` flag: drain a rotating session, cool
    /// down a static IP, now.
    Drain,
}

impl Verdict {
    /// Apply "drain if the zone repeats twice": a `Recheck` right after a
    /// `Recheck` becomes `Drain`. `previous` is the verdict of the last check
    /// of the same IP, if any.
    pub fn escalate(self, previous: Option<Verdict>) -> Verdict {
        match (self, previous) {
            (Verdict::Recheck, Some(Verdict::Recheck)) => Verdict::Drain,
            (verdict, _) => verdict,
        }
    }
}

/// The verdict over the scores of one lookup. The worst scorer decides (any
/// `tor` flag, the highest risk): one clean score does not hide a bad one.
/// The `proxy` flag is ignored. `rotate_at` is the policy's
/// `criteria.max_risk`. No scores gives `Keep`; the "no scorer answered" case
/// is [`unavailable_verdict`].
fn judge(scores: &[Score], warn_at: u8, rotate_at: u8) -> Verdict {
    let risk = scores.iter().map(|s| s.risk).max().unwrap_or(0);
    if scores.iter().any(|s| s.flags.tor) || risk > rotate_at {
        Verdict::Drain
    } else if risk >= warn_at && !scores.is_empty() {
        Verdict::Recheck
    } else {
        Verdict::Keep
    }
}

/// The verdict when no scorer gave a score (all down, over budget or none
/// configured): the policy's `on_score_unavailable`, passed with every
/// [`Reputation::assess`].
pub(crate) fn unavailable_verdict(on_unavailable: OnScoreUnavailable) -> Verdict {
    match on_unavailable {
        OnScoreUnavailable::Allow => Verdict::Keep,
        OnScoreUnavailable::Deny => Verdict::Drain,
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ReputationConfig {
    /// Lowest risk that asks for another check soon. The drain threshold is
    /// not configured here: every [`Reputation::assess`] gets the policy's
    /// `criteria.max_risk`.
    pub warn_at: u8,
    /// How long a score is reused.
    pub cache_ttl: Duration,
    /// Time limit of one scorer call.
    pub timeout: Duration,
}

impl Default for ReputationConfig {
    fn default() -> Self {
        Self {
            warn_at: 50,
            cache_ttl: Duration::from_secs(6 * 3600),
            timeout: Duration::from_secs(10),
        }
    }
}

/// A scorer with its daily lookup budget (lookups per UTC day; 0 disables it).
#[derive(Debug, Clone)]
pub struct ScorerSlot {
    pub scorer: Scorer,
    pub daily_budget: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assessment {
    pub verdict: Verdict,
    /// One score per scorer that answered (fresh or cached). Empty when none
    /// did and `on_score_unavailable` decided the verdict.
    pub scores: Vec<Score>,
}

#[derive(Default)]
struct State {
    cache: HashMap<(ScorerKind, IpAddr), (SystemTime, Score)>,
    /// Lookups used on a UTC day, per scorer.
    used: HashMap<ScorerKind, (u64, u32)>,
}

pub struct Reputation {
    cfg: ReputationConfig,
    slots: Vec<ScorerSlot>,
    http: Client,
    metrics: Arc<Metrics>,
    state: Mutex<State>,
}

impl Reputation {
    pub fn new(
        cfg: ReputationConfig,
        slots: Vec<ScorerSlot>,
        metrics: Arc<Metrics>,
    ) -> Result<Self, ClientError> {
        Ok(Self {
            http: direct_client(cfg.timeout)?,
            cfg,
            slots,
            metrics,
            state: Mutex::default(),
        })
    }

    /// Score `ip` with every scorer, reusing cached scores and respecting the
    /// budgets, and apply the rule. `on_unavailable` decides the verdict when
    /// no scorer gave a score; `rotate_at` is the policy's `criteria.max_risk`
    /// (the warn threshold stays the configured one).
    pub async fn assess(
        &self,
        ip: IpAddr,
        on_unavailable: OnScoreUnavailable,
        rotate_at: u8,
    ) -> Assessment {
        self.assess_with(ip, on_unavailable, rotate_at, SystemTime::now())
            .await
    }

    async fn assess_with(
        &self,
        ip: IpAddr,
        on_unavailable: OnScoreUnavailable,
        rotate_at: u8,
        now: SystemTime,
    ) -> Assessment {
        let mut scores = Vec::new();
        for slot in &self.slots {
            let kind = slot.scorer.kind();
            if let Some(score) = self.cached(kind, ip, now) {
                scores.push(score);
                continue;
            }
            if !self.take_budget(kind, slot.daily_budget, now) {
                tracing::warn!(service = kind.name(), "reputation daily budget exhausted");
                continue;
            }
            match slot.scorer.score(&self.http, ip).await {
                Ok(score) => {
                    self.store(ip, score, now);
                    scores.push(score);
                }
                Err(err) => {
                    self.metrics
                        .check_failures_total
                        .with_label_values(&[kind.name()])
                        .inc();
                    tracing::warn!(service = kind.name(), error = %err, "reputation scorer failed");
                }
            }
        }
        let verdict = if scores.is_empty() {
            tracing::warn!("no reputation score available, applying on_score_unavailable");
            unavailable_verdict(on_unavailable)
        } else {
            judge(&scores, self.cfg.warn_at, rotate_at)
        };
        Assessment { verdict, scores }
    }

    fn cached(&self, kind: ScorerKind, ip: IpAddr, now: SystemTime) -> Option<Score> {
        let state = self.state.lock();
        let (at, score) = state.cache.get(&(kind, ip))?;
        // A clock that went backwards counts as expired.
        let age = now.duration_since(*at).ok()?;
        (age < self.cfg.cache_ttl).then_some(*score)
    }

    fn store(&self, ip: IpAddr, score: Score, now: SystemTime) {
        let mut state = self.state.lock();
        let ttl = self.cfg.cache_ttl;
        state
            .cache
            .retain(|_, (at, _)| now.duration_since(*at).is_ok_and(|age| age < ttl));
        state.cache.insert((score.source, ip), (now, score));
    }

    /// Reserve one lookup of the scorer's UTC-day budget.
    fn take_budget(&self, kind: ScorerKind, daily: u32, now: SystemTime) -> bool {
        let mut state = self.state.lock();
        let day = now
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() / DAY_SECS);
        let (used_day, used) = state.used.entry(kind).or_insert((day, 0));
        if *used_day != day {
            (*used_day, *used) = (day, 0);
        }
        if *used >= daily {
            return false;
        }
        *used += 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use OnScoreUnavailable::{Allow, Deny};

    use super::*;
    use crate::score::Flags;
    use crate::testutil::{Resp, Stub, failures, fraud_score, fraud_score_slot, reputation};

    fn score(risk: u8, tor: bool, proxy: bool) -> Score {
        Score {
            risk,
            flags: Flags { tor, proxy },
            source: ScorerKind::FraudScore,
        }
    }

    #[test]
    fn thresholds_are_warn_at_inclusive_and_rotate_at_exclusive() {
        let v = |risk| judge(&[score(risk, false, false)], 50, 75);
        assert_eq!(v(0), Verdict::Keep);
        assert_eq!(v(49), Verdict::Keep);
        assert_eq!(v(50), Verdict::Recheck);
        assert_eq!(v(75), Verdict::Recheck);
        assert_eq!(v(76), Verdict::Drain);
        assert_eq!(v(100), Verdict::Drain);
        assert_eq!(judge(&[], 50, 75), Verdict::Keep);
    }

    #[test]
    fn tor_drains_at_any_risk_and_proxy_is_ignored() {
        let v = |score| judge(&[score], 50, 75);
        assert_eq!(v(score(0, true, false)), Verdict::Drain);
        assert_eq!(v(score(10, false, true)), Verdict::Keep);
        assert_eq!(v(score(60, false, true)), Verdict::Recheck);
    }

    #[test]
    fn the_worst_scorer_decides() {
        let abuse = Score {
            source: ScorerKind::AbuseConfidence,
            ..score(90, false, false)
        };
        assert_eq!(
            judge(&[score(5, false, false), abuse], 50, 75),
            Verdict::Drain
        );
        let tor = Score {
            source: ScorerKind::ProxyRisk,
            ..score(0, true, false)
        };
        assert_eq!(
            judge(&[score(5, false, false), tor], 50, 75),
            Verdict::Drain
        );
    }

    #[test]
    fn a_repeated_recheck_drains() {
        use Verdict::*;
        assert_eq!(Recheck.escalate(None), Recheck);
        assert_eq!(Recheck.escalate(Some(Keep)), Recheck);
        assert_eq!(Recheck.escalate(Some(Recheck)), Drain);
        assert_eq!(Keep.escalate(Some(Recheck)), Keep);
        assert_eq!(Drain.escalate(Some(Recheck)), Drain);
    }

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn ip(last: u8) -> IpAddr {
        IpAddr::from([5, 6, 7, last])
    }

    impl Reputation {
        /// `assess_with` at a given time and the default drain threshold.
        async fn assess_at(
            &self,
            ip: IpAddr,
            on_unavailable: OnScoreUnavailable,
            now: SystemTime,
        ) -> Assessment {
            self.assess_with(ip, on_unavailable, 75, now).await
        }
    }

    #[tokio::test]
    async fn a_cached_score_avoids_the_call_until_six_hours_pass() {
        let stub = fraud_score(80);
        let (rep, _) = reputation(vec![fraud_score_slot(&stub, 100)]);
        let t0 = 1_000_000;
        let first = rep.assess_at(ip(1), Allow, at(t0)).await;
        assert_eq!((first.verdict, stub.hits()), (Verdict::Drain, 1));
        let six_h = 6 * 3600;
        let cached = rep.assess_at(ip(1), Allow, at(t0 + six_h - 1)).await;
        assert_eq!(
            (cached.verdict, cached.scores, stub.hits()),
            (Verdict::Drain, first.scores.clone(), 1)
        );
        // Another IP is another lookup.
        rep.assess_at(ip(2), Allow, at(t0 + 1)).await;
        assert_eq!(stub.hits(), 2);
        // At exactly 6 h the entry has expired.
        rep.assess_at(ip(1), Allow, at(t0 + six_h)).await;
        assert_eq!(stub.hits(), 3);
    }

    #[tokio::test]
    async fn the_daily_budget_stops_lookups_and_resets_on_the_next_utc_day() {
        let stub = fraud_score(10);
        let (rep, metrics) = reputation(vec![fraud_score_slot(&stub, 2)]);
        let day = 20_000 * DAY_SECS;
        for last in [1, 2] {
            let a = rep.assess_at(ip(last), Allow, at(day + 100)).await;
            assert!(!a.scores.is_empty());
        }
        let third = rep.assess_at(ip(3), Allow, at(day + 200)).await;
        assert_eq!(stub.hits(), 2);
        assert!(third.scores.is_empty());
        // Budget exhaustion is not a service failure.
        assert_eq!(failures(&metrics, "fraud_score"), 0);
        // A cached score is still served when the budget is gone.
        let again = rep.assess_at(ip(1), Allow, at(day + 300)).await;
        assert!(!again.scores.is_empty());
        assert_eq!(stub.hits(), 2);
        // Next UTC day.
        let next = rep.assess_at(ip(3), Allow, at(day + DAY_SECS)).await;
        assert!(!next.scores.is_empty());
        assert_eq!(stub.hits(), 3);
    }

    #[tokio::test]
    async fn a_zero_budget_disables_the_scorer() {
        let stub = fraud_score(10);
        let (rep, _) = reputation(vec![fraud_score_slot(&stub, 0)]);
        assert!(
            rep.assess_at(ip(1), Allow, at(1_000))
                .await
                .scores
                .is_empty()
        );
        assert_eq!(stub.hits(), 0);
    }

    #[tokio::test]
    async fn on_score_unavailable_of_each_call_decides_when_every_scorer_is_down() {
        let down = Stub::spawn(|_| Resp::status(500, ""));
        // One Reputation, two policies: the value comes with the call.
        let (rep, metrics) = reputation(vec![fraud_score_slot(&down, 100)]);
        for (policy, verdict) in [(Allow, Verdict::Keep), (Deny, Verdict::Drain)] {
            let a = rep.assess_at(ip(1), policy, at(1_000)).await;
            assert_eq!(
                (a.verdict, a.scores.is_empty()),
                (verdict, true),
                "{policy:?}"
            );
        }
        assert_eq!(failures(&metrics, "fraud_score"), 2);
    }

    #[tokio::test]
    async fn on_score_unavailable_is_not_used_when_a_score_exists() {
        let stub = fraud_score(10);
        let (rep, _) = reputation(vec![fraud_score_slot(&stub, 10)]);
        let a = rep.assess_at(ip(1), Deny, at(1_000)).await;
        assert_eq!((a.verdict, a.scores.is_empty()), (Verdict::Keep, false));
    }

    #[tokio::test]
    async fn the_policy_max_risk_is_the_drain_boundary_of_each_assessment() {
        let stub = fraud_score(60);
        let (rep, _) = reputation(vec![fraud_score_slot(&stub, 100)]);
        let rep = &rep;
        let verdict = |rotate_at| async move {
            rep.assess_with(ip(1), Allow, rotate_at, at(1_000))
                .await
                .verdict
        };
        // risk 60 and a warn_at of 50: above max_risk drains, at it only rechecks
        assert_eq!(verdict(59).await, Verdict::Drain);
        assert_eq!(verdict(60).await, Verdict::Recheck);
        assert_eq!(verdict(75).await, Verdict::Recheck);
    }

    #[tokio::test]
    async fn one_scorer_down_leaves_the_others_to_decide() {
        let down = Stub::spawn(|_| Resp::status(500, ""));
        let good = fraud_score(60);
        let (rep, _) = reputation(vec![
            fraud_score_slot(&down, 10),
            fraud_score_slot(&good, 10),
        ]);
        let a = rep.assess_at(ip(1), Allow, at(1_000)).await;
        assert_eq!((a.verdict, a.scores.len()), (Verdict::Recheck, 1));
    }

    #[tokio::test]
    async fn a_scorer_that_never_answers_fails_after_the_timeout() {
        let cfg = ReputationConfig {
            timeout: Duration::from_millis(200),
            ..ReputationConfig::default()
        };
        let slots = vec![fraud_score_slot(&Stub::hanging(), 10)];
        let rep =
            Reputation::new(cfg, slots, Arc::new(Metrics::new("test"))).expect("call succeeds");
        let a = tokio::time::timeout(
            Duration::from_secs(10),
            rep.assess_at(ip(1), Allow, at(1_000)),
        )
        .await
        .expect("the scorer call must end by itself");
        assert!(a.scores.is_empty());
    }
}
