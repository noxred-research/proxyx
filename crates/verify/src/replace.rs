//! The replacement rule for static IPs and SIM boxes.
//! Pure: it reads history and decides; the warmer owns
//! the state change to *ReplaceRequested*.
//!
//! One rule is enough, so one noisy score cannot trigger a replacement by
//! itself: the reputation rule needs several services over several checks.

use std::collections::HashSet;
use std::time::Duration;

use crate::score::Score;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ReplaceRule {
    /// A score above this is bad (`criteria.max_risk`).
    pub max_risk: u8,
    /// Consecutive bad checks.
    pub replace_after_checks: usize,
    /// Services that must be above `max_risk` in each of those checks.
    pub replace_min_sources: usize,
    /// Share of test targets that must block, on two probes in a row.
    pub replace_blocked_share: f64,
    /// Time in *Quarantined* that ends in a replacement request.
    pub replace_quarantine_for: Duration,
    /// Failed SIM box resets in a row (`rotate_attempts`).
    pub rotate_attempts: u32,
}

/// How many of the test targets blocked one probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeRound {
    pub blocked: usize,
    pub total: usize,
}

/// What is known about one IP. History slices run oldest first.
#[derive(Debug, Clone, Copy, Default)]
pub struct IpHistory<'a> {
    /// Reputation checks: the scores each check obtained from its services.
    pub checks: &'a [Vec<Score>],
    /// Light probes.
    pub probes: &'a [ProbeRound],
    /// Unbroken time in *Quarantined*, if quarantined now.
    pub quarantined_for: Option<Duration>,
    /// Failed SIM box resets in a row (0 for a plain static IP).
    pub failed_resets: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplaceReason {
    /// Risk above `max_risk` from enough services in each of the last checks.
    Reputation,
    /// Enough test targets blocked on the last two probes.
    Blocked,
    /// Quarantined for long enough.
    Quarantined,
    /// SIM box resets kept failing.
    ResetsFailed,
}

impl ReplaceReason {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Reputation => "reputation",
            Self::Blocked => "blocked",
            Self::Quarantined => "quarantined",
            Self::ResetsFailed => "resets_failed",
        }
    }
}

impl ReplaceRule {
    /// Every rule that holds. Empty means the IP stays. Any single reason
    /// means *ReplaceRequested*.
    pub fn reasons(&self, history: &IpHistory<'_>) -> Vec<ReplaceReason> {
        let mut reasons = Vec::new();
        if self.reputation(history.checks) {
            reasons.push(ReplaceReason::Reputation);
        }
        if self.blocked(history.probes) {
            reasons.push(ReplaceReason::Blocked);
        }
        if history
            .quarantined_for
            .is_some_and(|d| d >= self.replace_quarantine_for)
        {
            reasons.push(ReplaceReason::Quarantined);
        }
        if history.failed_resets > 0 && history.failed_resets >= self.rotate_attempts {
            reasons.push(ReplaceReason::ResetsFailed);
        }
        reasons
    }

    /// The last `replace_after_checks` checks each had at least
    /// `replace_min_sources` distinct services above `max_risk`. A check where
    /// too few services answered cannot count, so an outage never causes a
    /// replacement.
    fn reputation(&self, checks: &[Vec<Score>]) -> bool {
        let needed = self.replace_after_checks;
        if needed == 0 || checks.len() < needed {
            return false;
        }
        checks[checks.len() - needed..].iter().all(|check| {
            let sources: HashSet<_> = check
                .iter()
                .filter(|s| s.risk > self.max_risk)
                .map(|s| s.source)
                .collect();
            sources.len() >= self.replace_min_sources
        })
    }

    /// The last two probes each had at least `replace_blocked_share` of their
    /// targets block.
    fn blocked(&self, probes: &[ProbeRound]) -> bool {
        probes.len() >= 2
            && probes[probes.len() - 2..].iter().all(|p| {
                p.total > 0 && p.blocked as f64 / p.total as f64 >= self.replace_blocked_share
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::score::{Flags, ScorerKind};

    /// The shipped policy defaults; production always builds the rule from the
    /// effective policy.
    impl Default for ReplaceRule {
        fn default() -> Self {
            Self {
                max_risk: 75,
                replace_after_checks: 3,
                replace_min_sources: 2,
                replace_blocked_share: 0.6,
                replace_quarantine_for: Duration::from_secs(24 * 3600),
                rotate_attempts: 3,
            }
        }
    }

    fn s(source: ScorerKind, risk: u8) -> Score {
        Score {
            risk,
            flags: Flags::default(),
            source,
        }
    }

    /// A check where the fraud-score and abuse-confidence scorers both say `risk`.
    fn both(risk: u8) -> Vec<Score> {
        vec![
            s(ScorerKind::FraudScore, risk),
            s(ScorerKind::AbuseConfidence, risk),
        ]
    }

    fn reasons(history: IpHistory<'_>) -> Vec<ReplaceReason> {
        ReplaceRule::default().reasons(&history)
    }

    fn on_checks(checks: &[Vec<Score>]) -> Vec<ReplaceReason> {
        reasons(IpHistory {
            checks,
            ..IpHistory::default()
        })
    }

    fn on_probes(probes: &[ProbeRound]) -> Vec<ReplaceReason> {
        reasons(IpHistory {
            probes,
            ..IpHistory::default()
        })
    }

    #[test]
    fn reputation_needs_three_bad_checks_in_a_row_from_two_services() {
        let bad = ReplaceReason::Reputation;
        assert_eq!(on_checks(&[both(90), both(90), both(90)]), [bad]);
        assert!(
            on_checks(&[both(90), both(90)]).is_empty(),
            "two checks are not enough"
        );
        // Window is the last 3: an old good check does not matter, a recent one resets.
        assert_eq!(on_checks(&[both(10), both(90), both(90), both(90)]), [bad]);
        assert!(on_checks(&[both(90), both(90), both(90), both(10)]).is_empty());
        assert!(on_checks(&[both(90), both(10), both(90), both(90)]).is_empty());
    }

    #[test]
    fn reputation_boundary_is_strictly_above_max_risk() {
        assert!(on_checks(&vec![both(75); 3]).is_empty());
        assert_eq!(on_checks(&vec![both(76); 3]), [ReplaceReason::Reputation]);
    }

    #[test]
    fn one_noisy_service_never_triggers_a_replacement() {
        let one = vec![
            s(ScorerKind::FraudScore, 100),
            s(ScorerKind::AbuseConfidence, 5),
        ];
        assert!(on_checks(&vec![one; 5]).is_empty());
        // The same service twice in a check is still one source.
        let twice = vec![
            s(ScorerKind::FraudScore, 100),
            s(ScorerKind::FraudScore, 100),
        ];
        assert!(on_checks(&vec![twice; 3]).is_empty());
        // A check where the second service was down breaks the run.
        assert!(on_checks(&[both(90), vec![s(ScorerKind::FraudScore, 90)], both(90)]).is_empty());
        // Which two services does not matter.
        let other = vec![
            s(ScorerKind::ProxyRisk, 99),
            s(ScorerKind::AbuseConfidence, 99),
        ];
        assert_eq!(
            on_checks(&[both(90), other, both(90)]),
            [ReplaceReason::Reputation]
        );
    }

    #[test]
    fn blocked_share_must_hold_on_two_probes_in_a_row() {
        let round = |blocked, total| ProbeRound { blocked, total };
        // 3 of 5 = 60% is enough; 2 of 5 is not.
        assert_eq!(
            on_probes(&[round(3, 5), round(3, 5)]),
            [ReplaceReason::Blocked]
        );
        assert!(on_probes(&[round(3, 5), round(2, 5)]).is_empty());
        assert!(on_probes(&[round(2, 5), round(3, 5)]).is_empty());
        assert!(
            on_probes(&[round(5, 5)]).is_empty(),
            "one probe is not enough"
        );
        // Only the last two probes count.
        assert_eq!(
            on_probes(&[round(0, 5), round(5, 5), round(4, 5)]),
            [ReplaceReason::Blocked]
        );
        assert!(on_probes(&[round(5, 5), round(5, 5), round(0, 5)]).is_empty());
        // A probe with no targets blocks nothing.
        assert!(on_probes(&[round(0, 0), round(0, 0)]).is_empty());
    }

    #[test]
    fn quarantine_boundary_is_inclusive() {
        let day = Duration::from_secs(24 * 3600);
        let q = |d| {
            reasons(IpHistory {
                quarantined_for: d,
                ..IpHistory::default()
            })
        };
        assert!(q(None).is_empty());
        assert!(q(Some(day - Duration::from_secs(1))).is_empty());
        assert_eq!(q(Some(day)), [ReplaceReason::Quarantined]);
    }

    #[test]
    fn failed_resets_boundary_is_rotate_attempts() {
        let r = |n| {
            reasons(IpHistory {
                failed_resets: n,
                ..IpHistory::default()
            })
        };
        assert!(r(0).is_empty());
        assert!(r(2).is_empty());
        assert_eq!(r(3), [ReplaceReason::ResetsFailed]);
        assert_eq!(r(4), [ReplaceReason::ResetsFailed]);
        // A zero limit must not replace healthy IPs.
        let zero = ReplaceRule {
            rotate_attempts: 0,
            replace_after_checks: 0,
            ..ReplaceRule::default()
        };
        assert!(zero.reasons(&IpHistory::default()).is_empty());
    }

    #[test]
    fn every_holding_rule_is_reported() {
        let checks = vec![both(90); 3];
        let probes = [ProbeRound {
            blocked: 5,
            total: 5,
        }; 2];
        let all = reasons(IpHistory {
            checks: &checks,
            probes: &probes,
            quarantined_for: Some(Duration::from_secs(48 * 3600)),
            failed_resets: 3,
        });
        assert_eq!(
            all,
            [
                ReplaceReason::Reputation,
                ReplaceReason::Blocked,
                ReplaceReason::Quarantined,
                ReplaceReason::ResetsFailed
            ]
        );
    }
}
