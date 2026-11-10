//! Admission of a new rotating session: the reputation rule and the light
//! probe on the policy targets, judged against the policy criteria.
//!
//! One function for both creators of a session, so a session that is served
//! never passed fewer checks than a warmed one: the warmer calls [`admit`]
//! without a deadline, the gateway's on-demand create calls it with the
//! create deadline.

use std::net::IpAddr;

use common::types::{SignalType, UpstreamEndpoint};
use policy::EffectivePolicy;
use reqwest::Url;
use tokio::time::{Instant, timeout_at};

use crate::http::ClientError;
use crate::probe::{LightProbe, Outcome, ProbeReport, TargetProbe};
use crate::replace::ProbeRound;
use crate::reputation::{Assessment, Reputation, Verdict, unavailable_verdict};

/// Estimated bytes of a TLS handshake and headers per probe GET.
const PROBE_SAMPLE_OVERHEAD: u64 = 6 * 1024;

/// What a probe says about a unit.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Quality {
    /// Share of samples that were clean and fast enough.
    pub success_share: f64,
    /// Share of samples that were clean, however slow.
    pub clean_share: f64,
    /// Blocked and total targets, for the replacement rule.
    pub round: ProbeRound,
    /// The type of a block signal, when a target blocked.
    pub block: Option<SignalType>,
    /// Estimated bytes the probe cost.
    pub bytes: u64,
}

impl Quality {
    pub fn passes(&self, min_success: f64) -> bool {
        self.success_share >= min_success
    }

    /// Fails only because of speed: no block, and enough clean answers that
    /// the unit would pass if its first bytes came in time.
    pub fn slow_only(&self, min_success: f64) -> bool {
        !self.passes(min_success) && self.block.is_none() && self.clean_share >= min_success
    }
}

/// A sample counts as a success when it was clean and its first byte came
/// within `max_ttfb_ms`.
pub fn quality(report: &ProbeReport, max_ttfb_ms: u32) -> Quality {
    let (mut good, mut clean, mut total, mut bytes) = (0usize, 0usize, 0usize, 0u64);
    for target in &report.targets {
        for sample in &target.samples {
            total += 1;
            bytes += PROBE_SAMPLE_OVERHEAD + sample.bytes as u64;
            let in_time = sample
                .ttfb
                .is_some_and(|t| t.as_millis() <= u128::from(max_ttfb_ms));
            if sample.outcome == Outcome::Clean {
                clean += 1;
                if in_time {
                    good += 1;
                }
            }
        }
    }
    let share = |n: usize| {
        if total == 0 {
            1.0
        } else {
            n as f64 / total as f64
        }
    };
    Quality {
        success_share: share(good),
        clean_share: share(clean),
        round: report.round(),
        block: report.targets.iter().find_map(TargetProbe::blocked),
        bytes,
    }
}

/// Score `ip` under `policy`: its `on_score_unavailable` decides the verdict
/// When no scorer answered and `criteria.max_risk` is the drain
/// threshold.
pub async fn assess(reputation: &Reputation, ip: IpAddr, policy: &EffectivePolicy) -> Assessment {
    reputation
        .assess(ip, policy.on_score_unavailable, policy.criteria.max_risk)
        .await
}

/// Why a session was refused. The labels are the `cause` of
/// `cache_evictions_total`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    Reputation,
    /// The probe was blocked by a target.
    Block,
    /// The probe was not blocked but too many requests failed or were slow.
    Quality,
    /// Like `Quality`, but the answers were clean: only the speed fell short.
    /// A caller may keep such a session as degraded.
    Slow,
}

impl Refusal {
    pub const fn label(self) -> &'static str {
        match self {
            Refusal::Reputation => "reputation",
            Refusal::Block => "block",
            Refusal::Quality | Refusal::Slow => "quality",
        }
    }
}

/// A session that passed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Admitted {
    /// Estimated bytes the probe cost, for the provider budget.
    pub bytes: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum AdmitError {
    #[error("session refused: {}", cause.label())]
    Refused {
        cause: Refusal,
        /// Estimated bytes the probe cost before the refusal.
        bytes: u64,
    },
    /// The upstream cannot be turned into an HTTP client: a misconfigured
    /// adapter, not a bad session.
    #[error("failed to build the probe client")]
    Probe(#[from] ClientError),
}

/// Run `fut` until `until`; `None` when the deadline passed first. Without a
/// deadline it runs to its end.
async fn bounded<F: Future>(until: Option<Instant>, fut: F) -> Option<F::Output> {
    match until {
        Some(until) => timeout_at(until, fut).await.ok(),
        None => Some(fut.await),
    }
}

/// Judge a new session whose exit IP is `ip`, reached through `upstream`:
/// the reputation rule with `criteria.max_risk`, then a light probe on
/// `targets` (none: no probe) against `criteria`.
///
/// With a deadline (`until`) the checks that cannot finish in time degrade
/// the way the policy says instead of failing the create: a reputation check
/// that is still running counts as "no score available" and follows
/// `on_score_unavailable` (`allow` admits, `deny` refuses); a probe that is
/// still running is skipped and the session is admitted on its reputation
/// alone. The probe is the only check that may be skipped: it measures
/// quality, while reputation is the abuse gate the policy has an explicit
/// switch for.
pub async fn admit(
    reputation: &Reputation,
    probe: &LightProbe,
    ip: IpAddr,
    upstream: &UpstreamEndpoint,
    targets: &[Url],
    policy: &EffectivePolicy,
    until: Option<Instant>,
) -> Result<Admitted, AdmitError> {
    let verdict = match bounded(until, assess(reputation, ip, policy)).await {
        Some(assessment) => assessment.verdict,
        None => {
            tracing::warn!("reputation check passed the deadline, applying on_score_unavailable");
            unavailable_verdict(policy.on_score_unavailable)
        }
    };
    if verdict == Verdict::Drain {
        return Err(AdmitError::Refused {
            cause: Refusal::Reputation,
            bytes: 0,
        });
    }
    if targets.is_empty() {
        return Ok(Admitted { bytes: 0 });
    }

    let Some(report) = bounded(until, probe.run(upstream, targets)).await else {
        tracing::warn!("light probe passed the deadline, admitting on reputation alone");
        return Ok(Admitted { bytes: 0 });
    };
    let criteria = &policy.criteria;
    let q = quality(&report?, criteria.max_ttfb_ms);
    if q.passes(criteria.min_success) {
        return Ok(Admitted { bytes: q.bytes });
    }
    Err(AdmitError::Refused {
        cause: if q.block.is_some() {
            Refusal::Block
        } else if q.slow_only(criteria.min_success) {
            Refusal::Slow
        } else {
            Refusal::Quality
        },
        bytes: q.bytes,
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use policy::{PolicyFile, PolicySet};

    use super::*;
    use crate::probe::{ProbeConfig, Sample};
    use crate::testutil::{self, Resp, Stub, ipqs, ipqs_slot, upstream};

    fn sample(outcome: Outcome, ttfb_ms: Option<u64>) -> Sample {
        Sample {
            status: Some(200),
            ttfb: ttfb_ms.map(Duration::from_millis),
            bytes: 1000,
            outcome,
        }
    }

    fn report(samples: Vec<Sample>) -> ProbeReport {
        ProbeReport {
            targets: vec![TargetProbe {
                target: Url::parse("https://t.example/").expect("url"),
                samples,
            }],
        }
    }

    #[test]
    fn a_slow_clean_sample_is_not_a_success() {
        let r = report(vec![
            sample(Outcome::Clean, Some(100)),
            sample(Outcome::Clean, Some(3000)),
            sample(Outcome::Clean, Some(3001)),
        ]);
        let q = quality(&r, 3000);
        assert!((q.success_share - 2.0 / 3.0).abs() < 1e-9, "{q:?}");
        assert!(q.passes(0.66));
        assert!(!q.passes(0.67));
    }

    #[test]
    fn only_clean_but_slow_answers_are_slow_only() {
        let slow = || sample(Outcome::Clean, Some(3001));
        let q = quality(&report(vec![slow(), slow(), slow()]), 3000);
        assert!(q.slow_only(0.66), "{q:?}");
        // Two clean slow answers and a failed one: the clean share still reaches min_success.
        let q = quality(
            &report(vec![slow(), slow(), sample(Outcome::Failed, None)]),
            3000,
        );
        assert!(q.slow_only(0.66), "{q:?}");
        // Too many failures: not slow, bad.
        let q = quality(
            &report(vec![
                slow(),
                sample(Outcome::Failed, None),
                sample(Outcome::Failed, None),
            ]),
            3000,
        );
        assert!(!q.slow_only(0.66), "{q:?}");
        // A block is never slow.
        let blocked = || sample(Outcome::Blocked(SignalType::Challenge), Some(50));
        let q = quality(&report(vec![blocked(), blocked(), slow()]), 3000);
        assert!(!q.slow_only(0.66), "{q:?}");
        // A fast unit passes: it is not slow.
        let fast = || sample(Outcome::Clean, Some(100));
        let q = quality(&report(vec![fast(), fast(), fast()]), 3000);
        assert!(!q.slow_only(0.66) && q.passes(0.66), "{q:?}");
    }

    #[test]
    fn blocked_and_failed_samples_lower_the_share_and_blocks_are_reported() {
        let r = report(vec![
            sample(Outcome::Blocked(SignalType::Challenge), Some(50)),
            sample(Outcome::Blocked(SignalType::Challenge), Some(50)),
            sample(Outcome::Failed, None),
        ]);
        let q = quality(&r, 3000);
        assert!(q.success_share.abs() < f64::EPSILON);
        assert_eq!(q.block, Some(SignalType::Challenge));
        assert_eq!((q.round.blocked, q.round.total), (1, 1));
        assert!(q.bytes >= 3 * PROBE_SAMPLE_OVERHEAD);
    }

    #[test]
    fn an_empty_report_passes() {
        let q = quality(&ProbeReport { targets: vec![] }, 3000);
        assert!(q.passes(1.0));
    }

    fn policy(on_unavailable: &str) -> EffectivePolicy {
        let text = format!(
            "[[policy]]\nname = \"global\"\nkinds = [\"rotating\"]\nregions = [\"fr\"]\n\
             min_ready = 1\nmax_ready = 2\non_score_unavailable = \"{on_unavailable}\"\n\
             [policy.criteria]\nmax_risk = 60\n"
        );
        let set = PolicySet::from_docs(PolicyFile::parse(&text).expect("parse").policies)
            .expect("policy set");
        set.effective(&"acme".parse().expect("org"), None).clone()
    }

    fn reputation(scorer: &Stub) -> Reputation {
        testutil::reputation(vec![ipqs_slot(scorer, 100)]).0
    }

    fn ip() -> IpAddr {
        IpAddr::from([5, 6, 7, 8])
    }

    /// An upstream that answers every probe GET with `status`.
    fn site(status: u16) -> Stub {
        Stub::spawn(move |_| Resp::status(status, "please solve this captcha"))
    }

    fn targets() -> Vec<Url> {
        vec![Url::parse("http://site.test/").expect("url")]
    }

    async fn run(
        rep: &Reputation,
        up: &Stub,
        targets: &[Url],
        policy: &EffectivePolicy,
        until: Option<Instant>,
    ) -> Result<Admitted, AdmitError> {
        admit(
            rep,
            &LightProbe::new(ProbeConfig::default()),
            ip(),
            &upstream(up),
            targets,
            policy,
            until,
        )
        .await
    }

    fn refused(r: Result<Admitted, AdmitError>) -> Option<Refusal> {
        match r {
            Err(AdmitError::Refused { cause, .. }) => Some(cause),
            _ => None,
        }
    }

    #[tokio::test]
    async fn risk_over_max_risk_is_refused_and_at_max_risk_is_admitted() {
        let up = site(200);
        let p = policy("allow");
        let over = run(&reputation(&ipqs(61)), &up, &[], &p, None).await;
        assert_eq!(refused(over), Some(Refusal::Reputation));
        let at = run(&reputation(&ipqs(60)), &up, &[], &p, None).await;
        assert!(at.is_ok(), "{at:?}");
    }

    #[tokio::test]
    async fn a_blocked_probe_is_refused_as_block_and_a_clean_one_is_admitted() {
        let p = policy("allow");
        let rep = reputation(&ipqs(10));
        let r = run(&rep, &site(403), &targets(), &p, None).await;
        assert_eq!(refused(r), Some(Refusal::Block));
        let r = run(&rep, &site(200), &targets(), &p, None)
            .await
            .expect("admitted");
        assert!(r.bytes > 0, "the probe ran and was counted");
    }

    #[tokio::test]
    async fn a_target_answering_404_500_or_503_is_a_quality_refusal_not_a_pass() {
        let p = policy("allow");
        let rep = reputation(&ipqs(10));
        for status in [404, 500, 503] {
            let up = Stub::spawn(move |_| Resp::status(status, "unavailable"));
            let r = run(&rep, &up, &targets(), &p, None).await;
            assert_eq!(refused(r), Some(Refusal::Quality), "status {status}");
        }
    }

    #[tokio::test]
    async fn a_clean_but_slow_probe_is_refused_as_slow_not_as_quality() {
        let text = "[[policy]]\nname = \"global\"\nkinds = [\"rotating\"]\nregions = [\"fr\"]\n\
                    min_ready = 1\nmax_ready = 2\n[policy.criteria]\nmax_ttfb_ms = 20\n";
        let set = PolicySet::from_docs(PolicyFile::parse(text).expect("parse").policies)
            .expect("policy set");
        let p = set.effective(&"acme".parse().expect("org"), None).clone();
        let up = Stub::spawn(|_| {
            std::thread::sleep(Duration::from_millis(100));
            Resp::ok("fine")
        });
        let r = run(&reputation(&ipqs(10)), &up, &targets(), &p, None).await;
        assert_eq!(refused(r), Some(Refusal::Slow));
        assert_eq!(Refusal::Slow.label(), "quality", "the metric label stays");
    }

    #[tokio::test]
    async fn a_reputation_check_past_the_deadline_follows_on_score_unavailable() {
        let slow = Stub::hanging();
        let up = site(200);
        for (value, admitted) in [("allow", true), ("deny", false)] {
            let until = Instant::now() + Duration::from_millis(200);
            let r = run(&reputation(&slow), &up, &[], &policy(value), Some(until)).await;
            assert_eq!(r.is_ok(), admitted, "on_score_unavailable = {value}: {r:?}");
        }
    }

    #[tokio::test]
    async fn a_probe_past_the_deadline_is_skipped_and_the_session_is_admitted() {
        let until = Instant::now() + Duration::from_millis(300);
        let r = run(
            &reputation(&ipqs(10)),
            &Stub::hanging(),
            &targets(),
            &policy("deny"),
            Some(until),
        )
        .await
        .expect("admitted on reputation alone");
        assert_eq!(r.bytes, 0, "no probe result was counted");
    }
}
