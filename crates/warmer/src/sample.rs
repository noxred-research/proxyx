//! Browser samples.
//!
//! Only a browser measures page load time, and it costs a pod, so only a
//! share of newly verified candidates (`criteria.browser_sample`) gets one:
//! rotating sessions right after they became ready, static IPs right after
//! *Candidate* became *Available*.
//!
//! The warmer reserves the candidate for the probe org under a fresh `sid`,
//! as the sticky key the gateway leases `px-sid-<sid>` under
//! ([`store::sid_sticky`], `Hot::lease_pin`), queues a [`store::SampleJob`]
//! and watches the `due`
//! set for the verdict the control API writes. A failed sample drains the
//! session or cools the IP, except for a slow verdict (pages loaded but over
//! the time limits), which only moves it to the degraded tier. A stale
//! verdict, or none (the browser pool is down), is ignored: then only the
//! light probe applies. The candidate is leasable while the sample runs; the
//! sample is a later check, not a gate.

use std::time::Duration;

use anyhow::Context as _;
use common::types::{IpState, Partition, Tier};
use policy::EffectivePolicy;
use rand::Rng as _;
use store::{SampleJob, Transition, Verdict, sid_sticky};
use time::OffsetDateTime;
use uuid::Uuid;
use verify::Url;

use crate::job::{SampleWatch, Subject};
use crate::state::{Warmer, policy_for};
use crate::statics::time_duration;

/// A queued sample stays listed this long; the watch gives up then.
const SAMPLE_TTL: Duration = Duration::from_secs(600);

/// How often the watch looks for the verdict.
const WATCH_POLL: Duration = Duration::from_secs(10);

/// Is `verdict` still worth acting on at `now` (unix seconds)?
fn verdict_is_fresh(verdict: &Verdict, max_age: Duration, now: i64) -> bool {
    now.saturating_sub(verdict.checked_at) <= time_duration(max_age).whole_seconds()
}

impl Warmer {
    /// Maybe queue a browser sample for a candidate that just became ready.
    /// Best effort: a failure is logged and never fails the create or check.
    pub(crate) async fn maybe_sample(
        &self,
        partition: &Partition,
        subject: Subject,
        unit: &str,
        policy: &EffectivePolicy,
    ) {
        let targets = self.loaded().probe_targets.for_region(&partition.region);
        if targets.is_empty() || rand::thread_rng().r#gen::<f64>() >= policy.criteria.browser_sample
        {
            return;
        }
        if let Err(error) = self.queue_sample(partition, subject, unit, &targets).await {
            tracing::warn!(%partition, error = ?error, "failed to queue a browser sample");
        }
    }

    async fn queue_sample(
        &self,
        p: &Partition,
        subject: Subject,
        unit: &str,
        targets: &[Url],
    ) -> anyhow::Result<()> {
        let id = Uuid::new_v4().simple().to_string();
        // The prober sends the key as an inbound username option: [a-z0-9_] only.
        let sid = format!("smp{}", &id[..16]);
        if !self
            .hot
            .lease_pin(p, &self.probe_org, &sid_sticky(&sid), unit, SAMPLE_TTL)
            .await
            .context("failed to reserve the candidate")?
        {
            return Ok(());
        }
        let job = SampleJob {
            job_id: id.clone(),
            route_class: p.provider.to_string(),
            provider: p.provider.clone(),
            region: p.region.clone(),
            sid: Some(sid.clone()),
            targets: targets.iter().map(Url::to_string).collect(),
        };
        let watch = SampleWatch {
            job_id: id.clone(),
            subject,
            partition: p.clone(),
            unit: unit.to_owned(),
            sid: sid.clone(),
            created: OffsetDateTime::now_utc().unix_timestamp(),
        };
        let queued = async {
            self.hot
                .sample_put(&job, SAMPLE_TTL)
                .await
                .context("failed to queue the sample")?;
            self.hot
                .due_schedule(&watch.encode(), OffsetDateTime::now_utc() + WATCH_POLL)
                .await
                .context("failed to watch the sample")
        }
        .await;
        if let Err(error) = queued {
            // Nothing will watch the sample: do not hold the candidate for the probe org.
            if let Err(undo) = self.hot.sample_done(&id).await {
                tracing::warn!(partition = %p, error = %undo, "failed to withdraw a sample");
            }
            if let Err(undo) = self.release_pin(p, &sid).await {
                tracing::warn!(partition = %p, error = %undo, "failed to release a sample reservation");
            }
            return Err(error);
        }
        tracing::debug!(partition = %p, "browser sample queued");
        Ok(())
    }

    pub(crate) async fn watch_step(&self, raw: String, watch: SampleWatch) {
        let next = match self.watch_outcome(&watch).await {
            Ok(false) => None,
            Ok(true) => Some((raw.clone(), WATCH_POLL)),
            Err(error) => {
                // The job returns after its visibility time and the step repeats.
                tracing::warn!(partition = %watch.partition, error = ?error, "sample watch failed");
                return;
            }
        };
        if let Err(error) = self.reschedule(&raw, next).await {
            self.metrics.redis_down.set(1);
            tracing::warn!(partition = %watch.partition, %error, "failed to reschedule a sample watch");
        }
    }

    /// True while the watch goes on.
    async fn watch_outcome(&self, w: &SampleWatch) -> anyhow::Result<bool> {
        let loaded = self.loaded();
        let policy = policy_for(&loaded, &w.partition.provider);
        let unix = OffsetDateTime::now_utc().unix_timestamp();
        let Some(verdict) = self.hot.verdict_get(&w.job_id).await? else {
            let waited = unix.saturating_sub(w.created);
            if waited < time_duration(SAMPLE_TTL).whole_seconds() {
                return Ok(true);
            }
            self.hot.sample_done(&w.job_id).await?;
            self.release_pin(&w.partition, &w.sid).await?;
            tracing::info!(
                partition = %w.partition,
                "no verdict for a browser sample, only the light probe applies"
            );
            return Ok(false);
        };
        self.release_pin(&w.partition, &w.sid).await?;
        if !verdict_is_fresh(&verdict, policy.criteria.verdict_max_age, unix) {
            tracing::info!(partition = %w.partition, "ignoring a stale browser sample verdict");
        } else if !verdict.ok {
            if verdict.slow {
                self.demote_candidate(w).await?;
            } else {
                self.fail_candidate(w, policy).await?;
            }
        }
        Ok(false)
    }

    async fn release_pin(&self, p: &Partition, sid: &str) -> anyhow::Result<()> {
        self.hot
            .release(p, &self.probe_org, &sid_sticky(sid), None)
            .await
            .context("failed to release the sample reservation")?;
        Ok(())
    }

    /// The browser loaded the pages through the candidate, but over the time
    /// limits: keep it leasable in the degraded tier.
    async fn demote_candidate(&self, w: &SampleWatch) -> anyhow::Result<()> {
        tracing::info!(partition = %w.partition, "browser sample slow, unit degraded");
        if w.subject == Subject::Static
            && let Ok(ip) = w.unit.parse()
        {
            if let Some(row) = self.db.inventory_row(ip).await?
                && row.state.is_leasable()
            {
                self.retier(row, Tier::Degraded).await?;
            }
            return Ok(());
        }
        self.hot
            .set_tier(&w.partition, &w.unit, Tier::Degraded)
            .await
            .context("failed to degrade a session")?;
        Ok(())
    }

    /// The browser could not load the pages through the candidate: drain the
    /// session, or cool the IP.
    async fn fail_candidate(
        &self,
        w: &SampleWatch,
        policy: &EffectivePolicy,
    ) -> anyhow::Result<()> {
        if self.hot.ready_take(&w.partition, &w.unit).await? {
            self.count_eviction("quality");
        }
        tracing::info!(partition = %w.partition, "browser sample failed");
        if w.subject == Subject::Static
            && let Ok(ip) = w.unit.parse()
            && let Some(row) = self.db.inventory_row(ip).await?
            && row.state.is_leasable()
        {
            let until = OffsetDateTime::now_utc() + time_duration(policy.static_ips.cooldown);
            let change =
                Transition::to(IpState::Cooldown, "browser sample failed").cooldown_until(until);
            self.transition(&row, change).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verdict(checked_at: i64) -> Verdict {
        Verdict {
            ok: false,
            success_ratio: 0.0,
            checked_at,
            detail: String::new(),
            slow: false,
        }
    }

    #[test]
    fn a_verdict_is_fresh_up_to_verdict_max_age() {
        let day = Duration::from_secs(86_400);
        assert!(verdict_is_fresh(&verdict(1_000), day, 1_000));
        assert!(verdict_is_fresh(&verdict(1_000), day, 1_000 + 86_400));
        assert!(!verdict_is_fresh(&verdict(1_000), day, 1_000 + 86_401));
    }
}
