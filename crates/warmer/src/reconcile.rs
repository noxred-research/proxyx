//! The rotating reconcile loop and one session create
//!  Every 5 s, per partition and under its lock, [`crate::plan`]
//! decides how many creates to start. A create is a reservation, a recipe
//! with a new session id, the exit-IP quorum, the reputation rule, a light
//! probe on the policy targets and `ready_put`. A session that fails any
//! check never becomes ready.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::retry::BreakerState;
use common::session::UNIT_MARGIN;
use common::types::{Partition, ProviderId, Tier};
use policy::EffectivePolicy;
use provider::Adapter;
use rand::Rng as _;
use store::loaded::Loaded;
use store::{Admit, ExitIpClaim, Phase, SessionJob, UnitRecord};
use time::OffsetDateTime;
use verify::{AdmitError, ExitIpError, ExitQuery, Refusal};

use crate::budget::{self, Budget, EXIT_CHECK_BYTES};
use crate::checks::{new_session_id, rotating_endpoint};
use crate::job::Subject;
use crate::plan::{self, Bounds};
use crate::state::{Warmer, keepalive_delay, rotating_partitions};

/// An exit-IP claim outlives the session a little, so a late duplicate is
/// still seen.
pub(crate) const CLAIM_MARGIN: Duration = Duration::from_secs(120);

/// Why a create ended without a ready session.
#[derive(Debug)]
enum CreateError {
    /// The provider did not give a session (down, slow, login refused).
    /// Counts for the breaker.
    Provider(&'static str),
    /// The provider gave a session that fails a check. The provider works,
    /// the IP is no good: the cause is the eviction label.
    Rejected(&'static str),
    /// The adapter or the HTTP client is misconfigured.
    Internal(String),
    Cancelled,
}

impl CreateError {
    fn internal(error: impl ToString) -> Self {
        Self::Internal(error.to_string())
    }
}

/// What a create did, kept outside the future so a timeout still sees it.
#[derive(Default)]
struct Progress {
    claimed: Option<Ipv4Addr>,
    bytes: u64,
}

struct CreateJob {
    partition: Partition,
    session: String,
    adapter: Adapter,
    policy: EffectivePolicy,
}

impl Warmer {
    /// One pass over every rotating partition.
    pub(crate) async fn reconcile_tick(self: &Arc<Self>) {
        let loaded = self.loaded();
        for (partition, policy) in rotating_partitions(&loaded) {
            if let Err(error) = self.reconcile_partition(&loaded, &partition, &policy).await {
                self.metrics.redis_down.set(1);
                tracing::warn!(%partition, %error, "failed to reconcile the partition");
            }
        }
    }

    async fn reconcile_partition(
        self: &Arc<Self>,
        loaded: &Loaded,
        p: &Partition,
        policy: &EffectivePolicy,
    ) -> store::Result<()> {
        let Some(adapter) = loaded.adapters.get(&p.provider) else {
            return Ok(());
        };
        if !self.holds(p) {
            return Ok(());
        }
        if self.hot.warm_paused(p).await? {
            tracing::debug!(partition = %p, "warming is paused by a failed canary");
            return Ok(());
        }
        self.sweep_partition(p).await?;

        let now = Instant::now();
        // Once the shared breaker is open it alone paces the probes (its wait
        // doubles from 5 s to 5 min): the local failure backoff must not stack on
        // top of it, or a recovered provider waits for both.
        if self.backing_off(p, now)
            && self.hot.breaker_peek(p, &self.timing.breaker).await?.0 == BreakerState::Closed
        {
            return Ok(());
        }
        let counts = self.hot.counts(p).await?;
        let used = self
            .hot
            .cost_used(&p.provider, OffsetDateTime::now_utc())
            .await?;
        let spend = budget::assess(&policy.cost, used);

        let rules = &policy.rotating;
        let ready = policy.capacity.target(&p.region);
        let slow = spend.budget == Budget::Slow;
        let leases_per_min = {
            let mut rates = self.rates.lock();
            let rate = rates.entry(p.clone()).or_default();
            rate.observe(now, counts.leased);
            rate.per_minute()
        };
        // A slow budget keeps only `min_ready`: no extra target, one create at a time.
        let extra = if slow {
            0
        } else {
            let create_secs = self
                .create_latency
                .lock()
                .get(p)
                .and_then(plan::CreateLatency::secs);
            plan::extra_target(
                rules.headroom,
                rules.headroom_auto,
                leases_per_min,
                create_secs,
            )
        };
        let target = plan::target(ready.min_ready, ready.max_ready, extra);
        let need = plan::need(target, ready.max_ready, &counts);
        if need == 0 {
            return Ok(());
        }
        if spend.budget == Budget::Stopped || spend.creates_left == 0 {
            self.count_create(&p.provider, "budget");
            return Ok(());
        }
        let tokens = self.with_gate(&p.provider, rules.refill_rate, |g| g.bucket.available(now));
        let n = plan::starts(&Bounds {
            need,
            refill_concurrency: if slow { 1 } else { rules.refill_concurrency },
            creating: counts.creating,
            tokens,
            creates_left: spend.creates_left,
        });
        if n == 0 {
            return Ok(());
        }

        // An open or half-open breaker lets one probe create through. The
        // state is shared with the other replicas and the gateway.
        let n = match self.hot.breaker_claim(p, &self.timing.breaker).await?.1 {
            Admit::Go => n,
            Admit::Probe => 1,
            Admit::Blocked => {
                self.count_create(&p.provider, "breaker");
                self.publish_breaker(&p.provider).await?;
                return Ok(());
            }
        };

        for _ in 0..n {
            let job = CreateJob {
                partition: p.clone(),
                session: new_session_id(adapter),
                adapter: adapter.clone(),
                policy: policy.clone(),
            };
            // A probe that cannot start is not reported: its lease runs out
            // and the next tick takes it again.
            if !self.start_create(job, ready.max_ready).await? {
                break;
            }
        }
        self.publish_breaker(&p.provider).await?;
        Ok(())
    }

    /// Reserve, mark in flight, take a rate token and spawn the create.
    /// False when the partition is full or the reservation expired.
    async fn start_create(self: &Arc<Self>, job: CreateJob, max_ready: u32) -> store::Result<bool> {
        let p = job.partition.clone();
        let Some(reservation) = self.hot.reserve_create(&p, max_ready).await? else {
            return Ok(false);
        };
        let in_flight_ttl = job.policy.create_deadline * 2;
        if !self
            .hot
            .create_start(&p, &reservation, &job.session, in_flight_ttl)
            .await?
        {
            return Ok(false);
        }
        let rate = job.policy.rotating.refill_rate;
        self.with_gate(&p.provider, rate, |g| {
            g.bucket.try_take(1, Instant::now());
        });
        // Counted at the start, so two replicas cannot both fit under the cap.
        if let Err(error) = self
            .hot
            .cost_add(&p.provider, 0, 1, OffsetDateTime::now_utc())
            .await
        {
            // Nothing is spawned: the slot would stay until the deadline.
            if let Err(abort) = self.hot.create_abort(&p, &job.session).await {
                tracing::warn!(partition = %p, %abort, "failed to abort a create that did not start");
            }
            return Err(error);
        }
        let w = self.clone();
        self.tracker
            .spawn(async move { w.create_session(job).await });
        Ok(true)
    }

    fn count_create(&self, provider: &ProviderId, outcome: &str) {
        self.metrics
            .warm_creates_total
            .with_label_values(&[provider.as_str(), outcome])
            .inc();
    }

    async fn create_session(self: Arc<Self>, job: CreateJob) {
        let mut progress = Progress::default();
        let limit = job.policy.create_deadline * 2;
        let result = tokio::select! {
            r = tokio::time::timeout(limit, self.try_create(&job, &mut progress)) => {
                r.unwrap_or(Err(CreateError::Provider("create deadline exceeded")))
            }
            () = self.cancel.cancelled() => Err(CreateError::Cancelled),
        };
        let ready = result.is_ok();
        self.finish_create(&job, &progress, result).await;
        if ready {
            // The session is final: a shutdown or a slow sample must not undo it.
            let p = &job.partition;
            tokio::select! {
                () = self.maybe_sample(p, Subject::Rotating, &job.session, &job.policy) => {}
                () = self.cancel.cancelled() => {}
            }
        }
    }

    async fn try_create(
        &self,
        job: &CreateJob,
        progress: &mut Progress,
    ) -> Result<(), CreateError> {
        let started = Instant::now();
        let p = &job.partition;
        let policy = &job.policy;
        let endpoint = rotating_endpoint(&job.adapter, &job.session, &p.region)
            .map_err(CreateError::internal)?;

        let query = ExitQuery::in_region(&p.region, job.adapter.echo_url());
        progress.bytes += EXIT_CHECK_BYTES;
        let exit = self
            .exit_ip
            .check(&endpoint, &query)
            .await
            .map_err(|e| match e {
                e if e.is_outage() => CreateError::Provider("exit ip services unreachable"),
                ExitIpError::Client(e) => CreateError::internal(e),
                _ => CreateError::Rejected("quality"),
            })?;

        let now = OffsetDateTime::now_utc();
        let max_age = {
            let life = job.adapter.session_life();
            let age = policy.rotating.max_age_for(life);
            // 20% jitter, downwards: sessions of one batch do not all end together.
            age.mul_f64(1.0 - 0.2 * rand::thread_rng().r#gen::<f64>())
        };
        let ip = IpAddr::V4(exit.ip);
        match self
            .hot
            .claim_exit_ip(ip, &job.session, max_age + CLAIM_MARGIN)
            .await
            .map_err(CreateError::internal)?
        {
            ExitIpClaim::Claimed => progress.claimed = Some(exit.ip),
            ExitIpClaim::Duplicate { .. } => return Err(CreateError::Rejected("duplicate")),
        }

        let targets = self.loaded().probe_targets.for_region(&p.region);
        let mut tier = Tier::Normal;
        match verify::admit(
            &self.reputation,
            &self.probe,
            ip,
            &endpoint,
            &targets,
            policy,
            None,
        )
        .await
        {
            Ok(admitted) => progress.bytes += admitted.bytes,
            // Clean but slow: kept as a degraded session while the partition
            // has room for one, so slow IPs serve when no fast one is left.
            Err(AdmitError::Refused {
                cause: Refusal::Slow,
                bytes,
            }) => {
                progress.bytes += bytes;
                let counts = self.hot.counts(p).await.map_err(CreateError::internal)?;
                let room = counts.degraded_free
                    < plan::degraded_cap(policy.capacity.target(&p.region).max_ready);
                if !room {
                    return Err(CreateError::Rejected(Refusal::Slow.label()));
                }
                tier = Tier::Degraded;
            }
            Err(AdmitError::Refused { cause, bytes }) => {
                progress.bytes += bytes;
                return Err(CreateError::Rejected(cause.label()));
            }
            Err(AdmitError::Probe(e)) => return Err(CreateError::internal(e)),
        }

        // The job first: a failure after this line leaves a job for a session
        // that is not ready, which its first step drains. The other order
        // would leave a ready session that nothing keeps alive or evicts.
        let unix = now.unix_timestamp();
        let session_job = SessionJob {
            partition: p.clone(),
            session: job.session.clone(),
            ip: exit.ip,
            born: unix,
            expires: unix + i64::try_from(max_age.as_secs()).unwrap_or(i64::MAX / 2),
            phase: Phase::fresh(unix),
        };
        let first = keepalive_delay(policy);
        self.hot
            .due_schedule(&session_job.encode(), now + first)
            .await
            .map_err(CreateError::internal)?;

        let unit = UnitRecord {
            id: job.session.clone(),
            ip,
            expires_at: Some(now + max_age),
            ttl: Some(max_age + UNIT_MARGIN),
            owner: None,
        };
        self.hot
            .ready_put_tier(p, &unit, tier)
            .await
            .map_err(CreateError::internal)?;
        // Ready from here on: the time it took feeds the adaptive headroom.
        self.create_latency
            .lock()
            .entry(p.clone())
            .or_default()
            .record(started.elapsed());
        Ok(())
    }

    async fn finish_create(
        &self,
        job: &CreateJob,
        progress: &Progress,
        result: Result<(), CreateError>,
    ) {
        let p = &job.partition;
        let provider = &p.provider;
        if progress.bytes > 0 {
            self.meter_bytes(provider, progress.bytes).await;
        }
        match &result {
            Ok(()) => {
                self.record_breaker(p, true).await;
                self.backoff_cleared(p);
                self.count_create(provider, "ok");
                tracing::debug!(partition = %p, "session ready");
            }
            Err(error) => {
                self.undo_create(job, progress).await;
                if !matches!(error, CreateError::Cancelled) {
                    // Only a provider that gave no session counts against its
                    // breaker: a rejected IP or a misconfiguration does not.
                    let provider_ok = !matches!(error, CreateError::Provider(_));
                    self.record_breaker(p, provider_ok).await;
                    self.backoff_failed(p);
                    self.count_create(provider, "failed");
                }
                match error {
                    CreateError::Cancelled => {}
                    CreateError::Provider(why) => {
                        tracing::warn!(partition = %p, reason = why, "session create failed");
                    }
                    CreateError::Rejected(cause) => {
                        self.count_eviction(cause);
                        tracing::info!(partition = %p, cause, "new session rejected");
                    }
                    CreateError::Internal(why) => {
                        tracing::error!(partition = %p, error = %why, "session create is misconfigured");
                    }
                }
            }
        }
        if let Err(error) = self.publish_breaker(provider).await {
            tracing::warn!(%provider, %error, "failed to read the breaker state");
        }
    }

    /// Give the in-flight slot and the exit-IP claim of a failed create back.
    async fn undo_create(&self, job: &CreateJob, progress: &Progress) {
        let p = &job.partition;
        if let Err(error) = self.hot.create_abort(p, &job.session).await {
            tracing::warn!(partition = %p, %error, "failed to abort a create");
        }
        if let Some(ip) = progress.claimed
            && let Err(error) = self.hot.release_exit_ip(IpAddr::V4(ip), &job.session).await
        {
            tracing::warn!(partition = %p, %error, "failed to release an exit ip claim");
        }
    }
}
