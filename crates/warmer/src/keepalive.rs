//! Keepalive and eviction of ready rotating sessions.
//!
//! Every ready session is one job in the shared `due` set (see [`crate::job`]).
//! A step sends a neutral request through the session to the adapter's echo
//! Endpoint, which also proves the exit IP, then applies
//! the eviction rules. Draining a session stops leasing it (`ready_take`);
//! its open tunnels continue until they end or the drain cap passes.
//! Keepalive never extends `max_age`.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use common::config::DRAIN_CAP;
use common::session::UNIT_MARGIN;
use common::types::Partition;
use policy::EffectivePolicy;
use provider::{Adapter, SessionMode};
use time::OffsetDateTime;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use verify::{ExitQuery, Verdict};

use store::{ExitIpClaim, Phase, SessionJob, UnitRecord};

use crate::budget::{EXIT_CHECK_BYTES, KEEPALIVE_BYTES};
use crate::checks::rotating_endpoint;
use crate::job::SampleWatch;
use crate::reconcile::CLAIM_MARGIN;
use crate::state::{Warmer, keepalive_delay, policy_for};
use crate::statics::time_duration;

/// Jobs claimed per tick.
const CLAIM_BATCH: u32 = 64;
/// A claimed job comes back after this unless its step finishes, so a
/// crashed replica loses nothing.
const VISIBILITY: Duration = Duration::from_secs(60);
/// Steps running at once.
const CONCURRENCY: usize = 16;
/// Time limit of one keepalive request.
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(15);
/// Failed keepalives in a row that drain a session.
const FAILS_TO_DRAIN: u32 = 3;
/// Window of the `stability` counts of drops and IP changes.
const STABILITY_WINDOW_SECS: i64 = 3_600;
/// First look at a session that began to drain, and the poll after it.
const FIRST_DRAIN_CHECK: Duration = Duration::from_secs(5);
const DRAIN_POLL: Duration = Duration::from_secs(30);

/// What a step decided.
enum Next {
    /// Run `job` again after the delay.
    Again(SessionJob, Duration),
    /// The session is gone.
    Done,
}

/// What re-checking a session that shows a new exit IP found.
enum Adopt {
    /// The echo was wrong: the IP is the same.
    Same,
    /// The new IP passed; the session moved to it.
    Moved(Ipv4Addr),
    /// The new IP is bad; drain for this cause.
    Drain(&'static str),
    /// The check services did not answer: count a failed keepalive.
    Unverified,
}

impl Warmer {
    /// Claim the jobs that are due and run their steps.
    pub(crate) async fn keepalive_tick(self: &Arc<Self>) {
        let claimed = match self.hot.due_claim(CLAIM_BATCH, VISIBILITY).await {
            Ok(jobs) => jobs,
            Err(error) => {
                self.metrics.redis_down.set(1);
                tracing::warn!(%error, "failed to claim due jobs");
                return;
            }
        };
        let permits = Arc::new(Semaphore::new(CONCURRENCY));
        let mut steps = JoinSet::new();
        for raw in claimed {
            let (w, permits) = (self.clone(), permits.clone());
            if let Some(job) = SessionJob::parse(&raw) {
                steps.spawn(async move {
                    let _permit = permits.acquire().await;
                    w.session_step(raw, job).await;
                });
            } else if let Some(watch) = SampleWatch::parse(&raw) {
                steps.spawn(async move {
                    let _permit = permits.acquire().await;
                    w.watch_step(raw, watch).await;
                });
            }
            // Another component's job: leave it; it returns after its visibility.
        }
        while let Some(joined) = steps.join_next().await {
            if let Err(error) = joined {
                tracing::error!(%error, "keepalive step died");
            }
        }
    }

    async fn session_step(&self, raw: String, job: SessionJob) {
        let next = match job.phase {
            Phase::Keep { .. } => self.keep_step(&job).await,
            Phase::Drain { since } => self.drain_step(&job, since).await,
        };
        let outcome = match next {
            Ok(Next::Again(next, delay)) => {
                self.reschedule(&raw, Some((next.encode(), delay))).await
            }
            Ok(Next::Done) => self.reschedule(&raw, None).await,
            Err(error) => Err(error),
        };
        if let Err(error) = outcome {
            self.metrics.redis_down.set(1);
            // The job returns after its visibility time and the step repeats.
            tracing::warn!(partition = %job.partition, %error, "keepalive step failed");
        }
    }

    /// Replace the claimed job `raw` by its next text, or remove it. The
    /// next job is written first: a crash then repeats a step instead of
    /// losing the session.
    pub(crate) async fn reschedule(
        &self,
        raw: &str,
        next: Option<(String, Duration)>,
    ) -> store::Result<()> {
        if let Some((encoded, delay)) = next {
            self.hot
                .due_schedule(&encoded, OffsetDateTime::now_utc() + delay)
                .await?;
            if encoded == raw {
                return Ok(());
            }
        }
        self.hot.due_done(raw).await?;
        Ok(())
    }

    async fn keep_step(&self, job: &SessionJob) -> store::Result<Next> {
        let Phase::Keep {
            mut fails,
            mut drops,
            mut changes,
            mut window_start,
            mut last_recheck,
            mut warn_zone,
        } = job.phase
        else {
            return Ok(Next::Done);
        };
        let p = &job.partition;
        let loaded = self.loaded();
        let Some(adapter) = loaded.adapters.get(&p.provider) else {
            return self.start_drain(job, "retired").await;
        };
        if adapter.session_mode() == SessionMode::PerRequest {
            return self.start_drain(job, "session_mode").await;
        }
        let policy = policy_for(&loaded, &p.provider);
        let stability = policy.rotating.stability;
        let unix = OffsetDateTime::now_utc().unix_timestamp();

        if !self.hot.is_ready(p, &job.session).await? {
            // The API drained it (failed canary, block): wait out its tunnels.
            return Ok(drain_next(job));
        }
        if unix >= job.expires {
            return self.start_drain(job, "max_age").await;
        }
        // The probe org's sample pin is a reservation, not use: a prober that
        // never answers must not keep the session past ready_ttl. Its open
        // tunnels still count, so a running sample keeps its session.
        let load = self
            .hot
            .unit_load_without_pins(p, &job.session, &self.probe_org)
            .await?;
        let in_use = load.leases > 0 || load.tunnels > 0;
        let ready_ttl = time_duration(policy.rotating.ready_ttl).whole_seconds();
        if !in_use && unix.saturating_sub(job.born) >= ready_ttl {
            return self.start_drain(job, "ready_ttl").await;
        }

        let seen = self.keepalive_request(adapter, p, &job.session).await;
        if unix - window_start >= STABILITY_WINDOW_SECS {
            (drops, changes, window_start) = (0, 0, unix);
        }
        let mut ip = job.ip;
        let dropped = match seen {
            Some(seen) if seen == ip => false,
            Some(_) => {
                // A new IP in the echo: drain above the limit, else check
                // the new IP like a new session and keep the session.
                if changes + 1 > stability.changes_per_hour {
                    return self.start_drain(job, "stability").await;
                }
                match self.adopt_ip(job, adapter, policy).await? {
                    Adopt::Same => false,
                    Adopt::Moved(new_ip) => {
                        (ip, changes) = (new_ip, changes + 1);
                        false
                    }
                    Adopt::Drain(cause) => return self.start_drain(job, cause).await,
                    Adopt::Unverified => true,
                }
            }
            None => true,
        };
        if dropped {
            fails += 1;
            drops += 1;
            if fails >= FAILS_TO_DRAIN {
                return self.start_drain(job, "keepalive").await;
            }
            if drops > stability.drops_per_hour {
                return self.start_drain(job, "stability").await;
            }
        } else {
            fails = 0;
        }

        let recheck_every = time_duration(policy.rotating.recheck_every).whole_seconds();
        if !dropped && unix.saturating_sub(last_recheck) >= recheck_every {
            let verdict = verify::assess(&self.reputation, IpAddr::V4(ip), policy)
                .await
                .verdict
                .escalate(warn_zone.then_some(Verdict::Recheck));
            if verdict == Verdict::Drain {
                return self.start_drain(job, "reputation").await;
            }
            warn_zone = verdict == Verdict::Recheck;
            last_recheck = unix;
        }

        let next = SessionJob {
            ip,
            phase: Phase::Keep {
                fails,
                drops,
                changes,
                window_start,
                last_recheck,
                warn_zone,
            },
            ..job.clone()
        };
        Ok(Next::Again(next, keepalive_delay(policy)))
    }

    /// The echo shows another exit IP than the one the session was verified
    /// with. Run the exit-IP quorum again (country included), the reputation
    /// rule and the duplicate claim for the new IP, and move the session's
    /// unit record, claim and job to it, in the tier it had. Nothing changes
    /// when a check fails.
    async fn adopt_ip(
        &self,
        job: &SessionJob,
        adapter: &Adapter,
        policy: &EffectivePolicy,
    ) -> store::Result<Adopt> {
        let p = &job.partition;
        let Ok(endpoint) = rotating_endpoint(adapter, &job.session, &p.region) else {
            return Ok(Adopt::Unverified);
        };
        let query = ExitQuery::in_region(&p.region, adapter.echo_url());
        let checked =
            tokio::time::timeout(KEEPALIVE_TIMEOUT, self.exit_ip.check(&endpoint, &query)).await;
        self.meter_bytes(&p.provider, EXIT_CHECK_BYTES).await;
        let exit = match checked {
            Ok(Ok(exit)) => exit,
            Ok(Err(error)) if error.is_outage() => return Ok(Adopt::Unverified),
            Ok(Err(error)) => {
                tracing::info!(partition = %p, %error, "the new exit ip fails the quorum");
                return Ok(Adopt::Drain("quality"));
            }
            Err(_) => return Ok(Adopt::Unverified),
        };
        if exit.ip == job.ip {
            // The echo disagreed with the quorum: the IP did not change.
            tracing::debug!(partition = %p, "echo and quorum disagree, keeping the ip");
            return Ok(Adopt::Same);
        }
        let new_ip = IpAddr::V4(exit.ip);
        let assessment = verify::assess(&self.reputation, new_ip, policy).await;
        if assessment.verdict == Verdict::Drain {
            return Ok(Adopt::Drain("reputation"));
        }

        let unix = OffsetDateTime::now_utc().unix_timestamp();
        let left = Duration::from_secs(u64::try_from(job.expires - unix).unwrap_or(0));
        // A new exit IP has no quality verdict of its own: the session keeps
        // its tier, so a slow session does not turn normal on a new IP.
        let tier = self.hot.tier(p, &job.session).await?;
        let claim = self
            .hot
            .claim_exit_ip(new_ip, &job.session, left + CLAIM_MARGIN)
            .await?;
        if matches!(claim, ExitIpClaim::Duplicate { .. }) {
            return Ok(Adopt::Drain("duplicate"));
        }
        let expires_at = OffsetDateTime::from_unix_timestamp(job.expires).ok();
        let unit = UnitRecord {
            id: job.session.clone(),
            ip: new_ip,
            expires_at,
            ttl: Some(left + UNIT_MARGIN),
            owner: None,
        };
        // Only while the session is still leasable: the checks above took up
        // to 30 s, and a drain in that time (a block, a canary, the release
        // rule) must not be undone.
        if !self.hot.ready_update(p, &unit, tier).await? {
            self.hot.release_exit_ip(new_ip, &job.session).await?;
            tracing::debug!(partition = %p, "session left the ready set while its new exit ip was checked");
            return Ok(Adopt::Same);
        }
        self.hot
            .release_exit_ip(IpAddr::V4(job.ip), &job.session)
            .await?;
        tracing::info!(partition = %p, "session moved to a new exit ip");
        Ok(Adopt::Moved(exit.ip))
    }

    /// The neutral request: the provider echo endpoint through the session.
    /// Without an echo endpoint the public quorum stands in.
    async fn keepalive_request(
        &self,
        adapter: &Adapter,
        p: &Partition,
        session: &str,
    ) -> Option<Ipv4Addr> {
        let endpoint = match rotating_endpoint(adapter, session, &p.region) {
            Ok(endpoint) => endpoint,
            Err(error) => {
                tracing::error!(partition = %p, %error, "failed to render a keepalive endpoint");
                return None;
            }
        };
        let (checker, query, bytes) = match adapter.echo_url() {
            Some(url) => {
                let query = ExitQuery {
                    echo_url: Some(url),
                    ..ExitQuery::default()
                };
                (&self.echo_ip, query, KEEPALIVE_BYTES)
            }
            None => (
                &self.exit_ip,
                ExitQuery::in_region(&p.region, None),
                EXIT_CHECK_BYTES,
            ),
        };
        let check = tokio::time::timeout(KEEPALIVE_TIMEOUT, checker.check(&endpoint, &query)).await;
        self.meter_bytes(&p.provider, bytes).await;
        match check {
            Ok(Ok(exit)) => Some(exit.ip),
            Ok(Err(error)) => {
                tracing::debug!(partition = %p, %error, "keepalive failed");
                None
            }
            Err(_) => {
                tracing::debug!(partition = %p, "keepalive timed out");
                None
            }
        }
    }

    /// Stop leasing the session and start waiting for its tunnels.
    async fn start_drain(&self, job: &SessionJob, cause: &'static str) -> store::Result<Next> {
        let p = &job.partition;
        self.hot.ready_take(p, &job.session).await?;
        self.count_eviction(cause);
        tracing::info!(partition = %p, cause, "session drains");
        Ok(drain_next(job))
    }

    async fn drain_step(&self, job: &SessionJob, since: i64) -> store::Result<Next> {
        let p = &job.partition;
        let load = self.hot.unit_load(p, &job.session).await?;
        let unix = OffsetDateTime::now_utc().unix_timestamp();
        let drained_for = Duration::from_secs(u64::try_from(unix - since).unwrap_or(0));
        if load.tunnels > 0 && drained_for < DRAIN_CAP {
            return Ok(Next::Again(job.clone(), DRAIN_POLL));
        }
        if load.tunnels > 0 {
            tracing::warn!(
                partition = %p,
                tunnels = load.tunnels,
                "drain cap reached, forgetting a session that still has tunnels"
            );
        }
        self.hot
            .release_exit_ip(IpAddr::V4(job.ip), &job.session)
            .await?;
        self.hot.unit_drop(p, &job.session).await?;
        Ok(Next::Done)
    }
}

/// The first step of a drain that starts now.
fn drain_next(job: &SessionJob) -> Next {
    let since = OffsetDateTime::now_utc().unix_timestamp();
    let drained = SessionJob {
        phase: Phase::Drain { since },
        ..job.clone()
    };
    Next::Again(drained, FIRST_DRAIN_CHECK)
}
