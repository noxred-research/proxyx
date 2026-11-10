//! The state every loop shares: the dependencies, the per-provider gates
//! (rate, breaker), the partition locks and small in-memory memory of the
//! static IPs.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use common::config::Settings;
use common::metrics::Metrics;
use common::retry::{BreakerConfig, BreakerState, TokenBucket, full_jitter};
use common::session::JOB_JITTER;
use common::types::{Kind, OrgId, Partition, ProviderId};
use parking_lot::Mutex;
use policy::EffectivePolicy;
use provider::MobileBoxClient;
use store::loaded::Loaded;
use store::{Db, Hot, InventoryRow};
use time::OffsetDateTime;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use verify::{ExitIpChecker, ExitIpConfig, LightProbe, ProbeRound, Reputation, Verdict};

use crate::gauges::LowSince;
use crate::plan::{CreateLatency, LeaseRate};

/// The org the warmer asks the policy set about: it has no policy of its
/// own, so the answer is the global policy merged with the route class.
const POLICY_ORG: &str = "proxyx-warmer";

/// Locks last this long and are renewed every few seconds.
const LOCK_TTL: Duration = Duration::from_secs(15);
/// One call of the keepalive echo check.
const ECHO_TIMEOUT: Duration = Duration::from_secs(10);
/// Longest wait after failed creates.
const BACKOFF_CAP: Duration = Duration::from_secs(300);

/// Probe rounds kept per IP for the replacement rule.
pub(crate) const PROBE_HISTORY: usize = 4;

/// The waits tests shorten.
pub(crate) struct Timing {
    /// Poll of the exit IP after a SIM box reset.
    pub box_poll: Duration,
    /// Poll of the leases while a box waits for `drain_wait`.
    pub drain_poll: Duration,
    /// First wait after a failed create (`base x 2^k`, up to [`BACKOFF_CAP`]).
    pub backoff_base: Duration,
    pub breaker: BreakerConfig,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            box_poll: Duration::from_secs(5),
            drain_poll: Duration::from_secs(1),
            backoff_base: Duration::from_secs(5),
            breaker: BreakerConfig::default(),
        }
    }
}

/// Rate limit of one provider. The breaker is shared through Redis, per
/// route class, so it is not here.
pub(crate) struct Gate {
    pub bucket: TokenBucket,
    /// `refill_rate` the bucket was built with: a changed policy rebuilds it.
    pub rate: u32,
}

struct Backoff {
    failures: u32,
    until: Instant,
}

/// What the static loop remembers between ticks. Lost on restart: the
/// deadlines and states live in Postgres, so the only cost of a loss is one
/// early re-check.
#[derive(Default)]
pub(crate) struct StaticMemory {
    /// Reputation verdict of the last check, for "twice in the warn zone".
    pub verdicts: HashMap<IpAddr, Verdict>,
    /// Newest probe rounds, oldest first.
    pub probes: HashMap<IpAddr, Vec<ProbeRound>>,
    /// Last retest and the `state_since` of the row it tested, so a retest is
    /// not repeated every tick within one cooldown, while an IP that cooled
    /// again (a new `state_since`) is not held back by an older retest.
    pub attempts: HashMap<IpAddr, (Instant, OffsetDateTime)>,
    /// Cooled IPs whose last retest failed like a provider outage, with the
    /// `state_since` of the cooldown: they are retested at the breaker's probe
    /// spacing, not after the policy cooldown.
    pub outage_retests: HashMap<IpAddr, OffsetDateTime>,
    /// SIM box resets that failed in a row.
    pub failed_resets: HashMap<IpAddr, u32>,
    /// SIM box resets started, for `rotate_min_interval` and `rotate_per_hour`.
    pub rotations: HashMap<IpAddr, Vec<Instant>>,
    /// Retired IPs whose unit is gone from Redis, with the `state_since` of
    /// the retirement: they are not looked at again until revived and retired
    /// once more.
    pub forgotten: HashMap<IpAddr, OffsetDateTime>,
    /// The partition each inventory row was listed in at the last pass, and
    /// the units still to be withdrawn from a partition their row left
    /// (another provider or region): the sync that moved the row does not
    /// touch Redis.
    pub listed: HashMap<IpAddr, Partition>,
    pub moved: HashSet<(IpAddr, Partition)>,
}

pub(crate) struct Warmer {
    pub settings: Settings,
    /// `settings.probe_org`, parsed once.
    pub probe_org: OrgId,
    pub db: Db,
    pub hot: Hot,
    pub loaded: watch::Receiver<Arc<Loaded>>,
    pub metrics: Arc<Metrics>,
    pub exit_ip: ExitIpChecker,
    /// Asks only the provider echo endpoint: the neutral keepalive request.
    pub echo_ip: ExitIpChecker,
    pub reputation: Reputation,
    pub probe: LightProbe,
    pub rotate: MobileBoxClient,
    pub timing: Timing,
    pub cancel: CancellationToken,
    /// Creates and SIM box resets run here, so shutdown can wait for them.
    pub tracker: TaskTracker,
    /// Names this replica in partition locks.
    holder: String,
    held: Mutex<HashSet<Partition>>,
    gates: Mutex<HashMap<ProviderId, Gate>>,
    backoffs: Mutex<HashMap<Partition, Backoff>>,
    pub rates: Mutex<HashMap<Partition, LeaseRate>>,
    /// How long a successful create took, per partition.
    pub create_latency: Mutex<HashMap<Partition, CreateLatency>>,
    pub memory: Mutex<StaticMemory>,
    /// SIM boxes being reset by this replica.
    pub resetting: Mutex<HashSet<IpAddr>>,
    /// Per (kind, provider, tier) of the cache gauges, since when the units have
    /// been below the low watermark without a break (`None`: not below), for
    /// `cache_low`. Lost on restart: the clock then starts again, so a restart
    /// delays the alert by `low_for`.
    pub low_since: Mutex<LowSince>,
}

/// The policy that applies to a provider's partitions.
pub(crate) fn policy_for<'a>(loaded: &'a Loaded, provider: &ProviderId) -> &'a EffectivePolicy {
    let org = POLICY_ORG
        .parse()
        .expect("the warmer org name is a valid slug");
    loaded.policies.effective(&org, Some(provider))
}

/// How long until a session's next keepalive step.
pub(crate) fn keepalive_delay(policy: &EffectivePolicy) -> Duration {
    common::retry::jittered(policy.keepalive_interval(), JOB_JITTER)
}

/// Rotating partitions to keep filled: for every rotating adapter the
/// policy allows, one partition per policy region.
pub(crate) fn rotating_partitions(loaded: &Loaded) -> Vec<(Partition, EffectivePolicy)> {
    let mut out = Vec::new();
    for adapter in loaded
        .adapters
        .iter()
        .filter(|a| a.kind() == Kind::Rotating)
    {
        let policy = policy_for(loaded, adapter.id());
        let listed = policy.providers.is_empty() || policy.providers.contains(adapter.id());
        if !policy.kinds.contains(&Kind::Rotating) || !listed {
            continue;
        }
        for region in &policy.regions {
            out.push((
                Partition {
                    provider: adapter.id().clone(),
                    region: region.clone(),
                },
                policy.clone(),
            ));
        }
    }
    out
}

/// Every partition the warmer may hold a lock on: the rotating ones and
/// those that hold static IPs. A retired row counts too: its unit leaves the
/// ready set under the partition lock.
pub(crate) fn all_partitions(loaded: &Loaded) -> Vec<Partition> {
    let mut out: Vec<Partition> = rotating_partitions(loaded)
        .into_iter()
        .map(|(p, _)| p)
        .chain(
            loaded
                .snapshot
                .inventory
                .iter()
                .map(InventoryRow::partition),
        )
        .collect();
    out.sort();
    out.dedup();
    out
}

impl Warmer {
    pub(crate) fn new(
        ctx: crate::WarmerCtx,
        timing: Timing,
        cancel: CancellationToken,
    ) -> anyhow::Result<Self> {
        let echo_cfg = ExitIpConfig {
            services: Vec::new(),
            min_agree: 1,
            timeout: ECHO_TIMEOUT,
        };
        Ok(Self {
            probe_org: ctx
                .settings
                .probe_org
                .parse()
                .context("probe_org is not a valid org id")?,
            echo_ip: ExitIpChecker::new(echo_cfg, ctx.metrics.clone()),
            settings: ctx.settings,
            db: ctx.db,
            hot: ctx.hot,
            loaded: ctx.loaded,
            metrics: ctx.metrics,
            exit_ip: ctx.exit_ip,
            reputation: ctx.reputation,
            probe: ctx.probe,
            rotate: ctx.rotate,
            timing,
            cancel,
            tracker: TaskTracker::new(),
            holder: uuid::Uuid::new_v4().to_string(),
            held: Mutex::default(),
            gates: Mutex::default(),
            backoffs: Mutex::default(),
            rates: Mutex::default(),
            create_latency: Mutex::default(),
            memory: Mutex::default(),
            resetting: Mutex::default(),
            low_since: Mutex::default(),
        })
    }

    /// The configuration now in force.
    pub(crate) fn loaded(&self) -> Arc<Loaded> {
        self.loaded.borrow().clone()
    }

    /// Keep the partition locks of every partition this warmer may work on.
    pub(crate) async fn locks_tick(&self) {
        let loaded = self.loaded();
        self.refresh_locks(&all_partitions(&loaded)).await;
    }

    /// Renew or take the lock of every partition. A partition whose lock is
    /// lost, or whose Redis call fails, is no longer ours: nothing starts
    /// work on it until the lock is back.
    pub(crate) async fn refresh_locks(&self, partitions: &[Partition]) {
        let mut mine = HashSet::new();
        for p in partitions {
            let outcome = match self.hot.lock_renew(p, &self.holder, LOCK_TTL).await {
                Ok(true) => Ok(true),
                Ok(false) => self.hot.lock_acquire(p, &self.holder, LOCK_TTL).await,
                Err(e) => Err(e),
            };
            match outcome {
                Ok(true) => {
                    mine.insert(p.clone());
                }
                Ok(false) => {}
                Err(error) => {
                    self.metrics.redis_down.set(1);
                    tracing::warn!(partition = %p, %error, "failed to take the partition lock");
                }
            }
        }
        *self.held.lock() = mine;
    }

    pub(crate) fn holds(&self, p: &Partition) -> bool {
        self.held.lock().contains(p)
    }

    /// Give every held lock back, so another replica takes over at once.
    pub(crate) async fn release_locks(&self) {
        let held: Vec<Partition> = self.held.lock().drain().collect();
        for p in held {
            if let Err(error) = self.hot.lock_release(&p, &self.holder).await {
                tracing::warn!(partition = %p, %error, "failed to release the partition lock");
            }
        }
    }

    /// Run `f` on the gate of `provider`, building it (and rebuilding the
    /// bucket when `refill_rate` changed) first.
    pub(crate) fn with_gate<T>(
        &self,
        provider: &ProviderId,
        refill_rate: u32,
        f: impl FnOnce(&mut Gate) -> T,
    ) -> T {
        let fresh = || Gate {
            bucket: TokenBucket::new(refill_rate, refill_rate, Instant::now()),
            rate: refill_rate,
        };
        let mut gates = self.gates.lock();
        let gate = gates.entry(provider.clone()).or_insert_with(fresh);
        if gate.rate != refill_rate {
            *gate = fresh();
        }
        f(gate)
    }

    /// A create ended: tell the route class's shared breaker. A Redis error
    /// is logged; the breaker only gets less accurate.
    pub(crate) async fn record_breaker(&self, p: &Partition, ok: bool) {
        let cfg = &self.timing.breaker;
        let result = if ok {
            self.hot.breaker_success(p, cfg).await
        } else {
            self.hot.breaker_failure(p, cfg).await
        };
        if let Err(error) = result {
            tracing::warn!(partition = %p, %error, "failed to record a breaker result");
        }
    }

    /// Charge `bytes` of provider traffic to the cost meter. A Redis error is
    /// logged; the meter only gets less accurate.
    pub(crate) async fn meter_bytes(&self, provider: &ProviderId, bytes: u64) {
        if let Err(error) = self
            .hot
            .cost_add(provider, bytes, 0, OffsetDateTime::now_utc())
            .await
        {
            tracing::warn!(%provider, %error, "failed to meter traffic");
        }
    }

    pub(crate) fn count_eviction(&self, cause: &str) {
        self.metrics
            .cache_evictions_total
            .with_label_values(&[cause])
            .inc();
    }

    /// Set `provider_breaker_state` to the worst state among the route
    /// classes of the provider: the breaker is per route class, the gauge per
    /// provider.
    pub(crate) async fn publish_breaker(&self, provider: &ProviderId) -> store::Result<()> {
        let mut worst = BreakerState::Closed as i64;
        for p in all_partitions(&self.loaded())
            .into_iter()
            .filter(|p| p.provider == *provider)
        {
            let (state, _) = self.hot.breaker_peek(&p, &self.timing.breaker).await?;
            worst = worst.max(state as i64);
        }
        self.metrics
            .provider_breaker_state
            .with_label_values(&[provider.as_str()])
            .set(worst);
        Ok(())
    }

    /// True while a partition waits out its backoff after a failed create.
    pub(crate) fn backing_off(&self, p: &Partition, now: Instant) -> bool {
        self.backoffs.lock().get(p).is_some_and(|b| b.until > now)
    }

    /// A create failed: wait `5 s x 2^k` (full jitter), up to 5 minutes.
    pub(crate) fn backoff_failed(&self, p: &Partition) {
        let mut all = self.backoffs.lock();
        let b = all.entry(p.clone()).or_insert(Backoff {
            failures: 0,
            until: Instant::now(),
        });
        b.until = Instant::now() + full_jitter(self.timing.backoff_base, BACKOFF_CAP, b.failures);
        b.failures = b.failures.saturating_add(1);
    }

    pub(crate) fn backoff_cleared(&self, p: &Partition) {
        self.backoffs.lock().remove(p);
    }

    /// Run `tick` on a jittered interval until shutdown. A tick that
    /// outlives `limit` is dropped and logged: no external call may stall a
    /// loop for good.
    pub(crate) async fn every<F, Fut>(
        &self,
        name: &'static str,
        interval: Duration,
        limit: Duration,
        mut tick: F,
    ) where
        F: FnMut() -> Fut,
        Fut: Future<Output = ()>,
    {
        loop {
            let wait = common::retry::jittered(interval, JOB_JITTER);
            tokio::select! {
                () = tokio::time::sleep(wait) => {}
                () = self.cancel.cancelled() => return,
            }
            tokio::select! {
                result = tokio::time::timeout(limit, tick()) => {
                    if result.is_err() {
                        tracing::warn!(loop_name = name, "warmer tick timed out");
                    }
                }
                () = self.cancel.cancelled() => return,
            }
        }
    }
}
