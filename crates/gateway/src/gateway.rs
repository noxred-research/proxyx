//! Shared state of the data plane and the open pipeline of one tunnel.
//!
//! Order of checks: org key, listener rule, options,
//! destination, org tunnel cap, failed-lease memo, then lease and dial
//! ([`crate::acquire`]). Every refusal is a [`Cause`]; none ends in a direct
//! dial.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use common::Cause;
use common::Secret;
use common::config::{DRAIN_CAP, Settings};
use common::metrics::Metrics;
use common::retry::BreakerConfig;
use common::session::gb_to_bytes;
use common::types::{OrgId, Rotation, StickyScope, Target};
use dial::ProxyStream;
use moka::future::Cache;
use parking_lot::Mutex;
use policy::{InboundOptions, StickyKeySource};
use store::loaded::Loaded;
use store::{AffinityRecord, Db, Hot, SessionRecord};
use time::OffsetDateTime;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tokio::time::{Instant, timeout};
use tokio_util::task::TaskTracker;
use uuid::Uuid;
use verify::{ExitIpChecker, LightProbe, Reputation};

use crate::GatewayCtx;
use crate::acquire::{ROTATING_RECHECK, Req, STATIC_RECHECK, candidates};
use crate::auth::KeyCache;
use crate::relay::Tunnel;
use crate::tunnels::{TunnelInfo, Tunnels};

/// How often the keeper of a tunnel looks at its counters and its unit. A
/// third of [`TUNNEL_TTL`], as `LeaseLimits::tunnel_ttl` asks.
const KEEP_EVERY: Duration = Duration::from_secs(5);
/// After one direction of a tunnel ended, the other gets this long to send a
/// byte before the tunnel is closed.
const HALF_CLOSE_LINGER: Duration = Duration::from_secs(60);
/// The `provider` label of a counter for a connection or lease no provider
/// served: refused before one was chosen, or by all of them.
pub(crate) const NO_PROVIDER: &str = "none";

/// Timing of the per-tunnel keeper and the breaker. Tests shorten it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Pacing {
    pub keep_every: Duration,
    /// How long a tunnel may keep running on a unit that was drained: a
    /// rotating session removed from the ready set, or a static IP that left
    /// leasing. The keeper closes the tunnel this long after it sees the
    /// drain ([`DRAIN_CAP`]). The warmer cuts the counters of a drained
    /// session at the same time. An org block has no cap: the keeper closes
    /// the tunnels it covers at its next tick, on every replica.
    pub drain_cap: Duration,
    /// How long a tunnel whose one direction ended waits for a byte in the
    /// other ([`HALF_CLOSE_LINGER`]).
    pub half_close_linger: Duration,
    /// When a route class opens and probes, as the warmer reads it.
    pub breaker: BreakerConfig,
    /// How long a session id resolves after its last write or refresh
    /// ([`SESSION_TTL`]). The keeper refreshes it every third of this while
    /// the tunnel is open.
    pub session_ttl: Duration,
}

impl Default for Pacing {
    fn default() -> Self {
        Self {
            keep_every: KEEP_EVERY,
            drain_cap: DRAIN_CAP,
            half_close_linger: HALF_CLOSE_LINGER,
            breaker: BreakerConfig::default(),
            session_ttl: SESSION_TTL,
        }
    }
}

/// The whole open (lease, create, dial, fallback) answers inside this time:
/// 2 s under the session proxy's 10 s dial limit.
pub(crate) const TOTAL_BUDGET: Duration = Duration::from_secs(8);
/// Bound on every Redis call of the tunnel path.
const REDIS_TIMEOUT: Duration = Duration::from_secs(1);
/// Bound on one Postgres write that no tunnel waits for.
const DB_WRITE_TIMEOUT: Duration = Duration::from_secs(5);
/// A tunnel counts in the counters this long unless touched.
pub(crate) const TUNNEL_TTL: Duration = Duration::from_secs(15);
/// How long a session id can be resolved by the control API after the last
/// time the gateway wrote it. Readers (`api/src/signals.rs`: the session proxy's block
/// signals, operator block reports) look a session up while its tunnel is
/// open and for the report delay after it closed, so the keeper refreshes
/// the key while the tunnel lives and the key lapses this long after the
/// last refresh (at least two thirds of it after close). Written once per
/// tunnel, so it sets Redis memory at open rate x this time.
const SESSION_TTL: Duration = Duration::from_secs(600);
const MAX_CACHED_UNITS: u64 = 50_000;
const CREDENTIALS_TTL: Duration = Duration::from_secs(60);

fn cache<V: Clone + Send + Sync + 'static>(ttl: Duration) -> Cache<String, V> {
    Cache::builder()
        .max_capacity(MAX_CACHED_UNITS)
        .time_to_live(ttl)
        .build()
}

/// The listener a connection came in on. It decides which org keys are valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Listener {
    Connect,
    Socks,
    Probe,
}

impl Listener {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Listener::Connect => "connect",
            Listener::Socks => "socks",
            Listener::Probe => "probe",
        }
    }
}

/// An open tunnel, ready for the `200` reply and the relay.
pub(crate) struct Opened {
    pub stream: ProxyStream,
    pub session: String,
    pub tunnel: Tunnel,
}

/// The pre-auth slot of one connection, until its request head is read and
/// its key checked: a permit of [`Gateway::pending`] and one of the
/// per-source count. Dropping it gives both back, on every exit path.
pub(crate) struct Pending {
    _permit: OwnedSemaphorePermit,
    sources: Arc<Mutex<HashMap<IpAddr, usize>>>,
    source: IpAddr,
}

impl Drop for Pending {
    fn drop(&mut self) {
        let mut sources = self.sources.lock();
        if let Some(count) = sources.get_mut(&self.source) {
            *count -= 1;
            if *count == 0 {
                sources.remove(&self.source);
            }
        }
    }
}

impl Pending {
    /// The per-source key of the connection ([`pending_source`]), also the
    /// source of the failure limit in [`KeyCache`].
    pub(crate) fn source(&self) -> IpAddr {
        self.source
    }
}

/// The key of a peer in the per-source count: an IPv4 address (also when it
/// came in mapped into IPv6) alone, an IPv6 address by its /64 prefix, which
/// is what one customer holds.
fn pending_source(peer: IpAddr) -> IpAddr {
    match peer.to_canonical() {
        IpAddr::V6(v6) => {
            let [a, b, c, d, ..] = v6.segments();
            Ipv6Addr::new(a, b, c, d, 0, 0, 0, 0).into()
        }
        v4 => v4,
    }
}

pub(crate) struct Gateway {
    pub settings: Arc<Settings>,
    pub db: Db,
    pub hot: Hot,
    pub loaded: watch::Receiver<Arc<Loaded>>,
    pub metrics: Arc<Metrics>,
    pub exit_ip: ExitIpChecker,
    pub reputation: Reputation,
    pub probe: LightProbe,
    pub tunnels: Tunnels,
    pub keys: KeyCache,
    pub probe_org: OrgId,
    /// Secret the probe listener's tokens are signed with
    /// (`settings.probe_key_file`); `None`: that listener refuses every login.
    probe_secret: Option<Secret>,
    /// Every connection task and background write of this pod.
    pub tracker: TaskTracker,
    /// One permit per open client connection, `settings.max_connections` in
    /// all. The accept loops take a permit before they accept.
    pub connections: Arc<Semaphore>,
    /// One permit per connection that has not authenticated yet,
    /// `settings.pending_limit()` in all. The accept loops take one after the
    /// permit of `connections` (see [`Gateway::try_pending`]); the handler
    /// returns it once the request head is read and the key checked, so
    /// silent clients hold no more than this share of `connections`. Over it
    /// a new connection is closed at once.
    pub pending: Arc<Semaphore>,
    /// Pre-auth connections per source ([`pending_source`]), at most
    /// `settings.pending_per_ip_limit()` each, so one host cannot take the
    /// whole of `pending`. A source with none has no entry.
    pending_sources: Arc<Mutex<HashMap<IpAddr, usize>>>,
    pub pacing: Pacing,
    /// Units whose exit IP passed a check recently (single-flight per unit).
    pub rotating_checks: Cache<String, ()>,
    pub static_checks: Cache<String, ()>,
    pub credentials: Cache<String, Arc<(Secret, Secret)>>,
}

impl Gateway {
    pub(crate) fn new(ctx: GatewayCtx, pacing: Pacing) -> anyhow::Result<Self> {
        let probe_org = ctx
            .settings
            .probe_org
            .parse()
            .context("failed to parse probe_org as an org id")?;
        let probe_secret = common::probe_token::load_secret(&ctx.settings)?;
        let connections = Arc::new(Semaphore::new(ctx.settings.max_connections));
        let pending = Arc::new(Semaphore::new(ctx.settings.pending_limit()));
        Ok(Self {
            settings: Arc::new(ctx.settings),
            db: ctx.db,
            hot: ctx.hot,
            loaded: ctx.loaded,
            metrics: Arc::clone(&ctx.metrics),
            exit_ip: ctx.exit_ip,
            reputation: ctx.reputation,
            probe: ctx.probe,
            tunnels: ctx.tunnels,
            keys: KeyCache::new(ctx.metrics),
            probe_org,
            probe_secret,
            tracker: TaskTracker::new(),
            pending,
            pending_sources: Arc::default(),
            connections,
            pacing,
            rotating_checks: cache(ROTATING_RECHECK),
            static_checks: cache(STATIC_RECHECK),
            credentials: cache(CREDENTIALS_TTL),
        })
    }

    /// The pre-auth slot of a connection from `peer`, or `None` when the pod
    /// has no pre-auth slot left or `peer`'s source holds its share already.
    pub(crate) fn try_pending(&self, peer: IpAddr) -> Option<Pending> {
        let permit = Arc::clone(&self.pending).try_acquire_owned().ok()?;
        let source = pending_source(peer);
        let mut sources = self.pending_sources.lock();
        let count = sources.entry(source).or_insert(0);
        // the limit is at least 1, so a full source has an entry already
        if *count >= self.settings.pending_per_ip_limit() {
            return None;
        }
        *count += 1;
        Some(Pending {
            _permit: permit,
            sources: Arc::clone(&self.pending_sources),
            source,
        })
    }

    /// The org of a login from `source` ([`Pending::source`]), or the cause to
    /// refuse with. On the connect and SOCKS5 listeners the password is an org
    /// key, and the probe org's keys do not work there. On the probe listener
    /// it is a signed, short-lived token ([`common::probe_token`]) that
    /// authenticates the probe org without a database lookup; no org key works
    /// there.
    pub(crate) async fn authenticate(
        &self,
        listener: Listener,
        source: IpAddr,
        key: &Secret,
    ) -> Result<OrgId, Cause> {
        if listener == Listener::Probe {
            return match &self.probe_secret {
                Some(secret)
                    if common::probe_token::verify(
                        secret,
                        key.expose(),
                        std::time::SystemTime::now(),
                    ) =>
                {
                    Ok(self.probe_org.clone())
                }
                _ => Err(Cause::AuthRequired),
            };
        }
        let org = self
            .keys
            .resolve(source, key.expose(), || {
                self.db.verify_org_key(key.expose())
            })
            .await?;
        if org == self.probe_org {
            Err(Cause::AuthRequired)
        } else {
            Ok(org)
        }
    }

    /// Run the whole open pipeline for an authenticated org and count the outcome.
    #[tracing::instrument(
        name = "proxyx.tunnel.open",
        skip_all,
        fields(listener = listener.label(), org = %org, outcome = tracing::field::Empty)
    )]
    pub(crate) async fn open(
        &self,
        listener: Listener,
        org: OrgId,
        username: &str,
        target: Target,
    ) -> Result<Opened, Cause> {
        let result = match self.probe_destination(listener, &target) {
            Ok(()) => self.open_inner(&org, username, &target).await,
            Err(cause) => Err(cause),
        };
        let (outcome, provider) = match &result {
            Ok(opened) => ("ok", opened.tunnel.lease.provider.as_str()),
            Err(cause) => (cause.code(), NO_PROVIDER),
        };
        tracing::Span::current().record("outcome", outcome);
        self.count_for(listener, outcome, provider);
        result
    }

    /// Count a connection of `listener` under its outcome (`ok` or a cause
    /// code), served by no provider.
    pub(crate) fn count(&self, listener: Listener, outcome: &str) {
        self.count_for(listener, outcome, NO_PROVIDER);
    }

    /// [`Self::count`] with the provider that served the connection.
    fn count_for(&self, listener: Listener, outcome: &str, provider: &str) {
        self.metrics
            .connections_total
            .with_label_values(&[listener.label(), outcome, provider])
            .inc();
    }

    /// The probe listener opens only the hosts of `probe-targets.toml`: a
    /// probe token that leaks (it sits in a BrowserInstance spec) is not an
    /// open proxy.
    fn probe_destination(&self, listener: Listener, target: &Target) -> Result<(), Cause> {
        if listener == Listener::Probe
            && !self
                .loaded
                .borrow()
                .probe_targets
                .allows(&target.host, target.port)
        {
            return Err(Cause::DestinationDenied);
        }
        Ok(())
    }

    async fn open_inner(
        &self,
        org: &OrgId,
        username: &str,
        target: &Target,
    ) -> Result<Opened, Cause> {
        let deadline = Instant::now() + TOTAL_BUDGET;
        let loaded = Arc::clone(&self.loaded.borrow());
        let opts = InboundOptions::parse(username)?;
        // The region and the lease time an option asks for are checked against
        // the policy of each provider that may serve it, route class included
        // (`candidates`): the policy of the request as a whole is the base one.
        let policy = loaded.policies.effective(org, opts.provider.as_ref());
        let narrowed = policy.narrow(&InboundOptions {
            region: None,
            ttl: None,
            ..opts.clone()
        })?;
        let cands = candidates(&loaded, org, &narrowed, &opts)?;
        if dial::is_denied_destination(target) {
            return Err(Cause::DestinationDenied);
        }

        let tunnel_id = Uuid::new_v4();
        let keys = StickyKeys::new(&narrowed, target, tunnel_id);
        let req = Req {
            org,
            target,
            loaded: &loaded,
            narrowed: &narrowed,
            org_cap: loaded
                .policies
                .effective(org, None)
                .max_tunnels_per_org
                .and_then(std::num::NonZeroU32::new),
            cands,
            tunnel_id,
            sticky: &keys.lease,
            per_connection: keys.per_connection,
            deadline,
            owed: Mutex::default(),
            reserved: Mutex::default(),
            provider_retried: std::sync::atomic::AtomicBool::default(),
        };

        self.open_slot(&req).await?;
        match self
            .lease_and_dial(&req, &keys.memo(&narrowed, &opts, target))
            .await
        {
            Ok(opened) => Ok(opened),
            Err(cause) => {
                // the org slot is held until here; no unit counter is
                let _ = redis(
                    "free an org slot",
                    self.hot.org_tunnel_close(org, tunnel_id),
                )
                .await;
                Err(cause)
            }
        }
    }

    /// Refuse a new tunnel of an org that used its daily byte budget
    /// (`limits.org_max_gb_per_day`). Open tunnels are not cut.
    pub(crate) async fn check_org_budget(
        &self,
        org: &OrgId,
        max_gb: Option<f64>,
    ) -> Result<(), Cause> {
        let Some(max_gb) = max_gb else {
            return Ok(());
        };
        let used = redis(
            "read the org's daily bytes",
            self.hot.org_cost_used(org, OffsetDateTime::now_utc()),
        )
        .await?;
        if budget_spent(used, max_gb) {
            tracing::info!(%org, used_bytes = used, max_gb, "org budget spent");
            return Err(Cause::OrgBudget);
        }
        Ok(())
    }

    async fn lease_and_dial(&self, req: &Req<'_>, memo: &str) -> Result<Opened, Cause> {
        if let Some(cause) = redis(
            "read the failed-lease memo",
            self.hot.failed_lease(req.org, memo),
        )
        .await?
        {
            tracing::debug!(cause = cause.code(), "answering from the failed-lease memo");
            return Err(cause);
        }
        let established = match self.acquire(req).await {
            Ok(e) => e,
            Err(cause) => {
                if matches!(
                    cause,
                    Cause::CacheEmpty | Cause::NoHealthyIp | Cause::LeaseTimeout
                ) {
                    let _ = redis(
                        "remember a failed lease",
                        self.hot.memo_failed_lease(req.org, memo, cause),
                    )
                    .await;
                }
                self.metrics
                    .cache_leases_total
                    .with_label_values(&[
                        req.narrowed.kinds.first().map_or("none", |k| k.as_str()),
                        cause.code(),
                        NO_PROVIDER,
                    ])
                    .inc();
                return Err(cause);
            }
        };

        let lease = established.lease;
        if !lease.per_connection {
            let now = OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000;
            let now = i64::try_from(now).unwrap_or(i64::MAX);
            let affinity = AffinityRecord {
                sticky: lease.sticky.clone(),
                partition: lease.partition.clone(),
                unit: lease.grant.unit.clone(),
                ip: lease.grant.ip,
                created_at_ms: now,
                last_seen_ms: now,
                bytes: 0,
            };
            let cap = req
                .loaded
                .policies
                .effective(&lease.org, Some(&lease.provider))
                .max_sticky_entries_per_org;
            // Best effort, like the correlation record below. The Redis script
            // atomically bounds the shared affinity table when Redis answers.
            let _ = redis(
                "record the sticky affinity",
                self.hot.affinity_touch(
                    &lease.org,
                    &affinity,
                    lease.affinity_ttl(),
                    cap,
                    !lease.grant.fresh,
                ),
            )
            .await;
        }
        let session = Uuid::new_v4().simple().to_string();
        let record = SessionRecord {
            org: lease.org.clone(),
            partition: lease.partition.clone(),
            unit: lease.grant.unit.clone(),
            ip: lease.grant.ip,
        };
        // Before the 200, so a block signal that names this session resolves.
        let _ = redis(
            "store the session record",
            self.hot
                .session_put(&session, &record, self.pacing.session_ttl),
        )
        .await;
        let registration = self.tunnels.register(
            session.clone(),
            TunnelInfo {
                org: lease.org.clone(),
                partition: lease.partition.clone(),
                ip: lease.grant.ip,
                pool: lease.pool,
            },
        );
        self.metrics.tunnels_open.inc();
        Ok(Opened {
            session: session.clone(),
            stream: established.stream,
            tunnel: Tunnel {
                lease,
                registration,
                session,
            },
        })
    }
}

/// True when `used` bytes reach `max_gb` gigabytes. A budget of zero is spent.
pub(crate) fn budget_spent(used: u64, max_gb: f64) -> bool {
    used >= gb_to_bytes(max_gb)
}

/// The lease key and the failed-lease memo key of a request.
struct StickyKeys {
    lease: String,
    scope: String,
    per_connection: bool,
}

impl StickyKeys {
    /// `sid` and the sticky scope select the lease key. `rot-each` and the `connection` scope give every tunnel its
    /// own lease, which ends with the tunnel.
    fn new(narrowed: &policy::LeaseRequest, target: &Target, tunnel: Uuid) -> Self {
        let (lease, scope, per_connection) = match (&narrowed.rotation, &narrowed.sticky) {
            (Rotation::Each, _) | (_, StickyKeySource::Scope(StickyScope::Connection)) => {
                (format!("conn:{tunnel}"), "conn".to_owned(), true)
            }
            (_, StickyKeySource::Sid(sid)) => {
                let key = store::sid_sticky(sid);
                (key.clone(), key, false)
            }
            (_, StickyKeySource::Scope(StickyScope::Org)) => {
                ("org".to_owned(), "org".to_owned(), false)
            }
            (_, StickyKeySource::Scope(StickyScope::Target)) => {
                let key = format!("host:{}", target.host);
                (key.clone(), key, false)
            }
        };
        Self {
            lease,
            scope,
            per_connection,
        }
    }

    /// The memo is per request shape and per target: a failure for
    /// `kind-static` must not refuse a `kind-rotating` request of the same
    /// sticky key, and a lease that failed for one host (every IP cooled for
    /// it, say) must not refuse the same key for another host.
    fn memo(
        &self,
        narrowed: &policy::LeaseRequest,
        opts: &InboundOptions,
        target: &Target,
    ) -> String {
        let join = |items: Vec<String>| items.join(",");
        let regions = match &opts.region {
            Some(region) => region.to_string(),
            None => join(narrowed.regions.iter().map(ToString::to_string).collect()),
        };
        format!(
            "{}|{}|{}|{}|{}",
            self.scope,
            join(narrowed.kinds.iter().map(ToString::to_string).collect()),
            join(narrowed.providers.iter().map(ToString::to_string).collect()),
            regions,
            target.host.to_ascii_lowercase(),
        )
    }
}

/// One Redis call of the tunnel path: bounded, and any failure is
/// `cache_unavailable` (new leases are refused, open tunnels go on). This is
/// where the failure is handled, so it is the only place that logs it; `what`
/// names the call and callers add no log line of their own.
pub(crate) async fn redis<T>(
    what: &'static str,
    call: impl Future<Output = store::Result<T>>,
) -> Result<T, Cause> {
    bounded(what, call, Cause::CacheUnavailable).await
}

/// [`redis`] for the lease script. The tunnel path shares one connection and
/// the script costs more as leases pile up, so under a burst a call waits in
/// the queue and runs out of time while Redis is healthy. That
/// is contention, not an outage: it answers `lease_timeout`, which the
/// failed-lease memo then absorbs. Redis errors stay `cache_unavailable`, and
/// so does a real outage, which fails the calls before the lease first.
pub(crate) async fn redis_lease<T>(
    what: &'static str,
    call: impl Future<Output = store::Result<T>>,
) -> Result<T, Cause> {
    bounded(what, call, Cause::LeaseTimeout).await
}

/// Run `call` for at most [`REDIS_TIMEOUT`]; running out of time (here or in
/// the connection) is `on_timeout`, any other failure `cache_unavailable`.
async fn bounded<T>(
    what: &'static str,
    call: impl Future<Output = store::Result<T>>,
    on_timeout: Cause,
) -> Result<T, Cause> {
    match timeout(REDIS_TIMEOUT, call).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(error)) => {
            tracing::warn!(call = what, %error, "redis call failed");
            if matches!(&error, store::StoreError::Redis(e) if e.is_timeout()) {
                Err(on_timeout)
            } else {
                Err(Cause::CacheUnavailable)
            }
        }
        Err(_) => {
            tracing::warn!(call = what, "redis call timed out");
            Err(on_timeout)
        }
    }
}

/// A Postgres write that no tunnel waits for: bounded, and a failure only
/// logged. Run it on [`Gateway::tracker`] so the drain waits for it.
pub(crate) async fn db_write<T>(what: &'static str, write: impl Future<Output = store::Result<T>>) {
    match timeout(DB_WRITE_TIMEOUT, write).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => tracing::warn!(write = what, error = %e, "background postgres write failed"),
        Err(_) => tracing::warn!(write = what, "background postgres write timed out"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn a_stalled_background_write_is_cut_off_at_its_timeout() {
        let stalled = std::future::pending::<store::Result<()>>();
        timeout(DB_WRITE_TIMEOUT * 2, db_write("stall", stalled))
            .await
            .expect("the write ends at its own timeout");
    }

    /// A lease call that runs out of time is contention, not an
    /// outage; any other Redis failure stays `cache_unavailable`.
    #[tokio::test(start_paused = true)]
    async fn a_lease_call_that_times_out_is_a_lease_timeout_not_a_redis_outage() {
        let slow = std::future::pending::<store::Result<()>>();
        assert_eq!(
            redis_lease("lease", slow).await,
            Err(Cause::LeaseTimeout),
            "the queue wait is contention"
        );
        let slow = std::future::pending::<store::Result<()>>();
        assert_eq!(redis("other", slow).await, Err(Cause::CacheUnavailable));

        let timed_out = || {
            let error = redis::RedisError::from(std::io::Error::from(std::io::ErrorKind::TimedOut));
            std::future::ready(Err::<(), _>(store::StoreError::Redis(error)))
        };
        assert_eq!(
            redis_lease("lease", timed_out()).await,
            Err(Cause::LeaseTimeout)
        );
        let refused =
            redis::RedisError::from(std::io::Error::from(std::io::ErrorKind::ConnectionRefused));
        assert_eq!(
            redis_lease(
                "lease",
                std::future::ready(Err::<(), _>(store::StoreError::Redis(refused)))
            )
            .await,
            Err(Cause::CacheUnavailable),
            "a connection error is still an outage"
        );
    }

    #[test]
    fn a_budget_is_spent_at_the_limit_and_a_zero_budget_is_always_spent() {
        assert!(!budget_spent(999_999_999, 1.0));
        assert!(budget_spent(1_000_000_000, 1.0));
        assert!(budget_spent(0, 0.0));
        assert!(!budget_spent(0, 0.000_001));
    }

    #[test]
    fn a_fractional_gb_budget_is_spent_at_exactly_its_byte_count() {
        // 0.0000077 GB * 1e9 is 7700.000000000001 in f64: the limit is 7700 bytes.
        assert!(!budget_spent(7_699, 0.000_007_7));
        assert!(budget_spent(7_700, 0.000_007_7));
        assert!(budget_spent(7_701, 0.000_007_7));
    }
}
