//! The byte relay of one open tunnel and the upkeep of its counters.
//!
//! Bytes are copied both ways without being read. The first byte from the
//! target is timed (`dial_duration_seconds{stage="first_byte"}`). A tunnel
//! ends when either side ends and the other stays silent for the linger, or
//! when no byte moves in either direction for `tunnel_idle_timeout`; a write
//! that cannot progress counts as silence. A separate task
//! keeps the tunnel's counters and session record alive, renews the lease
//! when traffic flowed and meters the traffic; it never shares a poll with
//! the relay, so a slow Redis cannot stall data.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use common::metrics::Metrics;
use common::session::BYTES_PER_GB;
use common::types::{Kind, OrgId, Partition, ProviderId, Target};
use dial::ProxyStream;
use policy::{AfterRelease, Pool};
use store::{Grant, LeaseLimits, LeaseRequest, ReleaseRule};
use time::OffsetDateTime;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Notify;
use tokio::time::{Instant, MissedTickBehavior, interval, sleep_until, timeout};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::gateway::{Gateway, TUNNEL_TTL, redis};
use crate::tunnels::Registration;

/// One copy buffer per direction. Two per tunnel; an idle tunnel holds them
/// for its whole life, so the size is the memory a connection costs.
const COPY_BUF_BYTES: usize = 8 * 1024;

/// What the lease of an open tunnel needs to renew and to close.
#[derive(Clone)]
pub(crate) struct LeaseData {
    pub org: OrgId,
    pub partition: Partition,
    pub kind: Kind,
    pub provider: ProviderId,
    pub sticky: String,
    pub target: Target,
    pub tunnel_id: Uuid,
    pub pool: Pool,
    pub limits: LeaseLimits,
    pub grant: Grant,
    /// A per-connection lease ends with its tunnel.
    pub per_connection: bool,
    /// `rotating.after_release` for a rotating lease; `None` for a static one.
    pub after_release: Option<AfterRelease>,
    /// `cost.fair_use_gb_per_ip_month` for a static lease; `None` for a rotating one.
    pub fair_use_gb: Option<f64>,
}

impl LeaseData {
    /// Affinity cannot outlive either the lease or its provider session.
    pub(crate) fn affinity_ttl(&self) -> Duration {
        self.grant
            .expires_at
            .map_or(self.limits.lease_ttl, |expires| {
                Duration::try_from(expires - OffsetDateTime::now_utc())
                    .unwrap_or_default()
                    .min(self.limits.lease_ttl)
            })
    }

    fn request(&self) -> LeaseRequest<'_> {
        LeaseRequest {
            partition: &self.partition,
            kind: self.kind,
            org: &self.org,
            sticky: &self.sticky,
            target: &self.target,
            tunnel: self.tunnel_id,
            pool: self.pool,
            limits: self.limits.clone(),
        }
    }
}

/// An open tunnel: its lease and its place in the registry. Call
/// [`Tunnel::finish`] exactly once when it ends.
pub(crate) struct Tunnel {
    pub lease: LeaseData,
    pub registration: Registration,
    /// The `X-ProxyX-Pool-Session` id the keeper keeps resolvable.
    pub session: String,
}

impl Tunnel {
    /// Close the counters: the unit's and the org's, and a per-connection lease.
    pub(crate) async fn finish(self, gw: &Gateway) {
        gw.metrics.tunnels_open.dec();
        let lease = &self.lease;
        // Best effort: redis() logged a failure already.
        let _ = redis(
            "close a tunnel counter",
            gw.hot.tunnel_close(&lease.grant.tunnel),
        )
        .await;
        if lease.per_connection {
            let _ = redis(
                "release a per-connection lease",
                gw.hot.release(
                    &lease.partition,
                    &lease.org,
                    &lease.sticky,
                    lease.after_release.map(|after| ReleaseRule {
                        after,
                        probe_org: &gw.probe_org,
                    }),
                ),
            )
            .await;
        }
    }
}

/// When bytes last moved in a tunnel, and whether one direction has ended.
struct Activity {
    opened: Instant,
    /// Longest silence of a tunnel, and of a write that cannot progress.
    idle: Duration,
    /// Longest silence once one direction ended.
    linger: Duration,
    /// Milliseconds after `opened` of the last byte (or of the half-close).
    last_ms: AtomicU64,
    half_closed: AtomicBool,
    /// Wakes [`Activity::silent`] when the limit shrinks.
    shortened: Notify,
}

impl Activity {
    fn new(opened: Instant, idle: Duration, linger: Duration) -> Self {
        Self {
            opened,
            idle,
            linger,
            last_ms: AtomicU64::new(0),
            half_closed: AtomicBool::new(false),
            shortened: Notify::new(),
        }
    }

    fn touch(&self) {
        let ms = u64::try_from(self.opened.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last_ms.store(ms, Ordering::Relaxed);
    }

    /// One direction ended: the other gets the linger from now.
    fn half_close(&self) {
        self.half_closed.store(true, Ordering::Relaxed);
        self.touch();
        self.shortened.notify_one();
    }

    /// When the tunnel counts as silent: the idle limit after the last byte,
    /// or the linger once a direction ended, whichever is shorter.
    fn deadline(&self) -> Instant {
        let limit = if self.half_closed.load(Ordering::Relaxed) {
            self.idle.min(self.linger)
        } else {
            self.idle
        };
        self.opened + Duration::from_millis(self.last_ms.load(Ordering::Relaxed)) + limit
    }

    /// Returns when the tunnel has been silent for its limit.
    async fn silent(&self) {
        loop {
            let deadline = self.deadline();
            if Instant::now() >= deadline {
                return;
            }
            tokio::select! {
                () = sleep_until(deadline) => {}
                () = self.shortened.notified() => {}
            }
        }
    }
}

/// Copy `r` to `w` until end of stream, then half-close `w`. With `first`, the
/// time to the first byte is recorded once.
async fn pump<R, W>(
    mut r: R,
    mut w: W,
    unmetered: &AtomicU64,
    activity: &Activity,
    first: Option<(&Metrics, &ProviderId, Instant)>,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; COPY_BUF_BYTES];
    let mut first = first;
    loop {
        let n = r.read(&mut buf).await?;
        if n == 0 {
            // the peer may already be gone: a failed half-close is not an error
            let _ = w.shutdown().await;
            activity.half_close();
            return Ok(());
        }
        activity.touch();
        if let Some((metrics, provider, opened)) = first.take() {
            dial::record_first_byte(metrics, provider, opened.elapsed());
        }
        // A write that makes no progress for the idle limit ends the tunnel
        // even while the other direction moves bytes.
        timeout(activity.idle, w.write_all(&buf[..n]))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "write made no progress"))??;
        activity.touch();
        unmetered.fetch_add(n as u64, Ordering::Relaxed);
    }
}

/// Run the tunnel until either side ends, an error, or the registry closes it.
pub(crate) async fn relay<S>(
    gw: &Arc<Gateway>,
    tunnel: Tunnel,
    client: S,
    mut upstream: ProxyStream,
    leftover: Vec<u8>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let opened = Instant::now();
    let activity = Activity::new(
        opened,
        gw.settings.tunnel_idle_timeout,
        gw.pacing.half_close_linger,
    );
    // Bytes copied and not yet metered: the keeper and the end of the relay
    // take them with `swap(0)`, so no byte is metered twice.
    let unmetered = Arc::new(AtomicU64::new(0));
    let stop = CancellationToken::new();
    gw.tracker.spawn(keep(
        Arc::clone(gw),
        tunnel.lease.clone(),
        tunnel.session.clone(),
        Arc::clone(&unmetered),
        stop.clone(),
        tunnel.registration.closed().clone(),
    ));

    let closed = tunnel.registration.closed().clone();
    let provider = tunnel.lease.provider.clone();
    let copied = async {
        if !leftover.is_empty() {
            upstream.write_all(&leftover).await?;
            unmetered.fetch_add(leftover.len() as u64, Ordering::Relaxed);
        }
        let (client_r, client_w) = tokio::io::split(client);
        let (upstream_r, upstream_w) = tokio::io::split(upstream);
        tokio::try_join!(
            pump(client_r, upstream_w, &unmetered, &activity, None),
            pump(
                upstream_r,
                client_w,
                &unmetered,
                &activity,
                Some((&gw.metrics, &provider, opened)),
            ),
        )
        .map(|_| ())
    };
    tokio::select! {
        result = copied => {
            if let Err(e) = result {
                tracing::debug!(error = %e, "tunnel ended with an i/o error");
            }
        }
        () = activity.silent() => tracing::debug!(
            idle_secs = activity.idle.as_secs(),
            "tunnel closed after no byte moved"
        ),
        () = closed.cancelled() => tracing::debug!("tunnel closed by the registry"),
    }
    stop.cancel();
    // Meter what the keeper has not taken yet; each byte is taken once. A
    // tunnel shorter than one keeper tick leaves all its bytes here.
    record_and_meter(gw, &tunnel.lease, unmetered.swap(0, Ordering::Relaxed)).await;
    tunnel.finish(gw).await;
}

/// Record the traffic of a unit for load spreading and meter the bytes.
async fn record_and_meter(gw: &Gateway, lease: &LeaseData, bytes: u64) {
    if bytes == 0 {
        return;
    }
    if !lease.per_connection {
        let _ = redis(
            "record sticky session traffic",
            gw.hot
                .affinity_add_bytes(&lease.org, &lease.sticky, bytes, lease.affinity_ttl()),
        )
        .await;
    }
    let _ = redis(
        "record traffic",
        gw.hot
            .record_traffic(&lease.partition, &lease.grant.unit, bytes),
    )
    .await;
    meter(gw, lease, bytes).await;
}

/// Count `bytes` against the provider's budget and the org's.
async fn meter(gw: &Gateway, lease: &LeaseData, bytes: u64) {
    if bytes == 0 {
        return;
    }
    let now = OffsetDateTime::now_utc();
    let _ = redis(
        "meter tunnel bytes",
        gw.hot.cost_add(&lease.provider, bytes, 0, now),
    )
    .await;
    let _ = redis(
        "meter org bytes",
        gw.hot.org_cost_add(&lease.org, bytes, now),
    )
    .await;
    meter_fair_use(gw, lease, bytes, now).await;
}

/// Count the bytes against the static IP's monthly fair use: a warning at
/// 80%, and at 100% the IP gets no new lease until the month ends. The
/// counter runs for a limit of 0 too (it never stops the IP).
async fn meter_fair_use(gw: &Gateway, lease: &LeaseData, bytes: u64, now: OffsetDateTime) {
    let Some(gb) = lease.fair_use_gb else {
        return;
    };
    let limit = (gb * BYTES_PER_GB) as u64;
    match redis(
        "meter fair use",
        gw.hot
            .fair_use_add(&lease.partition, lease.grant.ip, bytes, limit, now),
    )
    .await
    {
        Ok(f) if f.stopped => {
            gw.metrics
                .fair_use_exceeded_total
                .with_label_values(&[lease.provider.as_str()])
                .inc();
            tracing::warn!(
                provider = %lease.provider,
                limit_gb = gb,
                "a static ip used its monthly fair-use traffic, no new leases until next month"
            );
        }
        Ok(f) if f.warned => tracing::warn!(
            provider = %lease.provider,
            limit_gb = gb,
            "a static ip reached 80% of its monthly fair-use traffic"
        ),
        // redis() logged a failure already.
        Ok(_) | Err(_) => {}
    }
}

/// Every `keep_every`: push the tunnel's deadline in the counters, close the
/// tunnel at once when an org block covers its unit and when its unit has
/// been drained for the drain cap, and when bytes flowed since the last
/// tick renew the lease, record the traffic for load spreading and count the
/// bytes against the provider and org budgets.
/// Every third of the session TTL it also pushes out the expiry of the
/// tunnel's `sess:` key, so a block signal about a long tunnel still resolves.
async fn keep(
    gw: Arc<Gateway>,
    lease: LeaseData,
    session: String,
    unmetered: Arc<AtomicU64>,
    stop: CancellationToken,
    close: CancellationToken,
) {
    let mut tick = interval(gw.pacing.keep_every);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    tick.tick().await;
    let mut drained_since: Option<Instant> = None;
    let session_ttl = gw.pacing.session_ttl;
    let mut session_written = Instant::now();
    loop {
        tokio::select! {
            biased;
            () = stop.cancelled() => return,
            _ = tick.tick() => {}
        }
        if session_written.elapsed() >= session_ttl / 3
            && redis(
                "refresh the session record",
                gw.hot.session_touch(&session, session_ttl),
            )
            .await
            .is_ok()
        {
            session_written = Instant::now();
        }
        // A Redis failure says nothing about the unit: keep the last verdict.
        match drained(&gw, &lease).await {
            // A block is the operator's, and only the replica that served the
            // API call closed the tunnels it holds: the others close theirs
            // here, at the next tick, without the cap a drained unit gets.
            Some(Drain::Blocked) => {
                tracing::warn!(provider = %lease.provider, "an org block covers the tunnel, closing it");
                close.cancel();
                return;
            }
            Some(Drain::Unit) => {
                let since = *drained_since.get_or_insert_with(|| {
                    tracing::info!(
                        provider = %lease.provider,
                        cap_secs = gw.pacing.drain_cap.as_secs(),
                        "tunnel unit was drained, closing at the drain cap"
                    );
                    Instant::now()
                });
                if since.elapsed() >= gw.pacing.drain_cap {
                    tracing::warn!(provider = %lease.provider, "drain cap reached, closing tunnel");
                    close.cancel();
                    return;
                }
            }
            Some(Drain::Ready) => drained_since = None,
            None => {}
        }
        if redis(
            "touch a tunnel",
            gw.hot.tunnel_touch(&lease.grant.tunnel, TUNNEL_TTL),
        )
        .await
        .is_err()
        {
            continue;
        }
        let delta = unmetered.swap(0, Ordering::Relaxed);
        if delta == 0 {
            continue;
        }
        match redis("renew a lease", gw.hot.renew(&lease.request())).await {
            Ok(Some(_)) | Err(_) => {}
            // The unit left leasing (cooldown, block): the open tunnel goes on
            // until the drain cap (checked above); the next tunnel leases another unit.
            Ok(None) => tracing::debug!("lease no longer renewable"),
        }
        record_and_meter(&gw, &lease, delta).await;
    }
}

/// What the keeper finds out about a tunnel's unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Drain {
    /// The unit is leasable and no org block covers it.
    Ready,
    /// The unit left leasing (`ready_take`, dropped, expired).
    Unit,
    /// An org block covers the tunnel's unit.
    Blocked,
}

/// The state of the tunnel's unit and blocks. `None` when Redis does not
/// answer.
async fn drained(gw: &Gateway, lease: &LeaseData) -> Option<Drain> {
    let fields = redis("read the org blocks", gw.hot.org_blocks(&lease.org))
        .await
        .ok()?;
    if blocked_by(&fields, lease) {
        return Some(Drain::Blocked);
    }
    let ready = redis(
        "check that a unit is ready",
        gw.hot.is_ready(&lease.partition, &lease.grant.unit),
    )
    .await
    .ok()?;
    Some(if ready { Drain::Ready } else { Drain::Unit })
}

/// Whether one of the org's live block fields (`ip:`, `provider:`,
/// `route_class:`, `pool:`) covers the tunnel's unit.
fn blocked_by(fields: &[String], lease: &LeaseData) -> bool {
    let pool = match lease.pool {
        Pool::Shared => "pool:shared",
        Pool::Private => "pool:private",
    };
    let provider = format!("provider:{}", lease.partition.provider);
    let route = format!("route_class:{}", lease.partition.tag());
    let ip = format!("ip:{}", lease.grant.ip);
    fields
        .iter()
        .any(|f| *f == pool || *f == provider || *f == route || *f == ip)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn lease() -> LeaseData {
        let partition = Partition {
            provider: "p1".parse().expect("provider"),
            region: "fr".parse().expect("region"),
        };
        let org: OrgId = "acme".parse().expect("org");
        let tunnel_id = Uuid::new_v4();
        LeaseData {
            org: org.clone(),
            partition: partition.clone(),
            kind: Kind::Static,
            provider: partition.provider.clone(),
            sticky: "org".into(),
            target: Target {
                host: "a.test".into(),
                port: 443,
            },
            tunnel_id,
            pool: Pool::Shared,
            limits: LeaseLimits {
                lease_ttl: Duration::from_secs(60),
                tunnel_ttl: Duration::from_secs(15),
                orgs_hard: None,
                max_conns_per_ip: None,
                provider_conns_per_ip: None,
                rest_after_release: Duration::ZERO,
                min_remaining: Duration::ZERO,
                allow_create: false,
            },
            grant: Grant {
                unit: "1.2.3.4".into(),
                ip: "1.2.3.4".parse().expect("ip"),
                orgs: 1,
                tunnels: 1,
                expires_at: None,
                broke: None,
                struck: false,
                fresh: false,
                tunnel: store::TunnelRef {
                    partition,
                    unit: "1.2.3.4".into(),
                    org,
                    id: tunnel_id,
                    provider_counted: false,
                },
            },
            per_connection: false,
            after_release: None,
            fair_use_gb: None,
        }
    }

    #[test]
    fn affinity_lifetime_never_extends_a_provider_session() {
        let mut lease = lease();
        assert_eq!(lease.affinity_ttl(), Duration::from_secs(60));
        lease.grant.expires_at = Some(OffsetDateTime::now_utc() + time::Duration::seconds(10));
        assert!(lease.affinity_ttl() <= Duration::from_secs(10));
        lease.grant.expires_at = Some(OffsetDateTime::now_utc() - time::Duration::seconds(1));
        assert_eq!(lease.affinity_ttl(), Duration::ZERO);
    }

    #[test]
    fn only_a_block_that_covers_the_tunnel_unit_counts() {
        let l = lease();
        let f = |s: &[&str]| blocked_by(&s.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>(), &l);
        assert!(!f(&[]));
        assert!(f(&["ip:1.2.3.4"]));
        assert!(f(&["provider:p1"]));
        assert!(f(&["route_class:p1:fr"]));
        assert!(f(&["pool:shared"]));
        assert!(!f(&[
            "ip:1.2.3.5",
            "provider:p2",
            "route_class:p1:de",
            "pool:private"
        ]));
    }

    #[tokio::test(start_paused = true)]
    async fn a_tunnel_is_silent_after_the_idle_limit_and_a_byte_moves_the_limit() {
        let a = Activity::new(
            Instant::now(),
            Duration::from_secs(10),
            Duration::from_secs(2),
        );
        tokio::time::sleep(Duration::from_secs(6)).await;
        a.touch();
        // 6 s + 10 s from the last byte
        assert!(timeout(Duration::from_secs(9), a.silent()).await.is_err());
        assert!(timeout(Duration::from_secs(2), a.silent()).await.is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn one_direction_ending_shortens_the_limit_to_the_linger_at_once() {
        let a = Arc::new(Activity::new(
            Instant::now(),
            Duration::from_secs(600),
            Duration::from_secs(2),
        ));
        let watch = tokio::spawn({
            let a = Arc::clone(&a);
            async move { a.silent().await }
        });
        tokio::time::sleep(Duration::from_secs(100)).await;
        assert!(!watch.is_finished(), "idle is 600 s");
        a.half_close();
        // the watcher was asleep until second 600; the half-close wakes it
        assert!(timeout(Duration::from_secs(3), watch).await.is_ok());
    }
}
