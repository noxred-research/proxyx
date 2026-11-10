//! The sweeper, the Redis seed check, loop lifecycle and pure helpers.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use common::types::{IpState, Kind, Partition, Subtype, Tier};
use store::{LeaseOutcome, ScoreRow, Transition};
use time::OffsetDateTime;
use tokio::task::JoinHandle;

use super::support::{Harness, Setup, TestResult, harness, rotating_adapter, static_adapter, unit};
use crate::state::Warmer;
use crate::statics::checks_from;

fn sweeper_setup() -> Setup {
    Setup::new(rotating_adapter, "min_ready = 10\nmax_ready = 20\n", "")
}

#[tokio::test]
async fn the_sweeper_reclaims_stuck_creates_reservations_and_leases() -> TestResult {
    let mut h = harness!(Harness::start(sweeper_setup()));
    let p = h.partition("rot")?;

    // A create whose warmer died: in flight, past its deadline.
    let stuck = h
        .hot
        .reserve_create(&p, 20)
        .await?
        .ok_or("no reservation")?;
    assert!(
        h.hot
            .create_start(&p, &stuck, "stuck-session", Duration::from_millis(150))
            .await?
    );
    // A live create keeps the in-flight set (and its key TTL) alive, as a busy warmer does.
    let live = h
        .hot
        .reserve_create(&p, 20)
        .await?
        .ok_or("no reservation")?;
    assert!(
        h.hot
            .create_start(&p, &live, "live-session", Duration::from_secs(60))
            .await?
    );
    // A reservation; it expires below.
    let old = h
        .hot
        .reserve_create(&p, 20)
        .await?
        .ok_or("no reservation")?;
    // A lease past its expiry.
    h.hot
        .ready_put(&p, &unit("unit-1", "198.51.100.1".parse()?))
        .await?;
    let ttl = Duration::from_millis(150);
    let grant = h
        .lease_free(&p, Kind::Rotating, "acme", "conn:s", ttl)
        .await?;
    h.hot.tunnel_close(&grant.tunnel).await?;
    // A second org's long lease keeps the unit's lease key alive, as a busy unit does.
    let ttl = Duration::from_secs(60);
    let shared = h.lease(&p, Kind::Rotating, "other", "t", ttl).await?;
    assert!(matches!(shared, LeaseOutcome::Shared(_)), "{shared:?}");
    // A reservation past its 120 s, set last so no script drops it first.
    redis::cmd("ZADD")
        .arg("reserve:{rot:fr}")
        .arg(1)
        .arg(old.id.to_string())
        .query_async::<()>(&mut h.raw)
        .await?;
    tokio::time::sleep(Duration::from_millis(400)).await;

    // warmer N-W1: the gauges read the counts first and drop expired state on
    // the way; the sweeper must still report it.
    h.w.gauges_tick().await;
    h.w.sweep_tick().await;
    let reclaimed = |kind: &str| {
        h.metrics
            .sweeper_reclaimed_total
            .with_label_values(&[kind])
            .get()
    };
    assert_eq!(reclaimed("session"), 1, "the stuck create");
    assert_eq!(reclaimed("reservation"), 1);
    assert_eq!(reclaimed("lease"), 1);
    let counts = h.counts(&p).await?;
    assert_eq!(
        (counts.creating, counts.reserved),
        (1, 0),
        "only the live create is left: {counts:?}"
    );

    h.w.sweep_tick().await;
    assert_eq!(reclaimed("session"), 1, "nothing left to reclaim");
    Ok(())
}

/// The lease of a per-connection tunnel that a killed gateway
/// never released is counted when it expires; its index key used to expire
/// with it and the sweeper never saw it. A sticky lease that
/// simply ran out is normal traffic and not counted, or the critical
/// `ProxyXSweeperRising` pages permanently.
#[tokio::test]
async fn the_sweeper_counts_a_leaked_per_connection_lease_but_not_sticky_expiry() -> TestResult {
    let h = harness!(Harness::start(sweeper_setup()));
    let p = h.partition("rot")?;
    for (id, ip) in [
        ("unit-w53", "198.51.100.53"),
        ("unit-sticky", "198.51.100.54"),
    ] {
        h.hot.ready_put(&p, &unit(id, ip.parse()?)).await?;
    }
    let ttl = Duration::from_millis(150);
    let leaked = h
        .lease_free(&p, Kind::Rotating, "acme", "conn:tunnel-1", ttl)
        .await?;
    h.hot.tunnel_close(&leaked.tunnel).await?;
    let sticky = h
        .lease_free(&p, Kind::Rotating, "other", "sid:session-1", ttl)
        .await?;
    h.hot.tunnel_close(&sticky.tunnel).await?;
    tokio::time::sleep(Duration::from_millis(400)).await;

    h.w.sweep_tick().await;
    let reclaimed = h
        .metrics
        .sweeper_reclaimed_total
        .with_label_values(&["lease"])
        .get();
    assert_eq!(reclaimed, 1, "the leaked per-connection lease only");
    Ok(())
}

#[tokio::test]
async fn a_flushed_redis_is_rebuilt_from_postgres_without_leasing_a_banned_ip() -> TestResult {
    let mut h = harness!(Harness::start(Setup::new(
        static_adapter,
        "min_ready = 2\n",
        ""
    )));
    let p = h.partition("stat")?;
    let good = Ipv4Addr::new(203, 0, 113, 1);
    let banned = Ipv4Addr::new(203, 0, 113, 2);
    for ip in [good, banned] {
        h.add_inventory("stat", Subtype::Isp, ip, None).await?;
        let change = Transition::to(IpState::Available, "checks passed");
        h.transition(ip, change).await?;
    }
    let until = OffsetDateTime::now_utc() + time::Duration::hours(1);
    let change = Transition::to(IpState::Cooldown, "block").cooldown_until(until);
    h.transition(banned, change).await?;

    h.w.seed_tick().await;
    assert!(h.hot.is_seeded().await?);
    assert_eq!(h.hot.ready_ids(&p).await?, [good.to_string()]);

    redis::cmd("FLUSHDB").query_async::<()>(&mut h.raw).await?;
    assert!(!h.hot.is_seeded().await?, "the flush is detected");
    assert!(h.hot.ready_ids(&p).await?.is_empty());

    h.w.seed_tick().await;
    assert!(h.hot.is_seeded().await?);
    assert_eq!(
        h.hot.ready_ids(&p).await?,
        [good.to_string()],
        "the banned IP stays out of leasing"
    );

    // A seeded Redis is left alone.
    h.hot.ready_take(&p, &good.to_string()).await?;
    h.w.seed_tick().await;
    assert!(h.hot.ready_ids(&p).await?.is_empty());
    Ok(())
}

/// Run `every` on `w`, counting its ticks; a tick that `hangs` never ends.
fn spawn_loop(
    w: &Arc<Warmer>,
    name: &'static str,
    interval: Duration,
    limit: Duration,
    hangs: bool,
) -> (Arc<AtomicU32>, JoinHandle<()>) {
    let ticks = Arc::new(AtomicU32::new(0));
    let (w, counter) = (w.clone(), ticks.clone());
    let task = tokio::spawn(async move {
        w.every(name, interval, limit, move || {
            let counter = counter.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                if hangs {
                    std::future::pending::<()>().await;
                }
            }
        })
        .await;
    });
    (ticks, task)
}

#[tokio::test]
async fn a_loop_runs_on_its_interval_and_stops_when_cancelled() -> TestResult {
    let h = harness!(Harness::start(Setup::default()));
    let (ticks, task) = spawn_loop(
        &h.w,
        "test",
        Duration::from_millis(10),
        Duration::from_secs(1),
        false,
    );
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(
        ticks.load(Ordering::SeqCst) >= 3,
        "{}",
        ticks.load(Ordering::SeqCst)
    );

    h.w.cancel.cancel();
    tokio::time::timeout(Duration::from_secs(1), task).await??;
    let stopped_at = ticks.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert_eq!(
        ticks.load(Ordering::SeqCst),
        stopped_at,
        "no tick after cancel"
    );
    Ok(())
}

#[tokio::test]
async fn a_tick_that_hangs_is_dropped_so_the_loop_goes_on() -> TestResult {
    let h = harness!(Harness::start(Setup::default()));
    let (ticks, task) = spawn_loop(
        &h.w,
        "hang",
        Duration::from_millis(5),
        Duration::from_millis(20),
        true,
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        ticks.load(Ordering::SeqCst) >= 3,
        "{}",
        ticks.load(Ordering::SeqCst)
    );
    h.w.cancel.cancel();
    tokio::time::timeout(Duration::from_secs(1), task).await??;
    Ok(())
}

#[tokio::test]
async fn the_gauges_report_rotating_sessions_cost_and_breaker() -> TestResult {
    let h = harness!(Harness::start(Setup::new(
        rotating_adapter,
        "min_ready = 3\nmax_ready = 3\nlow_watermark = 1\n",
        "[policy.rotating]\nrefill_concurrency = 3\n[policy.cost]\nmax_creates_per_hour = 10\n",
    )));
    h.reconcile().await;
    h.w.gauges_tick().await;
    let m = &h.metrics;
    let rot = ["rotating", "rot"];
    let ready = |tier| m.cache_ready.with_label_values(&["rotating", "rot", tier]);
    assert_eq!((ready("normal").get(), ready("degraded").get()), (3, 0));
    assert_eq!(m.cache_min_ready.with_label_values(&rot).get(), 3);
    assert_eq!(m.cache_low_watermark.with_label_values(&rot).get(), 1);
    let sessions = |state| m.cache_sessions.with_label_values(&["rotating", state]);
    assert_eq!(sessions("ready").get(), 3);
    assert_eq!(sessions("creating").get(), 0);
    assert_eq!(
        m.provider_breaker_state.with_label_values(&["rot"]).get(),
        0
    );
    let used = m.cost_used_ratio.with_label_values(&["rot"]).get();
    assert!((used - 0.3).abs() < 1e-9, "3 of 10 creates: {used}");
    Ok(())
}

/// Sessions waiting to drain are counted, and the cost
/// ratio stops at 1 however far the spend is past the limit.
#[tokio::test]
async fn the_gauges_count_draining_sessions_and_cap_the_cost_ratio() -> TestResult {
    let h = harness!(Harness::start(Setup::new(
        rotating_adapter,
        "min_ready = 1\nmax_ready = 1\n",
        "[policy.cost]\nmax_creates_per_hour = 2\n",
    )));
    let p = h.partition("rot")?;
    let now = OffsetDateTime::now_utc();
    h.hot.cost_add(&"rot".parse()?, 0, 5, now).await?;
    let job = |session: &str, phase| {
        store::SessionJob {
            partition: p.clone(),
            session: session.to_owned(),
            ip: Ipv4Addr::new(10, 9, 9, 9),
            born: now.unix_timestamp(),
            expires: now.unix_timestamp() + 600,
            phase,
        }
        .encode()
    };
    let later = now + time::Duration::hours(1);
    h.hot
        .due_schedule(&job("d1", store::Phase::Drain { since: 0 }), later)
        .await?;
    h.hot
        .due_schedule(&job("d2", store::Phase::Drain { since: 0 }), later)
        .await?;
    h.hot
        .due_schedule(&job("k1", store::Phase::fresh(0)), later)
        .await?;

    h.w.gauges_tick().await;
    let m = &h.metrics;
    assert_eq!(
        m.cache_sessions
            .with_label_values(&["rotating", "draining"])
            .get(),
        2,
        "only the sessions in the drain phase"
    );
    let used = m.cost_used_ratio.with_label_values(&["rot"]).get();
    assert!((used - 1.0).abs() < 1e-9, "5 of 2 creates, capped: {used}");
    Ok(())
}

#[tokio::test]
async fn the_gauges_report_static_ips_by_state() -> TestResult {
    let h = harness!(Harness::start(Setup::new(
        static_adapter,
        "min_ready = 2\n",
        ""
    )));
    let good = Ipv4Addr::new(203, 0, 113, 1);
    let bad = Ipv4Addr::new(203, 0, 113, 2);
    h.add_inventory("stat", Subtype::Isp, good, None).await?;
    h.add_inventory("stat", Subtype::Isp, bad, None).await?;
    h.fake
        .set_user_ip("st-203-0-113-2", Ipv4Addr::new(198, 51, 100, 2));
    h.static_tick().await;
    h.w.gauges_tick().await;
    let m = &h.metrics;
    let stat = ["static", "stat"];
    let ips = |state: &str| m.inventory_ips.with_label_values(&["stat", state]).get();
    assert_eq!(
        (ips("available"), ips("quarantined"), ips("candidate")),
        (1, 1, 0)
    );
    assert_eq!(
        m.cache_ready
            .with_label_values(&["static", "stat", "normal"])
            .get(),
        1
    );
    assert_eq!(m.cache_min_ready.with_label_values(&stat).get(), 2);
    assert_eq!(
        m.cache_low_watermark.with_label_values(&stat).get(),
        1,
        "half of min_ready"
    );
    assert_eq!(ips("leased"), 0);

    // A lease lives in Redis; the row stays available but counts as leased.
    let p = h.partition("stat")?;
    let ttl = Duration::from_secs(60);
    h.lease_free(&p, Kind::Static, "acme", "s", ttl).await?;
    h.w.gauges_tick().await;
    assert_eq!((ips("available"), ips("leased")), (0, 1));
    Ok(())
}

/// A second rotating provider, `rot2`, for tests of per-provider state.
fn second_rotating_adapter(port: u16) -> String {
    rotating_adapter(port).replace("id = \"rot\"", "id = \"rot2\"")
}

const LOW_FOR_POLICY: &str = "min_ready = 4\nmax_ready = 4\nlow_watermark = 2\nlow_for = \"30s\"\n";

/// Ready units `ids` in `p`, exiting from 198.51.100.`first`, `first + 1`, ...
async fn put_ready(h: &Harness, p: &Partition, ids: [&str; 2], first: usize) -> TestResult {
    for (i, id) in ids.into_iter().enumerate() {
        let ip = format!("198.51.100.{}", first + i).parse()?;
        h.hot.ready_put(p, &unit(id, ip)).await?;
    }
    Ok(())
}

#[tokio::test]
async fn cache_low_is_set_after_low_for_below_the_watermark_and_recovery_restarts_the_clock()
-> TestResult {
    let h = harness!(Harness::start(Setup::new(
        rotating_adapter,
        LOW_FOR_POLICY,
        ""
    )));
    let p = h.partition("rot")?;
    let low = || {
        h.metrics
            .cache_low
            .with_label_values(&["rotating", "rot", "all"])
    };
    let t0 = Instant::now();
    let at = |secs| t0 + Duration::from_secs(secs);

    // Nothing is ready (0 < 2): the clock starts, the alert state waits.
    h.w.gauges_tick_at(at(0)).await;
    assert_eq!(low().get(), 0, "below, but not for low_for yet");
    h.w.gauges_tick_at(at(29)).await;
    assert_eq!(low().get(), 0, "29 s of 30");
    h.w.gauges_tick_at(at(30)).await;
    assert_eq!(low().get(), 1, "held for low_for");

    // Two ready units reach the watermark (2 is not below 2).
    put_ready(&h, &p, ["u1", "u2"], 1).await?;
    h.w.gauges_tick_at(at(40)).await;
    assert_eq!(low().get(), 0, "recovered");

    // Low again: the clock restarts from this reading, not from the first.
    assert!(h.hot.unit_drop(&p, "u2").await?);
    h.w.gauges_tick_at(at(50)).await;
    assert_eq!(low().get(), 0);
    h.w.gauges_tick_at(at(79)).await;
    assert_eq!(low().get(), 0, "29 s since the second low reading");
    h.w.gauges_tick_at(at(80)).await;
    assert_eq!(low().get(), 1);
    Ok(())
}

#[tokio::test]
async fn cache_low_clocks_run_per_provider() -> TestResult {
    let h = harness!(Harness::start(Setup {
        adapters: vec![rotating_adapter, second_rotating_adapter],
        ..Setup::new(rotating_adapter, LOW_FOR_POLICY, "")
    }));
    let (p, p2) = (h.partition("rot")?, h.partition("rot2")?);
    let low = |provider: &str| {
        h.metrics
            .cache_low
            .with_label_values(&["rotating", provider, "all"])
            .get()
    };
    let t0 = Instant::now();
    let at = |secs| t0 + Duration::from_secs(secs);

    // `rot` is full, `rot2` is empty: only `rot2` runs a clock.
    put_ready(&h, &p, ["a1", "a2"], 1).await?;
    h.w.gauges_tick_at(at(0)).await;
    h.w.gauges_tick_at(at(30)).await;
    assert_eq!((low("rot"), low("rot2")), (0, 1));

    // `rot2` fills up and `rot` runs dry: `rot` starts its own clock.
    put_ready(&h, &p2, ["b1", "b2"], 10).await?;
    for id in ["a1", "a2"] {
        assert!(h.hot.unit_drop(&p, id).await?);
    }
    h.w.gauges_tick_at(at(40)).await;
    assert_eq!((low("rot"), low("rot2")), (0, 0));
    h.w.gauges_tick_at(at(70)).await;
    assert_eq!((low("rot"), low("rot2")), (1, 0));
    Ok(())
}

#[tokio::test]
async fn the_gauges_split_ready_units_by_tier_and_cache_low_has_a_normal_view() -> TestResult {
    let h = harness!(Harness::start(Setup::new(
        rotating_adapter,
        LOW_FOR_POLICY,
        ""
    )));
    let p = h.partition("rot")?;
    h.hot
        .ready_put(&p, &unit("u1", "198.51.100.1".parse()?))
        .await?;
    h.hot
        .ready_put_tier(&p, &unit("u2", "198.51.100.2".parse()?), Tier::Degraded)
        .await?;
    let m = &h.metrics;
    let ready = |tier| m.cache_ready.with_label_values(&["rotating", "rot", tier]);
    let low = |tier| m.cache_low.with_label_values(&["rotating", "rot", tier]);
    let t0 = Instant::now();
    h.w.gauges_tick_at(t0).await;
    assert_eq!((ready("normal").get(), ready("degraded").get()), (1, 1));
    h.w.gauges_tick_at(t0 + Duration::from_secs(30)).await;
    assert_eq!(
        (low("all").get(), low("normal").get()),
        (0, 1),
        "both tiers reach the watermark of 2, the normal tier alone does not"
    );
    Ok(())
}

#[tokio::test]
async fn cache_low_covers_static_ips_with_the_policy_low_for() -> TestResult {
    let h = harness!(Harness::start(Setup::new(
        static_adapter,
        "min_ready = 4\nlow_for = \"30s\"\n",
        ""
    )));
    // One healthy IP against a watermark of 2 (half of min_ready).
    h.add_inventory("stat", Subtype::Isp, Ipv4Addr::new(203, 0, 113, 1), None)
        .await?;
    h.static_tick().await;
    let low = || {
        h.metrics
            .cache_low
            .with_label_values(&["static", "stat", "all"])
    };
    let t0 = Instant::now();
    h.w.gauges_tick_at(t0).await;
    assert_eq!(
        h.metrics
            .cache_ready
            .with_label_values(&["static", "stat", "normal"])
            .get(),
        1
    );
    assert_eq!(low().get(), 0);
    h.w.gauges_tick_at(t0 + Duration::from_secs(30)).await;
    assert_eq!(low().get(), 1);
    Ok(())
}

#[tokio::test]
async fn the_rental_gauge_goes_with_the_last_dated_ip() -> TestResult {
    let h = harness!(Harness::start(Setup::new(
        static_adapter,
        "min_ready = 1\n",
        ""
    )));
    let addr = Ipv4Addr::new(203, 0, 113, 7);
    h.add_inventory("stat", Subtype::Isp, addr, None).await?;
    let rows = h.db.list_inventory(None, None).await?;
    h.w.publish_rental_days(&rows);
    let series = "inventory_rental_days_left{";
    assert!(
        h.metrics.render().contains(series),
        "a dated IP has a gauge"
    );

    h.transition(addr, Transition::to(IpState::Retired, "removed"))
        .await?;
    let rows = h.db.list_inventory(None, None).await?;
    h.w.publish_rental_days(&rows);
    assert!(
        !h.metrics.render().contains(series),
        "no dated IP left: no stale days-left value for the alert"
    );
    Ok(())
}

fn score(source: &str, risk: u8, secs: i64) -> ScoreRow {
    ScoreRow {
        ip: "203.0.113.1".parse().expect("test ip"),
        source: source.to_owned(),
        risk,
        flags: vec!["tor".to_owned()],
        checked_at: OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(secs),
    }
}

#[test]
fn score_rows_become_checks_oldest_first() {
    // The store returns each service's newest first.
    let rows = [
        score("abuseipdb", 30, 3),
        score("abuseipdb", 20, 2),
        score("ipqs", 90, 3),
        score("ipqs", 80, 2),
        score("ipqs", 70, 1),
        score("nonsense", 99, 3),
    ];
    let checks = checks_from(&rows, 3);
    let risks: Vec<Vec<u8>> = checks
        .iter()
        .map(|c| {
            let mut r: Vec<u8> = c.iter().map(|s| s.risk).collect();
            r.sort_unstable();
            r
        })
        .collect();
    assert_eq!(risks, [vec![70], vec![20, 80], vec![30, 90]]);
    assert!(checks[2].iter().all(|s| s.flags.tor), "flags survive");
    assert!(checks_from(&[], 3).is_empty());
    assert_eq!(checks_from(&rows, 1).len(), 1, "depth caps the history");
}
