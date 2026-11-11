//! Regressions of review fixes in the warmer.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use common::types::{IpState, Subtype, Tier};
use store::{ScoreRow, Transition};
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;

use super::support::{Harness, Setup, TestResult, box_adapter, harness, static_adapter, unit};

fn ip(n: u8) -> Ipv4Addr {
    Ipv4Addr::new(203, 0, 113, n)
}

async fn start() -> TestResult<Option<Harness>> {
    Harness::start(Setup::new(static_adapter, "min_ready = 2\n", "")).await
}

/// An available, leasable static IP.
async fn available(h: &Harness, n: u8) -> TestResult {
    h.add_inventory("stat", Subtype::Isp, ip(n), None).await?;
    h.static_tick().await;
    assert_eq!(h.row(ip(n)).await?.state, IpState::Available);
    Ok(())
}

fn cooldown() -> Transition {
    Transition::to(IpState::Cooldown, "block")
        .cooldown_until(OffsetDateTime::now_utc() + time::Duration::minutes(15))
}

async fn ready(h: &Harness, n: u8) -> TestResult<bool> {
    let p = h.partition("stat")?;
    Ok(h.hot.is_ready(&p, &ip(n).to_string()).await?)
}

/// A recheck that worked from a snapshot must not lift a cooldown set
/// since by a block signal.
#[tokio::test]
async fn a_stale_recheck_does_not_lift_a_fresh_cooldown() -> TestResult {
    let h = harness!(start());
    available(&h, 1).await?;
    let stale = h.row(ip(1)).await?;
    h.transition(ip(1), cooldown()).await?;
    h.hot
        .ready_take(&h.partition("stat")?, &ip(1).to_string())
        .await?;

    // the recheck found it slow and moves the row it read as Available
    let kept = h.w.retier(stale, Tier::Degraded).await?;
    assert_eq!(kept.state, IpState::Available, "the caller keeps its row");
    assert_eq!(h.row(ip(1)).await?.state, IpState::Cooldown);
    assert!(!ready(&h, 1).await?);
    Ok(())
}

/// A tier that differs between Postgres and Redis is repaired.
#[tokio::test]
async fn a_tier_that_differs_between_postgres_and_redis_is_repaired() -> TestResult {
    let h = harness!(start());
    let p = h.partition("stat")?;
    let id = ip(2).to_string();
    available(&h, 2).await?;

    // the Redis write after a move to Degraded failed
    h.transition(ip(2), Transition::to(IpState::Degraded, "slow"))
        .await?;
    assert_eq!(h.hot.tier(&p, &id).await?, Tier::Normal);
    h.static_tick().await;
    assert_eq!(h.hot.tier(&p, &id).await?, Tier::Degraded);

    // and the other way round
    h.transition(ip(2), Transition::to(IpState::Available, "fast"))
        .await?;
    h.static_tick().await;
    assert_eq!(h.hot.tier(&p, &id).await?, Tier::Normal);
    Ok(())
}

/// The unit that a relist writes carries the exit IP of the last
/// check, which differs from the row key for a SIM box.
#[tokio::test]
async fn a_relisted_box_carries_its_exit_ip() -> TestResult {
    let mut h = harness!(Harness::start(Setup::new(
        box_adapter,
        "min_ready = 1\n",
        ""
    )));
    let box_ip = ip(200);
    h.add_inventory("bx", Subtype::MobileBox, box_ip, Some("m1"))
        .await?;
    h.static_tick().await;
    assert_eq!(h.row(box_ip).await?.state, IpState::Available);
    let exit = ip(201);
    h.db.record_check(
        IpAddr::V4(box_ip),
        Some(IpAddr::V4(exit)),
        OffsetDateTime::now_utc(),
    )
    .await?;
    let p = h.partition("bx")?;
    h.hot.ready_take(&p, &box_ip.to_string()).await?;

    h.static_tick().await;
    assert!(h.hot.is_ready(&p, &box_ip.to_string()).await?);
    let unit_ip: String = redis::cmd("HGET")
        .arg(format!("unit:{{{}}}:{box_ip}", p.tag()))
        .arg("ip")
        .query_async(&mut h.raw)
        .await?;
    assert_eq!(unit_ip, exit.to_string());
    Ok(())
}

/// A unit that a stale rebuild put back although its row rests in
/// cooldown is taken out by the static loop.
#[tokio::test]
async fn a_banned_ip_that_a_stale_rebuild_put_back_is_taken_out() -> TestResult {
    let h = harness!(start());
    available(&h, 3).await?;
    h.transition(ip(3), cooldown()).await?;
    assert!(
        ready(&h, 3).await?,
        "the rebuild's late write left it ready"
    );

    h.static_tick().await;
    assert!(!ready(&h, 3).await?);
    assert_eq!(h.row(ip(3)).await?.state, IpState::Cooldown);
    Ok(())
}

/// The API withdraws a retired IP first; the unit record still goes.
#[tokio::test]
async fn a_retired_ip_the_api_withdrew_still_loses_its_unit_record() -> TestResult {
    let mut h = harness!(start());
    let p = h.partition("stat")?;
    available(&h, 4).await?;
    h.hot.ready_take(&p, &ip(4).to_string()).await?;
    h.transition(ip(4), Transition::to(IpState::Retired, "removed"))
        .await?;

    h.static_tick().await;
    let exists: i64 = redis::cmd("EXISTS")
        .arg(format!("unit:{{{}}}:{}", p.tag(), ip(4)))
        .query_async(&mut h.raw)
        .await?;
    assert_eq!(exists, 0);
    Ok(())
}

/// The sweep loop prunes old history, once an hour.
#[tokio::test]
async fn the_sweep_prunes_scores_past_their_retention() -> TestResult {
    let h = harness!(start());
    let subject = IpAddr::V4(ip(5));
    for age_days in [400, 1] {
        h.db.record_score(&ScoreRow {
            ip: subject,
            source: "fraud_score".into(),
            risk: 10,
            flags: vec![],
            checked_at: OffsetDateTime::now_utc() - time::Duration::days(age_days),
        })
        .await?;
    }
    h.w.sweep_tick().await;
    assert_eq!(
        h.db.recent_scores(subject, 10).await?.len(),
        1,
        "the old score went"
    );
    Ok(())
}

/// A provider that left keeps no breaker or budget series.
#[tokio::test]
async fn a_provider_that_left_keeps_no_gauge_series() -> TestResult {
    let h = harness!(start());
    h.metrics
        .provider_breaker_state
        .with_label_values(&["gone"])
        .set(2);
    h.metrics.set_cost_used_ratio("gone", 1.0);
    h.w.gauges_tick().await;
    let text = h.metrics.render();
    assert!(!text.contains("provider=\"gone\""), "{text}");
    Ok(())
}

/// Told to stop while it waits for a box to drain, the warmer leaves
/// the box as it is: no reset, no failed reset.
#[tokio::test]
async fn a_box_reset_that_is_stopped_during_the_drain_wait_does_not_reset() -> TestResult {
    let h = harness!(Harness::start(Setup::new(
        box_adapter,
        "min_ready = 1\n",
        "[policy.mobile_box]\nrotate_timeout = \"1s\"\ndrain_wait = \"5s\"\n",
    )));
    let box_ip = ip(210);
    h.add_inventory("bx", Subtype::MobileBox, box_ip, Some("m1"))
        .await?;
    let retest = OffsetDateTime::now_utc() + time::Duration::hours(6);
    h.transition(
        box_ip,
        Transition::to(IpState::Quarantined, "block").retest_at(retest),
    )
    .await?;
    let p = h.partition("bx")?;
    h.hot
        .ready_put(&p, &unit(&box_ip.to_string(), IpAddr::V4(box_ip)))
        .await?;
    h.lease_free(
        &p,
        common::types::Kind::Static,
        "acme",
        "s",
        Duration::from_secs(60),
    )
    .await?;

    h.box_tick().await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    h.w.cancel.cancel();
    h.settle().await;

    assert_eq!(h.row(box_ip).await?.state, IpState::Quarantined);
    for outcome in ["changed", "unchanged", "timeout", "error"] {
        assert_eq!(
            h.metrics
                .rotate_total
                .with_label_values(&["bx", outcome])
                .get(),
            0,
            "{outcome}"
        );
    }
    assert!(h.w.memory.lock().failed_resets.is_empty());
    Ok(())
}

/// A loop that ends before shutdown stops the warmer with an error.
#[tokio::test]
async fn a_loop_that_dies_before_shutdown_stops_the_warmer() {
    let cancel = CancellationToken::new();
    let mut loops = tokio::task::JoinSet::new();
    loops.spawn(async { panic!("a loop died") });
    let waiting = cancel.clone();
    loops.spawn(async move { waiting.cancelled().await });

    let result = crate::supervise(&cancel, loops).await;
    assert!(cancel.is_cancelled(), "the other loops are told to stop");
    assert!(result.is_err());

    // a stop that was asked for is not an error
    let cancel = CancellationToken::new();
    let mut loops = tokio::task::JoinSet::new();
    let waiting = cancel.clone();
    loops.spawn(async move { waiting.cancelled().await });
    cancel.cancel();
    assert!(crate::supervise(&cancel, loops).await.is_ok());
}
