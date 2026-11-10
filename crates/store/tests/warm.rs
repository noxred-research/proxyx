//! Warmer helpers: the cost meter windows, the once-per-window claim, the
//! ready-set membership test and the stuck-state sweep.

#[macro_use]
mod support;

use std::time::Duration;

use common::types::Tier;
use proxyx_store::{CostUsage, LeaseOutcome, Swept, UnitRecord};
use redis::AsyncCommands;
use support::{
    Call, TestResult, assert_ttl, grant, granted, ip, lease_static, org, partition, raw_redis,
    seeded_partition, static_call, uniq,
};
use time::OffsetDateTime;

/// A reserved create that stays in flight for a minute, and one that is stuck
/// past its deadline after 100 ms.
async fn start_live_and_stuck_creates(
    hot: &proxyx_store::Hot,
    p: &common::types::Partition,
) -> TestResult {
    let live = hot.reserve_create(p, 10).await?.ok_or("reservation")?;
    assert!(
        hot.create_start(p, &live, "live", Duration::from_secs(60))
            .await?
    );
    let stuck = hot.reserve_create(p, 10).await?.ok_or("reservation")?;
    assert!(
        hot.create_start(p, &stuck, "stuck", Duration::from_millis(100))
            .await?
    );
    Ok(())
}

#[tokio::test]
async fn cost_counts_bytes_per_day_and_creates_per_hour() -> TestResult {
    let hot = hot_or_skip!();
    let provider = uniq("prov").parse()?;
    // 04:30 UTC: the next hour is the same day.
    let at = OffsetDateTime::from_unix_timestamp(1_791_001_800)?;
    assert_eq!(hot.cost_used(&provider, at).await?, CostUsage::default());

    hot.cost_add(&provider, 1_000, 1, at).await?;
    hot.cost_add(&provider, 500, 2, at + time::Duration::minutes(10))
        .await?;
    assert_eq!(
        hot.cost_used(&provider, at).await?,
        CostUsage {
            bytes_today: 1_500,
            creates_this_hour: 3
        }
    );

    // The next hour has a fresh creates counter; the day keeps its bytes.
    let next_hour = at + time::Duration::hours(1);
    assert_eq!(
        hot.cost_used(&provider, next_hour).await?,
        CostUsage {
            bytes_today: 1_500,
            creates_this_hour: 0
        }
    );
    // The next day starts from zero.
    let next_day = at + time::Duration::days(1);
    assert_eq!(
        hot.cost_used(&provider, next_day).await?,
        CostUsage::default()
    );

    // Another provider has its own meter, and a zero add writes nothing.
    let other = uniq("prov").parse()?;
    hot.cost_add(&other, 0, 0, at).await?;
    assert_eq!(hot.cost_used(&other, at).await?, CostUsage::default());
    Ok(())
}

#[tokio::test]
async fn cost_meter_keys_expire_a_window_after_their_own() -> TestResult {
    let hot = hot_or_skip!();
    let mut raw = raw_redis().await?;
    let name = uniq("prov");
    let provider = name.parse()?;
    let at = OffsetDateTime::from_unix_timestamp(1_791_001_800)?;
    hot.cost_add(&provider, 10, 1, at).await?;

    let day_key = format!("cost:{{{name}}}:bytes:{}", 1_791_001_800 / 86_400);
    assert_ttl(&mut raw, &day_key, Duration::from_secs(2 * 86_400)).await?;
    let hour_key = format!("cost:{{{name}}}:creates:{}", 1_791_001_800 / 3_600);
    assert_ttl(&mut raw, &hour_key, Duration::from_secs(2 * 3_600)).await?;
    Ok(())
}

#[tokio::test]
async fn a_once_claim_is_taken_once_per_window() -> TestResult {
    let hot = hot_or_skip!();
    let key = uniq("report:");
    let ttl = Duration::from_millis(200);
    assert!(hot.claim_once(&key, ttl).await?);
    assert!(!hot.claim_once(&key, ttl).await?, "taken inside the window");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        hot.claim_once(&key, ttl).await?,
        "free again after the window"
    );

    assert!(hot.claim_once("", ttl).await.is_err());
    assert!(hot.claim_once(&key, Duration::ZERO).await.is_err());
    Ok(())
}

#[tokio::test]
async fn is_ready_follows_the_ready_set() -> TestResult {
    let hot = hot_or_skip!();
    let p = partition()?;
    let id = ip(5).to_string();
    assert!(!hot.is_ready(&p, &id).await?);
    hot.ready_put(&p, &UnitRecord::static_ip(ip(5))).await?;
    assert!(hot.is_ready(&p, &id).await?);
    hot.ready_take(&p, &id).await?;
    assert!(!hot.is_ready(&p, &id).await?);
    Ok(())
}

#[tokio::test]
async fn a_unit_tier_is_set_kept_cleared_and_counted() -> TestResult {
    let hot = hot_or_skip!();
    let p = partition()?;
    let (a, b) = (ip(1).to_string(), ip(2).to_string());
    hot.ready_put(&p, &UnitRecord::static_ip(ip(1))).await?;
    hot.ready_put_tier(&p, &UnitRecord::static_ip(ip(2)), Tier::Degraded)
        .await?;
    assert_eq!(hot.tier(&p, &a).await?, Tier::Normal);
    assert_eq!(hot.tier(&p, &b).await?, Tier::Degraded);
    let c = hot.counts(&p).await?;
    assert_eq!((c.ready_free, c.degraded_free), (2, 1));

    assert!(hot.set_tier(&p, &a, Tier::Degraded).await?);
    assert_eq!(hot.counts(&p).await?.degraded_free, 2);
    assert!(hot.set_tier(&p, &b, Tier::Normal).await?);
    assert_eq!(hot.tier(&p, &b).await?, Tier::Normal);
    assert_eq!(hot.counts(&p).await?.degraded_free, 1);

    // A unit without a record is not created by a tier change.
    assert!(!hot.set_tier(&p, "10.9.9.9", Tier::Degraded).await?);
    assert_eq!(hot.ready_ids(&p).await?.len(), 2);

    // Making a unit leasable again without a tier puts it back in the normal tier.
    hot.ready_put(&p, &UnitRecord::static_ip(ip(1))).await?;
    assert_eq!(hot.tier(&p, &a).await?, Tier::Normal);
    Ok(())
}

#[tokio::test]
async fn sweep_drops_expired_creates_reservations_and_leases_only() -> TestResult {
    let hot = hot_or_skip!();
    let p = partition()?;
    assert_eq!(
        hot.sweep(&p, None).await?,
        Swept::default(),
        "an empty partition"
    );

    // A live create keeps the in-flight key; a stuck one has passed its deadline.
    start_live_and_stuck_creates(&hot, &p).await?;
    tokio::time::sleep(Duration::from_millis(200)).await;

    let swept = hot.sweep(&p, None).await?;
    assert_eq!(
        swept,
        Swept {
            sessions: 1,
            reservations: 0,
            leases: 0
        }
    );
    assert_eq!(hot.counts(&p).await?.creating, 1, "the live create stays");
    assert_eq!(
        hot.sweep(&p, None).await?,
        Swept::default(),
        "nothing twice"
    );
    Ok(())
}

/// warmer N-W1: `counts` and `unit_load` drop expired state on the way. The
/// sweep that follows must still report it, or the metric under-counts.
#[tokio::test]
async fn sweep_reports_what_other_scripts_dropped_before_it() -> TestResult {
    let hot = hot_or_skip!();
    let mut raw = raw_redis().await?;
    let p = seeded_partition(&hot, &[1]).await?;
    let tag = format!("{{{}}}", p.tag());

    // an expired lease (a second org's long lease keeps the unit's lease key
    // alive, as a busy unit does), a stuck create, an expired reservation and
    // a ghost ready id
    for (who, ttl) in [("acme", 100), ("other", 60_000)] {
        let who = org(who)?;
        let mut limits = support::limits();
        limits.lease_ttl = Duration::from_millis(ttl);
        // per-connection: only those count as leaked when they expire
        let call = Call {
            limits,
            ..static_call(&p, &who, "conn:t")
        };
        granted(&hot, &call).await?;
    }
    // a live create keeps the in-flight key (and its TTL) alive, as a busy
    // warmer does; the stuck one has passed its deadline
    start_live_and_stuck_creates(&hot, &p).await?;
    let _: () = raw
        .zadd(format!("reserve:{tag}"), "old-reservation", 1)
        .await?;
    let _: () = raw.sadd(format!("ready:{tag}"), "ghost").await?;
    tokio::time::sleep(Duration::from_millis(250)).await;

    // a reader drops everything before the sweep gets to it
    let counts = hot.counts(&p).await?;
    assert_eq!((counts.creating, counts.reserved), (1, 0));

    assert_eq!(
        hot.sweep(&p, None).await?,
        Swept {
            sessions: 2,
            reservations: 1,
            leases: 1
        }
    );
    assert_eq!(hot.sweep(&p, None).await?, Swept::default(), "booked once");
    Ok(())
}

#[tokio::test]
async fn a_pinned_lease_hands_the_org_exactly_that_unit() -> TestResult {
    let hot = hot_or_skip!();
    let p = seeded_partition(&hot, &[1, 2, 3]).await?;
    let probe = org("probe")?;
    let pinned = ip(3).to_string();
    let ttl = Duration::from_secs(60);

    assert!(
        !hot.lease_pin(&p, &probe, "cand", "not-a-unit", ttl).await?,
        "only a leasable unit can be pinned"
    );
    assert!(hot.lease_pin(&p, &probe, "cand", &pinned, ttl).await?);

    // Others do not get the pinned unit while free ones remain.
    let other = lease_static(&hot, &p, &org("other")?, "s").await?;
    assert_ne!(grant(&other)?.unit, pinned);

    // The probe org's lease for the key is exactly the pinned unit.
    let hit = lease_static(&hot, &p, &probe, "cand").await?;
    assert!(
        matches!(&hit, LeaseOutcome::Hit(g) if g.unit == pinned),
        "{hit:?}"
    );

    assert!(hot.release(&p, &probe, "cand", None).await?);
    assert!(
        hot.lease_pin(&p, &probe, "x", &pinned, Duration::ZERO)
            .await
            .is_err()
    );
    assert!(hot.lease_pin(&p, &probe, "", &pinned, ttl).await.is_err());
    Ok(())
}
