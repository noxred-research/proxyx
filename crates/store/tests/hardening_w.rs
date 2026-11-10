//! Hot-state regressions that the gateway and the
//! warmer rely on (real Redis).

#[macro_use]
mod support;

use std::time::Duration;

use common::Cause;
use proxyx_store::{LeaseOutcome, Phase, SessionJob};
use support::{Call, TestResult, ip, lease, org, partition, seeded_partition, static_call, target};
use time::OffsetDateTime;

/// A pool cooled by block signals only (no failed tunnel) answers at
/// once instead of making the caller wait for a unit that cannot come back.
#[tokio::test]
async fn a_pool_cooled_by_block_signals_answers_at_once() -> TestResult {
    let hot = hot_or_skip!();
    let a = org("a")?;
    let t = target("t1.example");
    let p = seeded_partition(&hot, &[1, 2]).await?;
    let call = Call {
        host: "t1.example",
        ..static_call(&p, &a, "s")
    };
    hot.cool_target(&p, ip(1), &t, Duration::from_secs(60))
        .await?;
    assert!(
        matches!(lease(&hot, &call).await?, LeaseOutcome::Free(_)),
        "ip 2 is not cooled"
    );
    hot.cool_target(&p, ip(2), &t, Duration::from_secs(60))
        .await?;
    assert_eq!(
        lease(&hot, &call).await?,
        LeaseOutcome::Cooled(Cause::NoHealthyIp)
    );
    Ok(())
}

/// The cooldowns failed tunnels set on an IP go when its login changes;
/// a block signal's cooldown and other IPs stay.
#[tokio::test]
async fn failed_tunnel_cooldowns_of_one_ip_are_cleared_and_block_cooldowns_stay() -> TestResult {
    let hot = hot_or_skip!();
    let p = partition()?;
    let ttl = Duration::from_secs(60);
    let (t1, t2, t3) = (
        target("t1.example"),
        target("t2.example"),
        target("t3.example"),
    );
    hot.cool_target_failed(&p, ip(1), &t1, ttl, Cause::ProviderAuth)
        .await?;
    hot.cool_target_failed(&p, ip(1), &t2, ttl, Cause::ProviderAuth)
        .await?;
    hot.cool_target(&p, ip(1), &t3, ttl).await?;
    hot.cool_target_failed(&p, ip(2), &t1, ttl, Cause::ProviderAuth)
        .await?;

    assert_eq!(hot.cool_clear_failed(&p, ip(1)).await?, 2);
    assert!(!hot.is_cooled(&p, ip(1), &t1).await?);
    assert!(!hot.is_cooled(&p, ip(1), &t2).await?);
    assert!(
        hot.is_cooled(&p, ip(1), &t3).await?,
        "a block signal's cooldown stays"
    );
    assert!(hot.is_cooled(&p, ip(2), &t1).await?, "another IP stays");
    assert_eq!(hot.cool_clear_failed(&p, ip(1)).await?, 0);
    Ok(())
}

/// Sessions in the drain phase are counted, the others are not.
#[tokio::test]
async fn draining_sessions_are_counted_from_the_due_set() -> TestResult {
    let hot = hot_or_skip!();
    let p = partition()?;
    let before = hot.draining_sessions().await?;
    let now = OffsetDateTime::now_utc();
    let later = now + time::Duration::hours(1);
    let job = |session: &str, phase| {
        SessionJob {
            partition: p.clone(),
            session: session.to_owned(),
            ip: "10.8.8.8".parse().expect("ip"),
            born: now.unix_timestamp(),
            expires: now.unix_timestamp() + 600,
            phase,
        }
        .encode()
    };
    let (d1, d2, k1) = (
        job("w-d1", Phase::Drain { since: 0 }),
        job("w-d2", Phase::Drain { since: 0 }),
        job("w-k1", Phase::fresh(0)),
    );
    for j in [&d1, &d2, &k1] {
        hot.due_schedule(j, later).await?;
    }
    assert_eq!(hot.draining_sessions().await? - before, 2);
    for j in [&d1, &d2, &k1] {
        hot.due_done(j).await?;
    }
    Ok(())
}

/// The index of a unit's leases outlives its last lease, so the sweep
/// still counts it; a unit's `ulz` key used to expire with the lease itself.
/// Only a per-connection lease counts (the gateway releases it with its
/// tunnel, so one that expired was leaked); a sticky lease ends by expiry in
/// normal traffic and is not a leak.
#[tokio::test]
async fn the_lease_index_outlives_the_last_lease_so_the_sweep_counts_it() -> TestResult {
    let hot = hot_or_skip!();
    let a = org("a")?;
    let p = seeded_partition(&hot, &[1, 2]).await?;
    let mut sticky = Call {
        host: "t1.example",
        ..static_call(&p, &a, "sid:normal-expiry")
    };
    sticky.limits.lease_ttl = Duration::from_millis(150);
    let first = lease(&hot, &sticky).await?;
    assert!(matches!(first, LeaseOutcome::Free(_)), "{first:?}");
    let mut leaked = Call {
        host: "t1.example",
        ..static_call(&p, &a, "conn:leaked-tunnel")
    };
    leaked.limits.lease_ttl = Duration::from_millis(150);
    let second = lease(&hot, &leaked).await?;
    assert!(matches!(second, LeaseOutcome::Free(_)), "{second:?}");
    tokio::time::sleep(Duration::from_millis(400)).await;

    let swept = hot.sweep(&p, None).await?;
    assert_eq!(
        swept.leases, 1,
        "the expired per-connection lease, not the sticky one"
    );
    assert_eq!(hot.sweep(&p, None).await?.leases, 0, "counted once");
    Ok(())
}
