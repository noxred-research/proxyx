//! Reservations, locks, the `due` set, duplicate exit IPs, the failed-lease
//! memo and the per-org tunnel counter.

#[macro_use]
mod support;

use std::time::Duration;

use common::Cause;
use common::types::{OrgId, Partition};
use proxyx_store::{
    ExitIpClaim, FAILED_LEASE_MEMO_TTL, Hot, RESERVATION_TTL, TunnelRef, UnitRecord,
};
use redis::AsyncCommands;
use support::{
    TestResult, assert_has_ttl, assert_ttl, grant, ip, lease_as, nz, org, partition, raw_redis,
    seeded_partition, session_unit, static_call, static_grant, uniq_org,
};
use time::OffsetDateTime;
use uuid::Uuid;

#[tokio::test]
async fn reservations_stop_at_ready_plus_in_flight_plus_reserved() -> TestResult {
    let hot = hot_or_skip!();
    let p = partition()?;
    hot.ready_put(&p, &UnitRecord::static_ip(ip(1))).await?;
    // 1 ready; max_ready 3 leaves room for two more.
    let r1 = hot
        .reserve_create(&p, 3)
        .await?
        .ok_or("first reservation")?;
    let r2 = hot
        .reserve_create(&p, 3)
        .await?
        .ok_or("second reservation")?;
    assert!(
        hot.reserve_create(&p, 3).await?.is_none(),
        "1 + 0 + 2 reaches the cap"
    );

    // A reservation that becomes an in-flight create still counts once.
    assert!(
        hot.create_start(&p, &r1, "sess-1", Duration::from_secs(30))
            .await?
    );
    assert!(hot.reserve_create(&p, 3).await?.is_none());
    let counts = hot.counts(&p).await?;
    assert_eq!(
        (counts.ready_free, counts.creating, counts.reserved),
        (1, 1, 1)
    );

    // An aborted create frees its slot.
    assert!(hot.create_abort(&p, &r2.id.to_string()).await?);
    let r3 = hot.reserve_create(&p, 3).await?.ok_or("slot after abort")?;
    assert!(hot.create_abort(&p, &r3.id.to_string()).await?);

    // The create finished elsewhere: a ready unit counts like an in-flight one.
    hot.ready_put(&p, &UnitRecord::static_ip(ip(2))).await?;
    assert!(hot.create_abort(&p, "sess-1").await?);
    assert!(
        hot.reserve_create(&p, 3).await?.is_some(),
        "2 ready + 1 reserved"
    );
    assert!(hot.reserve_create(&p, 3).await?.is_none());
    Ok(())
}

#[tokio::test]
async fn leased_ready_units_count_against_max_ready() -> TestResult {
    let hot = hot_or_skip!();
    let p = seeded_partition(&hot, &[1]).await?;
    static_grant(&hot, &p, &org("a")?, "s").await?;
    let counts = hot.counts(&p).await?;
    assert_eq!(counts.ready_free, 0, "the only ready unit is leased");
    // 1 leased ready unit; max_ready 2 leaves room for exactly one more.
    hot.reserve_create(&p, 2)
        .await?
        .ok_or("one slot beside the leased unit")?;
    assert!(
        hot.reserve_create(&p, 2).await?.is_none(),
        "1 leased + 1 reserved reaches the cap"
    );
    Ok(())
}

#[tokio::test]
async fn ready_put_ends_the_in_flight_entry_of_that_session() -> TestResult {
    let hot = hot_or_skip!();
    let p = partition()?;
    let r = hot.reserve_create(&p, 2).await?.ok_or("reservation")?;
    hot.create_start(&p, &r, "sess-1", Duration::from_secs(30))
        .await?;
    assert_eq!(hot.counts(&p).await?.creating, 1);
    hot.ready_put(
        &p,
        &session_unit("sess-1", ip(1), None, Duration::from_secs(60)),
    )
    .await?;
    let c = hot.counts(&p).await?;
    assert_eq!((c.creating, c.ready_free), (0, 1));
    Ok(())
}

#[tokio::test]
async fn concurrent_reservations_never_exceed_max_ready() -> TestResult {
    let hot = hot_or_skip!();
    let p = partition()?;
    hot.ready_put(&p, &UnitRecord::static_ip(ip(1))).await?;
    let mut tasks = Vec::new();
    for _ in 0..60 {
        let (h, p) = (hot.clone(), p.clone());
        tasks.push(tokio::spawn(async move {
            h.reserve_create(&p, 6).await.map_err(|e| e.to_string())
        }));
    }
    let mut granted = 0;
    for t in tasks {
        if t.await??.is_some() {
            granted += 1;
        }
    }
    assert_eq!(granted, 5, "6 - 1 ready");
    Ok(())
}

#[tokio::test]
async fn every_coordination_key_has_a_ttl() -> TestResult {
    let hot = hot_or_skip!();
    let mut raw = raw_redis().await?;
    let p = partition()?;
    let tag = format!("{{{}}}", p.tag());
    let a = org("ttl-org")?;

    hot.reserve_create(&p, 5).await?.ok_or("reservation")?;
    assert_ttl(&mut raw, &format!("reserve:{tag}"), RESERVATION_TTL).await?;

    hot.memo_failed_lease(&a, "s", Cause::CacheEmpty).await?;
    assert_ttl(&mut raw, &format!("memo:{{{a}}}:s"), FAILED_LEASE_MEMO_TTL).await?;

    assert!(hot.lock_acquire(&p, "me", Duration::from_secs(15)).await?);
    assert_ttl(&mut raw, &format!("lock:{tag}"), Duration::from_secs(15)).await?;

    hot.cool_target(
        &p,
        ip(1),
        &support::target("x.example"),
        Duration::from_secs(30),
    )
    .await?;
    let cool_key = format!("cool:{tag}:{}:x.example", ip(1));
    assert_ttl(&mut raw, &cool_key, Duration::from_secs(30)).await?;

    let tunnel = Uuid::new_v4();
    assert!(
        hot.org_tunnel_open(&a, tunnel, None, Duration::from_secs(60))
            .await?
    );
    assert_ttl(
        &mut raw,
        &format!("orgtun:{{{a}}}"),
        Duration::from_secs(60),
    )
    .await?;

    hot.claim_exit_ip(ip(9), "sess", Duration::from_secs(20))
        .await?;
    assert_ttl(&mut raw, &format!("ip:{}", ip(9)), Duration::from_secs(20)).await?;
    Ok(())
}

#[tokio::test]
async fn a_failed_lease_is_remembered_for_the_memo_ttl() -> TestResult {
    let hot = hot_or_skip!();
    let a = org("memo-org")?;
    let sticky = Uuid::new_v4().simple().to_string();
    assert_eq!(hot.failed_lease(&a, &sticky).await?, None);
    hot.memo_failed_lease(&a, &sticky, Cause::NoHealthyIp)
        .await?;
    assert_eq!(
        hot.failed_lease(&a, &sticky).await?,
        Some(Cause::NoHealthyIp)
    );
    assert_eq!(hot.failed_lease(&a, "other").await?, None);
    Ok(())
}

#[tokio::test]
async fn partition_lock_has_one_holder_and_expires() -> TestResult {
    let hot = hot_or_skip!();
    let p = partition()?;
    assert!(
        hot.lock_acquire(&p, "w1", Duration::from_millis(300))
            .await?
    );
    assert!(!hot.lock_acquire(&p, "w2", Duration::from_secs(5)).await?);
    assert!(!hot.lock_renew(&p, "w2", Duration::from_secs(5)).await?);
    assert!(
        !hot.lock_release(&p, "w2").await?,
        "only the holder releases"
    );
    assert!(hot.lock_renew(&p, "w1", Duration::from_millis(300)).await?);

    tokio::time::sleep(Duration::from_millis(450)).await;
    assert!(
        hot.lock_acquire(&p, "w2", Duration::from_secs(5)).await?,
        "the lock expired"
    );
    assert!(hot.lock_release(&p, "w2").await?);
    assert!(hot.lock_acquire(&p, "w1", Duration::from_secs(5)).await?);
    Ok(())
}

#[tokio::test]
async fn due_jobs_are_claimed_once_and_come_back_if_not_done() -> TestResult {
    let hot = hot_or_skip!();
    let job = format!("check:{}", Uuid::new_v4());
    let future = format!("later:{}", Uuid::new_v4());
    hot.due_schedule(&job, OffsetDateTime::now_utc() - time::Duration::seconds(1))
        .await?;
    hot.due_schedule(
        &future,
        OffsetDateTime::now_utc() + time::Duration::hours(1),
    )
    .await?;

    let first = hot.due_claim(1000, Duration::from_millis(300)).await?;
    assert!(first.contains(&job));
    assert!(!first.contains(&future), "a job in the future is not due");
    let second = hot.due_claim(1000, Duration::from_millis(300)).await?;
    assert!(!second.contains(&job), "claimed jobs are hidden");

    tokio::time::sleep(Duration::from_millis(450)).await;
    let third = hot.due_claim(1000, Duration::from_secs(60)).await?;
    assert!(
        third.contains(&job),
        "an unfinished job returns after the visibility time"
    );
    assert!(hot.due_done(&job).await?);
    assert!(
        !hot.due_claim(1000, Duration::from_secs(60))
            .await?
            .contains(&job)
    );
    hot.due_done(&future).await?;
    Ok(())
}

#[tokio::test]
async fn a_second_session_on_one_exit_ip_is_a_duplicate() -> TestResult {
    let hot = hot_or_skip!();
    let exit = std::net::IpAddr::from([203, 0, 113, 77]);
    let one = Uuid::new_v4().to_string();
    let two = Uuid::new_v4().to_string();
    assert_eq!(
        hot.claim_exit_ip(exit, &one, Duration::from_millis(300))
            .await?,
        ExitIpClaim::Claimed
    );
    assert_eq!(
        hot.claim_exit_ip(exit, &one, Duration::from_millis(300))
            .await?,
        ExitIpClaim::Claimed,
        "the owner may claim again"
    );
    assert_eq!(
        hot.claim_exit_ip(exit, &two, Duration::from_secs(5))
            .await?,
        ExitIpClaim::Duplicate { owner: one.clone() }
    );
    assert!(!hot.release_exit_ip(exit, &two).await?);
    tokio::time::sleep(Duration::from_millis(450)).await;
    assert_eq!(
        hot.claim_exit_ip(exit, &two, Duration::from_secs(1))
            .await?,
        ExitIpClaim::Claimed,
        "the claim expired"
    );
    assert!(hot.release_exit_ip(exit, &two).await?);
    Ok(())
}

#[tokio::test]
async fn org_tunnel_cap_counts_open_tunnels_and_expires_them() -> TestResult {
    let hot = hot_or_skip!();
    let a = uniq_org("cap-")?;
    let ttl = Duration::from_millis(400);
    let (t1, t2, t3) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    assert!(hot.org_tunnel_open(&a, t1, nz(2), ttl).await?);
    assert!(hot.org_tunnel_open(&a, t2, nz(2), ttl).await?);
    assert!(
        !hot.org_tunnel_open(&a, t3, nz(2), ttl).await?,
        "at the cap"
    );
    assert!(
        hot.org_tunnel_open(&a, t1, nz(2), ttl).await?,
        "a known tunnel only refreshes"
    );
    assert_eq!(hot.org_tunnel_count(&a).await?, 2);

    hot.org_tunnel_close(&a, t1).await?;
    assert!(hot.org_tunnel_open(&a, t3, nz(2), ttl).await?);

    tokio::time::sleep(Duration::from_millis(550)).await;
    assert_eq!(
        hot.org_tunnel_count(&a).await?,
        0,
        "tunnels that are not touched expire"
    );
    Ok(())
}

#[tokio::test]
async fn touching_an_org_tunnel_keeps_it_counted_past_its_first_ttl() -> TestResult {
    let hot = hot_or_skip!();
    let mut raw = raw_redis().await?;
    let a = uniq_org("touch-")?;
    let (_, tunnel) = open_tunnel(&hot, &a, Duration::from_millis(400)).await?;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(hot.tunnel_touch(&tunnel, Duration::from_secs(5)).await?);

    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        hot.org_tunnel_count(&a).await?,
        1,
        "the counter must outlive the tunnel's first deadline"
    );
    assert_has_ttl(&mut raw, &format!("orgtun:{{{a}}}")).await?;

    hot.tunnel_close(&tunnel).await?;
    assert!(!hot.tunnel_touch(&tunnel, Duration::from_secs(5)).await?);
    assert_eq!(
        hot.org_tunnel_count(&a).await?,
        0,
        "a closed tunnel is not brought back"
    );
    Ok(())
}

#[tokio::test]
async fn touch_counts_a_tunnel_again_after_redis_loses_its_counters() -> TestResult {
    let hot = hot_or_skip!();
    let mut raw = raw_redis().await?;
    let a = uniq_org("loss-")?;
    let (p, tunnel) = open_tunnel(&hot, &a, Duration::from_secs(5)).await?;

    // Redis loses the counters (a flush, or an outage longer than the tunnel TTL).
    let unit_key = format!("tun:{{{}}}:{}", p.tag(), tunnel.unit);
    let org_key = format!("orgtun:{{{a}}}");
    raw.del::<_, ()>(&[&unit_key, &org_key]).await?;
    assert_eq!(hot.unit_load(&p, &tunnel.unit).await?.tunnels, 0);
    assert_eq!(hot.org_tunnel_count(&a).await?, 0);

    assert!(
        hot.tunnel_touch(&tunnel, Duration::from_secs(5)).await?,
        "a touch counts the open tunnel again"
    );
    assert_eq!(hot.unit_load(&p, &tunnel.unit).await?.tunnels, 1);
    assert_eq!(hot.org_tunnel_count(&a).await?, 1);
    for key in [&unit_key, &org_key] {
        assert_has_ttl(&mut raw, key).await?;
    }
    Ok(())
}

#[tokio::test]
async fn a_late_touch_does_not_bring_back_a_closed_tunnel() -> TestResult {
    let hot = hot_or_skip!();
    let a = uniq_org("late-")?;
    let (p, tunnel) = open_tunnel(&hot, &a, Duration::from_secs(5)).await?;

    hot.tunnel_close(&tunnel).await?;
    assert!(!hot.tunnel_touch(&tunnel, Duration::from_secs(5)).await?);
    assert_eq!(hot.unit_load(&p, &tunnel.unit).await?.tunnels, 0);
    assert_eq!(hot.org_tunnel_count(&a).await?, 0);

    // Closing a tunnel the counters had already forgotten still blocks a late touch.
    let second = static_grant(&hot, &p, &a, "s").await?.tunnel;
    let mut raw = raw_redis().await?;
    raw.del::<_, ()>(format!("tun:{{{}}}:{}", p.tag(), second.unit))
        .await?;
    hot.tunnel_close(&second).await?;
    assert!(!hot.tunnel_touch(&second, Duration::from_secs(5)).await?);
    assert_eq!(hot.unit_load(&p, &second.unit).await?.tunnels, 0);
    Ok(())
}

#[tokio::test]
async fn a_tunnel_id_counted_again_after_close_is_kept_by_touch() -> TestResult {
    let hot = hot_or_skip!();
    let a = uniq_org("again-")?;
    let p = seeded_partition(&hot, &[1]).await?;
    let id = Uuid::new_v4();
    let call = static_call(&p, &a, "s");
    let first = lease_as(&hot, &call, id).await?;
    let tunnel = grant(&first)?.tunnel.clone();
    hot.tunnel_close(&tunnel).await?;

    // The gateway gives a grant back and retries with the same tunnel id.
    assert!(
        hot.org_tunnel_open(&a, id, nz(1), Duration::from_secs(5))
            .await?
    );
    let retry = lease_as(&hot, &call, id).await?;
    assert_eq!(grant(&retry)?.tunnel, tunnel);

    assert!(hot.tunnel_touch(&tunnel, Duration::from_secs(5)).await?);
    assert_eq!(hot.unit_load(&p, &tunnel.unit).await?.tunnels, 1);
    assert_eq!(hot.org_tunnel_count(&a).await?, 1);
    Ok(())
}

/// A static lease of `a` on a fresh one-IP partition, with its tunnel
/// counted against the org's cap of 1.
async fn open_tunnel(
    hot: &Hot,
    a: &OrgId,
    ttl: Duration,
) -> Result<(Partition, TunnelRef), Box<dyn std::error::Error>> {
    let p = seeded_partition(hot, &[1]).await?;
    let tunnel = static_grant(hot, &p, a, "s").await?.tunnel;
    assert!(hot.org_tunnel_open(a, tunnel.id, nz(1), ttl).await?);
    Ok((p, tunnel))
}
