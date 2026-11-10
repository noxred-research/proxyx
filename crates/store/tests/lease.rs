//! Lease decisions against a real Redis.

#[macro_use]
mod support;

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use common::Cause;
use common::types::{Kind, OrgId, Partition, Tier};
use policy::Pool;
use proxyx_store::{
    BlockScope, Hot, LeaseOutcome, LeaseRequest, MAX_RANK, UNIT_PENALTY_BASE, UNIT_PENALTY_MAX,
};
use support::{
    Call, TestResult, grant, granted, ip, lease, lease_static, limits, nz, org, partition,
    raw_redis, renew, seeded_partition, session_unit, static_call, static_grant, target, uniq_org,
};
use time::OffsetDateTime;
use uuid::Uuid;

#[tokio::test]
async fn exclusive_first_then_least_loaded_sharing() -> TestResult {
    let hot = hot_or_skip!();
    let p = seeded_partition(&hot, &[1, 2]).await?;
    let (a, b, c, d) = (org("a")?, org("b")?, org("c")?, org("d")?);

    let ga = lease_static(&hot, &p, &a, "s").await?;
    let gb = lease_static(&hot, &p, &b, "s").await?;
    let (LeaseOutcome::Free(ga), LeaseOutcome::Free(gb)) = (&ga, &gb) else {
        return Err(format!("both orgs should get a free IP: {ga:?} {gb:?}").into());
    };
    assert_ne!(ga.unit, gb.unit, "exclusive use comes first");

    // No free unit is left: c shares one; d shares the other (fewest orgs).
    let gc = lease_static(&hot, &p, &c, "s").await?;
    let LeaseOutcome::Shared(gc) = &gc else {
        return Err(format!("expected Shared, got {gc:?}").into());
    };
    assert_eq!((gc.orgs, gc.tunnels), (2, 2));
    let gd = lease_static(&hot, &p, &d, "s").await?;
    let LeaseOutcome::Shared(gd) = &gd else {
        return Err(format!("expected Shared, got {gd:?}").into());
    };
    assert_ne!(gd.unit, gc.unit, "least-loaded unit has fewer orgs");

    // The existing lease renews on its unit.
    let again = lease_static(&hot, &p, &a, "s").await?;
    let LeaseOutcome::Hit(again) = &again else {
        return Err(format!("expected Hit, got {again:?}").into());
    };
    assert_eq!(again.unit, ga.unit);
    assert_eq!(
        again.orgs, 2,
        "the org already on the unit is not counted twice"
    );
    Ok(())
}

#[tokio::test]
async fn sharing_breaks_ties_by_tunnels_then_traffic() -> TestResult {
    let hot = hot_or_skip!();
    let p = seeded_partition(&hot, &[1, 2]).await?;
    let (a, b, c) = (org("a")?, org("b")?, org("c")?);
    let ga = static_grant(&hot, &p, &a, "s").await?;
    let gb = static_grant(&hot, &p, &b, "s").await?;
    // a opens a second tunnel: its unit carries 2 tunnels, b's carries 1.
    lease_static(&hot, &p, &a, "s").await?;
    let gc = static_grant(&hot, &p, &c, "s").await?;
    assert_eq!(gc.unit, gb.unit, "fewer tunnels wins with equal orgs");

    // Equal orgs and tunnels on a fresh partition: traffic decides.
    let p2 = seeded_partition(&hot, &[1, 2]).await?;
    let x = static_grant(&hot, &p2, &a, "s").await?;
    let y = static_grant(&hot, &p2, &b, "s").await?;
    hot.record_traffic(&p2, &x.unit, 10_000).await?;
    let z = static_grant(&hot, &p2, &c, "s").await?;
    assert_eq!(z.unit, y.unit, "less traffic in 5 minutes wins");
    assert_ne!(ga.unit, gb.unit);
    Ok(())
}

#[tokio::test]
async fn static_prefers_previous_ip_then_least_recently_used() -> TestResult {
    let hot = hot_or_skip!();
    let p = seeded_partition(&hot, &[1, 2]).await?;
    let (a, b, c) = (org("a")?, org("b")?, org("c")?);
    let ga = static_grant(&hot, &p, &a, "s").await?;
    let gb = static_grant(&hot, &p, &b, "s").await?;
    for (g, o) in [(&ga, &a), (&gb, &b)] {
        hot.release(&p, o, "s", None).await?;
        hot.tunnel_close(&g.tunnel).await?;
    }
    // Unit 1 was used first, so it is the least recently used. b still gets
    // its previous IP; c, with no history, gets the least recently used.
    let again_b = lease_static(&hot, &p, &b, "new").await?;
    assert_eq!(grant(&again_b)?.unit, gb.unit);
    assert!(matches!(again_b, LeaseOutcome::Free(_)));
    let new_c = lease_static(&hot, &p, &c, "s").await?;
    assert_eq!(grant(&new_c)?.unit, ga.unit);
    Ok(())
}

#[tokio::test]
async fn orgs_hard_caps_orgs_per_unit_until_nothing_else_is_left() -> TestResult {
    let hot = hot_or_skip!();
    let p = seeded_partition(&hot, &[1]).await?;
    let mut l = limits();
    l.orgs_hard = nz(2);
    let call = |o, sticky| Call {
        limits: l.clone(),
        ..static_call(&p, o, sticky)
    };
    let (a, b, c) = (org("a")?, org("b")?, org("c")?);
    assert!(matches!(
        lease(&hot, &call(&a, "s")).await?,
        LeaseOutcome::Free(_)
    ));
    let within = lease(&hot, &call(&b, "s")).await?;
    assert!(matches!(within, LeaseOutcome::Shared(_)));
    assert_eq!(grant(&within)?.broke, None);
    // The unit is the last one: a third org breaks `orgs_hard`.
    let over = lease(&hot, &call(&c, "s")).await?;
    assert!(matches!(over, LeaseOutcome::Shared(_)), "{over:?}");
    assert_eq!(grant(&over)?.broke, Some("orgs_hard"));
    // An org already on the unit can add a second sticky key.
    let again = lease(&hot, &call(&a, "t")).await?;
    assert!(matches!(again, LeaseOutcome::Shared(_)));
    assert_eq!(grant(&again)?.broke, None);
    Ok(())
}

/// While another unit is within the limits, a unit past `orgs_hard` is not
/// taken.
#[tokio::test]
async fn a_unit_past_orgs_hard_is_left_alone_while_another_is_within_the_limits() -> TestResult {
    let hot = hot_or_skip!();
    let p = seeded_partition(&hot, &[1, 2]).await?;
    let mut l = limits();
    l.orgs_hard = nz(1);
    let call = |o, sticky| Call {
        limits: l.clone(),
        ..static_call(&p, o, sticky)
    };
    let (a, b) = (org("a")?, org("b")?);
    let ga = granted(&hot, &call(&a, "s")).await?;
    let gb = granted(&hot, &call(&b, "s")).await?;
    assert_ne!(ga.unit, gb.unit);
    assert_eq!((ga.broke, gb.broke), (None, None));
    Ok(())
}

#[tokio::test]
async fn max_conns_per_ip_caps_tunnels_per_unit_until_nothing_else_is_left() -> TestResult {
    let hot = hot_or_skip!();
    let p = seeded_partition(&hot, &[1]).await?;
    let mut l = limits();
    l.max_conns_per_ip = nz(2);
    let call = |o, sticky| Call {
        limits: l.clone(),
        ..static_call(&p, o, sticky)
    };
    let (a, b, c) = (org("a")?, org("b")?, org("c")?);
    let first = granted(&hot, &call(&a, "s")).await?;
    let second = lease(&hot, &call(&b, "s")).await?;
    assert!(matches!(second, LeaseOutcome::Shared(_)));
    assert_eq!(grant(&second)?.broke, None);
    // The unit is full and the last one: c breaks `max_conns`.
    let over = lease(&hot, &call(&c, "s")).await?;
    assert!(matches!(over, LeaseOutcome::Shared(_)), "{over:?}");
    assert_eq!(grant(&over)?.broke, Some("max_conns"));
    // A hit also needs a free slot: without one it is leased like any other.
    let hit = lease(&hot, &call(&a, "s")).await?;
    assert_eq!(grant(&hit)?.broke, Some("max_conns"));
    for g in [&first, grant(&second)?, grant(&over)?, grant(&hit)?] {
        hot.tunnel_close(&g.tunnel).await?;
    }
    let free = lease(&hot, &call(&c, "s")).await?;
    assert!(matches!(free, LeaseOutcome::Hit(_)), "{free:?}");
    assert_eq!(grant(&free)?.broke, None);
    Ok(())
}

/// Breaking `max_conns_per_ip` has a ceiling of twice the
/// limit per unit. Past it the unit is not leased, not even to a key that holds
/// a lease on it; the answer is Empty until a tunnel closes.
#[tokio::test]
async fn breaking_max_conns_stops_at_twice_the_limit() -> TestResult {
    let hot = hot_or_skip!();
    let p = seeded_partition(&hot, &[1]).await?;
    let mut l = limits();
    l.max_conns_per_ip = nz(2);
    let a = org("a")?;
    let call = |sticky| Call {
        limits: l.clone(),
        ..static_call(&p, &a, sticky)
    };
    let mut tunnels = Vec::new();
    for (sticky, broke) in [
        ("s0", None),
        ("s1", None),
        ("s2", Some("max_conns")),
        ("s3", Some("max_conns")),
    ] {
        let got = lease(&hot, &call(sticky)).await?;
        assert_eq!(grant(&got)?.broke, broke, "{sticky}: {got:?}");
        tunnels.push(grant(&got)?.tunnel.clone());
    }
    // 4 tunnels = 2 x max_conns: a new key and an existing lease are both refused
    assert_eq!(lease(&hot, &call("s4")).await?, LeaseOutcome::Empty);
    assert_eq!(lease(&hot, &call("s0")).await?, LeaseOutcome::Empty);
    hot.tunnel_close(&tunnels[0]).await?;
    let again = lease(&hot, &call("s4")).await?;
    assert_eq!(grant(&again)?.broke, Some("max_conns"), "{again:?}");
    Ok(())
}

/// The ceiling of breaking `max_conns_per_ip` is twice the limit but never more
/// than the provider allows per IP: with a policy limit of 2 and a provider
/// that allows 3, the unit takes 3 tunnels, not 4.
#[tokio::test]
async fn breaking_max_conns_never_passes_what_the_provider_allows() -> TestResult {
    let hot = hot_or_skip!();
    let p = seeded_partition(&hot, &[1]).await?;
    let mut l = limits();
    l.max_conns_per_ip = nz(2);
    l.provider_conns_per_ip = nz(3);
    let a = org("a")?;
    let call = |sticky| Call {
        limits: l.clone(),
        ..static_call(&p, &a, sticky)
    };
    for (sticky, broke) in [("s0", None), ("s1", None), ("s2", Some("max_conns"))] {
        let got = lease(&hot, &call(sticky)).await?;
        assert_eq!(grant(&got)?.broke, broke, "{sticky}: {got:?}");
    }
    assert_eq!(lease(&hot, &call("s3")).await?, LeaseOutcome::Empty);
    Ok(())
}

/// A tunnel that failed on a unit gives the unit's counter back
/// and keeps its org slot, so a concurrent tunnel of the org cannot take the
/// slot between the failure and the retry.
#[tokio::test]
async fn giving_a_unit_back_keeps_the_org_slot() -> TestResult {
    let hot = hot_or_skip!();
    let p = seeded_partition(&hot, &[1]).await?;
    let a = uniq_org("cap-")?;
    let cap = nz(1);
    let tunnel = Uuid::new_v4();
    assert!(
        hot.org_tunnel_open(&a, tunnel, cap, Duration::from_secs(15))
            .await?
    );
    let got = support::lease_as(&hot, &static_call(&p, &a, "s"), tunnel).await?;
    let g = grant(&got)?;
    assert_eq!(hot.unit_load(&p, &g.unit).await?.tunnels, 1);

    hot.unit_tunnel_close(&g.tunnel).await?;
    assert_eq!(hot.unit_load(&p, &g.unit).await?.tunnels, 0);
    assert_eq!(hot.org_tunnel_count(&a).await?, 1, "the org slot stays");
    // another tunnel of the org is refused until this one ends
    assert!(
        !hot.org_tunnel_open(&a, Uuid::new_v4(), cap, Duration::from_secs(15))
            .await?
    );
    hot.tunnel_close(&g.tunnel).await?;
    assert_eq!(hot.org_tunnel_count(&a).await?, 0);
    Ok(())
}

#[tokio::test]
async fn a_lease_on_a_full_unit_moves_to_a_free_one() -> TestResult {
    let hot = hot_or_skip!();
    let p = seeded_partition(&hot, &[1, 2]).await?;
    let mut l = limits();
    l.max_conns_per_ip = nz(1);
    let a = org("a")?;
    let call = Call {
        limits: l,
        ..static_call(&p, &a, "s")
    };
    let first = granted(&hot, &call).await?;
    let second = lease(&hot, &call).await?;
    assert!(matches!(second, LeaseOutcome::Free(_)));
    assert_ne!(grant(&second)?.unit, first.unit);
    Ok(())
}

#[tokio::test]
async fn target_cooldown_moves_only_that_target() -> TestResult {
    let hot = hot_or_skip!();
    // One IP: cooled for t1, still leasable for t2.
    let p = seeded_partition(&hot, &[1]).await?;
    hot.cool_target(&p, ip(1), &target("T1.example"), Duration::from_secs(60))
        .await?;
    assert!(hot.is_cooled(&p, ip(1), &target("t1.example")).await?);
    let (a, b) = (org("a")?, org("b")?);
    let call = |o, host| Call {
        host,
        ..static_call(&p, o, "s")
    };
    assert_eq!(
        lease(&hot, &call(&a, "t1.example")).await?,
        LeaseOutcome::Cooled(common::Cause::NoHealthyIp)
    );
    assert!(matches!(
        lease(&hot, &call(&b, "t2.example")).await?,
        LeaseOutcome::Free(_)
    ));

    // Two IPs: an existing lease on a cooled IP moves for that target.
    let p2 = seeded_partition(&hot, &[1, 2]).await?;
    let call2 = |host| Call {
        host,
        ..static_call(&p2, &a, "s")
    };
    let first = granted(&hot, &call2("t2.example")).await?;
    hot.cool_target(
        &p2,
        first.ip,
        &target("t1.example"),
        Duration::from_secs(60),
    )
    .await?;
    let moved = lease(&hot, &call2("t1.example")).await?;
    assert_ne!(grant(&moved)?.unit, first.unit, "the cooled IP is skipped");
    // The cooldown expires by itself.
    hot.cool_target(
        &p2,
        ip(2),
        &target("t3.example"),
        Duration::from_millis(200),
    )
    .await?;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!hot.is_cooled(&p2, ip(2), &target("t3.example")).await?);
    Ok(())
}

/// N-1: a lease that finds every unit cooled by failed tunnels answers with
/// the cause of the latest failure; a plain cooldown, a free unit, a create
/// in flight or a unit cooled for another reason keep the old answers.
#[tokio::test]
async fn a_pool_cooled_by_failed_tunnels_answers_cooled_with_the_latest_cause() -> TestResult {
    use common::Cause;

    let hot = hot_or_skip!();
    let a = org("a")?;
    let t = target("t1.example");
    let ttl = Duration::from_secs(60);
    let call = |p| Call {
        host: "t1.example",
        ..static_call(p, &a, "s")
    };

    let p = seeded_partition(&hot, &[1, 2]).await?;
    hot.cool_target_failed(&p, ip(1), &t, ttl, Cause::ProviderTimeout)
        .await?;
    assert!(
        matches!(lease(&hot, &call(&p)).await?, LeaseOutcome::Free(_)),
        "ip 2 is not cooled"
    );
    // the latest failure wins: ip 2 failed after ip 1 and keeps more time
    hot.cool_target_failed(&p, ip(2), &t, ttl * 2, Cause::ProviderAuth)
        .await?;
    assert_eq!(
        lease(&hot, &call(&p)).await?,
        LeaseOutcome::Cooled(Cause::ProviderAuth)
    );
    // another target is not affected
    let other = Call {
        host: "t2.example",
        ..call(&p)
    };
    assert!(matches!(
        lease(&hot, &other).await?,
        LeaseOutcome::Hit(_) | LeaseOutcome::Free(_) | LeaseOutcome::Shared(_)
    ));

    // a block signal's cooldown holds no cause: with a failed unit beside it
    // the failure's cause answers
    let q = seeded_partition(&hot, &[1, 2]).await?;
    hot.cool_target_failed(&q, ip(1), &t, ttl, Cause::ProviderAuth)
        .await?;
    hot.cool_target(&q, ip(2), &t, ttl).await?;
    assert_eq!(
        lease(&hot, &call(&q)).await?,
        LeaseOutcome::Cooled(Cause::ProviderAuth)
    );

    // a create under way may bring a unit that works: the wait stays
    let r = seeded_partition(&hot, &[1]).await?;
    hot.cool_target_failed(&r, ip(1), &t, ttl, Cause::UpstreamError)
        .await?;
    assert_eq!(
        lease(&hot, &call(&r)).await?,
        LeaseOutcome::Cooled(Cause::UpstreamError)
    );
    hot.reserve_create(&r, 10).await?.ok_or("reservation")?;
    assert_eq!(lease(&hot, &call(&r)).await?, LeaseOutcome::Empty);
    Ok(())
}

#[tokio::test]
async fn org_blocks_skip_units_and_scopes() -> TestResult {
    let hot = hot_or_skip!();
    let p = seeded_partition(&hot, &[1, 2]).await?;
    let (a, other) = (uniq_org("blk")?, uniq_org("fine")?);

    hot.org_block_set(&a, &BlockScope::Ip(ip(1)), None).await?;
    let g = lease_static(&hot, &p, &a, "s").await?;
    assert_eq!(
        grant(&g)?.unit,
        ip(2).to_string(),
        "the blocked IP is skipped"
    );
    // The other org is not affected, and the lease on unit 2 is a hit.
    let g = lease_static(&hot, &p, &other, "s").await?;
    assert_eq!(grant(&g)?.unit, ip(1).to_string());

    // Blocking the last IP leaves nothing: Blocked, not Empty.
    hot.org_block_set(&a, &BlockScope::Ip(ip(2)), None).await?;
    assert_eq!(
        lease_static(&hot, &p, &a, "s").await?,
        LeaseOutcome::Blocked
    );
    assert_eq!(renew(&hot, &static_call(&p, &a, "s")).await?, None);

    // Scope blocks use a fresh org, so the IP blocks above do not interfere.
    let scoped = uniq_org("scoped")?;
    // A block with an expiry lifts itself; a cleared block is gone.
    let q = seeded_partition(&hot, &[1]).await?;
    let soon = OffsetDateTime::now_utc() + Duration::from_millis(400);
    hot.org_block_set(&scoped, &BlockScope::RouteClass(q.clone()), Some(soon))
        .await?;
    assert_eq!(
        lease_static(&hot, &q, &scoped, "s").await?,
        LeaseOutcome::Blocked
    );
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(matches!(
        lease_static(&hot, &q, &scoped, "s").await?,
        LeaseOutcome::Free(_)
    ));

    // Provider and pool scopes cover the whole partition.
    let r = seeded_partition(&hot, &[1]).await?;
    hot.org_block_set(&scoped, &BlockScope::Provider(r.provider.clone()), None)
        .await?;
    assert_eq!(
        lease_static(&hot, &r, &scoped, "s").await?,
        LeaseOutcome::Blocked
    );
    assert!(
        hot.org_block_clear(&scoped, &BlockScope::Provider(r.provider.clone()))
            .await?
    );
    hot.org_block_set(&scoped, &BlockScope::Pool(Pool::Shared), None)
        .await?;
    assert_eq!(
        lease_static(&hot, &r, &scoped, "s").await?,
        LeaseOutcome::Blocked
    );
    hot.org_block_clear(&scoped, &BlockScope::Pool(Pool::Shared))
        .await?;
    assert!(matches!(
        lease_static(&hot, &r, &scoped, "s").await?,
        LeaseOutcome::Free(_)
    ));
    Ok(())
}

#[tokio::test]
async fn an_ip_blocked_after_the_lease_is_not_renewed() -> TestResult {
    let hot = hot_or_skip!();
    let p = seeded_partition(&hot, &[1, 2]).await?;
    let a = uniq_org("moved")?;
    let first = static_grant(&hot, &p, &a, "s").await?;
    hot.org_block_set(&a, &BlockScope::Ip(first.ip), None)
        .await?;
    let moved = lease_static(&hot, &p, &a, "s").await?;
    assert_ne!(grant(&moved)?.unit, first.unit);
    Ok(())
}

#[tokio::test]
async fn rest_after_release_holds_a_unit_back_from_other_orgs_until_nothing_else_is_left()
-> TestResult {
    let hot = hot_or_skip!();
    let p = seeded_partition(&hot, &[1]).await?;
    let mut l = limits();
    l.rest_after_release = Duration::from_millis(600);
    let call = |o| Call {
        limits: l.clone(),
        ..static_call(&p, o, "s")
    };
    let (a, b) = (org("a")?, org("b")?);
    let g = granted(&hot, &call(&a)).await?;
    hot.release(&p, &a, "s", None).await?;
    hot.tunnel_close(&g.tunnel).await?;

    // The same org may take its IP back at once.
    let back = lease(&hot, &call(&a)).await?;
    assert!(matches!(back, LeaseOutcome::Free(_)));
    assert_eq!(grant(&back)?.broke, None);
    hot.release(&p, &a, "s", None).await?;
    hot.tunnel_close(&grant(&back)?.tunnel).await?;

    // b finds only the resting unit: it breaks the rest.
    let early = lease(&hot, &call(&b)).await?;
    assert!(matches!(early, LeaseOutcome::Free(_)), "{early:?}");
    assert_eq!(grant(&early)?.broke, Some("rest"));
    hot.release(&p, &b, "s", None).await?;
    hot.tunnel_close(&grant(&early)?.tunnel).await?;

    tokio::time::sleep(Duration::from_millis(700)).await;
    let late = lease(&hot, &call(&a)).await?;
    assert!(matches!(late, LeaseOutcome::Free(_)));
    assert_eq!(grant(&late)?.broke, None);
    Ok(())
}

/// A unit that is not resting goes first: the rest is kept while it can be.
#[tokio::test]
async fn a_resting_unit_is_left_alone_while_another_is_free() -> TestResult {
    let hot = hot_or_skip!();
    let p = seeded_partition(&hot, &[1, 2]).await?;
    let mut l = limits();
    l.rest_after_release = Duration::from_secs(60);
    let call = |o| Call {
        limits: l.clone(),
        ..static_call(&p, o, "s")
    };
    let (a, b) = (org("a")?, org("b")?);
    let ga = granted(&hot, &call(&a)).await?;
    hot.release(&p, &a, "s", None).await?;
    hot.tunnel_close(&ga.tunnel).await?;
    let gb = granted(&hot, &call(&b)).await?;
    assert_ne!(gb.unit, ga.unit, "the resting unit is not taken");
    assert_eq!(gb.broke, None);
    Ok(())
}

#[tokio::test]
async fn a_released_long_lease_does_not_hold_the_unit_after_the_last_lease_ends() -> TestResult {
    let hot = hot_or_skip!();
    let p = seeded_partition(&hot, &[1]).await?;
    let call = |o, ttl, rest| {
        let mut l = limits();
        l.lease_ttl = ttl;
        l.rest_after_release = rest;
        Call {
            limits: l,
            ..static_call(&p, o, "s")
        }
    };
    let rest = Duration::from_millis(300);
    let (a, b, c) = (org("a")?, org("b")?, org("c")?);
    // a holds the unit for 400 ms; b shares it with a 600 s lease.
    let ga = granted(&hot, &call(&a, Duration::from_millis(400), rest)).await?;
    let gb = granted(&hot, &call(&b, Duration::from_secs(600), rest)).await?;
    assert_eq!(ga.unit, gb.unit);

    // b leaves while a's lease is live, then a's lease runs out by its ttl.
    hot.release(&p, &b, "s", None).await?;
    hot.tunnel_close(&gb.tunnel).await?;
    hot.tunnel_close(&ga.tunnel).await?;

    // The unit rests only `rest` after the last lease ended (400 ms), not
    // until b's 600 s lease would have expired.
    tokio::time::sleep(Duration::from_millis(900)).await;
    let third = lease(&hot, &call(&c, Duration::from_secs(60), rest)).await?;
    assert!(
        matches!(third, LeaseOutcome::Free(_)) && grant(&third)?.broke.is_none(),
        "a third org gets the unit once the rest after the last lease is over: {third:?}"
    );
    Ok(())
}

#[tokio::test]
async fn rotating_takes_the_session_with_least_life_that_keeps_min_remaining() -> TestResult {
    let hot = hot_or_skip!();
    let p = partition()?;
    let now = OffsetDateTime::now_utc();
    for (id, n, secs) in [("s1", 1, 600), ("s2", 2, 120), ("s3", 3, 30), ("s4", 4, -5)] {
        let expires_at = now + time::Duration::seconds(secs);
        let unit = session_unit(id, ip(n), Some(expires_at), Duration::from_secs(900));
        hot.ready_put(&p, &unit).await?;
    }
    let mut l = limits();
    l.min_remaining = Duration::from_secs(60);
    let call = |o, allow_create| {
        let mut limits = l.clone();
        limits.allow_create = allow_create;
        Call {
            kind: Kind::Rotating,
            limits,
            ..static_call(&p, o, "s")
        }
    };
    let (a, b, c, d) = (org("a")?, org("b")?, org("c")?, org("d")?);
    let ga = lease(&hot, &call(&a, true)).await?;
    assert!(matches!(ga, LeaseOutcome::Free(_)));
    assert_eq!(
        grant(&ga)?.unit,
        "s2",
        "least life left among those with min_remaining"
    );
    assert!(grant(&ga)?.expires_at.is_some());
    let gb = lease(&hot, &call(&b, true)).await?;
    assert_eq!(grant(&gb)?.unit, "s1");
    // Nothing free: a create is requested before anyone shares.
    assert_eq!(
        lease(&hot, &call(&c, true)).await?,
        LeaseOutcome::NeedCreate
    );
    let shared = lease(&hot, &call(&d, false)).await?;
    assert!(matches!(shared, LeaseOutcome::Shared(_)));
    assert!(
        ["s1", "s2"].contains(&grant(&shared)?.unit.as_str()),
        "s3 is too short and s4 is expired"
    );
    Ok(())
}

#[tokio::test]
async fn concurrent_leasers_never_exceed_the_caps() -> TestResult {
    let hot = hot_or_skip!();
    // A second handle stands for a second replica.
    let replica = hot_or_skip!();
    let p = seeded_partition(&hot, &[1, 2, 3]).await?;
    let mut l = limits();
    l.orgs_hard = nz(2);
    l.max_conns_per_ip = nz(5);

    let mut tasks = Vec::new();
    // 3 units x the ceiling of 2 x max_conns (10) = 30 tunnels: all fit
    for i in 0..30_u32 {
        let h = if i % 2 == 0 {
            hot.clone()
        } else {
            replica.clone()
        };
        let (p, l) = (p.clone(), l.clone());
        tasks.push(tokio::spawn(async move {
            let org = format!("org{}", i % 6)
                .parse()
                .map_err(|e| format!("{e}"))?;
            let sticky = format!("s{i}");
            let call = Call {
                limits: l,
                ..static_call(&p, &org, &sticky)
            };
            lease(&h, &call)
                .await
                .map(|o| (org, o))
                .map_err(|e| e.to_string())
        }));
    }
    type Tally = HashMap<String, (HashSet<String>, u32)>;
    let (mut per_unit, mut within): (Tally, Tally) = (HashMap::new(), HashMap::new());
    let mut granted = 0;
    for t in tasks {
        let (org, outcome) = t.await??;
        match outcome {
            LeaseOutcome::Free(g) | LeaseOutcome::Shared(g) | LeaseOutcome::Hit(g) => {
                granted += 1;
                let mut tallies = vec![&mut per_unit];
                if g.broke.is_none() {
                    tallies.push(&mut within);
                }
                for tally in tallies {
                    let e = tally.entry(g.unit.clone()).or_default();
                    e.0.insert(org.to_string());
                    e.1 += 1;
                }
            }
            other => return Err(format!("unexpected {other:?}").into()),
        }
    }
    assert_eq!(granted, 30, "every tunnel is leased: limits give way last");
    for (unit, (orgs, tunnels)) in &per_unit {
        let load = hot.unit_load(&p, unit).await?;
        assert_eq!(
            (load.orgs, load.tunnels),
            (orgs.len() as u64, u64::from(*tunnels))
        );
    }
    // a lease that broke no limit kept both
    for (unit, (orgs, tunnels)) in &within {
        assert!(orgs.len() <= 2, "{unit} carries {} orgs", orgs.len());
        assert!(*tunnels <= 5, "{unit} carries {tunnels} tunnels");
    }
    for (unit, (_, tunnels)) in &per_unit {
        assert!(
            *tunnels <= 10,
            "{unit} carries {tunnels} tunnels, past the ceiling"
        );
    }
    assert!(
        within.values().map(|(_, n)| n).sum::<u32>() <= 15,
        "3 units x 5 tunnels"
    );
    Ok(())
}

#[tokio::test]
async fn concurrent_leases_of_one_key_agree_on_one_unit() -> TestResult {
    let hot = hot_or_skip!();
    let p = seeded_partition(&hot, &[1, 2, 3]).await?;
    let mut tasks = Vec::new();
    for _ in 0..40 {
        let (h, p) = (hot.clone(), p.clone());
        tasks.push(tokio::spawn(async move {
            let org = "same-org".parse().map_err(|e| format!("{e}"))?;
            lease(&h, &static_call(&p, &org, "one"))
                .await
                .map_err(|e| e.to_string())
        }));
    }
    let mut units = HashSet::new();
    let mut frees = 0;
    for t in tasks {
        let o = t.await??;
        if matches!(o, LeaseOutcome::Free(_)) {
            frees += 1;
        }
        units.insert(grant(&o)?.unit.clone());
    }
    assert_eq!(units.len(), 1);
    assert_eq!(frees, 1, "only the first call takes a free unit");
    Ok(())
}

#[tokio::test]
async fn leases_and_tunnels_expire_by_ttl() -> TestResult {
    let hot = hot_or_skip!();
    let p = seeded_partition(&hot, &[1]).await?;
    let a = org("a")?;
    let mut l = limits();
    l.lease_ttl = Duration::from_millis(300);
    l.tunnel_ttl = Duration::from_millis(300);
    let call = Call {
        limits: l,
        ..static_call(&p, &a, "s")
    };
    let g = granted(&hot, &call).await?;
    assert_eq!(hot.unit_load(&p, &g.unit).await?.tunnels, 1);
    assert!(hot.tunnel_touch(&g.tunnel, Duration::from_secs(5)).await?);
    tokio::time::sleep(Duration::from_millis(450)).await;
    // The lease is gone (the tunnel was touched and stays).
    let load = hot.unit_load(&p, &g.unit).await?;
    assert_eq!((load.leases, load.tunnels), (0, 1));
    let next = lease(&hot, &call).await?;
    assert!(
        !matches!(next, LeaseOutcome::Hit(_)),
        "the expired lease must not hit"
    );

    // An untouched tunnel stops counting by itself.
    let q = seeded_partition(&hot, &[1]).await?;
    let g = granted(&hot, &Call { p: &q, ..call }).await?;
    tokio::time::sleep(Duration::from_millis(450)).await;
    assert_eq!(hot.unit_load(&q, &g.unit).await?.tunnels, 0);
    // A touch counts a tunnel the counter forgot again: the tunnel is open.
    assert!(hot.tunnel_touch(&g.tunnel, Duration::from_secs(1)).await?);
    assert_eq!(hot.unit_load(&q, &g.unit).await?.tunnels, 1);
    Ok(())
}

#[tokio::test]
async fn renew_extends_a_lease_without_opening_a_tunnel() -> TestResult {
    let hot = hot_or_skip!();
    let p = seeded_partition(&hot, &[1]).await?;
    let a = org("a")?;
    let g = static_grant(&hot, &p, &a, "s").await?;
    let call = static_call(&p, &a, "s");
    let renewed = renew(&hot, &call).await?.ok_or("lease should renew")?;
    assert_eq!(
        (renewed.unit.as_str(), renewed.tunnels),
        (g.unit.as_str(), 1)
    );
    assert_eq!(hot.unit_load(&p, &g.unit).await?.tunnels, 1);
    // Taking the unit out of leasing ends renewal.
    assert!(hot.ready_take(&p, &g.unit).await?);
    assert!(renew(&hot, &call).await?.is_none());
    Ok(())
}

/// Stress: holders are indexed (live-lease zset + org counters), not
/// found by reading every lease of the unit. The counts must stay right
/// through many sticky keys, releases and expiry.
#[tokio::test]
async fn lease_and_org_counts_follow_many_sticky_keys_releases_and_expiry() -> TestResult {
    let hot = hot_or_skip!();
    let p = seeded_partition(&hot, &[1]).await?;
    let (a, b) = (org("a")?, org("b")?);
    let g = lease_static(&hot, &p, &a, "first").await?;
    let unit = grant(&g)?.unit.clone();
    let long = Duration::from_secs(60);

    for n in 0..300 {
        assert!(hot.lease_pin(&p, &a, &format!("k{n}"), &unit, long).await?);
    }
    for n in 0..2 {
        assert!(hot.lease_pin(&p, &b, &format!("k{n}"), &unit, long).await?);
    }
    for n in 0..5 {
        let short = Duration::from_millis(300);
        assert!(
            hot.lease_pin(&p, &a, &format!("short{n}"), &unit, short)
                .await?
        );
    }
    let load = hot.unit_load(&p, &unit).await?;
    assert_eq!((load.orgs, load.leases), (2, 308));

    // b holds two keys: the org stays until its last key goes.
    hot.release(&p, &b, "k0", None).await?;
    assert_eq!(hot.unit_load(&p, &unit).await?.orgs, 2);
    hot.release(&p, &b, "k1", None).await?;
    let load = hot.unit_load(&p, &unit).await?;
    assert_eq!((load.orgs, load.leases), (1, 306));

    // Expired leases stop counting; renewing one does not count it twice.
    tokio::time::sleep(Duration::from_millis(450)).await;
    let load = hot.unit_load(&p, &unit).await?;
    assert_eq!(
        (load.orgs, load.leases),
        (1, 301),
        "the 5 short leases expired"
    );
    assert!(hot.lease_pin(&p, &a, "k1", &unit, long).await?);
    assert_eq!(hot.unit_load(&p, &unit).await?.leases, 301);
    Ok(())
}

/// Stress, cost side: a lease on a unit costs the same with 100 sticky
/// leases on it as with 5000. Reading every lease of the unit (the old
/// `HGETALL` over all of them) grows with their number; the index
/// (`ulz`/`uorgs`) does not. Wall time is noisy, so this only fails when the
/// median of 50 lease + release calls is both above 3x and above 2 ms.
#[tokio::test]
async fn lease_cost_does_not_grow_with_the_sticky_leases_of_a_unit() -> TestResult {
    let hot = hot_or_skip!();
    let p = seeded_partition(&hot, &[1]).await?;
    let a = org("a")?;
    let g = lease_static(&hot, &p, &a, "first").await?;
    let unit = grant(&g)?.unit.clone();
    let long = Duration::from_secs(60);

    // Median of 50 lease + release calls on fresh sticky keys.
    let measure = |round: u32| {
        let (hot, p, a, unit) = (&hot, &p, &a, &unit);
        async move {
            let mut times = Vec::with_capacity(50);
            for n in 0..50 {
                let sticky = format!("m{round}-{n}");
                let started = Instant::now();
                let out = lease_static(hot, p, a, &sticky).await?;
                assert_eq!(&grant(&out)?.unit, unit, "the only unit serves the lease");
                assert!(hot.release(p, a, &sticky, None).await?);
                times.push(started.elapsed());
            }
            times.sort();
            Ok::<_, Box<dyn std::error::Error>>(times[times.len() / 2])
        }
    };

    for n in 0..99 {
        assert!(hot.lease_pin(&p, &a, &format!("k{n}"), &unit, long).await?);
    }
    assert_eq!(hot.unit_load(&p, &unit).await?.leases, 100);
    let before = measure(0).await?;

    for n in 99..4999 {
        assert!(hot.lease_pin(&p, &a, &format!("k{n}"), &unit, long).await?);
    }
    assert_eq!(hot.unit_load(&p, &unit).await?.leases, 5000);
    let after = measure(1).await?;

    assert!(
        !(after > before * 3 && after > Duration::from_millis(2)),
        "a lease took {after:?} with 5000 sticky leases on the unit, {before:?} with 100"
    );
    Ok(())
}

/// The lease index keeps an expired member for the sweeper
///, but nothing that counts leases sees it: `unit_load` and `counts`
/// (the `leased` gauge, the `ready_ttl` check) are exact, and one sweep removes it.
#[tokio::test]
async fn an_expired_lease_left_in_the_index_is_not_counted_and_the_sweep_removes_it() -> TestResult
{
    let hot = hot_or_skip!();
    let p = seeded_partition(&hot, &[1]).await?;
    let a = org("a")?;
    let mut short = limits();
    short.lease_ttl = Duration::from_millis(300);
    let g = granted(
        &hot,
        &Call {
            limits: short,
            ..static_call(&p, &a, "s")
        },
    )
    .await?;
    hot.tunnel_close(&g.tunnel).await?;
    assert_eq!(hot.counts(&p).await?.leased, 1);
    tokio::time::sleep(Duration::from_millis(400)).await;

    let mut raw = support::raw_redis().await?;
    let key = format!("ulz:{{{}}}:{}", p.tag(), g.unit);
    let members: i64 = redis::cmd("ZCARD").arg(&key).query_async(&mut raw).await?;
    assert_eq!(members, 1, "the member lingers for the sweeper");
    assert_eq!(hot.unit_load(&p, &g.unit).await?.leases, 0);
    let counts = hot.counts(&p).await?;
    assert_eq!((counts.ready_free, counts.leased), (1, 0));

    // read-side trimming already dropped it; a fresh lease/sweep leaves none behind
    hot.sweep(&p, None).await?;
    let members: i64 = redis::cmd("ZCARD").arg(&key).query_async(&mut raw).await?;
    assert_eq!(members, 0);
    Ok(())
}

/// The count of distinct units of a partition that failed a
/// dial within the window, which tells a bad unit from a failed provider.
#[tokio::test]
async fn failed_dials_count_distinct_units_inside_the_window() -> TestResult {
    let hot = hot_or_skip!();
    let p = partition()?;
    let window = Duration::from_millis(300);
    assert_eq!(hot.dial_failed(&p, "10.0.0.1", window).await?, 1);
    assert_eq!(
        hot.dial_failed(&p, "10.0.0.1", window).await?,
        1,
        "the same unit failing again is still one unit"
    );
    assert_eq!(hot.dial_failed(&p, "10.0.0.2", window).await?, 2);
    let other = partition()?;
    assert_eq!(
        hot.dial_failed(&other, "10.0.0.1", window).await?,
        1,
        "another partition keeps its own count"
    );
    tokio::time::sleep(Duration::from_millis(350)).await;
    assert_eq!(
        hot.dial_failed(&p, "10.0.0.3", window).await?,
        1,
        "the earlier failures left the window"
    );
    Ok(())
}

/// S8-D2/D4: a unit reserved under `sid_sticky(sid)` is the one the
/// `px-sid-<sid>` tunnel of that org gets.
#[tokio::test]
async fn a_unit_pinned_for_a_sid_is_the_one_its_tunnel_leases() -> TestResult {
    let hot = hot_or_skip!();
    let p = seeded_partition(&hot, &[1, 2, 3]).await?;
    let probe = org("probe")?;
    let unit = ip(3).to_string();
    let sticky = proxyx_store::sid_sticky("smp1");
    assert!(
        hot.lease_pin(&p, &probe, &sticky, &unit, Duration::from_secs(60))
            .await?
    );
    let g = lease_static(&hot, &p, &probe, &sticky).await?;
    assert!(matches!(g, LeaseOutcome::Hit(_)), "{g:?}");
    assert_eq!(grant(&g)?.unit, unit);
    Ok(())
}

/// `px-sid-<hash>` gives every the session proxy session its own sticky
/// key, so the sessions of one org used to take every free IP and left no
/// exclusive IP for the next org. An org that holds `ceil(IPs / orgs)` IPs
/// reuses its own least-loaded one for a new sticky key instead.
#[tokio::test]
async fn orgs_with_many_sessions_hold_a_share_of_the_ips_and_do_not_share_them() -> TestResult {
    let hot = hot_or_skip!();
    let p = seeded_partition(&hot, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]).await?;
    let orgs = [org("a")?, org("b")?, org("c")?];
    let mut units: HashMap<&str, HashSet<String>> = HashMap::new();
    let mut orgs_of_unit: HashMap<String, HashSet<&str>> = HashMap::new();
    for session in 0..100 {
        for org in &orgs {
            let g = lease_static(&hot, &p, org, &format!("sid:{session}")).await?;
            let unit = grant(&g)?.unit.clone();
            units.entry(org.as_str()).or_default().insert(unit.clone());
            orgs_of_unit.entry(unit).or_default().insert(org.as_str());
        }
    }
    let held: Vec<usize> = orgs.iter().map(|o| units[o.as_str()].len()).collect();
    assert!(
        held.iter().all(|n| (3..=4).contains(n)) && held.iter().sum::<usize>() == 10,
        "3 orgs on 10 IPs hold 3 or 4 each: {held:?}"
    );
    assert!(
        orgs_of_unit.values().all(|orgs| orgs.len() == 1),
        "no IP is shared across orgs while the pool suffices: {orgs_of_unit:?}"
    );
    Ok(())
}

#[tokio::test]
async fn a_single_org_with_many_sessions_uses_every_ip() -> TestResult {
    let hot = hot_or_skip!();
    let p = seeded_partition(&hot, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]).await?;
    let a = org("a")?;
    let mut units = HashSet::new();
    for session in 0..100 {
        let g = lease_static(&hot, &p, &a, &format!("sid:{session}")).await?;
        units.insert(grant(&g)?.unit.clone());
    }
    assert_eq!(units.len(), 10, "an org alone may hold the whole pool");
    Ok(())
}

/// An org at its cap reuses its own least-loaded IP; a new org still gets
/// the free one.
#[tokio::test]
async fn an_org_at_its_ip_cap_reuses_its_least_loaded_ip_and_a_new_org_gets_the_free_one()
-> TestResult {
    let hot = hot_or_skip!();
    let p = seeded_partition(&hot, &[1, 2, 3, 4]).await?;
    let (a, b) = (org("a")?, org("b")?);
    // b holds one IP, so a's cap is ceil(4 / 2) = 2
    let gb = static_grant(&hot, &p, &b, "s").await?;
    let g0 = static_grant(&hot, &p, &a, "s0").await?;
    let g1 = static_grant(&hot, &p, &a, "s1").await?;
    assert_ne!(g0.unit, g1.unit, "below its cap a takes a second IP");
    // a loads its first IP with a second tunnel; a third key goes to the lighter one
    assert_eq!(static_grant(&hot, &p, &a, "s0").await?.unit, g0.unit);
    let g2 = lease_static(&hot, &p, &a, "s2").await?;
    let LeaseOutcome::Shared(g2) = &g2 else {
        return Err(format!("a is at its cap, expected Shared, got {g2:?}").into());
    };
    assert_eq!(g2.unit, g1.unit, "the least-loaded IP of a");
    assert_eq!(g2.orgs, 1, "no other org on it");
    // the fourth IP is still free for another org
    let c = org("c")?;
    let gc = lease_static(&hot, &p, &c, "s").await?;
    assert!(matches!(gc, LeaseOutcome::Free(_)), "{gc:?}");
    assert_ne!(grant(&gc)?.unit, gb.unit);
    Ok(())
}

/// An org that took the whole pool while alone does not keep it
/// when a second org arrives: the newcomer, below its cap, takes its cap of
/// distinct IPs and spreads its sessions over them.
#[tokio::test]
async fn a_later_org_takes_its_cap_of_ips_from_an_org_that_holds_the_whole_pool() -> TestResult {
    let hot = hot_or_skip!();
    let p = seeded_partition(&hot, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]).await?;
    let (a, b) = (org("a")?, org("b")?);
    for session in 0..200 {
        lease_static(&hot, &p, &a, &format!("sid:{session}")).await?;
    }
    let mut per_unit: HashMap<String, usize> = HashMap::new();
    for session in 0..60 {
        let g = lease_static(&hot, &p, &b, &format!("sid:{session}")).await?;
        *per_unit.entry(grant(&g)?.unit.clone()).or_default() += 1;
    }
    assert_eq!(per_unit.len(), 5, "b's cap is ceil(10 / 2): {per_unit:?}");
    assert!(
        per_unit.values().all(|n| (10..=14).contains(n)),
        "b's sessions spread over its IPs: {per_unit:?}"
    );
    Ok(())
}

/// Tunnels that close at once leave nothing to tell an org's
/// IPs apart by open tunnels; live sticky leases spread its sessions.
#[tokio::test]
async fn sessions_spread_over_an_orgs_ips_when_their_tunnels_close_at_once() -> TestResult {
    let hot = hot_or_skip!();
    let p = seeded_partition(&hot, &[1, 2, 3, 4]).await?;
    let (a, b) = (org("a")?, org("b")?);
    static_grant(&hot, &p, &b, "s").await?;
    // b holds one IP, so a's cap is 2
    let mut per_unit: HashMap<String, usize> = HashMap::new();
    for session in 0..20 {
        let g = static_grant(&hot, &p, &a, &format!("sid:{session}")).await?;
        hot.tunnel_close(&g.tunnel).await?;
        *per_unit.entry(g.unit).or_default() += 1;
    }
    assert_eq!(per_unit.len(), 2, "{per_unit:?}");
    assert_eq!(per_unit.values().sum::<usize>(), 20);
    assert!(
        per_unit.values().all(|n| *n == 10),
        "sessions spread over a's two IPs: {per_unit:?}"
    );
    Ok(())
}

/// A lease of `c` that leaves the units in `skip` out.
async fn lease_without(hot: &Hot, c: &Call<'_>, skip: &[&str]) -> TestResult2 {
    let t = target(c.host);
    let req = LeaseRequest {
        partition: c.p,
        kind: c.kind,
        org: c.org,
        sticky: c.sticky,
        target: &t,
        tunnel: Uuid::new_v4(),
        pool: Pool::Shared,
        limits: c.limits.clone(),
    };
    let skip: Vec<String> = skip.iter().map(|ip| (*ip).to_owned()).collect();
    Ok(hot
        .lease_ranked(&req, &skip, proxyx_store::MAX_RANK)
        .await?)
}

type TestResult2 = Result<LeaseOutcome, Box<dyn std::error::Error>>;

/// The IP of unit `n` as text: the unit id of a static unit.
fn unit(n: u8) -> String {
    ip(n).to_string()
}

/// Cool the unit at `ip` for example.com, as a failed tunnel does.
async fn cool(hot: &Hot, p: &Partition, ip: IpAddr) -> TestResult {
    hot.cool_target_failed(
        p,
        ip,
        &target("example.com"),
        Duration::from_secs(60),
        Cause::UpstreamError,
    )
    .await?;
    Ok(())
}

/// With nothing left within the limits, the lease breaks the
/// lowest limit first: the rest, `orgs_hard`, `max_conns`, the monthly fair-use
/// stop; and an IP cooled for the target stays out whatever is broken.
#[tokio::test]
async fn soft_limits_break_in_order_and_a_cooled_ip_stays_out() -> TestResult {
    let hot = hot_or_skip!();
    let p = seeded_partition(&hot, &[1, 2, 3, 4]).await?;
    let mut l = limits();
    l.orgs_hard = nz(1);
    l.max_conns_per_ip = nz(2);
    l.rest_after_release = Duration::from_secs(60);
    let call = |o, sticky| Call {
        limits: l.clone(),
        ..static_call(&p, o, sticky)
    };
    let (x, y, z, w) = (org("x")?, org("y")?, org("z")?, org("w")?);

    // unit 1 rests after x, unit 2 holds org y, unit 3 holds 2 tunnels of org
    // z, unit 4 used up its fair-use traffic
    let gx = lease_without(&hot, &call(&x, "s"), &[&unit(2), &unit(3), &unit(4)]).await?;
    assert_eq!(grant(&gx)?.unit, unit(1));
    hot.release(&p, &x, "s", None).await?;
    hot.tunnel_close(&grant(&gx)?.tunnel).await?;
    let gy = lease_without(&hot, &call(&y, "s"), &[&unit(1), &unit(3), &unit(4)]).await?;
    assert_eq!(grant(&gy)?.unit, unit(2));
    for sticky in ["s1", "s2"] {
        let gz = lease_without(&hot, &call(&z, sticky), &[&unit(1), &unit(2), &unit(4)]).await?;
        assert_eq!(
            (grant(&gz)?.unit.clone(), grant(&gz)?.broke),
            (unit(3), None)
        );
    }
    hot.fair_use_add(&p, ip(4), 2_000, 1_000, OffsetDateTime::now_utc())
        .await?;

    for (n, sticky, limit) in [
        (1, "w1", "rest"),
        (2, "w2", "orgs_hard"),
        (3, "w3", "max_conns"),
        (4, "w4", "fair_use"),
    ] {
        let got = lease(&hot, &call(&w, sticky)).await?;
        let g = grant(&got)?;
        assert_eq!((g.unit.clone(), g.broke), (unit(n), Some(limit)), "{got:?}");
        cool(&hot, &p, ip(n)).await?;
    }
    // every unit is cooled for the target now: it is not leased at all
    let none = lease(&hot, &call(&w, "w5")).await?;
    assert!(matches!(none, LeaseOutcome::Cooled(_)), "{none:?}");
    Ok(())
}

/// The org cap counts the units this call can use. An org whose
/// own IP is cooled for the target is not pinned to its other IP while a free
/// one is left.
#[tokio::test]
async fn the_org_cap_counts_only_units_usable_for_the_target() -> TestResult {
    let hot = hot_or_skip!();
    let p = seeded_partition(&hot, &[1, 2, 3, 4]).await?;
    let (a, b) = (org("a")?, org("b")?);
    let g1 = static_grant(&hot, &p, &a, "s1").await?;
    let g2 = static_grant(&hot, &p, &a, "s2").await?;
    static_grant(&hot, &p, &b, "s").await?;
    // a holds 2 of 4 IPs and b 1: a is at its cap (ceil(4 / 2))
    cool(&hot, &p, g2.ip).await?;
    let next = lease_static(&hot, &p, &a, "s3").await?;
    assert!(matches!(next, LeaseOutcome::Free(_)), "{next:?}");
    assert_ne!(grant(&next)?.unit, g1.unit);
    assert_ne!(grant(&next)?.unit, g2.unit);
    Ok(())
}

/// Delete the dwell mark of a lease: the lease counts as older than the
/// minimum dwell.
async fn age(p: &Partition, org: &OrgId, sticky: &str) -> TestResult {
    let mut raw = raw_redis().await?;
    let key = format!("since:{{{}}}:{org}:{sticky}", p.tag());
    let gone: i64 = redis::AsyncCommands::del(&mut raw, &key).await?;
    assert_eq!(gone, 1, "{key} marks a young lease");
    Ok(())
}

/// An org over its cap whose unit another org shares moves the
/// lease to an IP of its own that nobody shares, once the lease is older than
/// the minimum dwell, and only when the lease is renewed for a new tunnel.
#[tokio::test]
async fn an_over_cap_lease_on_a_shared_unit_moves_after_the_dwell() -> TestResult {
    let hot = hot_or_skip!();
    let p = seeded_partition(&hot, &[1, 2, 3, 4]).await?;
    let (a, b) = (org("a")?, org("b")?);
    for s in 0..4 {
        static_grant(&hot, &p, &a, &format!("s{s}")).await?;
    }
    // b arrives: its cap is 2 of 4 IPs and a holds all 4, so b takes two of a's
    let mut shared = Vec::new();
    for s in 0..2 {
        let gb = static_grant(&hot, &p, &b, &format!("t{s}")).await?;
        assert_eq!(gb.orgs, 2, "b shares an IP of a");
        shared.push(gb.unit);
    }
    let on_shared: Vec<String> = {
        let mut keys = Vec::new();
        for s in 0..4 {
            let key = format!("s{s}");
            let g = grant(&lease_static(&hot, &p, &a, &key).await?)?.clone();
            if shared.contains(&g.unit) {
                keys.push(key);
            }
        }
        keys
    };
    assert_eq!(on_shared.len(), 2, "two of a's four keys sit on shared IPs");
    let key = &on_shared[0];
    let before = grant(&lease_static(&hot, &p, &a, key).await?)?.unit.clone();

    // too young: the lease stays
    let young = lease_static(&hot, &p, &a, key).await?;
    assert!(matches!(young, LeaseOutcome::Hit(_)), "{young:?}");
    age(&p, &a, key).await?;

    // a traffic renewal never moves it
    let renewed = renew(&hot, &static_call(&p, &a, key)).await?;
    assert_eq!(renewed.map(|g| g.unit), Some(before.clone()));

    // a new tunnel does, to an IP that b does not share
    let moved = lease_static(&hot, &p, &a, key).await?;
    assert!(matches!(moved, LeaseOutcome::Shared(_)), "{moved:?}");
    let to = grant(&moved)?;
    assert_ne!(to.unit, before);
    assert!(!shared.contains(&to.unit), "moved onto an IP of its own");
    // the tunnels already open on the old unit stay there
    assert!(hot.unit_load(&p, &before).await?.tunnels >= 2);
    Ok(())
}

/// An org within its cap keeps a lease on a shared unit.
#[tokio::test]
async fn a_lease_on_a_shared_unit_stays_while_the_org_is_within_its_cap() -> TestResult {
    let hot = hot_or_skip!();
    let p = seeded_partition(&hot, &[1, 2, 3, 4]).await?;
    let (a, b, c) = (org("a")?, org("b")?, org("c")?);
    let mut units = HashMap::new();
    for (o, keys) in [(&a, ["s0", "s1"]), (&b, ["s0", "s1"])] {
        for key in keys {
            units.insert(
                (o.as_str(), key),
                static_grant(&hot, &p, o, key).await?.unit,
            );
        }
    }
    // c finds no free IP and shares one; nobody is over the cap (ceil(4 / 3))
    // of 2 IPs... a and b hold 2 each, the cap is 2
    let gc = static_grant(&hot, &p, &c, "s0").await?;
    assert_eq!(gc.orgs, 2);
    let (owner, key) = [(&a, "s0"), (&a, "s1"), (&b, "s0"), (&b, "s1")]
        .into_iter()
        .find(|(o, k)| units[&(o.as_str(), *k)] == gc.unit)
        .ok_or("c shares an IP of a or b")?;
    age(&p, owner, key).await?;
    let again = lease_static(&hot, &p, owner, key).await?;
    assert!(matches!(again, LeaseOutcome::Hit(_)), "{again:?}");
    Ok(())
}

/// A lease on a degraded unit moves to a normal unit that takes
/// it, after the dwell, and stays when none does.
#[tokio::test]
async fn a_lease_on_a_degraded_unit_moves_to_a_normal_one_after_the_dwell() -> TestResult {
    let hot = hot_or_skip!();
    let p = seeded_partition(&hot, &[1, 2]).await?;
    let a = org("a")?;
    let first = static_grant(&hot, &p, &a, "s").await?;
    hot.set_tier(&p, &first.unit, Tier::Degraded).await?;

    let young = lease_static(&hot, &p, &a, "s").await?;
    assert!(
        matches!(young, LeaseOutcome::Hit(_)),
        "too young: {young:?}"
    );
    age(&p, &a, "s").await?;

    // no better unit while the other one is degraded too
    let other = if first.unit == unit(1) {
        unit(2)
    } else {
        unit(1)
    };
    hot.set_tier(&p, &other, Tier::Degraded).await?;
    let stay = lease_static(&hot, &p, &a, "s").await?;
    assert!(matches!(stay, LeaseOutcome::Hit(_)), "{stay:?}");

    hot.set_tier(&p, &other, Tier::Normal).await?;
    let moved = lease_static(&hot, &p, &a, "s").await?;
    assert!(matches!(moved, LeaseOutcome::Free(_)), "{moved:?}");
    assert_eq!(grant(&moved)?.unit, other);
    Ok(())
}

/// Normal units go first, then degraded ones within the limits,
/// then the limits break (normal before degraded).
#[tokio::test]
async fn a_degraded_unit_is_leased_after_the_normal_ones_and_before_any_limit_breaks() -> TestResult
{
    let hot = hot_or_skip!();
    let p = seeded_partition(&hot, &[1, 2]).await?;
    hot.set_tier(&p, &unit(2), Tier::Degraded).await?;
    let mut l = limits();
    l.rest_after_release = Duration::from_secs(60);
    l.orgs_hard = nz(1);
    let call = |o, sticky| Call {
        limits: l.clone(),
        ..static_call(&p, o, sticky)
    };
    let (a, b, c) = (org("a")?, org("b")?, org("c")?);
    let ga = granted(&hot, &call(&a, "s")).await?;
    assert_eq!(
        (ga.unit.as_str(), ga.broke),
        ("198.51.100.1", None),
        "normal first"
    );
    let gb = granted(&hot, &call(&b, "s")).await?;
    assert_eq!(
        (gb.unit.as_str(), gb.broke),
        ("198.51.100.2", None),
        "then degraded"
    );
    // both held by another org (orgs_hard 1): the limit breaks over the
    // normal unit first
    let gc = granted(&hot, &call(&c, "s")).await?;
    assert_eq!(
        (gc.unit.as_str(), gc.broke),
        ("198.51.100.1", Some("orgs_hard"))
    );
    Ok(())
}

/// A lease of `c` that takes no unit of a rank above `max_rank`.
async fn lease_at(hot: &Hot, c: &Call<'_>, max_rank: u8) -> TestResult2 {
    let t = target(c.host);
    let req = LeaseRequest {
        partition: c.p,
        kind: c.kind,
        org: c.org,
        sticky: c.sticky,
        target: &t,
        tunnel: Uuid::new_v4(),
        pool: Pool::Shared,
        limits: c.limits.clone(),
    };
    Ok(hot.lease_ranked(&req, &[], max_rank).await?)
}

/// A call that may not go below normal units within the limits
/// leaves a degraded unit alone and names its rank; nothing is leased.
#[tokio::test]
async fn a_ranked_lease_leaves_a_degraded_unit_for_a_later_call() -> TestResult {
    let hot = hot_or_skip!();
    let p = seeded_partition(&hot, &[1]).await?;
    hot.set_tier(&p, &unit(1), Tier::Degraded).await?;
    let a = org("a")?;
    let call = static_call(&p, &a, "s");

    assert_eq!(lease_at(&hot, &call, 0).await?, LeaseOutcome::Lower(1));
    let load = hot.unit_load(&p, &unit(1)).await?;
    assert_eq!((load.leases, load.tunnels), (0, 0), "nothing was leased");

    let got = lease_at(&hot, &call, 1).await?;
    assert!(matches!(got, LeaseOutcome::Free(_)), "{got:?}");
    Ok(())
}

/// A unit that only a soft limit keeps back is a rank above the
/// degraded ones within the limits, and the lowest limit is the lowest rank.
#[tokio::test]
async fn a_ranked_lease_names_the_best_rank_that_is_left() -> TestResult {
    let hot = hot_or_skip!();
    let p = seeded_partition(&hot, &[1, 2]).await?;
    let mut l = limits();
    l.max_conns_per_ip = nz(1);
    let call = |o, sticky| Call {
        limits: l.clone(),
        ..static_call(&p, o, sticky)
    };
    let (a, b) = (org("a")?, org("b")?);
    // unit 1: normal and stopped by the fair-use limit (rank 5); unit 2:
    // degraded and full (rank 8)
    hot.set_tier(&p, &unit(2), Tier::Degraded).await?;
    let held = lease_without(&hot, &call(&b, "s"), &[&unit(1)]).await?;
    assert_eq!(grant(&held)?.unit, unit(2));
    hot.fair_use_add(&p, ip(1), 2_000, 1_000, OffsetDateTime::now_utc())
        .await?;

    assert_eq!(
        lease_at(&hot, &call(&a, "s"), 4).await?,
        LeaseOutcome::Lower(5)
    );
    let got = lease_at(&hot, &call(&a, "s"), 5).await?;
    assert_eq!(
        (grant(&got)?.unit.clone(), grant(&got)?.broke),
        (unit(1), Some("fair_use"))
    );
    Ok(())
}

/// A lease younger than the dwell stays on a degraded unit
/// whatever the rank; an older one is left for a normal unit, and a call that
/// may take a degraded unit still renews it.
#[tokio::test]
async fn a_ranked_call_renews_a_young_lease_but_not_an_old_one_on_a_degraded_unit() -> TestResult {
    let hot = hot_or_skip!();
    let p = seeded_partition(&hot, &[1]).await?;
    let a = org("a")?;
    let call = static_call(&p, &a, "s");
    let first = static_grant(&hot, &p, &a, "s").await?;
    hot.set_tier(&p, &first.unit, Tier::Degraded).await?;

    let young = lease_at(&hot, &call, 0).await?;
    assert!(matches!(young, LeaseOutcome::Hit(_)), "{young:?}");
    age(&p, &a, "s").await?;
    assert_eq!(lease_at(&hot, &call, 0).await?, LeaseOutcome::Lower(1));
    let old = lease_at(&hot, &call, 1).await?;
    assert!(matches!(old, LeaseOutcome::Hit(_)), "{old:?}");
    Ok(())
}

/// A lease is young until the dwell has passed since it came to
/// its unit, and only in the partition that holds it.
#[tokio::test]
async fn a_lease_is_young_until_the_dwell_has_passed() -> TestResult {
    let hot = hot_or_skip!();
    let (p, q) = (
        seeded_partition(&hot, &[1]).await?,
        seeded_partition(&hot, &[1]).await?,
    );
    let a = org("a")?;
    assert!(!hot.lease_is_young(&p, &a, "s").await?, "no lease yet");
    static_grant(&hot, &p, &a, "s").await?;
    assert!(hot.lease_is_young(&p, &a, "s").await?);
    assert!(!hot.lease_is_young(&q, &a, "s").await?, "another partition");
    age(&p, &a, "s").await?;
    assert!(!hot.lease_is_young(&p, &a, "s").await?);
    Ok(())
}

/// A lease a call bound to a unit is `fresh`; when its tunnel is
/// not served there, ending it takes the dwell key with it, so the key is not
/// young on a unit it never used. A lease that was there already is not fresh.
#[tokio::test]
async fn a_lease_that_served_no_tunnel_leaves_no_dwell_key() -> TestResult {
    let hot = hot_or_skip!();
    let p = seeded_partition(&hot, &[1, 2]).await?;
    let a = org("a")?;
    let first = static_grant(&hot, &p, &a, "s").await?;
    assert!(first.fresh);
    assert!(hot.lease_is_young(&p, &a, "s").await?);

    let again = granted(&hot, &static_call(&p, &a, "s")).await?;
    assert_eq!(again.unit, first.unit);
    assert!(!again.fresh, "the lease was there already");

    hot.lease_unserved(&first, "s").await?;
    assert!(!hot.lease_is_young(&p, &a, "s").await?);
    let load = hot.unit_load(&p, &first.unit).await?;
    assert_eq!(load.leases, 0, "the lease went with it");

    // a grant of another unit than the lease's own changes nothing
    let second = static_grant(&hot, &p, &a, "s").await?;
    let mut stale = first.clone();
    stale.unit = if second.unit == unit(1) {
        unit(2)
    } else {
        unit(1)
    };
    hot.lease_unserved(&stale, "s").await?;
    assert!(hot.lease_is_young(&p, &a, "s").await?);
    Ok(())
}

/// R1 (attractor): a unit that failed a tunnel at IP level is leased
/// after every other unit, for new sticky keys too, though it holds the
/// fewest leases; it stays the last resort and never leaves the ready set.
#[tokio::test]
async fn a_failed_unit_is_leased_after_the_others_and_stays_the_last_resort() -> TestResult {
    let hot = hot_or_skip!();
    let p = seeded_partition(&hot, &[1, 2, 3]).await?;
    let a = org("a")?;
    hot.unit_failed(&p, &unit(1), UNIT_PENALTY_BASE, UNIT_PENALTY_MAX)
        .await?;

    // free, and the first by every other measure, but failed: the other two
    // units take every key, shared once they are held
    for n in 0..6 {
        let key = format!("k{n}");
        let g = static_grant(&hot, &p, &a, &key).await?;
        assert_ne!(g.unit, unit(1), "key {key}");
    }
    assert_eq!(hot.unit_load(&p, &unit(1)).await?.leases, 0);

    // with nothing else left it takes the lease, and only a call that may
    // go that low gets it
    hot.ready_take(&p, &unit(2)).await?;
    hot.ready_take(&p, &unit(3)).await?;
    let call = static_call(&p, &a, "last");
    assert_eq!(lease_at(&hot, &call, 9).await?, LeaseOutcome::Lower(10));
    let last = lease_at(&hot, &call, MAX_RANK).await?;
    assert!(matches!(last, LeaseOutcome::Free(_)), "{last:?}");
    assert_eq!(grant(&last)?.unit, unit(1));
    assert!(grant(&last)?.struck, "the grant says it holds failures");
    Ok(())
}

/// The penalty doubles on every failure and ends by itself; the failures are
/// forgotten after a while without one, and when the unit serves a tunnel.
#[tokio::test]
async fn the_penalty_of_a_failed_unit_doubles_ends_by_itself_and_is_forgiven() -> TestResult {
    let hot = hot_or_skip!();
    let p = seeded_partition(&hot, &[1, 2]).await?;
    let a = org("a")?;
    let first = unit(1);
    let fail = || hot.unit_failed(&p, &first, UNIT_PENALTY_BASE, UNIT_PENALTY_MAX);
    let mut raw = raw_redis().await?;
    let key = format!("unit:{{{}}}:{}", p.tag(), unit(1));
    let now_ms = || OffsetDateTime::now_utc().unix_timestamp() * 1000;

    assert_eq!(fail().await?, UNIT_PENALTY_BASE);
    assert_eq!(fail().await?, UNIT_PENALTY_BASE * 2);
    assert_eq!(fail().await?, UNIT_PENALTY_BASE * 4);

    // failed: unit 2 takes both keys; the free unit 1 waits
    let x = static_grant(&hot, &p, &a, "x").await?;
    let y = static_grant(&hot, &p, &a, "y").await?;
    assert_eq!((x.unit, y.unit), (unit(2), unit(2)));

    // its penalty ended: it is the free unit the next key takes
    let _: i64 = redis::AsyncCommands::hset(&mut raw, &key, "penalty_until", now_ms() - 1).await?;
    let z = static_grant(&hot, &p, &a, "z").await?;
    assert_eq!(z.unit, unit(1), "the penalty ended by itself");
    assert!(z.struck, "its failures are remembered for a while");
    // ... and a failure soon after continues the doubling
    assert_eq!(fail().await?, UNIT_PENALTY_BASE * 8);

    // a long time after the last one, it starts over
    let long_ago = now_ms() - i64::try_from(UNIT_PENALTY_MAX.as_millis())? - 1_000;
    let _: i64 = redis::AsyncCommands::hset(&mut raw, &key, "penalty_until", long_ago).await?;
    assert_eq!(fail().await?, UNIT_PENALTY_BASE);

    // serving a tunnel forgives it
    hot.unit_served(&p, &unit(1)).await?;
    let strikes: Option<String> = redis::AsyncCommands::hget(&mut raw, &key, "strikes").await?;
    assert_eq!(strikes, None);
    assert_eq!(fail().await?, UNIT_PENALTY_BASE);

    // the penalty never passes its cap
    for _ in 0..10 {
        fail().await?;
    }
    assert_eq!(fail().await?, UNIT_PENALTY_MAX);

    // a unit that has no record is not made by a failure
    assert_eq!(
        hot.unit_failed(&p, "203.0.113.9", UNIT_PENALTY_BASE, UNIT_PENALTY_MAX)
            .await?,
        Duration::ZERO
    );
    Ok(())
}

/// A lease on a unit that failed moves to a unit that did not once it is older
/// than the dwell; a young one stays where it is.
#[tokio::test]
async fn a_lease_on_a_failed_unit_moves_to_another_after_the_dwell() -> TestResult {
    let hot = hot_or_skip!();
    let p = seeded_partition(&hot, &[1, 2]).await?;
    let a = org("a")?;
    let first = static_grant(&hot, &p, &a, "s").await?;
    hot.unit_failed(&p, &first.unit, UNIT_PENALTY_BASE, UNIT_PENALTY_MAX)
        .await?;

    let young = lease_static(&hot, &p, &a, "s").await?;
    assert!(matches!(young, LeaseOutcome::Hit(_)), "{young:?}");
    assert_eq!(grant(&young)?.unit, first.unit);
    age(&p, &a, "s").await?;

    // a call that may not take a failed unit leaves it for a better one
    let moved = lease_static(&hot, &p, &a, "s").await?;
    assert!(matches!(moved, LeaseOutcome::Free(_)), "{moved:?}");
    assert_ne!(grant(&moved)?.unit, first.unit);
    Ok(())
}

/// The org's tunnels on a provider are counted against the cap of
/// its route class, atomically, until the tunnel ends.
#[tokio::test]
async fn the_orgs_tunnels_on_a_provider_are_counted_against_a_cap() -> TestResult {
    let hot = hot_or_skip!();
    let p = seeded_partition(&hot, &[1, 2, 3]).await?;
    let a = org("a")?;
    let ttl = Duration::from_secs(60);
    let (t1, t2, t3) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let open = |t| hot.provider_tunnel_open(&a, &p.provider, t, nz(2).expect("cap"), ttl);
    assert!(open(t1).await?);
    assert!(open(t2).await?);
    assert!(!open(t3).await?, "at the cap");
    assert!(open(t1).await?, "a counted tunnel only refreshes");

    hot.provider_tunnel_close(&a, &p.provider, t1).await?;
    assert!(open(t3).await?);

    // another provider has its own count
    let other = partition()?;
    assert!(
        hot.provider_tunnel_open(&a, &other.provider, t1, nz(2).expect("cap"), ttl)
            .await?
    );

    // a served tunnel keeps its count until it closes, and a touch in flight
    // does not bring a closed one back
    let mut served = static_grant(&hot, &p, &a, "s").await?.tunnel;
    served.provider_counted = true;
    assert!(!open(served.id).await?, "t2 and t3 hold the cap");
    hot.provider_tunnel_close(&a, &p.provider, t2).await?;
    assert!(open(served.id).await?);
    hot.tunnel_close(&served).await?;
    assert!(!hot.tunnel_touch(&served, ttl).await?);
    assert!(
        open(Uuid::new_v4()).await?,
        "the closed tunnel freed its place"
    );
    Ok(())
}
