//! Affinity registry, org-wide LRU and rotation against real Valkey/Redis.

#[macro_use]
mod support;

use std::time::Duration;

use common::types::Kind;
use policy::Pool;
use proxyx_store::{AffinityRecord, AffinityStats, LeaseRequest, MAX_RANK, StoreError};
use redis::AsyncCommands as _;
use support::{
    TestResult, grant, ip, partition, raw_redis, seeded_partition, static_grant, target, uniq_org,
};
use uuid::Uuid;

const TTL: Duration = Duration::from_secs(60);

fn record(
    p: &common::types::Partition,
    sticky: &str,
    unit: &str,
    ip: std::net::IpAddr,
) -> AffinityRecord {
    AffinityRecord {
        sticky: sticky.into(),
        partition: p.clone(),
        unit: unit.into(),
        ip,
        created_at_ms: 0,
        last_seen_ms: 0,
        bytes: 0,
    }
}

#[tokio::test]
async fn lru_cap_spans_partitions_and_releases_only_evicted_orgs_lease() -> TestResult {
    let hot = hot_or_skip!();
    let (org, other) = (uniq_org("lru")?, uniq_org("other")?);
    let (a, b) = (
        seeded_partition(&hot, &[1, 2]).await?,
        seeded_partition(&hot, &[3]).await?,
    );
    let ra = record(&a, "sid:a", &ip(1).to_string(), ip(1));
    let rb = record(&b, "sid:b", &ip(3).to_string(), ip(3));
    let rc = record(&a, "sid:c", &ip(2).to_string(), ip(2));
    for rec in [&ra, &rb, &rc] {
        assert!(
            hot.lease_pin(&rec.partition, &org, &rec.sticky, &rec.unit, TTL)
                .await?
        );
    }
    hot.lease_pin(&a, &other, &ra.sticky, &ra.unit, TTL).await?;
    hot.affinity_touch(&other, &ra, TTL, Some(1), false).await?;
    hot.affinity_touch(&org, &ra, TTL, Some(2), false).await?;
    hot.affinity_touch(&org, &rb, TTL, Some(2), false).await?;
    hot.affinity_touch(&org, &ra, TTL, Some(2), true).await?;
    hot.affinity_touch(&org, &rc, TTL, Some(2), false).await?;
    let records = hot.affinity_sessions(&org).await?;
    assert_eq!(
        records
            .iter()
            .map(|r| r.sticky.as_str())
            .collect::<Vec<_>>(),
        ["sid:c", "sid:a"]
    );
    assert_eq!(hot.affinity_sessions(&other).await?.len(), 1);
    assert_eq!(
        hot.affinity_stats(&org).await?,
        AffinityStats {
            entries: 2,
            hits: 1,
            misses: 3,
            evictions: 1,
            rotations: 0,
        }
    );
    let mut raw = raw_redis().await?;
    let lease: Option<String> = raw
        .get(format!("lease:{{{}}}:{org}:sid:b", b.tag()))
        .await?;
    assert!(lease.is_none());
    let lease: Option<String> = raw
        .get(format!("lease:{{{}}}:{other}:sid:a", a.tag()))
        .await?;
    assert_eq!(lease.as_deref(), Some(ra.unit.as_str()));
    Ok(())
}

#[tokio::test]
async fn renewal_preserves_birth_and_bytes_and_expiration_never_resurrects() -> TestResult {
    let hot = hot_or_skip!();
    let org = uniq_org("bytes")?;
    let rec = record(&partition()?, "sid:bytes", "unit", ip(1));
    assert!(!hot.affinity_add_bytes(&org, &rec.sticky, 3, TTL).await?);
    hot.affinity_touch(&org, &rec, TTL, None, false).await?;
    let first = hot.affinity_sessions(&org).await?.remove(0);
    assert!(first.created_at_ms > 0);
    assert!(hot.affinity_add_bytes(&org, &rec.sticky, 123, TTL).await?);
    hot.affinity_touch(&org, &rec, TTL, None, true).await?;
    let next = hot.affinity_sessions(&org).await?.remove(0);
    assert_eq!(next.created_at_ms, first.created_at_ms);
    assert!(next.last_seen_ms >= first.last_seen_ms);
    assert_eq!(next.bytes, 123);
    let mut raw = raw_redis().await?;
    let _: usize = raw
        .zadd(format!("affinity:{{{org}}}:expiry"), &rec.sticky, 0)
        .await?;
    assert!(hot.affinity_sessions(&org).await?.is_empty());
    assert!(!hot.affinity_add_bytes(&org, &rec.sticky, 1, TTL).await?);
    assert_eq!(hot.affinity_stats(&org).await?.entries, 0);
    Ok(())
}

#[tokio::test]
async fn force_rotation_excludes_old_static_unit_until_replacement_succeeds() -> TestResult {
    let hot = hot_or_skip!();
    let org = uniq_org("rotate")?;
    let p = seeded_partition(&hot, &[4, 5]).await?;
    let old = static_grant(&hot, &p, &org, "sid:rotate").await?;
    hot.affinity_touch(
        &org,
        &record(&p, "sid:rotate", &old.unit, old.ip),
        TTL,
        Some(2),
        false,
    )
    .await?;
    assert!(hot.affinity_rotate(&org, "sid:rotate").await?);
    assert!(!hot.affinity_rotate(&org, "sid:rotate").await?);
    assert!(hot.affinity_sessions(&org).await?.is_empty());
    assert!(!hot.affinity_add_bytes(&org, "sid:rotate", 5, TTL).await?);
    assert_eq!(
        hot.unit_load(&p, &old.unit).await?.tunnels,
        1,
        "existing tunnel stays open"
    );
    let skip = hot
        .affinity_rotation_skip(&org, "sid:rotate", &p)
        .await?
        .into_iter()
        .collect::<Vec<_>>();
    assert_eq!(skip.as_slice(), std::slice::from_ref(&old.unit));
    assert_eq!(
        hot.affinity_rotation_skip(&uniq_org("outsider")?, "sid:rotate", &p)
            .await?,
        None
    );
    assert_eq!(
        hot.affinity_rotation_skip(&org, "sid:rotate", &partition()?)
            .await?,
        None
    );
    let target = target("example.com");
    let request = LeaseRequest {
        partition: &p,
        kind: Kind::Static,
        org: &org,
        sticky: "sid:rotate",
        target: &target,
        tunnel: Uuid::new_v4(),
        pool: Pool::Shared,
        limits: support::limits(),
    };
    let outcome = hot.lease_ranked(&request, &skip, MAX_RANK).await?;
    let next = grant(&outcome)?;
    assert_ne!(next.unit, old.unit);
    hot.affinity_touch(
        &org,
        &record(&p, "sid:rotate", &next.unit, next.ip),
        TTL,
        Some(2),
        false,
    )
    .await?;
    assert_eq!(
        hot.affinity_rotation_skip(&org, "sid:rotate", &p).await?,
        None
    );
    assert_eq!(hot.affinity_stats(&org).await?.rotations, 1);
    hot.tunnel_close(&old.tunnel).await?;
    hot.tunnel_close(&next.tunnel).await?;
    Ok(())
}

#[tokio::test]
async fn rotating_force_rotation_preserves_shared_unit_and_other_orgs_lease() -> TestResult {
    let hot = hot_or_skip!();
    let org = uniq_org("rotating")?;
    let other = uniq_org("shared")?;
    let p = partition()?;
    let unit = support::session_unit(
        "session1",
        ip(6),
        Some(time::OffsetDateTime::now_utc() + Duration::from_secs(600)),
        Duration::from_secs(660),
    );
    hot.ready_put(&p, &unit).await?;
    hot.lease_pin(&p, &org, "sid:a", &unit.id, TTL).await?;
    hot.affinity_touch(
        &org,
        &record(&p, "sid:a", &unit.id, unit.ip),
        TTL,
        None,
        false,
    )
    .await?;
    hot.lease_pin(&p, &other, "sid:a", &unit.id, TTL).await?;
    hot.affinity_touch(
        &other,
        &record(&p, "sid:a", &unit.id, unit.ip),
        TTL,
        None,
        false,
    )
    .await?;
    assert!(hot.affinity_rotate(&org, "sid:a").await?);
    assert!(
        hot.is_ready(&p, &unit.id).await?,
        "shared provider unit must not be withdrawn"
    );
    assert_eq!(hot.affinity_sessions(&other).await?.len(), 1);
    assert_eq!(hot.affinity_rotation_skip(&other, "sid:a", &p).await?, None);
    let mut raw = raw_redis().await?;
    let other_lease: Option<String> = raw
        .get(format!("lease:{{{}}}:{other}:sid:a", p.tag()))
        .await?;
    assert_eq!(other_lease.as_deref(), Some(unit.id.as_str()));
    assert_eq!(
        hot.affinity_rotation_skip(&org, "sid:a", &p).await?,
        Some(unit.id)
    );
    Ok(())
}

#[tokio::test]
async fn concurrent_touches_cannot_exceed_org_cap_and_bad_limits_fail() -> TestResult {
    let hot = hot_or_skip!();
    let org = uniq_org("parallel")?;
    let p = partition()?;
    let mut tasks = tokio::task::JoinSet::new();
    for n in 0..24 {
        let (hot, org, p) = (hot.clone(), org.clone(), p.clone());
        tasks.spawn(async move {
            hot.affinity_touch(
                &org,
                &record(&p, &format!("sid:s{n}"), "unit", ip(8)),
                TTL,
                Some(3),
                false,
            )
            .await
        });
    }
    while let Some(result) = tasks.join_next().await {
        result??;
    }
    let stats = hot.affinity_stats(&org).await?;
    assert_eq!((stats.entries, stats.misses, stats.evictions), (3, 24, 21));
    let rec = record(&p, "sid:a", "unit", ip(8));
    assert!(matches!(
        hot.affinity_touch(&org, &rec, TTL, Some(0), false).await,
        Err(StoreError::Invalid(_))
    ));
    assert!(matches!(
        hot.affinity_touch(&org, &rec, Duration::ZERO, None, false)
            .await,
        Err(StoreError::Invalid(_))
    ));
    Ok(())
}

#[tokio::test]
async fn org_rate_limit_is_shared_atomic_isolated_and_has_retry_ttl() -> TestResult {
    let hot = hot_or_skip!();
    let org = uniq_org("rate")?;
    assert_eq!(hot.org_api_rate_limit(&org, 2, TTL).await?, 0);
    assert_eq!(hot.clone().org_api_rate_limit(&org, 2, TTL).await?, 0);
    assert!((1..=60).contains(&hot.org_api_rate_limit(&org, 2, TTL).await?));
    assert_eq!(
        hot.org_api_rate_limit(&uniq_org("other")?, 2, TTL).await?,
        0
    );
    let mut raw = raw_redis().await?;
    let _: usize = raw.del(format!("affinity:{{{org}}}:rate")).await?;
    assert_eq!(hot.org_api_rate_limit(&org, 2, TTL).await?, 0);
    Ok(())
}

#[tokio::test]
async fn cancelling_race_loser_does_not_fence_winners_touch() -> TestResult {
    let hot = hot_or_skip!();
    let org = uniq_org("race")?;
    let p = seeded_partition(&hot, &[10, 11]).await?;
    let tunnel = Uuid::new_v4();
    let first =
        support::lease_as(&hot, &support::static_call(&p, &org, "attempt1"), tunnel).await?;
    let second =
        support::lease_as(&hot, &support::static_call(&p, &org, "attempt2"), tunnel).await?;
    let (first, second) = (grant(&first)?, grant(&second)?);
    assert_ne!(first.unit, second.unit);
    hot.unit_tunnel_cancel(&first.tunnel).await?;
    hot.lease_unserved(first, "attempt1").await?;
    assert!(hot.tunnel_touch(&second.tunnel, TTL).await?);
    hot.tunnel_close(&second.tunnel).await?;
    Ok(())
}

#[tokio::test]
async fn byte_renewal_keeps_short_session_live_without_changing_lru_or_hit_counts() -> TestResult {
    let hot = hot_or_skip!();
    let org = uniq_org("livebytes")?;
    let p = partition()?;
    let a = record(&p, "sid:a", "unit1", ip(12));
    let b = record(&p, "sid:b", "unit2", ip(13));
    let ttl = Duration::from_millis(500);
    hot.affinity_touch(&org, &a, ttl, Some(2), false).await?;
    hot.affinity_touch(&org, &b, TTL, Some(2), false).await?;
    for _ in 0..4 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(hot.affinity_add_bytes(&org, &a.sticky, 7, ttl).await?);
    }
    let records = hot.affinity_sessions(&org).await?;
    assert_eq!(
        records
            .iter()
            .map(|r| r.sticky.as_str())
            .collect::<Vec<_>>(),
        ["sid:b", "sid:a"]
    );
    assert_eq!(records[1].bytes, 28);
    assert_eq!(hot.affinity_stats(&org).await?.hits, 0);
    assert_eq!(hot.affinity_stats(&org).await?.misses, 2);
    let c = record(&p, "sid:c", "unit3", ip(14));
    hot.affinity_touch(&org, &c, TTL, Some(2), false).await?;
    assert!(
        !hot.affinity_add_bytes(&org, &a.sticky, 1, TTL).await?,
        "traffic never revives an evicted key"
    );
    Ok(())
}

#[tokio::test]
async fn byte_counts_remain_exact_above_lua_integer_precision_and_saturate_u64() -> TestResult {
    let hot = hot_or_skip!();
    let org = uniq_org("exactbytes")?;
    let rec = record(&partition()?, "sid:exact", "unit", ip(15));
    hot.affinity_touch(&org, &rec, TTL, None, false).await?;
    hot.affinity_add_bytes(&org, &rec.sticky, 9_007_199_254_740_993, TTL)
        .await?;
    hot.affinity_add_bytes(&org, &rec.sticky, 11, TTL).await?;
    assert_eq!(
        hot.affinity_sessions(&org).await?[0].bytes,
        9_007_199_254_741_004
    );
    hot.affinity_add_bytes(&org, &rec.sticky, u64::MAX, TTL)
        .await?;
    assert_eq!(hot.affinity_sessions(&org).await?[0].bytes, u64::MAX);
    Ok(())
}

#[tokio::test]
async fn zero_remaining_provider_life_drops_entry_and_never_renews_it() -> TestResult {
    let hot = hot_or_skip!();
    let org = uniq_org("expiredunit")?;
    let rec = record(&partition()?, "sid:expired", "unit", ip(16));
    hot.affinity_touch(&org, &rec, TTL, None, false).await?;
    assert!(
        !hot.affinity_add_bytes(&org, &rec.sticky, 123, Duration::ZERO)
            .await?
    );
    assert!(hot.affinity_sessions(&org).await?.is_empty());
    assert!(!hot.affinity_add_bytes(&org, &rec.sticky, 123, TTL).await?);
    assert_eq!(hot.affinity_stats(&org).await?.entries, 0);
    Ok(())
}
