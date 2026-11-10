//! Redis loss and rebuild from Postgres. This file flushes the
//! Redis test database, so it holds a single test and cargo runs it alone.

#[macro_use]
mod support;

use common::types::{IpState, Partition, SignalSource, SignalType, Tier};
use proxyx_store::{BlockScope, LeaseOutcome, Transition, UnitRecord, rebuild_hot};
use std::time::Duration;
use support::{
    Call, TestResult, assert_ttl, entry_at, fresh_db, lease, lease_static, raw_redis, static_call,
    target, uniq, uniq_ip, uniq_org,
};
use time::OffsetDateTime;

#[tokio::test]
async fn rebuild_restores_leasable_units_cooldowns_and_org_blocks_after_flushdb() -> TestResult {
    let hot = hot_or_skip!();
    let Some((db, _raw)) = fresh_db("rebuild").await? else {
        return Ok(());
    };
    let mut raw = raw_redis().await?;

    let provider = uniq("prov");
    let p = Partition {
        provider: provider.parse()?,
        region: "fr".parse()?,
    };
    let ips: Vec<_> = (0..5).map(|_| uniq_ip()).collect();
    let entries = ips
        .iter()
        .map(|ip| entry_at(&provider, *ip))
        .collect::<Result<Vec<_>, _>>()?;
    let now = OffsetDateTime::now_utc();
    db.replace_inventory(&p.provider, &entries, "gitops")
        .await?;
    let go = |state: IpState| Transition::to(state, "test");
    for ip in &ips {
        db.transition_ip(*ip, &go(IpState::Available), "w").await?;
    }
    // ips[0] stays available; the others are banned or not yet verified.
    let cooldown = Transition::to(IpState::Cooldown, "block")
        .cooldown_until(now + time::Duration::minutes(15));
    for ip in [ips[1], ips[2]] {
        db.transition_ip(ip, &cooldown, "w").await?;
    }
    db.transition_ip(
        ips[2],
        &Transition::to(IpState::Quarantined, "blocks").retest_at(now + time::Duration::hours(6)),
        "w",
    )
    .await?;
    db.transition_ip(ips[3], &go(IpState::Candidate), "w")
        .await?;
    db.transition_ip(ips[4], &go(IpState::Retired), "w").await?;

    // A slow IP of another provider: leasable, in the degraded tier.
    let slow_provider = uniq("slow");
    let slow_p = Partition {
        provider: slow_provider.parse()?,
        region: "fr".parse()?,
    };
    let slow_ip = uniq_ip();
    db.replace_inventory(
        &slow_p.provider,
        &[entry_at(&slow_provider, slow_ip)?],
        "gitops",
    )
    .await?;
    db.transition_ip(slow_ip, &go(IpState::Available), "w")
        .await?;
    db.transition_ip(slow_ip, &go(IpState::Degraded), "w")
        .await?;

    let (blocked_org, free_org) = (uniq_org("blk")?, uniq_org("free")?);
    db.create_org_block(
        &hot,
        &blocked_org,
        &BlockScope::Provider(p.provider.clone()),
        "abuse",
        "ops",
        None,
    )
    .await?;
    let lifted = db
        .create_org_block(
            &hot,
            &free_org,
            &BlockScope::Provider(p.provider.clone()),
            "abuse",
            "ops",
            None,
        )
        .await?;
    db.revoke_org_block(&hot, lifted.id, "ops").await?;
    for (host, until) in [
        ("g.example", now + time::Duration::minutes(30)),
        ("old.example", now - time::Duration::minutes(1)),
    ] {
        db.record_block(
            ips[0],
            Some(host),
            SignalSource::Probe,
            SignalType::Challenge,
            Some(until),
        )
        .await?;
    }

    // Redis loses everything.
    redis::cmd("FLUSHDB").query_async::<()>(&mut raw).await?;
    assert!(!hot.is_seeded().await?, "a flushed Redis is detected");
    assert!(hot.ready_ids(&p).await?.is_empty());
    assert_eq!(
        lease_static(&hot, &p, &free_org, "s").await?,
        LeaseOutcome::Empty
    );

    let report = rebuild_hot(&db, &hot).await?;
    assert_eq!(
        (
            report.units,
            report.withdrawn,
            report.target_cooldowns,
            report.org_blocks
        ),
        (2, 0, 1, 1)
    );
    assert!(hot.is_seeded().await?);

    // Only the available IP is leasable; no banned IP comes back.
    assert_eq!(hot.ready_ids(&p).await?, [ips[0].to_string()]);
    // The slow IP is leasable again, in its tier.
    let slow_id = slow_ip.to_string();
    assert_eq!(
        hot.ready_ids(&slow_p).await?,
        std::slice::from_ref(&slow_id)
    );
    assert_eq!(hot.tier(&slow_p, &slow_id).await?, Tier::Degraded);
    assert_eq!(hot.tier(&p, &ips[0].to_string()).await?, Tier::Normal);
    // The target cooldown is back with its remaining time, the expired one is not.
    assert!(hot.is_cooled(&p, ips[0], &target("g.example")).await?);
    assert!(!hot.is_cooled(&p, ips[0], &target("old.example")).await?);
    let cool_key = format!("cool:{{{}}}:{}:g.example", p.tag(), ips[0]);
    assert_ttl(&mut raw, &cool_key, Duration::from_secs(30 * 60)).await?;

    let cooled_call = Call {
        host: "g.example",
        ..static_call(&p, &free_org, "s")
    };
    assert_eq!(
        lease(&hot, &cooled_call).await?,
        LeaseOutcome::Cooled(common::Cause::NoHealthyIp)
    );
    let other_call = Call {
        host: "other.example",
        ..cooled_call
    };
    let g = lease(&hot, &other_call).await?;
    assert!(matches!(&g, LeaseOutcome::Free(g) if g.ip == ips[0]));
    // The org block is back.
    assert_eq!(
        lease_static(&hot, &p, &blocked_org, "s").await?,
        LeaseOutcome::Blocked
    );

    // Rebuilding a live Redis keeps the lease and withdraws a stale unit.
    hot.ready_put(&p, &UnitRecord::static_ip(ips[1])).await?;
    let report = rebuild_hot(&db, &hot).await?;
    assert_eq!(report.withdrawn, 1);
    assert_eq!(hot.ready_ids(&p).await?, [ips[0].to_string()]);
    // A rebuild on a live Redis sets the tier from Postgres, too.
    hot.ready_put(&slow_p, &UnitRecord::static_ip(slow_ip))
        .await?;
    assert_eq!(hot.tier(&slow_p, &slow_id).await?, Tier::Normal);
    rebuild_hot(&db, &hot).await?;
    assert_eq!(hot.tier(&slow_p, &slow_id).await?, Tier::Degraded);
    assert!(matches!(
        lease_static(&hot, &p, &free_org, "s").await?,
        LeaseOutcome::Hit(_)
    ));
    Ok(())
}
