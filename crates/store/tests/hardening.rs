//! Regressions of the review fixes in the store (real Redis and
//! Postgres).

#[macro_use]
mod support;

use std::time::Duration;

use common::types::{IpState, Partition, Subtype, Tier};
use proxyx_store::{BlockScope, Db, Transition, UnitRecord, rebuild_hot};
use support::{TestResult, db, entry_at, org, partition, raw_redis, uniq, uniq_ip, uniq_org};
use time::OffsetDateTime;

fn available() -> Transition {
    Transition::to(IpState::Available, "checks passed")
}

fn cooldown() -> Transition {
    Transition::to(IpState::Cooldown, "block")
        .cooldown_until(OffsetDateTime::now_utc() + time::Duration::minutes(15))
}

async fn row_in(db: &Db, provider: &str, ip: std::net::IpAddr) -> TestResult {
    db.replace_inventory(&provider.parse()?, &[entry_at(provider, ip)?], "gitops")
        .await?;
    Ok(())
}

/// A caller that worked from a snapshot moves the IP only from the
/// state it saw.
#[tokio::test]
async fn a_transition_that_expects_a_state_is_refused_when_the_ip_moved_since() -> TestResult {
    let Some((db, _raw)) = db("hardening_fix").await? else {
        return Ok(());
    };
    let (provider, ip) = (uniq("prov"), uniq_ip());
    row_in(&db, &provider, ip).await?;
    db.transition_ip(ip, &available(), "w").await?;
    // a block signal cools it while a recheck that read `Available` runs
    db.transition_ip(ip, &cooldown(), "signal").await?;

    let stale = Transition::to(IpState::Degraded, "slow").expecting(IpState::Available);
    let refused = db.transition_ip(ip, &stale, "w").await;
    assert!(
        matches!(
            refused,
            Err(proxyx_store::StoreError::InvalidTransition {
                from: IpState::Cooldown,
                ..
            })
        ),
        "{refused:?}"
    );
    assert_eq!(
        db.inventory_row(ip).await?.ok_or("row")?.state,
        IpState::Cooldown,
        "the cooldown stays"
    );

    // the same move from the state it was read in goes through
    let fresh = Transition::to(IpState::Degraded, "slow").expecting(IpState::Cooldown);
    assert_eq!(
        db.transition_ip(ip, &fresh, "w").await?.state,
        IpState::Degraded
    );
    Ok(())
}

/// After a rebuild the unit of a box carries the exit IP its last
/// check saw, not the address of its row.
#[tokio::test]
async fn rebuild_puts_the_exit_ip_of_the_last_check_into_every_unit() -> TestResult {
    let hot = hot_or_skip!();
    let Some((db, _raw)) = db("hardening_fix").await? else {
        return Ok(());
    };
    let provider = uniq("box");
    let p = Partition {
        provider: provider.parse()?,
        region: "fr".parse()?,
    };
    let (entry_ip, exit_ip) = (uniq_ip(), uniq_ip());
    let mut entry = entry_at(&provider, entry_ip)?;
    entry.subtype = Subtype::MobileBox;
    entry.box_handle = Some("m1".into());
    db.replace_inventory(&p.provider, &[entry], "gitops")
        .await?;
    db.transition_ip(entry_ip, &available(), "w").await?;
    db.record_check(entry_ip, Some(exit_ip), OffsetDateTime::now_utc())
        .await?;

    rebuild_hot(&db, &hot).await?;
    let mut raw = raw_redis().await?;
    let unit_ip: String = redis::cmd("HGET")
        .arg(format!("unit:{{{}}}:{entry_ip}", p.tag()))
        .arg("ip")
        .query_async(&mut raw)
        .await?;
    assert_eq!(unit_ip, exit_ip.to_string());
    assert!(hot.is_ready(&p, &entry_ip.to_string()).await?);
    Ok(())
}

/// The sync names the partition an IP was listed in when its provider
/// or region changed.
#[tokio::test]
async fn a_sync_names_the_old_partition_of_an_ip_that_changed_region_or_provider() -> TestResult {
    let Some((db, _raw)) = db("hardening_fix").await? else {
        return Ok(());
    };
    let (first, second) = (uniq("prov"), uniq("prov"));
    let (moved_region, moved_provider, still) = (uniq_ip(), uniq_ip(), uniq_ip());
    let entries = [moved_region, moved_provider, still]
        .map(|ip| entry_at(&first, ip))
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    let sync = db
        .replace_inventory(&first.parse()?, &entries, "gitops")
        .await?;
    assert!(sync.moved.is_empty(), "{sync:?}");

    let mut changed = entries.clone();
    changed[0].region = "de".parse()?;
    let sync = db
        .replace_inventory(&first.parse()?, &changed, "gitops")
        .await?;
    let old = Partition {
        provider: first.parse()?,
        region: "fr".parse()?,
    };
    assert_eq!(sync.moved, [(moved_region, old.clone())]);

    // another provider lists the IP now
    let sync = db
        .replace_inventory(
            &second.parse()?,
            &[entry_at(&second, moved_provider)?],
            "gitops",
        )
        .await?;
    assert_eq!(sync.moved, [(moved_provider, old)]);
    Ok(())
}

/// A retired unit that still has tunnels keeps its record until they
/// end; one without is forgotten whether or not it was in the ready set.
#[tokio::test]
async fn a_retired_unit_is_forgotten_once_its_tunnels_end() -> TestResult {
    let hot = hot_or_skip!();
    let p = partition()?;
    let (busy, idle) = (uniq_ip(), uniq_ip());
    for ip in [busy, idle] {
        hot.ready_put(&p, &UnitRecord::static_ip(ip)).await?;
    }
    // a tunnel on `busy`, and the API took both out of the ready set already
    let a = org("a")?;
    let grant = support::granted(&hot, &support::static_call(&p, &a, "conn:t")).await?;
    let (busy_id, idle_id) = if grant.unit == busy.to_string() {
        (busy.to_string(), idle.to_string())
    } else {
        (idle.to_string(), busy.to_string())
    };
    hot.ready_take(&p, &busy_id).await?;
    hot.ready_take(&p, &idle_id).await?;

    let kept = hot.unit_retire(&p, &busy_id).await?;
    assert!(
        !kept.was_ready && !kept.forgotten,
        "a tunnel is open: {kept:?}"
    );
    let gone = hot.unit_retire(&p, &idle_id).await?;
    assert!(gone.forgotten, "{gone:?}");

    hot.tunnel_close(&grant.tunnel).await?;
    hot.release(&p, &a, "conn:t", None).await?;
    assert!(hot.unit_retire(&p, &busy_id).await?.forgotten);
    let mut raw = raw_redis().await?;
    let exists: i64 = redis::cmd("EXISTS")
        .arg(format!("unit:{{{}}}:{busy_id}", p.tag()))
        .query_async(&mut raw)
        .await?;
    assert_eq!(exists, 0, "the unit hash is gone");
    Ok(())
}

/// Refreshing a session that left the ready set must not bring it back.
#[tokio::test]
async fn ready_update_refreshes_a_ready_unit_and_leaves_a_drained_one_out() -> TestResult {
    let hot = hot_or_skip!();
    let p = partition()?;
    let (old, new) = (uniq_ip(), uniq_ip());
    let id = uniq("sess");
    let unit = |ip| UnitRecord {
        id: id.clone(),
        ip,
        expires_at: None,
        ttl: Some(Duration::from_secs(300)),
        owner: None,
    };
    hot.ready_put(&p, &unit(old)).await?;

    assert!(hot.ready_update(&p, &unit(new), Tier::Normal).await?);
    assert!(hot.is_ready(&p, &id).await?);

    // drained while the new exit IP was checked
    hot.ready_take(&p, &id).await?;
    assert!(!hot.ready_update(&p, &unit(old), Tier::Normal).await?);
    assert!(
        !hot.is_ready(&p, &id).await?,
        "it stays out of the ready set"
    );
    Ok(())
}

/// A reservation that expired starts no create, so it must not leave
/// an in-flight entry that holds a slot until its deadline.
#[tokio::test]
async fn create_start_on_an_expired_reservation_leaves_no_phantom_create() -> TestResult {
    let hot = hot_or_skip!();
    let p = partition()?;
    let reservation = hot.reserve_create(&p, 5).await?.ok_or("reservation")?;
    // the reservation is gone (expired or given back)
    assert!(hot.create_abort(&p, &reservation.id.to_string()).await?);

    let started = hot
        .create_start(&p, &reservation, "late-session", Duration::from_secs(60))
        .await?;
    assert!(!started);
    let counts = hot.counts(&p).await?;
    assert_eq!((counts.creating, counts.reserved), (0, 0), "{counts:?}");
    Ok(())
}

/// An event marked applied is seen again, others are not.
#[tokio::test]
async fn an_applied_event_is_remembered_for_a_retry() -> TestResult {
    let hot = hot_or_skip!();
    let key = format!("signal:{}", uniq("evt"));
    assert!(!hot.event_seen(&key).await?);
    hot.event_done(&key, Duration::from_secs(60)).await?;
    assert!(hot.event_seen(&key).await?);
    assert!(!hot.event_seen(&format!("{key}-other")).await?);
    Ok(())
}

/// The cache field of an org block is written from what Postgres holds
/// when the lock is taken, so a block revoked after a rebuild read it does not
/// come back.
#[tokio::test]
async fn resync_org_block_drops_a_field_whose_block_was_revoked_meanwhile() -> TestResult {
    let hot = hot_or_skip!();
    let Some((db, raw)) = db("hardening_fix").await? else {
        return Ok(());
    };
    let org = uniq_org("blk")?;
    let scope = BlockScope::Provider(uniq("prov").parse()?);
    let block = db
        .create_org_block(&hot, &org, &scope, "abuse", "ops", None)
        .await?;
    assert_eq!(hot.org_blocks(&org).await?.len(), 1);

    // revoked by another pod: Postgres knows, this Redis write is stale
    raw.execute(
        "UPDATE org_blocks SET revoked_at = ? WHERE id = ?",
        &[OffsetDateTime::now_utc().into(), block.id.into()],
    )
    .await?;
    assert_eq!(hot.org_blocks(&org).await?.len(), 1, "the cache is stale");

    db.resync_org_block(&hot, &org, &scope).await?;
    assert!(hot.org_blocks(&org).await?.is_empty());
    Ok(())
}

/// Scores, blocks and the machine-written audit rows past their age
/// go; what is younger, what a person did and the git inventory trail stay.
#[tokio::test]
async fn prune_history_deletes_old_rows_and_keeps_the_rest() -> TestResult {
    let Some((db, raw)) = db("hardening_fix_prune").await? else {
        return Ok(());
    };
    let ip = uniq_ip().to_string();
    let old = OffsetDateTime::now_utc() - time::Duration::days(400);
    let recent = OffsetDateTime::now_utc() - time::Duration::days(1);
    for at in [old, recent] {
        raw.execute(
            "INSERT INTO ip_scores (ip, source, risk, checked_at) VALUES (?, 'fraud_score', 10, ?)",
            &[ip.as_str().into(), at.into()],
        )
        .await?;
        raw.execute(
            "INSERT INTO ip_blocks (ip, target, source, signal_type, created_at, expires_at)
             VALUES (?, NULL, 'probe', 'forbidden', ?, NULL)",
            &[ip.as_str().into(), at.into()],
        )
        .await?;
    }
    // an old block of a target that is still cooled stays
    raw.execute(
        "INSERT INTO ip_blocks (ip, target, source, signal_type, created_at, expires_at)
         VALUES (?, 'a.example', 'probe', 'forbidden', ?, ?)",
        &[
            ip.as_str().into(),
            old.into(),
            (OffsetDateTime::now_utc() + time::Duration::hours(1)).into(),
        ],
    )
    .await?;
    for (actor, action, at) in [
        ("warmer", "inventory.transition", old),
        ("warmer", "inventory.transition", recent),
        ("ops", "inventory.retire", old),
        ("gitops", "inventory.add", old),
    ] {
        raw.execute(
            "INSERT INTO audit (at, actor, action, subject) VALUES (?, ?, ?, ?)",
            &[at.into(), actor.into(), action.into(), ip.as_str().into()],
        )
        .await?;
    }

    let pruned = db.prune_history().await?;
    assert!(
        pruned.scores >= 1 && pruned.blocks >= 1 && pruned.audit >= 1,
        "{pruned:?}"
    );
    let count = |table: &'static str| {
        let raw = raw.clone();
        let ip = ip.clone();
        async move {
            let column = if table == "audit" { "subject" } else { "ip" };
            raw.int(
                &format!("SELECT count(*) FROM {table} WHERE {column} = ?"),
                &[ip.into()],
            )
            .await
        }
    };
    assert_eq!(count("ip_scores").await?, 1, "the recent score");
    assert_eq!(
        count("ip_blocks").await?,
        2,
        "the recent block and the cooled target"
    );
    assert_eq!(
        count("audit").await?,
        3,
        "the recent transition, the old operator row and the git inventory trail"
    );
    assert_eq!(
        db.prune_history().await?,
        proxyx_store::Pruned::default(),
        "nothing twice"
    );
    Ok(())
}
