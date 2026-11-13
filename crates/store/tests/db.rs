//! Postgres repository against a real database.

mod support;

use std::net::IpAddr;
use std::time::Duration;

use common::Secret;
use common::types::{IpState, SignalSource, SignalType};
use policy::{PolicyDoc, Pool, Scope};
use proxyx_db::Backend;
use proxyx_store::{
    BlockScope, Db, InventoryRow, KeyStatus, PolicyPut, StoreError, Transition, UpsertOutcome,
    sha256_hex,
};
use support::{TestResult, db, entry_at, org, uniq, uniq_ip, unmigrated_db};
use time::OffsetDateTime;
use uuid::Uuid;

fn close(a: Option<OffsetDateTime>, b: OffsetDateTime) -> bool {
    a.is_some_and(|a| (a - b).abs() < time::Duration::milliseconds(1))
}

async fn row_of(db: &Db, ip: IpAddr) -> Result<InventoryRow, Box<dyn std::error::Error>> {
    Ok(db.inventory_row(ip).await?.ok_or("inventory row")?)
}

/// The actions audited for `subject`, newest first.
async fn audit_actions(db: &Db, subject: &str, limit: i64) -> Result<Vec<String>, StoreError> {
    Ok(db
        .audit_for(subject, limit)
        .await?
        .into_iter()
        .map(|r| r.action)
        .collect())
}

async fn put_one(db: &Db, doc: &PolicyDoc, actor: &str) -> Result<PolicyPut, StoreError> {
    db.put_policies(std::slice::from_ref(doc), actor).await
}

#[tokio::test]
async fn migrations_are_idempotent_and_safe_to_race() -> TestResult {
    let Some((db, raw)) = db("migrate").await? else {
        return Ok(());
    };
    let before = raw
        .int("SELECT count(*) FROM _sqlx_migrations", &[])
        .await?;
    let (a, b, c) = tokio::join!(db.migrate(), db.migrate(), db.migrate());
    a?;
    b?;
    c?;
    let after = raw
        .int("SELECT count(*) FROM _sqlx_migrations", &[])
        .await?;
    assert_eq!(before, after);
    assert!(after >= 1);
    // Every table of the contract exists.
    for table in [
        "org_keys",
        "policies",
        "inventory",
        "ip_scores",
        "ip_blocks",
        "org_blocks",
        "data_sources",
        "gateway_trees",
        "audit",
    ] {
        assert!(raw.pool().table_exists(table).await?, "table {table}");
    }
    Ok(())
}

#[tokio::test]
async fn pending_migrations_lists_the_unapplied_ones_and_changes_nothing() -> TestResult {
    let Some(db) = unmigrated_db("pending").await? else {
        return Ok(());
    };
    let pending = db.pending_migrations().await?;
    assert!(!pending.is_empty());
    assert!(pending[0].ends_with("_init"), "{pending:?}");
    // Asking twice must not have created `_sqlx_migrations` or applied anything.
    assert_eq!(db.pending_migrations().await?, pending);

    db.migrate().await?;
    assert!(db.pending_migrations().await?.is_empty());
    Ok(())
}

#[tokio::test]
async fn org_keys_store_only_a_hash_and_write_audit() -> TestResult {
    let Some((db, raw)) = db("keys").await? else {
        return Ok(());
    };
    let o = org(&uniq("org"))?;
    let key = format!("ak_{}", Uuid::new_v4().simple());
    db.add_org_key(&o, &Secret::new(key.clone()), "prod", "tester")
        .await?;

    assert_eq!(
        db.verify_org_key(&key).await?,
        KeyStatus::Enabled(o.clone())
    );
    assert_eq!(db.verify_org_key("ak_wrong").await?, KeyStatus::Unknown);
    assert!(matches!(
        db.add_org_key(&o, &Secret::new(key.clone()), "dup", "tester")
            .await,
        Err(StoreError::Conflict { .. })
    ));
    assert!(matches!(
        db.add_org_key(&o, &Secret::new(""), "", "tester").await,
        Err(StoreError::Invalid(_))
    ));

    // The key is nowhere in the row, and the hash is the sha256 of it.
    let pattern = format!("%{key}%");
    let leaked = raw
        .int(
            "SELECT count(*) FROM org_keys WHERE org LIKE ? OR label LIKE ?",
            &[pattern.as_str().into(), pattern.as_str().into()],
        )
        .await?;
    assert_eq!(leaked, 0);
    let stored = raw
        .bytes(
            "SELECT key_hash FROM org_keys WHERE org = ?",
            &[o.as_str().into()],
        )
        .await?;
    assert_eq!(stored, proxyx_store::hash_org_key(&key));
    assert_eq!(sha256_hex(key.as_bytes()).len(), 64);

    assert_eq!(db.disable_org_keys(&o, "tester").await?, 1);
    assert_eq!(
        db.verify_org_key(&key).await?,
        KeyStatus::Disabled,
        "a disabled key is known and refused"
    );

    let audit = db.audit_for(o.as_str(), 10).await?;
    let actions: Vec<_> = audit.iter().map(|r| r.action.as_str()).collect();
    assert_eq!(actions, ["org_key.disable", "org_key.add"]);
    assert!(
        audit
            .iter()
            .all(|r| r.actor == "tester" && !r.detail.to_string().contains(&key))
    );
    Ok(())
}

#[tokio::test]
async fn audit_rows_cannot_be_changed_or_removed() -> TestResult {
    let Some((db, raw)) = db("audit").await? else {
        return Ok(());
    };
    let subject = uniq("subject");
    db.audit(
        "tester",
        "test.action",
        &subject,
        serde_json::json!({ "k": 1 }),
    )
    .await?;
    let rows = db.audit_for(&subject, 5).await?;
    assert_eq!(rows.len(), 1);
    assert!(
        raw.execute(
            "UPDATE audit SET actor = 'x' WHERE subject = ?",
            &[subject.as_str().into()]
        )
        .await
        .is_err()
    );
    assert!(
        raw.execute(
            "DELETE FROM audit WHERE subject = ?",
            &[subject.as_str().into()]
        )
        .await
        .is_err()
    );
    // PostgreSQL stops TRUNCATE with a trigger. MariaDB runs no trigger for it
    // (the application user must not hold DROP) and SQLite has no TRUNCATE.
    if raw.backend() == Backend::Postgres {
        assert!(raw.execute("TRUNCATE audit", &[]).await.is_err());
    }
    assert_eq!(db.audit_for(&subject, 5).await?.len(), 1);
    Ok(())
}

#[tokio::test]
async fn policies_get_a_new_version_only_when_they_change() -> TestResult {
    let Some((db, _raw)) = db("policies").await? else {
        return Ok(());
    };
    let name = uniq("fr-web-");
    let mut doc = PolicyDoc {
        name: name.clone(),
        scope: Scope::RouteClass,
        target: Some("isp_static_port".into()),
        lease_ttl: Some(Duration::from_secs(600)),
        orgs_hard: Some(2),
        pool: Some(Pool::Shared),
        ..PolicyDoc::default()
    };
    let first = put_one(&db, &doc, "gitops").await?;
    assert_eq!((first.stored.len(), first.unchanged), (1, 0));
    let same = put_one(&db, &doc, "gitops").await?;
    assert_eq!((same.stored.len(), same.unchanged), (0, 1));

    doc.orgs_hard = Some(3);
    let changed = put_one(&db, &doc, "gitops").await?;
    assert_eq!(changed.stored, [format!("route_class/{name}")]);

    let versions = db.policy_versions("route_class", &name).await?;
    assert_eq!(
        versions
            .iter()
            .map(|v| (v.version, v.current))
            .collect::<Vec<_>>(),
        [(2, true), (1, false)]
    );
    // The stored JSON parses back into the same document, durations included.
    assert_eq!(versions[0].doc()?, doc);
    let current = db.current_policies().await?;
    assert_eq!(current.iter().filter(|p| p.name == name).count(), 1);

    assert!(db.deactivate_policy("route_class", &name, "ops").await?);
    assert!(!db.deactivate_policy("route_class", &name, "ops").await?);
    assert!(db.current_policies().await?.iter().all(|p| p.name != name));
    // After deactivation the next put continues the numbering.
    put_one(&db, &doc, "gitops").await?;
    let versions = db.policy_versions("route_class", &name).await?;
    assert_eq!(versions[0].version, 3);
    let audit = db.audit_for(&format!("route_class/{name}"), 10).await?;
    assert_eq!(audit.len(), 4, "three puts and one deactivation");
    Ok(())
}

#[tokio::test]
async fn policy_history_is_capped_and_stored_documents_carry_only_what_is_set() -> TestResult {
    let Some((db, _raw)) = db("policies_cap").await? else {
        return Ok(());
    };
    let name = uniq("loop-");
    let mut doc = PolicyDoc {
        name: name.clone(),
        scope: Scope::RouteClass,
        target: Some("isp_static_port".into()),
        orgs_hard: Some(1),
        ..PolicyDoc::default()
    };
    for n in 1..=60 {
        doc.orgs_hard = Some(n);
        put_one(&db, &doc, "ops").await?;
    }
    let versions = db.policy_versions("route_class", &name).await?;
    assert_eq!(versions.len(), 50, "the newest 50 versions stay");
    assert_eq!(
        (
            versions[0].version,
            versions[49].version,
            versions[0].current
        ),
        (60, 11, true)
    );
    assert_eq!(versions[0].doc()?, doc, "the capped history still decodes");

    // no null and no empty section: the snapshot of every gateway and warmer
    // holds this document
    let stored = versions[0].doc.as_object().expect("an object");
    let mut keys: Vec<&str> = stored.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["match", "name", "orgs_hard", "scope"]);
    Ok(())
}

#[tokio::test]
async fn replace_inventory_upserts_keeps_state_and_retires_the_missing() -> TestResult {
    let Some((db, _raw)) = db("inventory").await? else {
        return Ok(());
    };
    let provider = uniq("prov");
    let pid = provider.parse()?;
    let (i1, i2, i3) = (uniq_ip(), uniq_ip(), uniq_ip());
    let (e1, e2, e3) = (
        entry_at(&provider, i1)?,
        entry_at(&provider, i2)?,
        entry_at(&provider, i3)?,
    );

    let sync = db
        .replace_inventory(&pid, &[e1.clone(), e2.clone(), e3.clone()], "gitops")
        .await?;
    assert_eq!(sync.added.len(), 3);
    let rows = db.list_inventory(Some(&pid), None).await?;
    assert!(rows.iter().all(|r| r.state == IpState::Candidate));

    // Give the IPs a history that the next sync must keep.
    for ip in [i1, i2] {
        db.transition_ip(
            ip,
            &Transition::to(IpState::Available, "checks passed"),
            "warmer",
        )
        .await?;
    }
    let until = OffsetDateTime::now_utc() + time::Duration::minutes(15);
    db.transition_ip(
        i2,
        &Transition::to(IpState::Cooldown, "blocked").cooldown_until(until),
        "warmer",
    )
    .await?;

    let mut e1b = e1.clone();
    e1b.port = 9001;
    let sync = db
        .replace_inventory(&pid, &[e1b.clone(), e2.clone()], "gitops")
        .await?;
    assert_eq!(sync.updated, [i1]);
    assert_eq!(sync.unchanged, 1);
    assert_eq!(sync.retired, [i3]);
    assert!(sync.added.is_empty() && sync.revived.is_empty());

    let r1 = row_of(&db, i1).await?;
    assert_eq!((r1.state, r1.entry.port), (IpState::Available, 9001));
    let r2 = row_of(&db, i2).await?;
    assert_eq!(r2.state, IpState::Cooldown);
    assert!(
        close(r2.cooldown_until, until),
        "the deadline survives the sync"
    );
    let r3 = row_of(&db, i3).await?;
    assert_eq!(r3.state, IpState::Retired);

    // An IP that comes back is a new Candidate.
    let sync = db
        .replace_inventory(&pid, &[e1b.clone(), e2.clone(), e3.clone()], "gitops")
        .await?;
    assert_eq!(sync.revived, [i3]);
    assert_eq!(row_of(&db, i3).await?.state, IpState::Candidate);

    let actions = audit_actions(&db, &i3.to_string(), 10).await?;
    assert_eq!(
        actions,
        ["inventory.revive", "inventory.retire", "inventory.add"]
    );

    // A bad list changes nothing.
    let other = entry_at(&uniq("other"), uniq_ip())?;
    assert!(matches!(
        db.replace_inventory(&pid, &[other], "gitops").await,
        Err(StoreError::Invalid(_))
    ));
    assert!(matches!(
        db.replace_inventory(&pid, &[e1b.clone(), e1b], "gitops")
            .await,
        Err(StoreError::Invalid(_))
    ));
    assert_eq!(
        db.list_inventory(Some(&pid), Some(IpState::Candidate))
            .await?
            .len(),
        1
    );
    assert_eq!(
        db.upsert_inventory_entry(&e2, "gitops").await?,
        UpsertOutcome::Unchanged
    );
    Ok(())
}

/// warmer D-W12: a new host, port or credentials file is another upstream
/// behind the same IP, so the last check no longer counts.
#[tokio::test]
async fn a_changed_upstream_endpoint_clears_the_last_check_and_a_plan_change_does_not() -> TestResult
{
    let Some((db, _raw)) = db("inv_recheck").await? else {
        return Ok(());
    };
    let provider = uniq("prov");
    let ip = uniq_ip();
    let e = entry_at(&provider, ip)?;
    db.upsert_inventory_entry(&e, "gitops").await?;
    db.record_check(ip, Some(uniq_ip()), OffsetDateTime::now_utc())
        .await?;

    let mut renamed_plan = e.clone();
    renamed_plan.plan = "other plan".into();
    db.upsert_inventory_entry(&renamed_plan, "gitops").await?;
    assert!(row_of(&db, ip).await?.last_check_at.is_some());

    for change in [
        |e: &mut common::types::InventoryEntry| e.port += 1,
        |e: &mut common::types::InventoryEntry| e.host = "other.example".into(),
        |e: &mut common::types::InventoryEntry| e.credentials = Some("other-file".into()),
    ] {
        db.record_check(ip, Some(uniq_ip()), OffsetDateTime::now_utc())
            .await?;
        let mut changed = row_of(&db, ip).await?.entry;
        change(&mut changed);
        assert_eq!(
            db.upsert_inventory_entry(&changed, "gitops").await?,
            UpsertOutcome::Updated
        );
        assert!(
            row_of(&db, ip).await?.last_check_at.is_none(),
            "the next tick must check it"
        );
    }

    // an invalid rental_end is refused before anything is written
    let mut bad = e.clone();
    bad.rental_end = Some("2026-02-30".into());
    assert!(matches!(
        db.upsert_inventory_entry(&bad, "gitops").await,
        Err(StoreError::Invalid(_))
    ));
    Ok(())
}

#[tokio::test]
async fn transitions_set_and_clear_deadlines_and_write_audit() -> TestResult {
    let Some((db, _raw)) = db("transitions").await? else {
        return Ok(());
    };
    let provider = uniq("prov");
    let ip = uniq_ip();
    db.upsert_inventory_entry(&entry_at(&provider, ip)?, "gitops")
        .await?;
    let now = OffsetDateTime::now_utc();

    assert!(matches!(
        db.transition_ip(
            ip,
            &Transition::to(IpState::Cooldown, "x").cooldown_until(now),
            "w"
        )
        .await,
        Err(StoreError::InvalidTransition { .. })
    ));
    db.transition_ip(ip, &Transition::to(IpState::Available, "ok"), "w")
        .await?;
    // Deadlines are required where they belong and refused elsewhere.
    assert!(matches!(
        db.transition_ip(ip, &Transition::to(IpState::Cooldown, "x"), "w")
            .await,
        Err(StoreError::Invalid(_))
    ));
    assert!(matches!(
        db.transition_ip(
            ip,
            &Transition::to(IpState::Offline, "x").retest_at(now),
            "w"
        )
        .await,
        Err(StoreError::Invalid(_))
    ));
    assert!(matches!(
        db.transition_ip(uniq_ip(), &Transition::to(IpState::Available, "x"), "w")
            .await,
        Err(StoreError::NotFound { .. })
    ));

    let past = now - time::Duration::seconds(5);
    let row = db
        .transition_ip(
            ip,
            &Transition::to(IpState::Cooldown, "block").cooldown_until(past),
            "w",
        )
        .await?;
    assert!(close(row.cooldown_until, past));

    let retest = now + time::Duration::hours(6);
    let row = db
        .transition_ip(
            ip,
            &Transition::to(IpState::Quarantined, "3 blocks").retest_at(retest),
            "w",
        )
        .await?;
    assert!(
        row.cooldown_until.is_none(),
        "the cooldown deadline is cleared"
    );
    assert!(row.quarantined_at.is_some() && close(row.retest_at, retest));
    let row = db
        .transition_ip(
            ip,
            &Transition::to(IpState::ReplaceRequested, "quarantined 24h"),
            "w",
        )
        .await?;
    assert!(
        row.quarantined_at.is_some(),
        "the report keeps when it was quarantined"
    );
    assert!(row.retest_at.is_none());
    db.transition_ip(ip, &Transition::to(IpState::Retired, "removed"), "w")
        .await?;
    assert!(matches!(
        db.transition_ip(ip, &Transition::to(IpState::Candidate, "x"), "w")
            .await,
        Err(StoreError::InvalidTransition {
            from: IpState::Retired,
            ..
        })
    ));

    let audit = db.audit_for(&ip.to_string(), 20).await?;
    assert_eq!(
        audit.len(),
        6,
        "add and five accepted moves; refused moves leave no row"
    );
    assert_eq!(audit[0].detail["to"], "retired");

    db.record_check(ip, Some(uniq_ip()), now).await?;
    let row = row_of(&db, ip).await?;
    assert!(row.exit_ip.is_some() && close(row.last_check_at, now));
    Ok(())
}

#[tokio::test]
async fn scores_and_blocks_keep_history_for_the_rules() -> TestResult {
    let Some((db, _raw)) = db("history").await? else {
        return Ok(());
    };
    let ip = uniq_ip();
    let now = OffsetDateTime::now_utc();
    for (i, (source, risk)) in [
        ("fraud_score", 80),
        ("fraud_score", 90),
        ("fraud_score", 85),
        ("abuse", 10),
    ]
    .into_iter()
    .enumerate()
    {
        db.record_score(&proxyx_store::ScoreRow {
            ip,
            source: source.into(),
            risk,
            flags: vec!["tor".into()],
            checked_at: now + time::Duration::seconds(i64::try_from(i)?),
        })
        .await?;
    }
    let recent = db.recent_scores(ip, 2).await?;
    let fraud_score: Vec<_> = recent
        .iter()
        .filter(|s| s.source == "fraud_score")
        .map(|s| s.risk)
        .collect();
    assert_eq!(
        fraud_score,
        [85, 90],
        "the newest two of one service, newest first"
    );
    assert_eq!(recent.iter().filter(|s| s.source == "abuse").count(), 1);
    assert_eq!(recent[0].flags, ["tor"]);
    assert!(
        db.record_score(&proxyx_store::ScoreRow {
            ip,
            source: "x".into(),
            risk: 101,
            flags: vec![],
            checked_at: now,
        })
        .await
        .is_err()
    );

    let hour_ago = now - time::Duration::hours(1);
    let until = now + time::Duration::minutes(30);
    let blocks = [
        (
            Some("Example.com"),
            SignalSource::Probe,
            SignalType::Challenge,
            Some(until),
        ),
        (
            Some("example.net"),
            SignalSource::Client,
            SignalType::RateLimited,
            Some(until),
        ),
        (
            Some("example.com"),
            SignalSource::Probe,
            SignalType::Challenge,
            Some(until),
        ),
        (None, SignalSource::Operator, SignalType::Forbidden, None),
    ];
    for (target, source, signal, expires) in blocks {
        db.record_block(ip, target, source, signal, expires).await?;
    }
    assert_eq!(
        db.blocked_targets_since(ip, hour_ago).await?,
        2,
        "distinct targets, case folded"
    );
    assert_eq!(db.ip_wide_blocks_since(ip, hour_ago).await?, 1);
    assert_eq!(
        db.ip_wide_blocks_since(ip, now + time::Duration::hours(1))
            .await?,
        0
    );
    assert_eq!(db.blocks_since(ip, hour_ago).await?.len(), 4);
    let refused = [
        (Some("a.com"), SignalSource::Probe, SignalType::Reset, None),
        (None, SignalSource::Probe, SignalType::Reset, Some(until)),
    ];
    for (target, source, signal, expires) in refused {
        assert!(
            db.record_block(ip, target, source, signal, expires)
                .await
                .is_err()
        );
    }
    assert_eq!(db.audit_for(&ip.to_string(), 10).await?.len(), 4);
    Ok(())
}

#[tokio::test]
async fn org_blocks_expire_and_can_be_revoked() -> TestResult {
    let Some(hot) = support::hot().await? else {
        return Ok(());
    };
    let Some((db, _raw)) = db("orgblocks").await? else {
        return Ok(());
    };
    let o = org(&uniq("org"))?;
    let partition = support::partition()?;
    let scopes = [
        BlockScope::Ip(uniq_ip()),
        BlockScope::Provider(partition.provider.clone()),
        BlockScope::RouteClass(partition.clone()),
        BlockScope::Pool(Pool::Private),
    ];
    let mut ids = Vec::new();
    for s in &scopes {
        let b = db
            .create_org_block(&hot, &o, s, "abuse complaint", "ops", None)
            .await?;
        assert_eq!(&b.scope, s);
        ids.push(b.id);
    }
    let now = OffsetDateTime::now_utc();
    let mine = |all: Vec<proxyx_store::OrgBlock>| all.into_iter().filter(|b| b.org == o).count();
    assert_eq!(mine(db.active_org_blocks(now).await?), 4);

    let revoked = db
        .revoke_org_block(&hot, ids[0], "ops")
        .await?
        .ok_or("block")?;
    assert!(revoked.revoked_at.is_some());
    assert!(
        db.revoke_org_block(&hot, ids[0], "ops").await?.is_none(),
        "already lifted"
    );
    assert_eq!(mine(db.active_org_blocks(now).await?), 3);

    // The store rejects an expiry that is already past when the block is created, so
    // give it a margin a loaded CI host cannot eat, then ask about an instant after it.
    let expires = OffsetDateTime::now_utc() + time::Duration::seconds(5);
    let short = db
        .create_org_block(
            &hot,
            &o,
            &BlockScope::Pool(Pool::Shared),
            "test",
            "ops",
            Some(expires),
        )
        .await?;
    assert_eq!(mine(db.active_org_blocks(now).await?), 4);
    assert!(
        db.active_org_blocks(expires + time::Duration::milliseconds(1))
            .await?
            .iter()
            .all(|b| b.id != short.id)
    );

    for (reason, expires) in [(" ", None), ("why", Some(now - time::Duration::hours(1)))] {
        assert!(
            db.create_org_block(&hot, &o, &scopes[3], reason, "ops", expires)
                .await
                .is_err()
        );
    }
    let actions = audit_actions(&db, o.as_str(), 20).await?;
    assert_eq!(
        actions.iter().filter(|a| *a == "org_block.create").count(),
        5
    );
    assert_eq!(
        actions.iter().filter(|a| *a == "org_block.revoke").count(),
        1
    );
    Ok(())
}

/// Changes of one org's blocks run one at a time, across processes: a request that
/// reads the active blocks and writes the cache from that read must not be
/// overtaken by a newer change (it would erase it). The test plays the other
/// process by holding the org's lock (PostgreSQL: an advisory lock; MariaDB: the
/// org's lock row). SQLite has one writer for everything, so there is no
/// per-org lock to hold and the test does not apply.
#[tokio::test]
async fn org_block_changes_of_one_org_wait_for_each_other_and_not_for_another_org() -> TestResult {
    let Some(hot) = support::hot().await? else {
        return Ok(());
    };
    let Some((db, raw)) = db("orgblocks_lock").await? else {
        return Ok(());
    };
    if raw.backend() == Backend::Sqlite {
        eprintln!("SKIP: SQLite serialises all writers; there is no per-org lock");
        return Ok(());
    }
    let held = org(&uniq("held"))?;
    let mut other = org(&uniq("other"))?;
    while raw.backend() == Backend::MariaDb
        && proxyx_store::testing::mariadb_org_lock_name(held.as_str())
            == proxyx_store::testing::mariadb_org_lock_name(other.as_str())
    {
        other = org(&uniq("other"))?;
    }
    let scope = BlockScope::Pool(Pool::Shared);
    let peer = support::hold_org_lock(&raw, held.as_str()).await?;

    let waiting = {
        let (db, hot, held, scope) = (db.clone(), hot.clone(), held.clone(), scope.clone());
        tokio::spawn(async move {
            db.create_org_block(&hot, &held, &scope, "second", "ops", None)
                .await
        })
    };
    db.create_org_block(&hot, &other, &scope, "free", "ops", None)
        .await?;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!waiting.is_finished(), "the block waits for the org's lock");
    assert!(hot.org_blocks(&held).await?.is_empty());

    peer.release().await?;
    waiting.await??;
    assert_eq!(hot.org_blocks(&held).await?, vec!["pool:shared".to_owned()]);
    Ok(())
}

#[tokio::test]
async fn data_source_hash_is_stored_per_source() -> TestResult {
    let Some((db, _raw)) = db("sources").await? else {
        return Ok(());
    };
    let name = uniq("inventory/");
    assert_eq!(db.source_hash(&name).await?, None);
    let h1 = sha256_hex(b"one");
    let h2 = sha256_hex(b"two");
    assert_eq!(h1.len(), 64);
    assert_ne!(h1, h2);
    db.set_source_hash(&name, &h1, "gitops").await?;
    assert_eq!(db.source_hash(&name).await?, Some(h1));
    db.set_source_hash(&name, &h2, "gitops").await?;
    assert_eq!(db.source_hash(&name).await?, Some(h2));
    assert_eq!(db.audit_for(&name, 10).await?.len(), 2);
    Ok(())
}
