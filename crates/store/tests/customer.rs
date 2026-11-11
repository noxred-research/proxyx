//! Org-owned units (customer upstreams): a unit with an owner is leasable
//! only by that org, in Redis and through the durable rows.

mod support;

use common::Secret;
use common::types::{InventoryEntry, IpState, OrgId, Partition, Subtype};
use proxyx_store::{
    BlockScope, CustomerLogin, CustomerSet, LeaseOutcome, Snapshot, StoreError, Transition,
    UnitRecord, rebuild_hot,
};
use support::{
    TestResult, db, entry_at, grant, hot, ip, lease_static, org, partition, uniq, uniq_ip,
};
use time::OffsetDateTime;

fn owned(owner: &OrgId, n: u8) -> UnitRecord {
    UnitRecord {
        owner: Some(owner.clone()),
        ..UnitRecord::static_ip(ip(n))
    }
}

fn stale<T>(r: Result<T, StoreError>) -> bool {
    matches!(r, Err(StoreError::Stale { .. }))
}

async fn version_of(db: &proxyx_store::Db, org: &OrgId) -> Result<i64, Box<dyn std::error::Error>> {
    Ok(db.customer_upstream(org).await?.ok_or("live unit")?.version)
}

fn login(user: &str, pass: &str) -> CustomerLogin {
    CustomerLogin {
        username: Secret::new(user),
        password: Secret::new(pass),
    }
}

fn customer_entry(
    provider: &str,
    ip: std::net::IpAddr,
) -> Result<InventoryEntry, Box<dyn std::error::Error>> {
    Ok(InventoryEntry {
        subtype: Subtype::Datacenter,
        region: "us".parse()?,
        ..entry_at(provider, ip)?
    })
}

/// Set `provider`'s address `ip` as `org`'s upstream, with the login `u` and
/// `password` when given.
async fn put_upstream(
    db: &proxyx_store::Db,
    org: &OrgId,
    provider: &str,
    ip: std::net::IpAddr,
    password: Option<&str>,
) -> Result<CustomerSet, Box<dyn std::error::Error>> {
    let creds = password.map(|p| login("u", p));
    let entry = customer_entry(provider, ip)?;
    Ok(db
        .set_customer_upstream(org, &entry, creds.as_ref(), "op")
        .await?)
}

/// A validation that read `version` and lands after the upstream moved on.
async fn validation_is_stale(db: &proxyx_store::Db, org: &OrgId, version: i64) -> bool {
    stale(db.customer_validated(org, version, ip(5), "op").await)
}

// --- Redis: the lease scripts ---

#[tokio::test]
async fn an_owned_unit_is_leasable_only_by_its_owner() -> TestResult {
    let Some(hot) = hot().await? else {
        return Ok(());
    };
    let p = partition()?;
    let (a, b) = (org("acme")?, org("other")?);
    hot.ready_put(&p, &owned(&a, 1)).await?;

    // The other org sees nothing: Empty, never the owner's unit.
    assert_eq!(lease_static(&hot, &p, &b, "s").await?, LeaseOutcome::Empty);
    // The owner gets it, and a second tunnel of the owner shares it.
    let first = lease_static(&hot, &p, &a, "s").await?;
    assert!(matches!(first, LeaseOutcome::Free(_)), "{first:?}");
    let second = lease_static(&hot, &p, &a, "other-key").await?;
    let LeaseOutcome::Shared(second) = &second else {
        return Err(format!("expected Shared, got {second:?}").into());
    };
    assert_eq!((second.orgs, second.tunnels), (1, 2));
    // While the owner holds it, the other org is still refused.
    assert_eq!(lease_static(&hot, &p, &b, "s").await?, LeaseOutcome::Empty);
    Ok(())
}

#[tokio::test]
async fn a_shared_unit_next_to_an_owned_one_goes_to_other_orgs_only() -> TestResult {
    let Some(hot) = hot().await? else {
        return Ok(());
    };
    let p = partition()?;
    let (a, b) = (org("acme")?, org("other")?);
    hot.ready_put(&p, &owned(&a, 1)).await?;
    hot.ready_put(&p, &UnitRecord::static_ip(ip(2))).await?;

    let gb = lease_static(&hot, &p, &b, "s").await?;
    assert_eq!(grant(&gb)?.ip, ip(2), "b never gets the owned unit");
    // Load does not push b onto the owned unit: b shares ip(2), not ip(1).
    let gb2 = lease_static(&hot, &p, &b, "again").await?;
    assert_eq!(grant(&gb2)?.ip, ip(2));
    Ok(())
}

#[tokio::test]
async fn ownership_taken_after_a_lease_ends_the_other_orgs_lease() -> TestResult {
    let Some(hot) = hot().await? else {
        return Ok(());
    };
    let p = partition()?;
    let (a, b) = (org("acme")?, org("other")?);
    hot.ready_put(&p, &UnitRecord::static_ip(ip(1))).await?;
    let held = lease_static(&hot, &p, &b, "s").await?;
    assert_eq!(grant(&held)?.ip, ip(1));

    // The unit becomes a's: b's renewal and new leases are refused.
    hot.ready_put(&p, &owned(&a, 1)).await?;
    assert_eq!(lease_static(&hot, &p, &b, "s").await?, LeaseOutcome::Empty);
    assert!(
        hot.renew(&proxyx_store::LeaseRequest {
            partition: &p,
            kind: common::types::Kind::Static,
            org: &b,
            sticky: "s",
            target: &support::target("example.com"),
            tunnel: uuid::Uuid::new_v4(),
            pool: policy::Pool::Shared,
            limits: support::limits(),
        })
        .await?
        .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn org_blocks_on_an_owned_unit_do_not_reach_other_orgs() -> TestResult {
    let Some(hot) = hot().await? else {
        return Ok(());
    };
    let p = partition()?;
    let (a, b) = (org(&uniq("acme"))?, org(&uniq("other"))?);
    hot.ready_put(&p, &owned(&a, 1)).await?;

    // b has a block on that exit IP, but the unit is not b's to lease:
    // the answer is Empty, not Blocked.
    hot.org_block_set(&b, &BlockScope::Ip(ip(1)), None).await?;
    assert_eq!(lease_static(&hot, &p, &b, "s").await?, LeaseOutcome::Empty);
    // The same block on the owner leaves nothing: Blocked.
    hot.org_block_set(&a, &BlockScope::Ip(ip(1)), None).await?;
    assert_eq!(
        lease_static(&hot, &p, &a, "s").await?,
        LeaseOutcome::Blocked
    );
    Ok(())
}

// --- Postgres: rows and logins ---

#[tokio::test]
async fn set_replace_and_clear_keep_one_live_unit_per_org() -> TestResult {
    let Some((db, _)) = db("customer").await? else {
        return Ok(());
    };
    let acme = org(&uniq("acme"))?;
    let provider = uniq("cust");
    let (first_ip, second_ip) = (uniq_ip(), uniq_ip());

    let set = put_upstream(&db, &acme, &provider, first_ip, Some("p-1")).await?;
    assert_eq!(set.row.state, IpState::Candidate);
    assert_eq!(set.row.owner.as_ref(), Some(&acme));
    assert!(set.replaced.is_none());

    // Another address: the old unit is retired, the new one is the live unit.
    let moved = put_upstream(&db, &acme, &provider, second_ip, Some("p-2")).await?;
    assert_eq!(
        moved.replaced.as_ref().map(|r| r.entry.ip),
        Some(first_ip),
        "the caller must take the old unit out of the ready set"
    );
    let old = db.inventory_row(first_ip).await?.ok_or("old row")?;
    assert_eq!(old.state, IpState::Retired);
    let live = db.customer_unit(&acme).await?.ok_or("live unit")?;
    assert_eq!(live.entry.ip, second_ip);

    // Setting the same address again resets a validated unit to Candidate.
    let version = version_of(&db, &acme).await?;
    db.customer_validated(&acme, version, ip(9), "op").await?;
    let again = put_upstream(&db, &acme, &provider, second_ip, Some("p-3")).await?;
    assert_eq!(again.row.state, IpState::Candidate);
    assert_eq!(again.row.exit_ip, None, "the exit IP is learned again");

    let cleared = db.clear_customer_upstream(&acme, "op").await?;
    assert_eq!(cleared.entry.ip, second_ip);
    assert_eq!(
        db.inventory_row(second_ip).await?.ok_or("row")?.state,
        IpState::Retired
    );
    assert!(db.customer_login(&acme).await?.is_none());
    assert!(matches!(
        db.clear_customer_upstream(&acme, "op").await,
        Err(StoreError::NotFound { .. })
    ));

    let actions: Vec<String> = db
        .audit_for(acme.as_str(), 20)
        .await?
        .into_iter()
        .map(|r| r.action)
        .collect();
    for want in ["customer.set", "customer.validate", "customer.clear"] {
        assert!(actions.iter().any(|a| a == want), "{want} in {actions:?}");
    }
    Ok(())
}

#[tokio::test]
async fn an_address_cannot_be_owned_twice_or_claimed_by_other_inventory() -> TestResult {
    let Some((db, _)) = db("customer").await? else {
        return Ok(());
    };
    let (acme, other) = (org(&uniq("acme"))?, org(&uniq("other"))?);
    let provider = uniq("cust");
    let address = uniq_ip();
    put_upstream(&db, &acme, &provider, address, None).await?;

    // Another org cannot take a live address, and neither can a git sync or
    // the operator list: the unit is not theirs.
    assert!(matches!(
        db.set_customer_upstream(&other, &customer_entry(&provider, address)?, None, "op")
            .await,
        Err(StoreError::Conflict { .. })
    ));
    assert!(matches!(
        db.upsert_inventory_entry(&customer_entry(&provider, address)?, "gitops")
            .await,
        Err(StoreError::Conflict { .. })
    ));
    // A provider sync that omits the unit does not retire it.
    let provider_id = provider.parse()?;
    let sync = db.replace_inventory(&provider_id, &[], "gitops").await?;
    assert!(sync.retired.is_empty(), "{sync:?}");
    assert_eq!(
        db.customer_unit(&acme).await?.ok_or("still live")?.state,
        IpState::Candidate
    );

    // After the owner clears it, the address is free for the other org.
    db.clear_customer_upstream(&acme, "op").await?;
    let taken = put_upstream(&db, &other, &provider, address, None).await?;
    assert_eq!(taken.row.owner.as_ref(), Some(&other));
    Ok(())
}

#[tokio::test]
async fn logins_reach_the_snapshot_but_never_a_debug_print_or_the_audit_trail() -> TestResult {
    let Some((db, _)) = db("customer").await? else {
        return Ok(());
    };
    let acme = org(&uniq("acme"))?;
    let provider = uniq("cust");
    db.set_customer_upstream(
        &acme,
        &customer_entry(&provider, uniq_ip())?,
        Some(&login("user-x", "hunter2-secret")),
        "op",
    )
    .await?;

    let snapshot = Snapshot::load(&db).await?;
    let stored = snapshot
        .customer_logins
        .get(&acme)
        .ok_or("login in snapshot")?;
    assert_eq!(stored.password.expose(), "hunter2-secret");
    let printed = format!("{snapshot:?}");
    assert!(!printed.contains("hunter2-secret") && !printed.contains("user-x"));

    // Rotation replaces the password and audits it without the value.
    let version = version_of(&db, &acme).await?;
    db.rotate_customer_login(&acme, version, &login("user-x", "rotated-secret"), "op")
        .await?;
    let now = db.customer_login(&acme).await?.ok_or("login")?;
    assert_eq!(now.password.expose(), "rotated-secret");
    let audit = db.audit_for(acme.as_str(), 20).await?;
    assert!(audit.iter().any(|r| r.action == "customer.rotate"));
    let all = serde_json::to_string(&audit.iter().map(|r| r.detail.clone()).collect::<Vec<_>>())?;
    assert!(!all.contains("secret") && !all.contains("user-x"), "{all}");

    // No upstream, no rotation.
    let nobody = org(&uniq("nobody"))?;
    assert!(matches!(
        db.rotate_customer_login(&nobody, 0, &login("u", "p"), "op")
            .await,
        Err(StoreError::NotFound { .. })
    ));
    Ok(())
}

/// A check through an upstream runs outside any transaction. If a PUT,
/// rotate or clear lands meanwhile, the result is about another proxy and
/// must change nothing.
#[tokio::test]
async fn a_result_checked_against_an_older_upstream_is_turned_away() -> TestResult {
    let Some((db, _)) = db("customer").await? else {
        return Ok(());
    };
    let acme = org(&uniq("acme"))?;
    let provider = uniq("cust");
    let (old_ip, new_ip) = (uniq_ip(), uniq_ip());

    // validate: read the version, check the old proxy, a PUT replaces it.
    put_upstream(&db, &acme, &provider, old_ip, Some("old-pass")).await?;
    let read = version_of(&db, &acme).await?;
    put_upstream(&db, &acme, &provider, new_ip, Some("new-pass")).await?;
    assert!(validation_is_stale(&db, &acme, read).await);
    let unit = db.customer_unit(&acme).await?.ok_or("live unit")?;
    assert_eq!(
        unit.state,
        IpState::Candidate,
        "the replacement stays unvalidated"
    );
    assert_eq!(unit.exit_ip, None);

    // the same address set again also moves the version
    let read = version_of(&db, &acme).await?;
    put_upstream(&db, &acme, &provider, new_ip, None).await?;
    assert!(validation_is_stale(&db, &acme, read).await);

    // rotate-secret: read, check the new login against the old proxy, a PUT
    // replaces the proxy and its login.
    put_upstream(&db, &acme, &provider, new_ip, Some("put-pass")).await?;
    let read = version_of(&db, &acme).await?;
    put_upstream(&db, &acme, &provider, new_ip, Some("second-put-pass")).await?;
    assert!(stale(
        db.rotate_customer_login(&acme, read, &login("u", "checked-against-old"), "op")
            .await
    ));
    let kept = db.customer_login(&acme).await?.ok_or("login")?;
    assert_eq!(kept.password.expose(), "second-put-pass");

    // a rotation moves the version too: a validate that began before it is stale
    let read = version_of(&db, &acme).await?;
    db.rotate_customer_login(&acme, read, &login("u", "rotated"), "op")
        .await?;
    assert!(validation_is_stale(&db, &acme, read).await);
    assert!(stale(
        db.rotate_customer_login(&acme, read, &login("u", "again"), "op")
            .await
    ));

    // the current version is accepted
    let read = version_of(&db, &acme).await?;
    db.customer_validated(&acme, read, ip(5), "op").await?;

    // a clear retires the unit: nothing is left to validate
    let read = version_of(&db, &acme).await?;
    db.clear_customer_upstream(&acme, "op").await?;
    assert!(matches!(
        db.customer_validated(&acme, read, ip(5), "op").await,
        Err(StoreError::NotFound { .. })
    ));
    // and a new upstream is not the one the old read saw
    put_upstream(&db, &acme, &provider, new_ip, None).await?;
    assert!(validation_is_stale(&db, &acme, read).await);
    Ok(())
}

#[tokio::test]
async fn validation_makes_the_unit_available_from_every_resting_state() -> TestResult {
    let Some((db, _)) = db("customer").await? else {
        return Ok(());
    };
    let acme = org(&uniq("acme"))?;
    let address = uniq_ip();
    put_upstream(&db, &acme, &uniq("cust"), address, None).await?;

    let exit = ip(77);
    let version = version_of(&db, &acme).await?;
    let v = db.customer_validated(&acme, version, exit, "op").await?;
    assert_eq!((v.state, v.exit_ip), (IpState::Available, Some(exit)));
    assert!(v.last_check_at.is_some());

    // A quarantined unit comes back on a passed validation, with its deadlines cleared.
    let in_an_hour = OffsetDateTime::now_utc() + time::Duration::hours(1);
    db.transition_ip(
        address,
        &Transition::to(IpState::Cooldown, "x").cooldown_until(in_an_hour),
        "op",
    )
    .await?;
    db.transition_ip(
        address,
        &Transition::to(IpState::Quarantined, "x").retest_at(in_an_hour),
        "op",
    )
    .await?;
    let v = db.customer_validated(&acme, version, exit, "op").await?;
    assert_eq!(v.state, IpState::Available);
    assert!(v.cooldown_until.is_none() && v.quarantined_at.is_none() && v.retest_at.is_none());

    // A unit that waits for a replacement is not the customer's to revive.
    db.transition_ip(
        address,
        &Transition::to(IpState::ReplaceRequested, "x"),
        "op",
    )
    .await?;
    let version = version_of(&db, &acme).await?;
    assert!(matches!(
        db.customer_validated(&acme, version, exit, "op").await,
        Err(StoreError::InvalidTransition { .. })
    ));
    Ok(())
}

#[tokio::test]
async fn a_redis_rebuild_restores_the_owner_and_the_exit_ip() -> TestResult {
    let Some(hot) = hot().await? else {
        return Ok(());
    };
    let Some((db, _)) = db("customer").await? else {
        return Ok(());
    };
    let (acme, other) = (org(&uniq("acme"))?, org(&uniq("other"))?);
    let provider = uniq("cust");
    let entry = customer_entry(&provider, uniq_ip())?;
    let p = Partition {
        provider: entry.provider.clone(),
        region: entry.region.clone(),
    };
    db.set_customer_upstream(&acme, &entry, None, "op").await?;
    let exit = ip(88);
    let version = version_of(&db, &acme).await?;
    db.customer_validated(&acme, version, exit, "op").await?;

    rebuild_hot(&db, &hot).await?;

    assert_eq!(
        lease_static(&hot, &p, &other, "s").await?,
        LeaseOutcome::Empty
    );
    let g = lease_static(&hot, &p, &acme, "s").await?;
    let g = grant(&g)?;
    assert_eq!(g.unit, entry.ip.to_string(), "the unit id is the row key");
    assert_eq!(g.ip, exit, "the reported exit IP is the validated one");
    Ok(())
}
