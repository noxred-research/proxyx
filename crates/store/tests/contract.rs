//! The cross-backend contract of the pool store.
//!
//! One scenario runs against every backend whose test variable is set
//! (`PROXYX_TEST_DATABASE_URL`, `PROXYX_TEST_MARIADB_URL`,
//! `PROXYX_TEST_SQLITE_DIR`) and writes down what the repository answers:
//! counts, states, orderings, error kinds, the triggers that keep the audit
//! trail append-only, the retention of old history. The transcripts of all
//! backends must be identical, and each must match `CONTRACT`, the transcript
//! PostgreSQL gave when the contract was written. A backend that differs fails
//! with the first differing line.
//!
//! Ids, version numbers and clock values differ by nature and never appear in
//! the transcript. The org block part needs Redis (`PROXYX_TEST_REDIS_URL`) and
//! is a second test.

mod support;

use std::time::Duration;

use common::Secret;
use common::types::{InventoryEntry, IpState, SignalSource, SignalType, Subtype};
use policy::{PolicyDoc, Pool, Scope};
use proxyx_db::Backend;
use proxyx_db::testing::Raw;
use proxyx_store::{
    BlockScope, CustomerLogin, Db, InventorySync, KeyStatus, ScoreRow, StoreError, Transition,
};
use support::{TestResult, db_on, entry_at, org, uniq, uniq_ip};
use time::OffsetDateTime;

/// What every backend must answer, line by line.
const CONTRACT: &str = "\
inventory.sync: added=3 updated=0 revived=0 retired=0 moved=0 unchanged=0
inventory.sync again: added=0 updated=0 revived=0 retired=0 moved=0 unchanged=3
inventory.sync shrunk: added=0 updated=0 revived=0 retired=1 moved=0 unchanged=2
inventory.sync revived: added=0 updated=0 revived=1 retired=0 moved=0 unchanged=2
inventory.list: candidate,candidate,candidate
inventory.list ordered by ip: true
inventory.to available: ok
inventory.to leased: ok
inventory.forbidden move: invalid transition
inventory.expecting another state: invalid transition
inventory.cooldown without deadline: invalid
inventory.unknown ip: not found
inventory.cooldown deadline kept to the microsecond: true
inventory.cooldown clears the other deadlines: true
inventory.check time kept to the microsecond: true
inventory.check of an unknown ip: not found
inventory.plan change keeps the check time: true
inventory.new host clears the check time: true
inventory.audit: inventory.update,inventory.update,inventory.transition,inventory.transition,inventory.transition,inventory.add
inventory.providers written by gitops: 1
policies.put: stored=1 unchanged=0
policies.put the same: stored=0 unchanged=1
policies.put changed: stored=1 unchanged=0
policies.versions newest first: 2,1
policies.current versions: 2
policies.exactly one current row: 1
policies.document round trip: true
policies.cap: versions=50 oldest=2
policies.deactivate: true
policies.deactivate again: false
policies.current after: 0
policies.latest by gitops: 1
keys.add: ok
keys.duplicate: conflict
keys.empty: invalid
keys.verify: enabled
keys.disable: 1
keys.disable again: 0
keys.verify disabled: disabled
keys.verify unknown: unknown
blocks.invalid shapes: invalid,invalid
blocks.ip wide: 2
blocks.distinct targets: 2
blocks.in the window: 5
blocks.newest first: true
blocks.targets lowercased: 0
blocks.window excludes the future: 0
blocks.window includes its own start: 5
scores.two newest per source: abuse:50,abuse:40,fraud_score:30,fraud_score:20
scores.flags round trip: true
scores.highest of the latest per source: 50
scores.over 100: invalid
customer.set: candidate
customer.owner: true
customer.address taken: conflict
customer.shared inventory refused: conflict
customer.rotate: ok
customer.rotate with the old version: stale
customer.version grew: true
customer.login rotated: true
customer.validated: available
customer.validated with the old version: stale
customer.exit ip: 203.0.113.4
customer.clear: available
customer.after clear: true
customer.login gone: true
customer.clear again: not found
customer.address of a retired unit is free: ok
customer.last setter: op
audit.detail round trip: true
audit.update: refused (append-only)
audit.delete a recent row: refused (append-only)
audit.delete an old operator row: refused (append-only)
audit.prune: scores>=1:true blocks>=1:true audit>=1:true
audit.old operator row survives: 1
audit.old machine row gone: 0
audit.prune twice: true
sources.hash: none,h1,h2
sources.audit rows: 2
trees.live before, during, own mark, after: false,true,false,false
trees.applied tree: false
trees.applied tree after its audit row: true
";

/// Collects the lines of one backend's transcript.
#[derive(Default)]
struct Transcript(Vec<String>);

impl Transcript {
    fn line(&mut self, key: &str, value: impl std::fmt::Display) {
        self.0.push(format!("{key}: {value}"));
    }
}

fn counts(s: &InventorySync) -> String {
    format!(
        "added={} updated={} revived={} retired={} moved={} unchanged={}",
        s.added.len(),
        s.updated.len(),
        s.revived.len(),
        s.retired.len(),
        s.moved.len(),
        s.unchanged
    )
}

/// The kind of an error, or `ok`.
fn outcome<T>(result: Result<T, StoreError>) -> &'static str {
    match result {
        Ok(_) => "ok",
        Err(StoreError::NotFound { .. }) => "not found",
        Err(StoreError::Conflict { .. }) => "conflict",
        Err(StoreError::Stale { .. }) => "stale",
        Err(StoreError::Invalid(_)) => "invalid",
        Err(StoreError::InvalidTransition { .. }) => "invalid transition",
        Err(_) => "other",
    }
}

fn micros(t: OffsetDateTime) -> i128 {
    t.unix_timestamp_nanos() / 1_000
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

async fn scenario(db: &Db, raw: &Raw, t: &mut Transcript) -> TestResult {
    inventory(db, t).await?;
    policies(db, t).await?;
    keys(db, t).await?;
    blocks_and_scores(db, t).await?;
    customer(db, t).await?;
    audit(db, raw, t).await?;
    sources(db, t).await?;
    Ok(())
}

async fn inventory(db: &Db, t: &mut Transcript) -> TestResult {
    let provider = uniq("ct");
    let provider_id = provider.parse()?;
    let mut entries = Vec::new();
    for _ in 0..3 {
        entries.push(entry_at(&provider, uniq_ip())?);
    }
    t.line(
        "inventory.sync",
        counts(
            &db.replace_inventory(&provider_id, &entries, "gitops")
                .await?,
        ),
    );
    t.line(
        "inventory.sync again",
        counts(
            &db.replace_inventory(&provider_id, &entries, "gitops")
                .await?,
        ),
    );
    let dropped = entries.pop().ok_or("entry")?;
    t.line(
        "inventory.sync shrunk",
        counts(
            &db.replace_inventory(&provider_id, &entries, "gitops")
                .await?,
        ),
    );
    entries.push(dropped);
    t.line(
        "inventory.sync revived",
        counts(
            &db.replace_inventory(&provider_id, &entries, "gitops")
                .await?,
        ),
    );
    let rows = db.list_inventory(Some(&provider_id), None).await?;
    t.line(
        "inventory.list",
        rows.iter()
            .map(|r| r.state.as_str())
            .collect::<Vec<_>>()
            .join(","),
    );
    // Ordered by the text of the address, byte by byte.
    let texts: Vec<String> = rows.iter().map(|r| r.entry.ip.to_string()).collect();
    let mut sorted = texts.clone();
    sorted.sort();
    t.line("inventory.list ordered by ip", texts == sorted);

    let ip = entries[0].ip;
    t.line(
        "inventory.to available",
        outcome(
            db.transition_ip(ip, &Transition::to(IpState::Available, "ready"), "t")
                .await,
        ),
    );
    t.line(
        "inventory.to leased",
        outcome(
            db.transition_ip(ip, &Transition::to(IpState::Leased, "lease"), "t")
                .await,
        ),
    );
    t.line(
        "inventory.forbidden move",
        outcome(
            db.transition_ip(
                ip,
                &Transition::to(IpState::Quarantined, "x").retest_at(OffsetDateTime::now_utc()),
                "t",
            )
            .await,
        ),
    );
    t.line(
        "inventory.expecting another state",
        outcome(
            db.transition_ip(
                ip,
                &Transition::to(IpState::Available, "x").expecting(IpState::Candidate),
                "t",
            )
            .await,
        ),
    );
    t.line(
        "inventory.cooldown without deadline",
        outcome(
            db.transition_ip(ip, &Transition::to(IpState::Cooldown, "x"), "t")
                .await,
        ),
    );
    t.line(
        "inventory.unknown ip",
        outcome(
            db.transition_ip(uniq_ip(), &Transition::to(IpState::Available, "x"), "t")
                .await,
        ),
    );

    let now = OffsetDateTime::now_utc();
    let until = now + Duration::from_micros(3_600_000_123);
    let cooled = db
        .transition_ip(
            ip,
            &Transition::to(IpState::Cooldown, "slow").cooldown_until(until),
            "t",
        )
        .await?;
    t.line(
        "inventory.cooldown deadline kept to the microsecond",
        cooled.cooldown_until.map(micros) == Some(micros(until)),
    );
    t.line(
        "inventory.cooldown clears the other deadlines",
        cooled.quarantined_at.is_none() && cooled.retest_at.is_none(),
    );
    let at = now - Duration::from_micros(1_234_567);
    db.record_check(ip, Some("203.0.113.9".parse()?), at)
        .await?;
    let row = db.inventory_row(ip).await?.ok_or("row")?;
    t.line(
        "inventory.check time kept to the microsecond",
        row.last_check_at.map(micros) == Some(micros(at))
            && row.exit_ip == Some("203.0.113.9".parse()?),
    );
    t.line(
        "inventory.check of an unknown ip",
        outcome(db.record_check(uniq_ip(), None, at).await),
    );
    // A new host behind the same IP clears the check time; a plan change does not.
    let mut plan = entries[0].clone();
    plan.plan = "other-plan".into();
    db.upsert_inventory_entry(&plan, "gitops").await?;
    t.line(
        "inventory.plan change keeps the check time",
        db.inventory_row(ip)
            .await?
            .ok_or("row")?
            .last_check_at
            .is_some(),
    );
    let mut host = plan.clone();
    host.host = "other.example".into();
    db.upsert_inventory_entry(&host, "gitops").await?;
    t.line(
        "inventory.new host clears the check time",
        db.inventory_row(ip)
            .await?
            .ok_or("row")?
            .last_check_at
            .is_none(),
    );
    let audit = db.audit_for(&ip.to_string(), 20).await?;
    t.line(
        "inventory.audit",
        audit
            .iter()
            .map(|r| r.action.as_str())
            .collect::<Vec<_>>()
            .join(","),
    );
    t.line(
        "inventory.providers written by gitops",
        db.providers_written_by("gitops")
            .await?
            .iter()
            .filter(|p| p.as_str() == provider)
            .count(),
    );
    Ok(())
}

fn doc(name: &str, min_ready: u32) -> PolicyDoc {
    PolicyDoc {
        name: name.to_owned(),
        scope: Scope::RouteClass,
        target: Some("isp_static_port".into()),
        min_ready: Some(min_ready),
        ..PolicyDoc::default()
    }
}

async fn policies(db: &Db, t: &mut Transcript) -> TestResult {
    let name = uniq("ct-pol-");
    let put = |d: PolicyDoc, actor: &'static str| {
        let db = db.clone();
        async move { db.put_policies(std::slice::from_ref(&d), actor).await }
    };
    let first = put(doc(&name, 2), "ops").await?;
    t.line(
        "policies.put",
        format!(
            "stored={} unchanged={}",
            first.stored.len(),
            first.unchanged
        ),
    );
    let same = put(doc(&name, 2), "ops").await?;
    t.line(
        "policies.put the same",
        format!("stored={} unchanged={}", same.stored.len(), same.unchanged),
    );
    let changed = put(doc(&name, 3), "gitops").await?;
    t.line(
        "policies.put changed",
        format!(
            "stored={} unchanged={}",
            changed.stored.len(),
            changed.unchanged
        ),
    );
    let versions = db.policy_versions("route_class", &name).await?;
    t.line(
        "policies.versions newest first",
        versions
            .iter()
            .map(|v| v.version.to_string())
            .collect::<Vec<_>>()
            .join(","),
    );
    t.line(
        "policies.current versions",
        db.current_policies()
            .await?
            .iter()
            .filter(|p| p.name == name)
            .map(|p| p.version.to_string())
            .collect::<Vec<_>>()
            .join(","),
    );
    t.line(
        "policies.exactly one current row",
        versions.iter().filter(|v| v.current).count(),
    );
    t.line(
        "policies.document round trip",
        versions[0].doc()?.min_ready == Some(3),
    );
    // The history is capped at the newest 50 versions.
    for n in 4..=52 {
        put(doc(&name, n), "ops").await?;
    }
    let all = db.policy_versions("route_class", &name).await?;
    t.line(
        "policies.cap",
        format!(
            "versions={} oldest={}",
            all.len(),
            all.last().map_or(0, |v| v.version)
        ),
    );
    t.line(
        "policies.deactivate",
        db.deactivate_policy("route_class", &name, "ops").await?,
    );
    t.line(
        "policies.deactivate again",
        db.deactivate_policy("route_class", &name, "ops").await?,
    );
    t.line(
        "policies.current after",
        db.current_policies()
            .await?
            .iter()
            .filter(|p| p.name == name)
            .count(),
    );
    let gitops = db.latest_policy_docs_by("gitops").await?;
    t.line(
        "policies.latest by gitops",
        gitops.keys().filter(|(_, n)| *n == name).count(),
    );
    Ok(())
}

async fn keys(db: &Db, t: &mut Transcript) -> TestResult {
    let o = org(&uniq("org"))?;
    let key = format!("ak_{}", uniq(""));
    t.line(
        "keys.add",
        outcome(
            db.add_org_key(&o, &Secret::new(key.clone()), "prod", "t")
                .await,
        ),
    );
    t.line(
        "keys.duplicate",
        outcome(
            db.add_org_key(&o, &Secret::new(key.clone()), "dup", "t")
                .await,
        ),
    );
    t.line(
        "keys.empty",
        outcome(db.add_org_key(&o, &Secret::new(""), "", "t").await),
    );
    let status = |s: KeyStatus| match s {
        KeyStatus::Enabled(got) if got == o => "enabled",
        KeyStatus::Enabled(_) => "enabled for another org",
        KeyStatus::Disabled => "disabled",
        KeyStatus::Unknown => "unknown",
    };
    t.line("keys.verify", status(db.verify_org_key(&key).await?));
    t.line("keys.disable", db.disable_org_keys(&o, "t").await?);
    t.line("keys.disable again", db.disable_org_keys(&o, "t").await?);
    t.line(
        "keys.verify disabled",
        status(db.verify_org_key(&key).await?),
    );
    t.line(
        "keys.verify unknown",
        status(db.verify_org_key("ak_nobody").await?),
    );
    Ok(())
}

async fn blocks_and_scores(db: &Db, t: &mut Transcript) -> TestResult {
    let ip = uniq_ip();
    let now = OffsetDateTime::now_utc();
    let until = now + Duration::from_secs(600);
    for target in ["X.example", "y.example", "x.example"] {
        db.record_block(
            ip,
            Some(target),
            SignalSource::Client,
            SignalType::RateLimited,
            Some(until),
        )
        .await?;
    }
    for _ in 0..2 {
        db.record_block(
            ip,
            None,
            SignalSource::Operator,
            SignalType::Forbidden,
            None,
        )
        .await?;
    }
    t.line(
        "blocks.invalid shapes",
        format!(
            "{},{}",
            outcome(
                db.record_block(
                    ip,
                    Some("a"),
                    SignalSource::Client,
                    SignalType::Challenge,
                    None
                )
                .await
            ),
            outcome(
                db.record_block(
                    ip,
                    None,
                    SignalSource::Client,
                    SignalType::Challenge,
                    Some(until)
                )
                .await
            )
        ),
    );
    let hour = now - Duration::from_secs(3600);
    t.line("blocks.ip wide", db.ip_wide_blocks_since(ip, hour).await?);
    t.line(
        "blocks.distinct targets",
        db.blocked_targets_since(ip, hour).await?,
    );
    let blocks = db.blocks_since(ip, hour).await?;
    t.line("blocks.in the window", blocks.len());
    t.line(
        "blocks.newest first",
        blocks.windows(2).all(|w| w[0].id > w[1].id),
    );
    t.line(
        "blocks.targets lowercased",
        blocks
            .iter()
            .filter_map(|b| b.target.clone())
            .filter(|target| target.contains(char::is_uppercase))
            .count(),
    );
    t.line(
        "blocks.window excludes the future",
        db.blocks_since(ip, now + Duration::from_secs(60))
            .await?
            .len(),
    );
    t.line(
        "blocks.window includes its own start",
        db.blocks_since(ip, blocks.last().ok_or("block")?.created_at)
            .await?
            .len(),
    );

    let sip = uniq_ip();
    let same = now - Duration::from_secs(10);
    for (source, risk, at) in [
        ("fraud_score", 10, same - Duration::from_secs(60)),
        ("fraud_score", 20, same),
        ("fraud_score", 30, same),
        ("abuse", 40, same),
        ("abuse", 50, same),
    ] {
        db.record_score(&ScoreRow {
            ip: sip,
            source: source.into(),
            risk,
            flags: vec!["proxy".into()],
            checked_at: at,
        })
        .await?;
    }
    // Two checks at the same instant: the one inserted later is newer.
    t.line(
        "scores.two newest per source",
        db.recent_scores(sip, 2)
            .await?
            .iter()
            .map(|s| format!("{}:{}", s.source, s.risk))
            .collect::<Vec<_>>()
            .join(","),
    );
    t.line(
        "scores.flags round trip",
        db.recent_scores(sip, 1).await?[0].flags == ["proxy"],
    );
    t.line(
        "scores.highest of the latest per source",
        db.latest_risks()
            .await?
            .iter()
            .find(|(ip, _)| *ip == sip)
            .map_or(0, |(_, risk)| *risk),
    );
    t.line(
        "scores.over 100",
        outcome(
            db.record_score(&ScoreRow {
                ip: sip,
                source: "x".into(),
                risk: 101,
                flags: vec![],
                checked_at: now,
            })
            .await,
        ),
    );
    Ok(())
}

async fn customer(db: &Db, t: &mut Transcript) -> TestResult {
    let (acme, other) = (org(&uniq("acme"))?, org(&uniq("other"))?);
    let provider = uniq("cust");
    let address = uniq_ip();
    let entry = customer_entry(&provider, address)?;
    let login = |n: &str| CustomerLogin {
        username: Secret::new(format!("u{n}")),
        password: Secret::new(format!("p{n}")),
    };
    let set = db
        .set_customer_upstream(&acme, &entry, Some(&login("1")), "op")
        .await?;
    t.line("customer.set", set.row.state.as_str());
    t.line("customer.owner", set.row.owner.as_ref() == Some(&acme));
    t.line(
        "customer.address taken",
        outcome(db.set_customer_upstream(&other, &entry, None, "op").await),
    );
    t.line(
        "customer.shared inventory refused",
        outcome(db.upsert_inventory_entry(&entry, "gitops").await),
    );
    let first = db.customer_upstream(&acme).await?.ok_or("unit")?.version;
    // A check that started before another change is turned away.
    t.line(
        "customer.rotate",
        outcome(
            db.rotate_customer_login(&acme, first, &login("2"), "op")
                .await,
        ),
    );
    t.line(
        "customer.rotate with the old version",
        outcome(
            db.rotate_customer_login(&acme, first, &login("3"), "op")
                .await,
        ),
    );
    let second = db.customer_upstream(&acme).await?.ok_or("unit")?.version;
    t.line("customer.version grew", second > first);
    t.line(
        "customer.login rotated",
        db.customer_login(&acme)
            .await?
            .is_some_and(|l| l.username.expose() == "u2"),
    );
    t.line(
        "customer.validated",
        db.customer_validated(&acme, second, "203.0.113.4".parse()?, "op")
            .await?
            .state
            .as_str(),
    );
    t.line(
        "customer.validated with the old version",
        outcome(
            db.customer_validated(&acme, first, "203.0.113.4".parse()?, "op")
                .await,
        ),
    );
    t.line(
        "customer.exit ip",
        db.customer_unit(&acme)
            .await?
            .ok_or("unit")?
            .exit_ip
            .map(|ip| ip.to_string())
            .unwrap_or_default(),
    );
    t.line(
        "customer.clear",
        db.clear_customer_upstream(&acme, "op")
            .await?
            .state
            .as_str(),
    );
    t.line(
        "customer.after clear",
        db.customer_unit(&acme).await?.is_none(),
    );
    t.line(
        "customer.login gone",
        db.customer_login(&acme).await?.is_none(),
    );
    t.line(
        "customer.clear again",
        outcome(db.clear_customer_upstream(&acme, "op").await),
    );
    t.line(
        "customer.address of a retired unit is free",
        outcome(db.set_customer_upstream(&other, &entry, None, "op").await),
    );
    t.line(
        "customer.last setter",
        db.last_customer_setter(&other).await?.unwrap_or_default(),
    );
    Ok(())
}

async fn audit(db: &Db, raw: &Raw, t: &mut Transcript) -> TestResult {
    let subject = uniq("subject");
    db.audit(
        "tester",
        "test.action",
        &subject,
        serde_json::json!({ "k": 1, "nested": { "a": [1, 2] } }),
    )
    .await?;
    let rows = db.audit_for(&subject, 5).await?;
    t.line(
        "audit.detail round trip",
        rows[0].detail == serde_json::json!({ "k": 1, "nested": { "a": [1, 2] } }),
    );
    let append_only = |result: Result<u64, sqlx::Error>| match result {
        Err(e) if e.to_string().contains("append-only") => "refused (append-only)".to_owned(),
        Err(e) => format!("refused ({e})"),
        Ok(n) => format!("accepted ({n} rows)"),
    };
    t.line(
        "audit.update",
        append_only(
            raw.execute(
                "UPDATE audit SET actor = 'x' WHERE subject = ?",
                &[subject.as_str().into()],
            )
            .await,
        ),
    );
    t.line(
        "audit.delete a recent row",
        append_only(
            raw.execute(
                "DELETE FROM audit WHERE subject = ?",
                &[subject.as_str().into()],
            )
            .await,
        ),
    );

    // History past its age: machine-written rows, scores and blocks go; a row
    // an operator wrote stays even when it is as old.
    let ip = uniq_ip().to_string();
    let old = OffsetDateTime::now_utc() - time::Duration::days(400);
    for (actor, action) in [
        ("warmer", "inventory.transition"),
        ("ops", "inventory.retire"),
    ] {
        raw.execute(
            "INSERT INTO audit (at, actor, action, subject) VALUES (?, ?, ?, ?)",
            &[old.into(), actor.into(), action.into(), ip.as_str().into()],
        )
        .await?;
    }
    raw.execute(
        "INSERT INTO ip_scores (ip, source, risk, checked_at) VALUES (?, 'fraud_score', 10, ?)",
        &[ip.as_str().into(), old.into()],
    )
    .await?;
    raw.execute(
        "INSERT INTO ip_blocks (ip, source, signal_type, created_at) VALUES (?, 'probe', 'forbidden', ?)",
        &[ip.as_str().into(), old.into()],
    )
    .await?;
    t.line(
        "audit.delete an old operator row",
        append_only(
            raw.execute(
                "DELETE FROM audit WHERE subject = ? AND actor = 'ops'",
                &[ip.as_str().into()],
            )
            .await,
        ),
    );
    let pruned = db.prune_history().await?;
    t.line(
        "audit.prune",
        format!(
            "scores>=1:{} blocks>=1:{} audit>=1:{}",
            pruned.scores >= 1,
            pruned.blocks >= 1,
            pruned.audit >= 1
        ),
    );
    t.line(
        "audit.old operator row survives",
        raw.int(
            "SELECT count(*) FROM audit WHERE subject = ? AND actor = 'ops'",
            &[ip.as_str().into()],
        )
        .await?,
    );
    t.line(
        "audit.old machine row gone",
        raw.int(
            "SELECT count(*) FROM audit WHERE subject = ? AND actor = 'warmer'",
            &[ip.as_str().into()],
        )
        .await?,
    );
    t.line("audit.prune twice", {
        let again = db.prune_history().await?;
        again.audit == 0
    });
    Ok(())
}

async fn sources(db: &Db, t: &mut Transcript) -> TestResult {
    let name = uniq("inventory/");
    let first = db.source_hash(&name).await?;
    db.set_source_hash(&name, "h1", "gitops").await?;
    let h1 = db.source_hash(&name).await?;
    db.set_source_hash(&name, "h2", "gitops").await?;
    let h2 = db.source_hash(&name).await?;
    t.line(
        "sources.hash",
        [first, h1, h2]
            .iter()
            .map(|h| h.clone().unwrap_or_else(|| "none".to_owned()))
            .collect::<Vec<_>>()
            .join(","),
    );
    t.line("sources.audit rows", db.audit_for(&name, 10).await?.len());

    let (me, peer, tree) = (uniq("gw"), uniq("gw"), uniq("tree"));
    let live = Duration::from_secs(60);
    let before = db.gateway_tree_is_live(&me, &tree, live).await?;
    db.beat_gateway_tree(&peer, &tree).await?;
    let during = db.gateway_tree_is_live(&me, &tree, live).await?;
    let own = db.gateway_tree_is_live(&peer, &tree, live).await?;
    db.forget_gateway_tree(&peer).await?;
    let after = db.gateway_tree_is_live(&me, &tree, live).await?;
    t.line(
        "trees.live before, during, own mark, after",
        format!("{before},{during},{own},{after}"),
    );
    t.line(
        "trees.applied tree",
        db.policy_tree_was_applied(&tree).await?,
    );
    db.audit(
        "gitops",
        "data_source.applied",
        "policies",
        serde_json::json!({ "sha256": tree }),
    )
    .await?;
    t.line(
        "trees.applied tree after its audit row",
        db.policy_tree_was_applied(&tree).await?,
    );
    Ok(())
}

#[tokio::test]
async fn every_backend_gives_the_same_answers() -> TestResult {
    let backends = proxyx_db::testing::configured();
    if backends.is_empty() {
        eprintln!("SKIP: no test database is configured (see crates/store/tests/contract.rs)");
        return Ok(());
    }
    let mut transcripts: Vec<(Backend, Vec<String>)> = Vec::new();
    for backend in backends {
        let Some((db, raw)) = db_on(backend, "contract", true).await? else {
            continue;
        };
        let mut t = Transcript::default();
        scenario(&db, &raw, &mut t).await?;
        transcripts.push((backend, t.0));
    }
    let want: Vec<&str> = CONTRACT.lines().collect();
    for (backend, got) in &transcripts {
        if want.is_empty() {
            eprintln!("--- transcript of {backend}\n{}\n---", got.join("\n"));
        }
        for (n, line) in got.iter().enumerate() {
            assert_eq!(
                Some(line.as_str()),
                want.get(n).copied(),
                "{backend}: line {n} differs from the contract"
            );
        }
        assert_eq!(
            got.len(),
            want.len(),
            "{backend}: the transcript has another length"
        );
    }
    // Pairwise as well: a line that is wrong in the same way everywhere fails
    // above, one that differs between two backends fails here with both named.
    if let Some((first, reference)) = transcripts.first() {
        for (backend, got) in &transcripts[1..] {
            assert_eq!(got, reference, "{backend} differs from {first}");
        }
    }
    Ok(())
}

/// Org blocks keep a Redis cache: needs `PROXYX_TEST_REDIS_URL`.
#[tokio::test]
async fn org_blocks_behave_the_same_on_every_backend() -> TestResult {
    let Some(hot) = support::hot().await? else {
        return Ok(());
    };
    for backend in proxyx_db::testing::configured() {
        let Some((db, raw)) = db_on(backend, "contract_blocks", false).await? else {
            continue;
        };
        let o = org(&uniq("blk"))?;
        let scope = BlockScope::Pool(Pool::Shared);
        let block = db
            .create_org_block(&hot, &o, &scope, "abuse", "ops", None)
            .await?;
        assert_eq!(
            hot.org_blocks(&o).await?,
            vec!["pool:shared".to_owned()],
            "{backend}"
        );
        let too_late = db
            .create_org_block(
                &hot,
                &o,
                &scope,
                "x",
                "ops",
                Some(OffsetDateTime::now_utc() - time::Duration::hours(1)),
            )
            .await;
        assert!(matches!(too_late, Err(StoreError::Invalid(_))), "{backend}");
        assert!(
            db.active_org_blocks(OffsetDateTime::now_utc())
                .await?
                .iter()
                .any(|b| b.id == block.id),
            "{backend}"
        );

        let revoked = db.revoke_org_block(&hot, block.id, "ops").await?;
        assert!(revoked.is_some_and(|b| b.revoked_at.is_some()), "{backend}");
        assert!(hot.org_blocks(&o).await?.is_empty(), "{backend}");
        assert!(
            db.revoke_org_block(&hot, uuid::Uuid::new_v4(), "ops")
                .await?
                .is_none(),
            "{backend}"
        );
        // A block another process revoked: the cache is stale until a resync.
        let again = db
            .create_org_block(&hot, &o, &scope, "again", "ops", None)
            .await?;
        raw.execute(
            "UPDATE org_blocks SET revoked_at = ? WHERE id = ?",
            &[OffsetDateTime::now_utc().into(), again.id.into()],
        )
        .await?;
        assert_eq!(hot.org_blocks(&o).await?.len(), 1, "{backend}: stale cache");
        db.resync_org_block(&hot, &o, &scope).await?;
        assert!(hot.org_blocks(&o).await?.is_empty(), "{backend}");
    }
    Ok(())
}
