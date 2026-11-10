//! Regressions of the review fixes in the control API (real Redis and
//! Postgres): block signals for units whose exit IP is not their key,
//! a retried batch that does not count twice, and the canary promotion.

#[macro_use]
mod support;

use std::net::IpAddr;

use common::Secret;
use common::types::{InventoryEntry, IpState, Partition, Subtype, Target, Tier};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use store::{CustomerLogin, UnitRecord};
use support::*;

fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

fn target(host: &str) -> Target {
    Target {
        host: host.to_owned(),
        port: 0,
    }
}

fn event(session: &str, exit: IpAddr, host: &str, time: i64) -> Value {
    json!({ "session": session, "exit_ip": exit, "target": format!("{host}:443"),
            "type": "challenge", "time": time })
}

fn three_targets(session: &str, exit: IpAddr) -> Value {
    Value::Array(
        ["a.test", "b.test", "c.test"]
            .iter()
            .map(|host| event(session, exit, host, now()))
            .collect(),
    )
}

async fn post_signals(h: &Harness, key: &str, body: Value) -> (StatusCode, Value) {
    h.send(
        Method::POST,
        "/v1/block-signals",
        Some(&basic("client", key)),
        Some(body),
    )
    .await
}

fn count(h: &Harness, scope: &str) -> u64 {
    h.metrics
        .block_signals_total
        .with_label_values(&["client", "challenge", scope])
        .get()
}

/// A SIM box: the tunnel's session says the unit is the row key and the exit
/// IP is what the box has now. The signal must cool the box and ask for its
/// reset, with blocks and cooldowns keyed by the exit IP.
#[tokio::test]
async fn a_signal_for_a_sim_box_cools_its_row_though_the_exit_ip_is_not_its_key() -> TestResult {
    let h = or_skip!(harness("hardening_box").await?);
    let (acme, p) = (org(&uniq("acme")), h.partition());
    let key = h.org_key(&acme).await?;
    let ips = h.seed_ips_of(2, Subtype::MobileBox).await?;
    let (unit, exit): (IpAddr, IpAddr) = (ips[0], "198.51.100.77".parse()?);
    h.db.record_check(unit, Some(exit), time::OffsetDateTime::now_utc())
        .await?;
    let session = h.session(&acme, &unit.to_string(), exit).await?;

    let (status, out) = post_signals(&h, &key, three_targets(&session, exit)).await;
    assert_eq!(status, StatusCode::OK, "{out}");
    assert_eq!(out["accepted"], 3, "{out}");

    assert_eq!(h.state_of(unit).await, IpState::Cooldown);
    assert!(!h.hot.ready_ids(&p).await?.contains(&unit.to_string()));
    assert!(
        h.hot.ready_ids(&p).await?.contains(&ips[1].to_string()),
        "the other box keeps serving"
    );
    let audit = h.db.audit_for(&unit.to_string(), 10).await?;
    assert!(
        audit.iter().any(|a| a.action == "ip.rotate_requested"),
        "the box is flagged for a reset: {audit:?}"
    );
    // blocks and cooldowns use the exit IP the tunnel had, which is what the
    // unit record carries
    assert!(h.hot.is_cooled(&p, exit, &target("a.test")).await?);
    assert_eq!(h.db.blocked_targets_since(exit, past()).await?, 3);
    assert_eq!(count(&h, "ip"), 1);
    Ok(())
}

fn past() -> time::OffsetDateTime {
    time::OffsetDateTime::now_utc() - time::Duration::hours(1)
}

const CUSTOMER_PROVIDER: &str = "customer";

/// An org's own upstream: its row is keyed by a unit key, and the unit record
/// stands for the exit IP the validation saw.
async fn customer_unit(
    h: &Harness,
    org: &common::types::OrgId,
    key: u8,
    exit: IpAddr,
) -> Result<IpAddr, Box<dyn std::error::Error>> {
    let address: IpAddr = format!("fd00::{key:x}").parse()?;
    let entry = InventoryEntry {
        provider: CUSTOMER_PROVIDER.parse()?,
        subtype: Subtype::Datacenter,
        plan: "customer".into(),
        ip: address,
        host: "up.example".into(),
        port: 3128,
        region: "fr".parse()?,
        asn: None,
        credentials: None,
        box_handle: None,
        rental_end: None,
    };
    let login = CustomerLogin {
        username: Secret::new("svc"),
        password: Secret::new("pw"),
    };
    h.db.set_customer_upstream(org, &entry, Some(&login), "test")
        .await?;
    let version = h.db.customer_upstream(org).await?.ok_or("unit")?.version;
    let row = h.db.customer_validated(org, version, exit, "op").await?;
    h.hot
        .ready_put(
            &row.partition(),
            &UnitRecord {
                id: address.to_string(),
                ip: exit,
                expires_at: None,
                ttl: None,
                owner: Some(org.clone()),
            },
        )
        .await?;
    Ok(address)
}

fn customer_partition() -> Result<Partition, Box<dyn std::error::Error>> {
    Ok(Partition {
        provider: CUSTOMER_PROVIDER.parse()?,
        region: "fr".parse()?,
    })
}

async fn customer_session(
    h: &Harness,
    org: &common::types::OrgId,
    unit: IpAddr,
    exit: IpAddr,
) -> Result<String, Box<dyn std::error::Error>> {
    let id = uniq("sess");
    h.hot
        .session_put(
            &id,
            &store::SessionRecord {
                org: org.clone(),
                partition: customer_partition()?,
                unit: unit.to_string(),
                ip: exit,
            },
            std::time::Duration::from_secs(600),
        )
        .await?;
    Ok(id)
}

/// A customer upstream is only cooled: the owner's unit rests in cooldown
/// however often it is blocked, nobody replaces or quarantines it, and a
/// cooled neighbour does not trip the pool guard for it.
#[tokio::test]
async fn a_signal_for_a_customer_upstream_cools_the_owners_unit_and_never_quarantines_it()
-> TestResult {
    let h = or_skip!(
        harness_with(
            "hardening_customer",
            Options {
                adapters_toml: Some(CUSTOMER_ADAPTERS),
                ..Options::default()
            },
        )
        .await?
    );
    let (acme, rival) = (org(&uniq("acme")), org(&uniq("rival")));
    let key = h.org_key(&acme).await?;
    let (exit, rival_exit): (IpAddr, IpAddr) = ("203.0.113.9".parse()?, "203.0.113.10".parse()?);
    let unit = customer_unit(&h, &acme, 1, exit).await?;
    let neighbour = customer_unit(&h, &rival, 2, rival_exit).await?;
    // the other customer's unit rests already: half of the "partition" is cooled
    h.db.transition_ip(
        neighbour,
        &store::Transition::to(IpState::Cooldown, "test")
            .cooldown_until(time::OffsetDateTime::now_utc() + std::time::Duration::from_secs(600)),
        "test",
    )
    .await?;
    let p = customer_partition()?;
    let session = customer_session(&h, &acme, unit, exit).await?;

    for round in 1..=4 {
        let (status, out) = post_signals(&h, &key, three_targets(&session, exit)).await;
        assert_eq!(status, StatusCode::OK, "{out}");
        assert_eq!(
            h.state_of(unit).await,
            IpState::Cooldown,
            "round {round}: cooled, never quarantined"
        );
        assert!(!h.hot.ready_ids(&p).await?.contains(&unit.to_string()));
        // the retest passes and the unit returns
        h.db.transition_ip(
            unit,
            &store::Transition::to(IpState::Available, "retest"),
            "test",
        )
        .await?;
        h.hot
            .ready_put(
                &p,
                &UnitRecord {
                    id: unit.to_string(),
                    ip: exit,
                    expires_at: None,
                    ttl: None,
                    owner: Some(acme.clone()),
                },
            )
            .await?;
        // fresh events for the next round
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    }
    assert_eq!(count(&h, "pool_guard"), 0);
    assert_eq!(h.db.blocked_targets_since(exit, past()).await?, 3);
    assert!(count(&h, "ip") >= 4, "every round escalated");
    Ok(())
}

/// The session proxy sends a batch again when it got a 5xx; an event that went
/// through the first time is not applied a second time.
#[tokio::test]
async fn a_batch_sent_again_does_not_count_its_events_twice() -> TestResult {
    let h = or_skip!(harness("hardening_retry").await?);
    let acme = org(&uniq("acme"));
    let key = h.org_key(&acme).await?;
    let ips = h.seed_ips(3).await?;
    let session = h.session(&acme, &ips[0].to_string(), ips[0]).await?;

    let batch = json!([
        event(&session, ips[0], "a.test", now()),
        event(&session, ips[0], "b.test", now()),
    ]);
    for _ in 0..2 {
        let (status, out) = post_signals(&h, &key, batch.clone()).await;
        assert_eq!(status, StatusCode::OK, "{out}");
        assert_eq!(out["accepted"], 2, "{out}");
    }
    assert_eq!(count(&h, "target"), 2, "applied once");
    assert_eq!(
        h.db.blocks_since(ips[0], past()).await?.len(),
        2,
        "two block rows, not four"
    );
    Ok(())
}

fn slow_canary(h: &Harness) -> Value {
    canary(h, 12_000)
}

fn fast_canary(h: &Harness) -> Value {
    canary(h, 800)
}

fn canary(h: &Harness, load_ms: u32) -> Value {
    let run = json!({ "target": "https://t.test/", "run": 1, "outcome": "ok", "status": 200,
                      "ttfb_ms": 100, "dom_content_loaded_ms": load_ms, "load_ms": load_ms });
    json!({ "kind": "canary", "route_class": "fr-web", "provider": h.provider,
            "region": "fr", "country": "fr", "session": "sid1",
            "started_at": "2026-10-15T10:00:00Z", "results": [run.clone(), run.clone(), run] })
}

/// A fast canary returns what the slow canary degraded. An IP the warmer
/// degraded on its own is the warmer's to return, in Postgres and in Redis.
#[tokio::test]
async fn a_fast_canary_leaves_an_ip_the_warmer_degraded_alone() -> TestResult {
    let h = or_skip!(harness("hardening_promote").await?);
    let p = h.partition();
    let ips = h.seed_ips(3).await?;
    let own = ips[2];
    // the warmer found this IP slow before any canary ran
    h.db.transition_ip(
        own,
        &store::Transition::to(IpState::Degraded, "slow"),
        "warmer",
    )
    .await?;
    h.hot.set_tier(&p, &own.to_string(), Tier::Degraded).await?;

    // the slow canary degrades the other two
    let (_, out) = h.probe_results(slow_canary(&h)).await;
    assert_eq!(out["degraded"], 3, "{out}");
    assert_eq!(h.state_of(own).await, IpState::Degraded);

    let (_, out) = h.probe_results(fast_canary(&h)).await;
    assert_eq!(out["verdict"]["ok"], true, "{out}");
    for ip in &ips[..2] {
        assert_eq!(h.state_of(*ip).await, IpState::Available, "{ip}");
        assert_eq!(h.hot.tier(&p, &ip.to_string()).await?, Tier::Normal);
    }
    assert_eq!(
        h.state_of(own).await,
        IpState::Degraded,
        "the warmer's own verdict stands"
    );
    assert_eq!(h.hot.tier(&p, &own.to_string()).await?, Tier::Degraded);
    assert_eq!(out["promoted"], 2, "{out}");
    Ok(())
}
