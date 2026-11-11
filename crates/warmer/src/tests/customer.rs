//! Customer upstreams in the static loop: an org-owned unit is checked with
//! its owner's stored login, its entry is an address (not an expected exit
//! IP), and it is never scored or replaced.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use common::Secret;
use common::types::{InventoryEntry, IpState, Kind, OrgId, Subtype};
use store::{CustomerLogin, LeaseOutcome, UnitRecord};

use super::support::{Harness, Setup, TestResult, harness, unit};

fn customer_adapter(_port: u16) -> String {
    r#"
[[adapter]]
id = "cust"
kind = "static"
subtype = "datacenter"
credentials_optional = true
user = "{base_user}"
pass = "{base_pass}"
"#
    .to_owned()
}

const EXIT: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 55);
/// The upstream's address, which is the row key.
const ADDRESS: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

async fn start() -> TestResult<Option<Harness>> {
    Harness::start(Setup {
        two_scorers: true,
        ..Setup::new(customer_adapter, "min_ready = 2\n", "")
    })
    .await
}

/// The org's upstream: the fake provider, logged in as `user`.
async fn set_upstream(h: &Harness, org: &OrgId, user: &str) -> TestResult {
    let entry = InventoryEntry {
        provider: "cust".parse()?,
        subtype: Subtype::Datacenter,
        plan: "customer".into(),
        ip: ADDRESS,
        host: "127.0.0.1".into(),
        port: h.fake.port,
        region: "fr".parse()?,
        asn: None,
        credentials: None,
        box_handle: None,
        rental_end: None,
    };
    let login = CustomerLogin {
        username: Secret::new(user),
        password: Secret::new("pw"),
    };
    h.db.set_customer_upstream(org, &entry, Some(&login), "test")
        .await?;
    h.reload().await
}

async fn lease(h: &Harness, org: &OrgId, sticky: &str) -> TestResult<LeaseOutcome> {
    let p = h.partition("cust")?;
    let ttl = Duration::from_secs(60);
    h.lease(&p, Kind::Static, org.as_str(), sticky, ttl).await
}

/// What `POST /v1/orgs/{org}/upstream/validate` does after a passing check:
/// the row turns available and the unit becomes leasable by its owner.
async fn validate(h: &Harness, org: &OrgId, exit: Ipv4Addr) -> TestResult {
    let upstream = h.db.customer_upstream(org).await?.ok_or("unit")?;
    let row =
        h.db.customer_validated(org, upstream.version, IpAddr::V4(exit), "op")
            .await?;
    let record = UnitRecord {
        owner: Some(org.clone()),
        ..unit(&row.entry.ip.to_string(), IpAddr::V4(exit))
    };
    h.hot.ready_put(&row.partition(), &record).await?;
    Ok(())
}

#[tokio::test]
async fn a_customer_candidate_stays_a_candidate_until_validated() -> TestResult {
    let h = harness!(start());
    let (acme, other): (OrgId, OrgId) = ("acme".parse()?, "other".parse()?);
    set_upstream(&h, &acme, "cust-user").await?;
    h.fake.set_user_ip("cust-user", EXIT);
    assert_eq!(lease(&h, &acme, "s").await?, LeaseOutcome::Empty);

    // The check passes (it is recorded), but only `validate` makes the unit
    // leasable.
    h.static_tick().await;
    h.static_tick().await;
    let r = h.row(ADDRESS).await?;
    assert_eq!(r.state, IpState::Candidate);
    assert!(r.last_check_at.is_some(), "the check ran");
    assert_eq!(lease(&h, &acme, "s").await?, LeaseOutcome::Empty);

    validate(&h, &acme, EXIT).await?;
    // A shared IP whose exit differs from its entry is quarantined; an owned
    // unit's entry is only its address.
    let r = h.row(ADDRESS).await?;
    assert_eq!(r.state, IpState::Available);
    assert_eq!(r.exit_ip, Some(IpAddr::V4(EXIT)));
    assert_eq!(r.entry.ip, ADDRESS);

    // Leasable by its owner, with the exit IP the check saw; nobody else's.
    let LeaseOutcome::Free(grant) = lease(&h, &acme, "s").await? else {
        return Err("the owner should get the unit".into());
    };
    assert_eq!(grant.ip, IpAddr::V4(EXIT));
    assert_eq!(lease(&h, &other, "s").await?, LeaseOutcome::Empty);
    Ok(())
}

#[tokio::test]
async fn a_customer_candidate_whose_upstream_does_not_answer_stays_a_candidate() -> TestResult {
    let h = harness!(start());
    let acme: OrgId = "acme".parse()?;
    set_upstream(&h, &acme, "cust-user").await?;
    h.fake.set_down(true);
    h.static_tick().await;
    assert_eq!(h.row(ADDRESS).await?.state, IpState::Candidate);
    assert_eq!(lease(&h, &acme, "s").await?, LeaseOutcome::Empty);
    Ok(())
}

#[tokio::test]
async fn a_customer_unit_follows_a_changed_exit_ip_and_is_never_scored_or_replaced() -> TestResult {
    let h = harness!(start());
    let acme: OrgId = "acme".parse()?;
    set_upstream(&h, &acme, "cust-user").await?;
    h.fake.set_user_ip("cust-user", EXIT);
    h.static_tick().await;
    validate(&h, &acme, EXIT).await?;
    assert_eq!(h.row(ADDRESS).await?.state, IpState::Available);

    // The customer's proxy moves to another exit IP and every scorer calls it
    // bad: a shared IP would be cooled and replaced; the customer's is not.
    let moved = Ipv4Addr::new(203, 0, 113, 77);
    h.fake.set_user_ip("cust-user", moved);
    h.fake.set_default_risk(95);
    h.make_stale(ADDRESS).await?;
    h.static_tick().await;

    let r = h.row(ADDRESS).await?;
    assert_eq!(r.state, IpState::Available);
    assert_eq!(r.exit_ip, Some(IpAddr::V4(moved)));
    assert!(
        h.db.recent_scores(IpAddr::V4(moved), 3).await?.is_empty(),
        "no reputation check for the customer's own IP"
    );
    // The unit record reports the new exit IP to the gateway's reply header.
    let LeaseOutcome::Free(grant) = lease(&h, &acme, "s").await? else {
        return Err("the owner should get the unit".into());
    };
    assert_eq!(grant.ip, IpAddr::V4(moved));
    Ok(())
}
