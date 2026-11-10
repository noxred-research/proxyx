//! The rest between orgs also holds when the leases of the first org end by
//! their ttl and not by a release.

#[macro_use]
mod support;

use std::time::Duration;

use proxyx_store::LeaseOutcome;
use support::{Call, TestResult, granted, lease, limits, org, seeded_partition, static_call};

const LEASE_TTL: Duration = Duration::from_millis(300);

fn call<'a>(
    p: &'a common::types::Partition,
    o: &'a common::types::OrgId,
    sticky: &'a str,
) -> Call<'a> {
    let mut l = limits();
    l.lease_ttl = LEASE_TTL;
    l.rest_after_release = Duration::from_secs(60);
    Call {
        limits: l,
        ..static_call(p, o, sticky)
    }
}

/// `a` leases two units and its leases run out while the tunnels are open;
/// the tunnels then close, with no release.
#[tokio::test]
async fn units_whose_leases_expired_while_their_tunnels_ran_rest_after_the_tunnels_close()
-> TestResult {
    let hot = hot_or_skip!();
    let p = seeded_partition(&hot, &[1, 2, 3]).await?;
    let (a, b) = (org("a")?, org("b")?);
    let g1 = granted(&hot, &call(&p, &a, "s1")).await?;
    let g2 = granted(&hot, &call(&p, &a, "s2")).await?;
    assert_ne!(g1.unit, g2.unit);
    tokio::time::sleep(LEASE_TTL + Duration::from_millis(200)).await;
    hot.tunnel_close(&g1.tunnel).await?;
    hot.tunnel_close(&g2.tunnel).await?;

    // The third unit never was a's: every lease of b goes there, none breaks the rest.
    let mut units = std::collections::HashSet::new();
    for sticky in ["b1", "b2", "b3"] {
        let g = granted(&hot, &call(&p, &b, sticky)).await?;
        assert_eq!(g.broke, None, "{sticky}");
        units.insert(g.unit);
    }
    assert_eq!(units.len(), 1, "{units:?}");
    assert!(!units.contains(&g1.unit) && !units.contains(&g2.unit));
    Ok(())
}

/// The same with the tunnels closed first and the leases running out later.
#[tokio::test]
async fn units_whose_leases_expire_after_their_tunnels_closed_rest_too() -> TestResult {
    let hot = hot_or_skip!();
    let p = seeded_partition(&hot, &[1, 2]).await?;
    let (a, b) = (org("a")?, org("b")?);
    let g1 = granted(&hot, &call(&p, &a, "s1")).await?;
    let g2 = granted(&hot, &call(&p, &a, "s2")).await?;
    hot.tunnel_close(&g1.tunnel).await?;
    hot.tunnel_close(&g2.tunnel).await?;
    tokio::time::sleep(LEASE_TTL + Duration::from_millis(200)).await;

    // Only units a held last are left: b takes one and breaks the rest.
    let early = lease(&hot, &call(&p, &b, "b1")).await?;
    assert!(matches!(early, LeaseOutcome::Free(_)), "{early:?}");
    assert_eq!(support::grant(&early)?.broke, Some("rest"));
    Ok(())
}
