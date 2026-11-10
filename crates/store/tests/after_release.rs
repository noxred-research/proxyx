//! `rotating.after_release`: what becomes of a rotating session when its last
//! lease ends, by release or by expiry.

#[macro_use]
mod support;

use std::time::Duration;

use common::types::{Kind, OrgId, Partition};
use policy::AfterRelease;
use proxyx_store::{Hot, LeaseLimits, LeaseOutcome, ReleaseRule};
use support::{
    Call, TestResult, grant, ip, lease, limits, org, partition, session_unit, static_call,
};
use time::OffsetDateTime;

async fn one_session(hot: &Hot) -> Result<Partition, Box<dyn std::error::Error>> {
    let p = partition()?;
    let expires_at = OffsetDateTime::now_utc() + time::Duration::hours(1);
    let unit = session_unit("s1", ip(1), Some(expires_at), Duration::from_secs(7200));
    hot.ready_put(&p, &unit).await?;
    Ok(p)
}

fn rotating<'a>(p: &'a Partition, org: &'a OrgId) -> Call<'a> {
    Call {
        kind: Kind::Rotating,
        ..static_call(p, org, "s")
    }
}

async fn take(
    hot: &Hot,
    p: &Partition,
    org: &OrgId,
) -> Result<LeaseOutcome, Box<dyn std::error::Error>> {
    lease(hot, &rotating(p, org)).await
}

/// The tunnel closes, then the lease is released, as the gateway does.
async fn end_lease(
    hot: &Hot,
    p: &Partition,
    org: &OrgId,
    outcome: &LeaseOutcome,
    rule: Option<ReleaseRule<'_>>,
) -> TestResult {
    hot.tunnel_close(&grant(outcome)?.tunnel).await?;
    assert!(hot.release(p, org, "s", rule).await?);
    Ok(())
}

#[tokio::test]
async fn drain_takes_a_released_session_out_of_the_ready_set_for_every_org() -> TestResult {
    let hot = hot_or_skip!();
    let p = one_session(&hot).await?;
    let (a, b, probe) = (org("a")?, org("b")?, org("probe")?);
    let rule = ReleaseRule {
        after: AfterRelease::Drain,
        probe_org: &probe,
    };
    let g = take(&hot, &p, &a).await?;
    end_lease(&hot, &p, &a, &g, Some(rule)).await?;

    assert!(!hot.is_ready(&p, "s1").await?, "the session is burnt");
    assert_eq!(take(&hot, &p, &b).await?, LeaseOutcome::Empty);
    assert_eq!(
        take(&hot, &p, &a).await?,
        LeaseOutcome::Empty,
        "even its own org gets a new session"
    );
    Ok(())
}

#[tokio::test]
async fn reuse_same_org_keeps_a_released_session_for_the_org_that_used_it() -> TestResult {
    let hot = hot_or_skip!();
    let p = one_session(&hot).await?;
    let (a, b, probe) = (org("a")?, org("b")?, org("probe")?);
    let rule = ReleaseRule {
        after: AfterRelease::ReuseSameOrg,
        probe_org: &probe,
    };
    let g = take(&hot, &p, &a).await?;
    end_lease(&hot, &p, &a, &g, Some(rule)).await?;

    assert!(hot.is_ready(&p, "s1").await?);
    assert_eq!(
        take(&hot, &p, &b).await?,
        LeaseOutcome::Empty,
        "another org cannot take it"
    );
    let again = take(&hot, &p, &a).await?;
    assert!(matches!(again, LeaseOutcome::Free(_)), "{again:?}");
    assert_eq!(grant(&again)?.unit, "s1");
    Ok(())
}

#[tokio::test]
async fn a_session_that_another_lease_still_holds_is_left_alone() -> TestResult {
    let hot = hot_or_skip!();
    let p = one_session(&hot).await?;
    let (a, b, probe) = (org("a")?, org("b")?, org("probe")?);
    let rule = ReleaseRule {
        after: AfterRelease::Drain,
        probe_org: &probe,
    };
    let ga = take(&hot, &p, &a).await?;
    let gb = take(&hot, &p, &b).await?;
    assert!(matches!(gb, LeaseOutcome::Shared(_)));
    end_lease(&hot, &p, &a, &ga, Some(rule)).await?;
    assert!(hot.is_ready(&p, "s1").await?, "b still uses it");
    end_lease(&hot, &p, &b, &gb, Some(rule)).await?;
    assert!(!hot.is_ready(&p, "s1").await?, "the last lease burns it");
    Ok(())
}

#[tokio::test]
async fn a_session_the_probe_org_used_is_not_burnt_by_its_sample() -> TestResult {
    let hot = hot_or_skip!();
    let p = one_session(&hot).await?;
    let (b, probe) = (org("b")?, org("probe")?);
    let rule = ReleaseRule {
        after: AfterRelease::Drain,
        probe_org: &probe,
    };
    let g = take(&hot, &p, &probe).await?;
    end_lease(&hot, &p, &probe, &g, Some(rule)).await?;
    assert!(hot.is_ready(&p, "s1").await?);
    let next = take(&hot, &p, &b).await?;
    assert!(matches!(next, LeaseOutcome::Free(_)), "{next:?}");
    Ok(())
}

#[tokio::test]
async fn an_expired_lease_applies_the_rule_in_the_sweep() -> TestResult {
    let hot = hot_or_skip!();
    let (a, b, probe) = (org("a")?, org("b")?, org("probe")?);
    for (after, ready, b_may_lease) in [
        (None, true, true),
        (Some(AfterRelease::ReuseSameOrg), true, false),
        (Some(AfterRelease::Drain), false, false),
    ] {
        let p = one_session(&hot).await?;
        let short = Call {
            limits: LeaseLimits {
                lease_ttl: Duration::from_millis(150),
                ..limits()
            },
            ..rotating(&p, &a)
        };
        let g = lease(&hot, &short).await?;
        hot.tunnel_close(&grant(&g)?.tunnel).await?;
        // the lease is still alive: nothing to reclaim yet
        let rule = after.map(|after| ReleaseRule {
            after,
            probe_org: &probe,
        });
        assert_eq!(hot.sweep(&p, rule).await?.leases, 0);
        assert!(hot.is_ready(&p, "s1").await?);

        tokio::time::sleep(Duration::from_millis(250)).await;
        hot.sweep(&p, rule).await?;
        assert_eq!(hot.is_ready(&p, "s1").await?, ready, "{after:?}");
        let theirs = take(&hot, &p, &b).await?;
        assert_eq!(
            matches!(theirs, LeaseOutcome::Free(_)),
            b_may_lease,
            "{after:?}: {theirs:?}"
        );
    }
    Ok(())
}
