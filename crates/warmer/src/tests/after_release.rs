//! `rotating.after_release` in the sweeper: a session whose leases ran out is
//! drained or kept for the org that used it.

use std::time::Duration;

use common::types::Kind;
use store::LeaseOutcome;

use super::support::{Harness, Setup, TestResult, harness, rotating_adapter, unit};

#[tokio::test]
async fn a_session_whose_leases_ran_out_is_drained_or_kept_for_its_org_by_the_policy() -> TestResult
{
    for (after, ready) in [("drain", false), ("reuse_same_org", true)] {
        let h = harness!(Harness::start(Setup::new(
            rotating_adapter,
            "min_ready = 0\nmax_ready = 5\n",
            &format!("[policy.rotating]\nafter_release = \"{after}\"\n"),
        )));
        let p = h.partition("rot")?;
        h.hot
            .ready_put(&p, &unit("unit-1", "198.51.100.1".parse()?))
            .await?;
        let grant = h
            .lease_free(&p, Kind::Rotating, "acme", "s", Duration::from_millis(150))
            .await?;
        h.hot.tunnel_close(&grant.tunnel).await?;

        h.w.sweep_tick().await;
        assert!(
            h.hot.is_ready(&p, "unit-1").await?,
            "{after}: the lease is alive, nothing happens yet"
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
        h.w.sweep_tick().await;

        assert_eq!(h.hot.is_ready(&p, "unit-1").await?, ready, "{after}");
        let ttl = Duration::from_secs(60);
        assert_eq!(
            h.lease(&p, Kind::Rotating, "other", "s", ttl).await?,
            LeaseOutcome::Empty,
            "{after}: another org never gets it"
        );
        let again = h.lease(&p, Kind::Rotating, "acme", "s", ttl).await?;
        assert_eq!(matches!(again, LeaseOutcome::Free(_)), ready, "{after}");
    }
    Ok(())
}
