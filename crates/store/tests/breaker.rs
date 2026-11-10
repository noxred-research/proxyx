//! The shared breaker of a route class: opens on failures in a window, one
//! probe at a time, a failed probe doubles the wait, passes close it.

#[macro_use]
mod support;

use std::time::Duration;

use common::retry::{BreakerConfig, BreakerState};
use proxyx_store::Admit;
use support::{TestResult, partition};
use tokio::time::sleep;

fn cfg() -> BreakerConfig {
    BreakerConfig {
        failures_to_open: 3,
        window: Duration::from_millis(300),
        first_probe_after: Duration::from_millis(120),
        max_probe_after: Duration::from_millis(250),
        passes_to_close: 2,
    }
}

#[tokio::test]
async fn failures_open_it_only_inside_the_window() -> TestResult {
    let hot = hot_or_skip!();
    let (p, cfg) = (partition()?, cfg());
    assert_eq!(
        hot.breaker_peek(&p, &cfg).await?,
        (BreakerState::Closed, Admit::Go)
    );

    hot.breaker_failure(&p, &cfg).await?;
    hot.breaker_failure(&p, &cfg).await?;
    sleep(Duration::from_millis(350)).await;
    // the two old failures left the window: this is the first of a new one
    assert_eq!(hot.breaker_failure(&p, &cfg).await?, BreakerState::Closed);
    assert_eq!(hot.breaker_failure(&p, &cfg).await?, BreakerState::Closed);
    assert_eq!(hot.breaker_failure(&p, &cfg).await?, BreakerState::Open);
    assert_eq!(
        hot.breaker_peek(&p, &cfg).await?,
        (BreakerState::Open, Admit::Blocked),
        "no probe is due right after opening"
    );

    // another route class of the same provider is not affected
    let other = common::types::Partition {
        provider: p.provider.clone(),
        region: "de".parse()?,
    };
    assert_eq!(hot.breaker_peek(&other, &cfg).await?.1, Admit::Go);
    Ok(())
}

#[tokio::test]
async fn one_probe_at_a_time_and_a_failed_probe_doubles_the_wait_up_to_the_cap() -> TestResult {
    let hot = hot_or_skip!();
    let (p, cfg) = (partition()?, cfg());
    for _ in 0..3 {
        hot.breaker_failure(&p, &cfg).await?;
    }
    sleep(Duration::from_millis(150)).await;
    assert_eq!(
        hot.breaker_peek(&p, &cfg).await?,
        (BreakerState::Open, Admit::Probe),
        "peeking does not take the probe"
    );
    assert_eq!(
        hot.breaker_claim(&p, &cfg).await?,
        (BreakerState::HalfOpen, Admit::Probe)
    );
    assert_eq!(
        hot.breaker_claim(&p, &cfg).await?,
        (BreakerState::HalfOpen, Admit::Blocked),
        "the probe is taken"
    );

    // The probe fails: the wait doubles from 120 to 240 ms.
    assert_eq!(hot.breaker_failure(&p, &cfg).await?, BreakerState::Open);
    sleep(Duration::from_millis(160)).await;
    assert_eq!(hot.breaker_peek(&p, &cfg).await?.1, Admit::Blocked);
    sleep(Duration::from_millis(120)).await;
    assert_eq!(hot.breaker_claim(&p, &cfg).await?.1, Admit::Probe);

    // Failing again would double to 480 ms, but the cap is 250 ms.
    hot.breaker_failure(&p, &cfg).await?;
    sleep(Duration::from_millis(300)).await;
    assert_eq!(hot.breaker_peek(&p, &cfg).await?.1, Admit::Probe);
    Ok(())
}

#[tokio::test]
async fn passes_close_it_and_a_lost_probe_is_given_again() -> TestResult {
    let hot = hot_or_skip!();
    let (p, cfg) = (partition()?, cfg());
    for _ in 0..3 {
        hot.breaker_failure(&p, &cfg).await?;
    }
    sleep(Duration::from_millis(150)).await;

    assert_eq!(hot.breaker_claim(&p, &cfg).await?.1, Admit::Probe);
    assert_eq!(hot.breaker_success(&p, &cfg).await?, BreakerState::HalfOpen);
    // after a pass the next probe may go at once
    assert_eq!(hot.breaker_claim(&p, &cfg).await?.1, Admit::Probe);
    assert_eq!(hot.breaker_success(&p, &cfg).await?, BreakerState::Closed);
    assert_eq!(
        hot.breaker_peek(&p, &cfg).await?,
        (BreakerState::Closed, Admit::Go)
    );

    // Closed again with a clean window: two failures do not open it.
    hot.breaker_failure(&p, &cfg).await?;
    assert_eq!(hot.breaker_failure(&p, &cfg).await?, BreakerState::Closed);

    // A probe whose holder never reports is lost after `first_probe_after`.
    hot.breaker_failure(&p, &cfg).await?;
    sleep(Duration::from_millis(150)).await;
    assert_eq!(hot.breaker_claim(&p, &cfg).await?.1, Admit::Probe);
    assert_eq!(hot.breaker_claim(&p, &cfg).await?.1, Admit::Blocked);
    sleep(Duration::from_millis(150)).await;
    assert_eq!(hot.breaker_claim(&p, &cfg).await?.1, Admit::Probe);
    Ok(())
}
