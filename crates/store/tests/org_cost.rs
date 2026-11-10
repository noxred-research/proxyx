//! The per-org byte meter. Needs the local Redis.

#[macro_use]
mod support;

use std::time::Duration;

use support::{TestResult, assert_ttl, org, raw_redis, uniq, uniq_org};
use time::OffsetDateTime;

#[tokio::test]
async fn the_org_meter_sums_bytes_per_utc_day_and_org() -> TestResult {
    let hot = hot_or_skip!();
    let (a, b) = (uniq_org("m")?, uniq_org("n")?);
    let day1 = OffsetDateTime::from_unix_timestamp(10 * 86_400 + 5)?;
    let day2 = OffsetDateTime::from_unix_timestamp(11 * 86_400)?;
    assert_eq!(hot.org_cost_used(&a, day1).await?, 0);
    hot.org_cost_add(&a, 700, day1).await?;
    hot.org_cost_add(&a, 300, day1).await?;
    hot.org_cost_add(&a, 0, day1).await?;
    hot.org_cost_add(&a, 9, day2).await?;
    assert_eq!(hot.org_cost_used(&a, day1).await?, 1_000);
    assert_eq!(hot.org_cost_used(&a, day2).await?, 9);
    assert_eq!(hot.org_cost_used(&b, day1).await?, 0);
    Ok(())
}

#[tokio::test]
async fn the_org_meter_expires() -> TestResult {
    let hot = hot_or_skip!();
    let name = uniq("ttl");
    let acme = org(&name)?;
    let at = OffsetDateTime::from_unix_timestamp(10 * 86_400 + 5)?;
    hot.org_cost_add(&acme, 5, at).await?;
    let key = format!("ocost:{{{name}}}:bytes:10");
    assert_ttl(
        &mut raw_redis().await?,
        &key,
        Duration::from_secs(2 * 86_400),
    )
    .await?;
    Ok(())
}
