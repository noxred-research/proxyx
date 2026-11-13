//! Pool hot state on a Redis (or Valkey) instance shared with another product.
//!
//! The pool's keys carry no prefix: a deployment that shares an instance gives
//! each product its own database index in the URL (`redis://host:6379/3`), or
//! its own instance. This pins that two indexes of one server do not see each
//! other's pool state, and that the pool never needs a server-wide command.

mod support;

use proxyx_store::{Hot, UnitRecord};
use support::{TestResult, ip, partition};

fn with_index(url: &str, index: u32) -> String {
    let (scheme, rest) = url.split_once("://").expect("scheme");
    let authority = rest.split('/').next().unwrap_or(rest);
    format!("{scheme}://{authority}/{index}")
}

#[tokio::test]
async fn two_database_indexes_on_one_server_hold_separate_pool_state() -> TestResult {
    let Ok(base) = std::env::var("PROXYX_TEST_REDIS_URL") else {
        eprintln!("SKIP: PROXYX_TEST_REDIS_URL is not set");
        return Ok(());
    };
    let first = Hot::connect(&with_index(&base, 4)).await?;
    let second = Hot::connect(&with_index(&base, 5)).await?;
    let p = partition()?;
    first.ready_put(&p, &UnitRecord::static_ip(ip(1))).await?;
    assert_eq!(first.ready_ids(&p).await?.len(), 1);
    assert!(
        second.ready_ids(&p).await?.is_empty(),
        "the other index of the same server does not see the unit"
    );
    // taking it in one index leaves the other's state alone
    second.ready_put(&p, &UnitRecord::static_ip(ip(2))).await?;
    let id = first.ready_ids(&p).await?.remove(0);
    assert!(first.ready_take(&p, &id).await?);
    assert!(first.ready_ids(&p).await?.is_empty());
    assert_eq!(second.ready_ids(&p).await?.len(), 1);
    // clean up the two units this test created, by key, not by flushing
    let second_id = second.ready_ids(&p).await?.remove(0);
    assert!(second.ready_take(&p, &second_id).await?);
    Ok(())
}
