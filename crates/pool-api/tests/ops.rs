//! `/readyz` and the `redis_down` gauge against a real Redis (skipped when unset).

#[macro_use]
mod support;

use std::sync::Arc;
use std::time::Duration;

use proxyx_pool_api::{OpsDeps, OpsState, serve_ops_on};
use store::Hot;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use support::{Options, TestResult, harness, harness_with};

#[tokio::test]
async fn readyz_is_503_until_the_dependencies_arrive_then_200_with_redis_up() -> TestResult {
    let h = or_skip!(harness("ops").await?);
    let (tx, rx) = watch::channel(None);
    let state = Arc::new(OpsState::new(h.metrics.clone(), rx));
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let cancel = CancellationToken::new();
    tokio::spawn(serve_ops_on(listener, state, cancel.clone()));

    let url = format!("http://{addr}/readyz");
    let starting = reqwest::get(&url).await?;
    assert_eq!(starting.status(), 503);
    assert_eq!(starting.text().await?, "starting");

    tx.send(Some(OpsDeps {
        db: h.db.clone(),
        hot: h.hot.clone(),
        loaded: h.loaded.clone(),
    }))?;
    let ready = reqwest::get(&url).await?;
    assert_eq!(ready.status(), 200);
    assert_eq!(h.metrics.redis_down.get(), 0);

    let metrics = reqwest::get(format!("http://{addr}/metrics"))
        .await?
        .text()
        .await?;
    assert!(
        metrics.contains("proxyx_pool_snapshot_age_seconds"),
        "the snapshot age is refreshed on scrape"
    );
    cancel.cancel();
    Ok(())
}

/// The gauge follows Redis on its own tick: nobody probes `/readyz` here.
#[tokio::test]
async fn redis_down_follows_redis_without_a_readiness_probe() -> TestResult {
    let h = or_skip!(
        harness_with(
            "ops_gauge",
            Options {
                redis_proxy: true,
                ..Options::default()
            },
        )
        .await?
    );
    let proxy = h.proxy.as_ref().ok_or("no proxy")?;
    let hot = Hot::connect(proxy.url()).await?;
    let (_tx, rx) = watch::channel(Some(OpsDeps {
        db: h.db.clone(),
        hot,
        loaded: h.loaded.clone(),
    }));
    let state = Arc::new(
        OpsState::new(h.metrics.clone(), rx).with_redis_check_every(Duration::from_millis(100)),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let cancel = CancellationToken::new();
    tokio::spawn(serve_ops_on(listener, state, cancel.clone()));

    let metrics = h.metrics.clone();
    let settled = |want: i64| {
        let metrics = metrics.clone();
        async move {
            for _ in 0..100 {
                if metrics.redis_down.get() == want {
                    return true;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            false
        }
    };
    // an outage that was noted by a failing call stays until a check clears it
    metrics.redis_down.set(1);
    assert!(settled(0).await, "a healthy Redis clears the gauge");
    proxy.cut();
    assert!(settled(1).await, "a cut Redis raises it");
    proxy.restore();
    assert!(settled(0).await, "a restored Redis clears it again");
    cancel.cancel();
    Ok(())
}
