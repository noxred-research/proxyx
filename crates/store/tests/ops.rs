//! Session registry, warm pause, sample jobs and verdicts (real Redis).

#[macro_use]
mod support;

use std::time::Duration;

use proxyx_store::{SampleJob, SessionRecord, StoreError, Verdict};
use support::{TestResult, assert_has_ttl, ip, org, partition, raw_redis, uniq};

fn session_record() -> Result<SessionRecord, Box<dyn std::error::Error>> {
    Ok(SessionRecord {
        org: org("acme")?,
        partition: partition()?,
        unit: "198.51.100.1".into(),
        ip: ip(1),
    })
}

fn assert_invalid<T: std::fmt::Debug>(result: Result<T, StoreError>) {
    assert!(
        matches!(result, Err(StoreError::Invalid(_))),
        "expected Invalid, got {result:?}"
    );
}

#[tokio::test]
async fn a_session_maps_back_to_its_org_until_it_expires() -> TestResult {
    let hot = hot_or_skip!();
    let id = uniq("sess");
    let rec = session_record()?;
    assert_eq!(hot.session_get(&id).await?, None);
    hot.session_put(&id, &rec, Duration::from_millis(300))
        .await?;
    assert_eq!(hot.session_get(&id).await?, Some(rec.clone()));
    tokio::time::sleep(Duration::from_millis(450)).await;
    assert_eq!(
        hot.session_get(&id).await?,
        None,
        "the registry forgets by itself"
    );

    assert_invalid(hot.session_put("", &rec, Duration::from_secs(1)).await);
    assert_invalid(hot.session_put(&id, &rec, Duration::ZERO).await);
    Ok(())
}

#[tokio::test]
async fn touching_a_session_pushes_its_expiry_out_but_never_creates_it() -> TestResult {
    let hot = hot_or_skip!();
    let id = uniq("sess");
    let rec = session_record()?;
    assert!(!hot.session_touch(&id, Duration::from_secs(60)).await?);
    assert_eq!(hot.session_get(&id).await?, None, "touch writes nothing");

    hot.session_put(&id, &rec, Duration::from_millis(300))
        .await?;
    assert!(hot.session_touch(&id, Duration::from_secs(60)).await?);
    tokio::time::sleep(Duration::from_millis(450)).await;
    assert_eq!(hot.session_get(&id).await?, Some(rec));

    assert_invalid(hot.session_touch(&id, Duration::ZERO).await);
    Ok(())
}

#[tokio::test]
async fn warm_pause_is_per_partition_and_ends_by_resume_or_ttl() -> TestResult {
    let hot = hot_or_skip!();
    let (a, b) = (partition()?, partition()?);
    assert!(!hot.warm_paused(&a).await?);
    hot.warm_pause(&a, Duration::from_secs(60)).await?;
    assert!(hot.warm_paused(&a).await?);
    assert!(!hot.warm_paused(&b).await?, "other partitions keep warming");
    assert!(hot.warm_resume(&a).await?);
    assert!(!hot.warm_resume(&a).await?, "nothing left to lift");

    hot.warm_pause(&b, Duration::from_millis(200)).await?;
    tokio::time::sleep(Duration::from_millis(350)).await;
    assert!(
        !hot.warm_paused(&b).await?,
        "a pause the canary never lifts still ends"
    );
    assert_invalid(hot.warm_pause(&a, Duration::ZERO).await);
    Ok(())
}

fn job(id: &str) -> Result<SampleJob, Box<dyn std::error::Error>> {
    Ok(SampleJob {
        job_id: id.into(),
        route_class: "fr-web".into(),
        provider: "oxy".parse()?,
        region: "fr".parse()?,
        sid: Some("cand".into()),
        targets: vec!["https://t.test/".into()],
    })
}

#[tokio::test]
async fn sample_jobs_are_listed_until_done_or_expired() -> TestResult {
    let hot = hot_or_skip!();
    let (keep, gone, short) = (uniq("job"), uniq("job"), uniq("job"));
    hot.sample_put(&job(&keep)?, Duration::from_secs(60))
        .await?;
    hot.sample_put(&job(&gone)?, Duration::from_secs(60))
        .await?;
    hot.sample_put(&job(&short)?, Duration::from_millis(200))
        .await?;
    assert_has_ttl(&mut raw_redis().await?, "samples:{probe}").await?;
    let ids = |jobs: Vec<SampleJob>| jobs.into_iter().map(|j| j.job_id).collect::<Vec<_>>();

    let pending = ids(hot.sample_pending().await?);
    assert!(
        [&keep, &gone, &short].iter().all(|id| pending.contains(id)),
        "{pending:?}"
    );

    assert!(hot.sample_done(&gone).await?);
    assert!(
        !hot.sample_done(&gone).await?,
        "a second result finds nothing"
    );
    tokio::time::sleep(Duration::from_millis(350)).await;
    let pending = ids(hot.sample_pending().await?);
    assert!(pending.contains(&keep));
    assert!(
        !pending.contains(&gone) && !pending.contains(&short),
        "{pending:?}"
    );
    hot.sample_done(&keep).await?;
    Ok(())
}

#[tokio::test]
async fn a_verdict_is_kept_under_its_key() -> TestResult {
    let hot = hot_or_skip!();
    let key = uniq("v");
    let v = Verdict {
        ok: false,
        success_ratio: 0.25,
        checked_at: 1_700_000_000,
        detail: "1 of 4".into(),
        slow: true,
    };
    assert_eq!(hot.verdict_get(&key).await?, None);
    hot.verdict_put(&key, &v, Duration::from_secs(60)).await?;
    assert_eq!(hot.verdict_get(&key).await?, Some(v));
    let other = Verdict {
        ok: true,
        success_ratio: 1.0,
        checked_at: 0,
        detail: String::new(),
        slow: false,
    };
    assert_invalid(hot.verdict_put(&key, &other, Duration::ZERO).await);
    Ok(())
}
