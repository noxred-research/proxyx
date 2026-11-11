//! Rotating reconcile: how many creates start, and what stops them.

use std::time::Duration;

use common::retry::{BreakerConfig, BreakerState};
use common::types::{Kind, Partition};
use time::OffsetDateTime;

use super::support::{
    Harness, Setup, TestResult, evictions, harness, policy_toml, rotating_adapter, unix_now,
};

/// A policy for the `rot` provider in region `fr`.
fn rot_policy(min: u32, max: u32, concurrency: u32, rate: u32, creates_per_hour: u32) -> String {
    policy_toml(
        &format!("min_ready = {min}\nmax_ready = {max}\nlow_watermark = 1\n"),
        &format!(
            "[policy.rotating]\nrefill_concurrency = {concurrency}\nrefill_rate = {rate}\n\
             [policy.cost]\nmax_creates_per_hour = {creates_per_hour}\n"
        ),
    )
}

async fn rotating(policy: String) -> TestResult<Option<Harness>> {
    Harness::start(Setup {
        adapters: vec![rotating_adapter],
        policy,
        ..Setup::default()
    })
    .await
}

/// A breaker that probes again 150 ms after it opens.
fn breaker(passes_to_close: u32) -> BreakerConfig {
    BreakerConfig {
        failures_to_open: 2,
        window: Duration::from_secs(60),
        first_probe_after: Duration::from_millis(150),
        max_probe_after: Duration::from_millis(150),
        passes_to_close,
    }
}

fn counter(h: &Harness, outcome: &str) -> u64 {
    h.metrics
        .warm_creates_total
        .with_label_values(&["rot", outcome])
        .get()
}

#[tokio::test]
async fn reconcile_creates_exactly_need_and_never_more_than_the_concurrency() -> TestResult {
    let h = harness!(rotating(rot_policy(6, 6, 2, 600, 600)));
    let p = h.partition("rot")?;
    h.fake.set_ip_json_delay(150);

    h.reconcile_tick().await;
    assert_eq!(
        h.counts(&p).await?.creating,
        2,
        "two creates start, not six"
    );
    h.w.reconcile_tick().await;
    assert_eq!(
        h.counts(&p).await?.creating,
        2,
        "with two in flight the next tick starts none"
    );
    h.settle().await;

    for _ in 0..4 {
        h.reconcile().await;
    }
    let counts = h.counts(&p).await?;
    assert_eq!(counts.ready_free, 6, "{counts:?}");
    assert_eq!(h.fake.hits("/ip_json"), 6, "exactly need creates, no spare");
    assert!(h.fake.peak_creates() <= 2, "peak {}", h.fake.peak_creates());

    h.reconcile().await;
    assert_eq!(
        h.fake.hits("/ip_json"),
        6,
        "a full partition starts nothing"
    );
    assert_eq!(counter(&h, "ok"), 6);
    Ok(())
}

#[tokio::test]
async fn the_rate_bucket_limits_creates_per_minute() -> TestResult {
    let h = harness!(rotating(rot_policy(6, 6, 6, 2, 600)));
    let p = h.partition("rot")?;
    h.reconcile().await;
    h.reconcile().await;
    assert_eq!(h.fake.hits("/ip_json"), 2, "refill_rate 2 a minute");
    assert_eq!(h.counts(&p).await?.ready_free, 2);
    Ok(())
}

#[tokio::test]
async fn the_create_budget_stops_at_one_hundred_percent_and_resumes_next_window() -> TestResult {
    let mut h = harness!(rotating(rot_policy(8, 8, 8, 100, 3)));
    h.reconcile().await;
    assert_eq!(
        h.fake.hits("/ip_json"),
        3,
        "three creates an hour pay for three"
    );
    h.reconcile().await;
    assert_eq!(h.fake.hits("/ip_json"), 3, "stopped at 100%");
    assert!(counter(&h, "budget") >= 1);

    // The window ends: the hour counter is gone.
    let keys: Vec<String> = redis::cmd("KEYS")
        .arg("cost:*:creates:*")
        .query_async(&mut h.raw)
        .await?;
    assert_eq!(keys.len(), 1, "{keys:?}");
    redis::cmd("DEL")
        .arg(&keys[0])
        .query_async::<()>(&mut h.raw)
        .await?;
    h.reconcile().await;
    assert_eq!(
        h.fake.hits("/ip_json"),
        6,
        "creates resume with the new window"
    );
    Ok(())
}

#[tokio::test]
async fn a_budget_at_eighty_percent_slows_creates_to_one_at_a_time() -> TestResult {
    let h = harness!(rotating(rot_policy(4, 8, 4, 100, 10)));
    let p = h.partition("rot")?;
    h.hot
        .cost_add(&p.provider, 0, 8, OffsetDateTime::now_utc())
        .await?;
    h.reconcile().await;
    assert_eq!(h.fake.hits("/ip_json"), 1, "slow: one create, not four");
    h.reconcile().await;
    assert_eq!(h.fake.hits("/ip_json"), 2, "9 of 10 is still slow");
    h.reconcile().await;
    assert_eq!(h.fake.hits("/ip_json"), 2, "10 of 10 is stopped");
    Ok(())
}

/// W154: at 80% every partition runs one create at a time, however many ticks
/// start while it is in flight. Two regions of one provider run at most two.
#[tokio::test]
async fn a_slow_budget_keeps_one_create_in_flight_per_region_across_ticks() -> TestResult {
    let policy =
        rot_policy(6, 12, 4, 600, 600).replace("regions = [\"fr\"]", "regions = [\"fr\", \"de\"]");
    let h = harness!(rotating(policy));
    let fr = h.partition("rot")?;
    let de = Partition {
        region: "de".parse()?,
        ..fr.clone()
    };
    h.hot
        .cost_add(&fr.provider, 0, 480, OffsetDateTime::now_utc())
        .await?;
    h.fake.set_ip_json_delay(250);

    h.w.locks_tick().await;
    let mut most = 0;
    for _ in 0..12 {
        h.w.reconcile_tick().await;
        for p in [&fr, &de] {
            let creating = h.counts(p).await?.creating;
            assert!(creating <= 1, "{p}: {creating} creates in flight");
            most = most.max(creating);
        }
        tokio::time::sleep(Duration::from_millis(120)).await;
    }
    h.settle().await;
    assert_eq!(most, 1, "creates did run");
    assert!(h.fake.peak_creates() <= 2, "peak {}", h.fake.peak_creates());
    Ok(())
}

#[tokio::test]
async fn an_open_breaker_stops_creates_and_closes_after_passes() -> TestResult {
    let h = harness!(Harness::start(Setup {
        adapters: vec![rotating_adapter],
        policy: rot_policy(4, 4, 4, 100, 600),
        timing: |t| t.breaker = breaker(2),
        ..Setup::default()
    }));
    let p = h.partition("rot")?;
    let cfg = h.w.timing.breaker;
    let state = async |h: &Harness| -> TestResult<BreakerState> {
        Ok(h.hot.breaker_peek(&p, &cfg).await?.0)
    };

    h.fake.set_down(true);
    h.reconcile().await;
    assert_eq!(state(&h).await?, BreakerState::Open);
    assert_eq!(
        h.metrics
            .provider_breaker_state
            .with_label_values(&["rot"])
            .get(),
        2
    );
    let attempts = h.fake.hits("/ip_json") + counter(&h, "failed");
    h.reconcile().await;
    assert_eq!(
        h.fake.hits("/ip_json") + counter(&h, "failed"),
        attempts,
        "an open breaker starts no create"
    );
    assert!(counter(&h, "breaker") >= 1);

    tokio::time::sleep(Duration::from_millis(200)).await;
    h.fake.set_down(false);
    h.reconcile().await;
    assert_eq!(
        h.counts(&p).await?.ready_free,
        1,
        "one probe create goes through"
    );
    assert_eq!(state(&h).await?, BreakerState::HalfOpen);
    h.reconcile().await;
    assert_eq!(
        state(&h).await?,
        BreakerState::Closed,
        "two passes close it"
    );
    h.reconcile().await;
    assert!(
        h.counts(&p).await?.ready_free >= 3,
        "traffic returns by itself"
    );
    Ok(())
}

#[tokio::test]
async fn max_ready_caps_leased_sessions_too() -> TestResult {
    let h = harness!(rotating(rot_policy(2, 2, 2, 600, 600)));
    let p = h.partition("rot")?;
    h.reconcile().await;
    assert_eq!(h.counts(&p).await?.ready_free, 2);

    let ttl = Duration::from_secs(60);
    h.lease_free(&p, Kind::Rotating, "acme", "s", ttl).await?;
    for _ in 0..3 {
        h.reconcile().await;
    }
    let counts = h.counts(&p).await?;
    assert_eq!(
        (counts.ready_free, counts.leased),
        (1, 1),
        "min_ready 2 = max_ready 2: a leased session fills a slot, no third create: {counts:?}"
    );
    assert_eq!(h.fake.hits("/ip_json"), 2);
    Ok(())
}

#[tokio::test]
async fn an_open_breaker_probes_on_its_own_schedule_not_after_the_local_backoff() -> TestResult {
    let h = harness!(Harness::start(Setup {
        adapters: vec![rotating_adapter],
        policy: rot_policy(2, 2, 2, 100, 600),
        timing: |t| {
            // a failure backoff far longer than the probe wait
            t.backoff_base = Duration::from_secs(600);
            t.breaker = breaker(1);
        },
        ..Setup::default()
    }));
    let p = h.partition("rot")?;
    let cfg = h.w.timing.breaker;
    h.fake.set_down(true);
    h.reconcile().await;
    assert_eq!(h.hot.breaker_peek(&p, &cfg).await?.0, BreakerState::Open);
    // The jitter may draw a short wait: make sure the backoff is in force.
    while !h.w.backing_off(&p, std::time::Instant::now()) {
        h.w.backoff_failed(&p);
    }

    tokio::time::sleep(Duration::from_millis(200)).await;
    h.fake.set_down(false);
    h.w.reconcile_tick().await;
    h.settle().await;
    assert_eq!(
        h.counts(&p).await?.ready_free,
        1,
        "the probe create goes through although the backoff runs"
    );
    assert_eq!(h.hot.breaker_peek(&p, &cfg).await?.0, BreakerState::Closed);
    Ok(())
}

#[tokio::test]
async fn a_paused_route_class_starts_no_creates_until_resumed() -> TestResult {
    let h = harness!(rotating(rot_policy(2, 2, 2, 100, 600)));
    let p = h.partition("rot")?;
    h.hot.warm_pause(&p, Duration::from_secs(60)).await?;
    h.reconcile().await;
    assert_eq!(h.fake.hits("/ip_json"), 0, "a failed canary pauses warming");
    assert!(h.hot.warm_resume(&p).await?);
    h.reconcile().await;
    assert_eq!(h.counts(&p).await?.ready_free, 2);
    Ok(())
}

#[tokio::test]
async fn a_partition_locked_by_another_replica_is_left_alone() -> TestResult {
    let h = harness!(rotating(rot_policy(2, 2, 2, 100, 600)));
    let p = h.partition("rot")?;
    assert!(
        h.hot
            .lock_acquire(&p, "other-replica", Duration::from_secs(15))
            .await?
    );
    h.reconcile().await;
    assert_eq!(h.fake.hits("/ip_json"), 0);
    assert!(h.hot.lock_release(&p, "other-replica").await?);
    h.reconcile().await;
    assert_eq!(
        h.counts(&p).await?.ready_free,
        2,
        "the lock is ours once free"
    );
    Ok(())
}

#[tokio::test]
async fn a_second_session_with_the_same_exit_ip_is_a_duplicate_and_drains() -> TestResult {
    let h = harness!(rotating(rot_policy(3, 3, 3, 100, 600)));
    let p = h.partition("rot")?;
    h.fake.set_same_ip(Some("198.51.100.7".parse()?));
    h.reconcile().await;
    let counts = h.counts(&p).await?;
    assert_eq!(counts.ready_free, 1, "one session owns the IP: {counts:?}");
    assert_eq!(counts.creating, 0, "the duplicates were aborted");
    assert_eq!(evictions(&h, "duplicate"), 2);
    Ok(())
}

#[tokio::test]
async fn a_session_that_fails_reputation_or_the_probe_never_becomes_ready() -> TestResult {
    let h = harness!(rotating(rot_policy(2, 2, 2, 100, 600)));
    let p = h.partition("rot")?;

    h.fake.set_default_risk(90);
    h.reconcile().await;
    assert_eq!(h.counts(&p).await?.ready_free, 0);
    assert!(evictions(&h, "reputation") >= 1);

    h.fake.set_default_risk(0);
    h.fake.set_probe_status(403);
    h.reconcile().await;
    assert_eq!(h.counts(&p).await?.ready_free, 0);
    assert!(evictions(&h, "block") >= 1, "a captcha page is a block");
    assert_eq!(
        h.counts(&p).await?.creating,
        0,
        "failed creates give their slot back"
    );

    h.fake.set_probe_status(200);
    h.reconcile().await;
    assert_eq!(h.counts(&p).await?.ready_free, 2);
    Ok(())
}

/// With every scorer down, the policy's `on_score_unavailable` decides
/// whether a new session may become ready.
#[tokio::test]
async fn on_score_unavailable_of_the_policy_decides_creates_when_the_scorers_are_down() -> TestResult
{
    for (value, ready) in [("allow", 2), ("deny", 0)] {
        let policy = policy_toml(
            &format!(
                "min_ready = 2\nmax_ready = 2\nlow_watermark = 1\non_score_unavailable = \"{value}\"\n"
            ),
            "[policy.rotating]\nrefill_concurrency = 2\nrefill_rate = 100\n",
        );
        let h = harness!(rotating(policy));
        let p = h.partition("rot")?;
        h.fake.set_scorers_down(true);
        h.reconcile().await;
        assert_eq!(h.counts(&p).await?.ready_free, ready, "{value}");
        assert_eq!(evictions(&h, "reputation") > 0, ready == 0, "{value}");
    }
    Ok(())
}

#[tokio::test]
async fn a_new_session_gets_a_keepalive_job_and_a_record_that_matches_its_unit() -> TestResult {
    let mut h = harness!(rotating(rot_policy(1, 1, 1, 100, 600)));
    let p = h.partition("rot")?;
    h.reconcile().await;
    let jobs = h.due_jobs().await?;
    assert_eq!(jobs.len(), 1, "{jobs:?}");
    let job = store::SessionJob::parse(&jobs[0]).ok_or("job does not parse")?;
    assert_eq!(job.partition, p);
    assert_eq!(
        h.hot.ready_ids(&p).await?,
        std::slice::from_ref(&job.session)
    );
    assert_eq!(job.session.len(), 12, "the adapter fixes the id length");
    assert!(job.expires > unix_now(), "max_age is in the future");
    assert!(
        job.expires - job.born <= 30 * 60 * 80 / 100,
        "80% of the provider maximum at most"
    );
    Ok(())
}

#[tokio::test]
async fn a_create_that_cannot_schedule_its_job_leaves_no_ready_session() -> TestResult {
    let mut h = harness!(rotating(rot_policy(1, 1, 1, 100, 600)));
    let p = h.partition("rot")?;
    // A string where the due set belongs: scheduling a job fails.
    redis::cmd("SET")
        .arg("due")
        .arg("x")
        .query_async::<()>(&mut h.raw)
        .await?;
    h.reconcile().await;
    let counts = h.counts(&p).await?;
    assert_eq!(
        (counts.ready_free, counts.creating),
        (0, 0),
        "a session nothing keeps alive never becomes ready: {counts:?}"
    );
    assert_eq!(counter(&h, "failed"), 1);
    Ok(())
}

/// A session whose probe is clean but slow is kept as a degraded session,
/// up to a quarter of `max_ready`; the warmer still wants normal ones.
#[tokio::test]
async fn a_slow_session_is_admitted_as_degraded_up_to_a_quarter_of_max_ready() -> TestResult {
    let h = harness!(Harness::start(Setup {
        adapters: vec![rotating_adapter],
        policy: policy_toml(
            "min_ready = 4\nmax_ready = 8\nlow_watermark = 1\n",
            "[policy.rotating]\nrefill_concurrency = 1\nrefill_rate = 600\n\
             [policy.cost]\nmax_creates_per_hour = 600\n\
             [policy.criteria]\nmax_ttfb_ms = 100\nbrowser_sample = 0.0\n",
        ),
        timing: |t| t.backoff_base = Duration::from_millis(1),
        ..Setup::default()
    }));
    let p = h.partition("rot")?;
    h.fake.set_probe_delay(300);
    for _ in 0..5 {
        h.reconcile().await;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let counts = h.counts(&p).await?;
    assert_eq!(
        (counts.ready_free, counts.degraded_free),
        (2, 2),
        "two degraded sessions, no more: {counts:?}"
    );
    assert!(evictions(&h, "quality") >= 1, "the rest were refused");

    // Fast sessions fill the target on top of the degraded ones.
    h.fake.set_probe_delay(0);
    for _ in 0..5 {
        h.reconcile().await;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let counts = h.counts(&p).await?;
    assert_eq!(
        (counts.ready_free, counts.degraded_free),
        (6, 2),
        "four normal sessions next to the two degraded ones: {counts:?}"
    );
    Ok(())
}
