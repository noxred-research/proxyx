//! Browser samples: which candidates get one, the reservation for the probe
//! org, and what a verdict (or the lack of one) does.

use std::net::Ipv4Addr;
use std::time::Duration;

use common::types::{IpState, Kind, Partition, Subtype, Tier};
use store::{LeaseOutcome, SampleJob, SessionJob, Transition, Verdict};

use super::support::{
    Harness, Setup, TestResult, evictions, harness, rotating_adapter, static_adapter, unix_now,
};
use crate::job::SampleWatch;

const TARGET: &str = "http://probe.test/probe/ok";

async fn rotating(share: f64, probe_targets: Vec<&'static str>) -> TestResult<Option<Harness>> {
    Harness::start(Setup {
        probe_targets,
        ..Setup::new(
            rotating_adapter,
            "min_ready = 1\nmax_ready = 1\nlow_watermark = 1\n",
            &format!(
                "[policy.rotating]\nrefill_concurrency = 1\n\
                 [policy.criteria]\nbrowser_sample = {share}\n"
            ),
        )
    })
    .await
}

async fn static_ips(share: f64) -> TestResult<Option<Harness>> {
    Harness::start(Setup::new(
        static_adapter,
        "min_ready = 2\n",
        &format!("[policy.criteria]\nbrowser_sample = {share}\n"),
    ))
    .await
}

async fn pending(h: &Harness) -> TestResult<Vec<SampleJob>> {
    Ok(h.hot.sample_pending().await?)
}

async fn watch_of(h: &mut Harness) -> TestResult<Option<SampleWatch>> {
    Ok(h.due_jobs()
        .await?
        .iter()
        .find_map(|j| SampleWatch::parse(j)))
}

async fn session_of(h: &mut Harness) -> TestResult<SessionJob> {
    h.due_jobs()
        .await?
        .iter()
        .find_map(|j| SessionJob::parse(j))
        .ok_or_else(|| "no session job".into())
}

/// Reconcile one sampled rotating session; return it and its sample watch.
async fn sampled_session(h: &mut Harness) -> TestResult<(SessionJob, SampleWatch)> {
    h.reconcile().await;
    let session = session_of(h).await?;
    let watch = watch_of(h).await?.ok_or("no sample watch")?;
    Ok((session, watch))
}

/// The browser's verdict for `job_id` arrives and the next keepalive pass
/// reads it.
async fn deliver_verdict(h: &mut Harness, job_id: &str, ok: bool, checked_at: i64) -> TestResult {
    let verdict = Verdict {
        ok,
        success_ratio: if ok { 1.0 } else { 0.0 },
        checked_at,
        detail: if ok { String::new() } else { "blocked".into() },
        slow: false,
    };
    h.hot
        .verdict_put(job_id, &verdict, Duration::from_secs(3600))
        .await?;
    h.make_due().await?;
    h.w.keepalive_tick().await;
    Ok(())
}

/// A verdict for pages that loaded but over the time limits.
async fn deliver_slow_verdict(h: &mut Harness, job_id: &str) -> TestResult {
    let verdict = Verdict {
        ok: false,
        success_ratio: 0.0,
        checked_at: unix_now(),
        detail: "slow".into(),
        slow: true,
    };
    h.hot
        .verdict_put(job_id, &verdict, Duration::from_secs(3600))
        .await?;
    h.make_due().await?;
    h.w.keepalive_tick().await;
    Ok(())
}

/// The probe org's tunnel for `px-sid-<sid>`: the gateway leases it under
/// `sid_sticky(sid)`.
async fn probe_lease(
    h: &Harness,
    partition: &Partition,
    kind: Kind,
    sid: &str,
) -> TestResult<LeaseOutcome> {
    let ttl = Duration::from_secs(60);
    let sticky = store::sid_sticky(sid);
    h.lease(partition, kind, &h.settings.probe_org, &sticky, ttl)
        .await
}

#[tokio::test]
async fn a_new_session_is_sampled_and_reserved_for_the_probe_org() -> TestResult {
    let mut h = harness!(rotating(1.0, vec![TARGET]));
    let p = h.partition("rot")?;
    let (session, watch) = sampled_session(&mut h).await?;

    let jobs = pending(&h).await?;
    assert_eq!(jobs.len(), 1, "{jobs:?}");
    let sample = &jobs[0];
    assert_eq!(
        (sample.provider.as_str(), sample.region.to_string()),
        ("rot", "fr".into())
    );
    assert_eq!(sample.route_class, "rot");
    assert_eq!(sample.targets, [TARGET]);
    let sid = sample.sid.clone().ok_or("the sample has no sticky key")?;
    assert!(
        sid.starts_with("smp")
            && sid
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()),
        "the prober sends it as an option, [a-z0-9] only: {sid}"
    );

    assert_eq!(
        (
            watch.job_id.as_str(),
            watch.unit.as_str(),
            watch.sid.as_str()
        ),
        (
            sample.job_id.as_str(),
            session.session.as_str(),
            sid.as_str()
        )
    );

    // The probe org's lease for the key is exactly the candidate.
    let outcome = probe_lease(&h, &p, Kind::Rotating, &sid).await?;
    assert!(
        matches!(&outcome, LeaseOutcome::Hit(g) if g.unit == session.session),
        "{outcome:?}"
    );
    Ok(())
}

#[tokio::test]
async fn no_sample_when_the_share_is_zero_or_there_are_no_targets() -> TestResult {
    let mut h = harness!(rotating(0.0, vec![TARGET]));
    h.reconcile().await;
    assert!(pending(&h).await?.is_empty());
    assert!(watch_of(&mut h).await?.is_none());
    drop(h);

    let mut h = harness!(rotating(1.0, vec![]));
    h.reconcile().await;
    assert!(
        pending(&h).await?.is_empty(),
        "nothing to load in the browser"
    );
    assert!(watch_of(&mut h).await?.is_none());
    Ok(())
}

#[tokio::test]
async fn a_sample_that_cannot_be_queued_does_not_hold_the_candidate_for_the_probe_org() -> TestResult
{
    let mut h = harness!(rotating(1.0, vec![TARGET]));
    let p = h.partition("rot")?;
    // A string where the samples set belongs: queueing the sample fails after the pin.
    redis::cmd("SET")
        .arg("samples:{probe}")
        .arg("x")
        .query_async::<()>(&mut h.raw)
        .await?;
    h.reconcile().await;

    let session = session_of(&mut h).await?;
    assert!(h.hot.is_ready(&p, &session.session).await?, "still ready");
    assert!(watch_of(&mut h).await?.is_none());
    let counts = h.counts(&p).await?;
    assert_eq!(
        (counts.ready_free, counts.leased),
        (1, 0),
        "the pin was given back: {counts:?}"
    );
    Ok(())
}

#[tokio::test]
async fn a_failed_sample_drains_the_rotating_session() -> TestResult {
    let mut h = harness!(rotating(1.0, vec![TARGET]));
    let p = h.partition("rot")?;
    let (session, watch) = sampled_session(&mut h).await?;

    h.w.keepalive_tick().await;
    assert!(
        h.hot.is_ready(&p, &session.session).await?,
        "no verdict yet: the session keeps serving"
    );
    assert!(watch_of(&mut h).await?.is_some(), "the watch goes on");

    deliver_verdict(&mut h, &watch.job_id, false, unix_now()).await?;
    assert!(!h.hot.is_ready(&p, &session.session).await?, "drained");
    assert_eq!(evictions(&h, "quality"), 1);
    assert!(watch_of(&mut h).await?.is_none(), "the watch is done");
    assert_eq!(
        h.hot.unit_load(&p, &session.session).await?.leases,
        0,
        "the reservation for the probe org is released"
    );
    Ok(())
}

#[tokio::test]
async fn a_passing_sample_keeps_the_session() -> TestResult {
    let mut h = harness!(rotating(1.0, vec![TARGET]));
    let p = h.partition("rot")?;
    let (session, watch) = sampled_session(&mut h).await?;

    deliver_verdict(&mut h, &watch.job_id, true, unix_now()).await?;
    assert!(h.hot.is_ready(&p, &session.session).await?);
    assert_eq!(evictions(&h, "quality"), 0);
    assert!(watch_of(&mut h).await?.is_none());
    assert_eq!(h.hot.unit_load(&p, &session.session).await?.leases, 0);
    Ok(())
}

#[tokio::test]
async fn a_verdict_older_than_verdict_max_age_is_ignored() -> TestResult {
    let mut h = harness!(rotating(1.0, vec![TARGET]));
    let p = h.partition("rot")?;
    let (session, watch) = sampled_session(&mut h).await?;

    // The default verdict_max_age is 24 h: one hour over it.
    let old = unix_now() - 25 * 3600;
    deliver_verdict(&mut h, &watch.job_id, false, old).await?;
    assert!(
        h.hot.is_ready(&p, &session.session).await?,
        "a stale failure does not drain: only the light probe applies"
    );
    assert_eq!(evictions(&h, "quality"), 0);
    assert!(watch_of(&mut h).await?.is_none(), "and the watch ends");
    Ok(())
}

#[tokio::test]
async fn a_sample_without_a_verdict_is_given_up_when_the_browser_pool_is_down() -> TestResult {
    let mut h = harness!(rotating(1.0, vec![TARGET]));
    let p = h.partition("rot")?;
    let (session, watch) = sampled_session(&mut h).await?;

    let waited = SampleWatch {
        created: unix_now() - 599,
        ..watch.clone()
    };
    h.replace_due(&watch.encode(), &waited.encode()).await?;
    h.w.keepalive_tick().await;
    assert!(
        watch_of(&mut h).await?.is_some(),
        "just under 10 minutes: keep waiting"
    );
    assert_eq!(pending(&h).await?.len(), 1);

    let given_up = SampleWatch {
        created: unix_now() - 601,
        ..watch
    };
    h.replace_due(&waited.encode(), &given_up.encode()).await?;
    h.w.keepalive_tick().await;
    assert!(watch_of(&mut h).await?.is_none());
    assert!(
        pending(&h).await?.is_empty(),
        "the job is no longer listed for the prober"
    );
    assert!(
        h.hot.is_ready(&p, &session.session).await?,
        "the session is untouched"
    );
    assert_eq!(h.hot.unit_load(&p, &session.session).await?.leases, 0);
    Ok(())
}

/// The session job of `session`, born `age_secs` ago, takes the place of the
/// current one.
async fn age_session(h: &mut Harness, session: &SessionJob, age_secs: i64) -> TestResult {
    let old = SessionJob {
        born: unix_now() - age_secs,
        ..session.clone()
    };
    h.replace_due(&session.encode(), &old.encode()).await
}

/// A prober that never answers left its pin on the session; the pin is
/// a reservation, not use, so the session still drains at ready_ttl.
#[tokio::test]
async fn an_unanswered_sample_pin_does_not_keep_a_session_past_ready_ttl() -> TestResult {
    let mut h = harness!(rotating(1.0, vec![TARGET]));
    let p = h.partition("rot")?;
    let (session, _watch) = sampled_session(&mut h).await?;
    assert_eq!(h.hot.unit_load(&p, &session.session).await?.leases, 1);

    age_session(&mut h, &session, 31 * 60).await?;
    h.make_due().await?;
    h.w.keepalive_tick().await;
    assert!(
        !h.hot.is_ready(&p, &session.session).await?,
        "the pin alone is not use"
    );
    assert_eq!(evictions(&h, "ready_ttl"), 1);
    Ok(())
}

/// A sample that is running holds a tunnel through the session: that counts
/// as use, so ready_ttl does not drain the session under it.
#[tokio::test]
async fn a_session_with_a_running_sample_tunnel_is_not_drained_at_ready_ttl() -> TestResult {
    let mut h = harness!(rotating(1.0, vec![TARGET]));
    let p = h.partition("rot")?;
    let (session, watch) = sampled_session(&mut h).await?;
    let running = probe_lease(&h, &p, Kind::Rotating, &watch.sid).await?;
    let LeaseOutcome::Hit(grant) = &running else {
        return Err(format!("the prober gets the pinned session: {running:?}").into());
    };

    age_session(&mut h, &session, 31 * 60).await?;
    h.make_due().await?;
    h.w.keepalive_tick().await;
    assert!(h.hot.is_ready(&p, &session.session).await?);
    assert_eq!(evictions(&h, "ready_ttl"), 0);

    h.hot.tunnel_close(&grant.tunnel).await?;
    h.make_due().await?;
    h.w.keepalive_tick().await;
    assert!(
        !h.hot.is_ready(&p, &session.session).await?,
        "the sample's tunnel ended: only the pin is left"
    );
    assert_eq!(evictions(&h, "ready_ttl"), 1);
    Ok(())
}

/// A customer lease still counts next to the pin.
#[tokio::test]
async fn a_customer_lease_on_a_pinned_session_still_keeps_it_past_ready_ttl() -> TestResult {
    let mut h = harness!(rotating(1.0, vec![TARGET]));
    let p = h.partition("rot")?;
    let (session, _watch) = sampled_session(&mut h).await?;
    let ttl = Duration::from_secs(60);
    h.lease(&p, Kind::Rotating, "acme", "s", ttl).await?;

    age_session(&mut h, &session, 31 * 60).await?;
    h.make_due().await?;
    h.w.keepalive_tick().await;
    assert!(h.hot.is_ready(&p, &session.session).await?);
    assert_eq!(evictions(&h, "ready_ttl"), 0);
    Ok(())
}

#[tokio::test]
async fn a_new_static_ip_is_sampled_and_a_failed_sample_cools_it() -> TestResult {
    let mut h = harness!(static_ips(1.0));
    let ip = Ipv4Addr::new(203, 0, 113, 40);
    let p = h.partition("stat")?;
    h.add_inventory("stat", Subtype::Isp, ip, None).await?;
    h.static_tick().await;
    assert_eq!(h.row(ip).await?.state, IpState::Available);

    let jobs = pending(&h).await?;
    assert_eq!(jobs.len(), 1, "{jobs:?}");
    assert_eq!(jobs[0].provider.as_str(), "stat");
    let sid = jobs[0].sid.clone().ok_or("no sticky key")?;
    let outcome = probe_lease(&h, &p, Kind::Static, &sid).await?;
    assert!(
        matches!(&outcome, LeaseOutcome::Hit(g) if g.unit == ip.to_string()),
        "the probe org gets exactly the candidate: {outcome:?}"
    );

    deliver_verdict(&mut h, &jobs[0].job_id, false, unix_now()).await?;
    let row = h.row(ip).await?;
    assert_eq!(row.state, IpState::Cooldown, "a failed sample cools the IP");
    assert!(row.cooldown_until.is_some());
    assert!(!h.hot.ready_ids(&p).await?.contains(&ip.to_string()));
    Ok(())
}

#[tokio::test]
async fn a_slow_sample_degrades_a_session_and_a_static_ip_instead_of_draining_them() -> TestResult {
    let mut h = harness!(rotating(1.0, vec![TARGET]));
    let p = h.partition("rot")?;
    let (session, watch) = sampled_session(&mut h).await?;
    deliver_slow_verdict(&mut h, &watch.job_id).await?;
    assert!(
        h.hot.is_ready(&p, &session.session).await?,
        "still leasable"
    );
    assert_eq!(h.hot.tier(&p, &session.session).await?, Tier::Degraded);
    assert_eq!(evictions(&h, "quality"), 0);
    assert!(watch_of(&mut h).await?.is_none(), "the watch is done");
    assert_eq!(h.hot.unit_load(&p, &session.session).await?.leases, 0);
    drop(h);

    let mut h = harness!(static_ips(1.0));
    let ip = Ipv4Addr::new(203, 0, 113, 42);
    let p = h.partition("stat")?;
    h.add_inventory("stat", Subtype::Isp, ip, None).await?;
    h.static_tick().await;
    let jobs = pending(&h).await?;
    assert_eq!(jobs.len(), 1, "{jobs:?}");
    deliver_slow_verdict(&mut h, &jobs[0].job_id).await?;
    let row = h.row(ip).await?;
    assert_eq!(
        row.state,
        IpState::Degraded,
        "a slow sample degrades the IP"
    );
    assert!(h.hot.ready_ids(&p).await?.contains(&ip.to_string()));
    assert_eq!(h.hot.tier(&p, &ip.to_string()).await?, Tier::Degraded);
    Ok(())
}

#[tokio::test]
async fn a_passing_sample_keeps_a_static_ip_and_a_retest_is_not_sampled() -> TestResult {
    let mut h = harness!(static_ips(1.0));
    let ip = Ipv4Addr::new(203, 0, 113, 41);
    h.add_inventory("stat", Subtype::Isp, ip, None).await?;
    h.static_tick().await;
    let jobs = pending(&h).await?;
    assert_eq!(jobs.len(), 1);

    deliver_verdict(&mut h, &jobs[0].job_id, true, unix_now()).await?;
    assert_eq!(h.row(ip).await?.state, IpState::Available);
    assert!(watch_of(&mut h).await?.is_none());

    // Cooled and retested IPs are not new candidates: no second sample.
    h.hot.sample_done(&jobs[0].job_id).await?;
    let until = time::OffsetDateTime::now_utc() - time::Duration::seconds(5);
    h.transition(
        ip,
        Transition::to(IpState::Cooldown, "test").cooldown_until(until),
    )
    .await?;
    h.static_tick().await;
    assert_eq!(
        h.row(ip).await?.state,
        IpState::Available,
        "the retest passed"
    );
    assert!(
        pending(&h).await?.is_empty(),
        "a retest is not a new candidate"
    );
    Ok(())
}
