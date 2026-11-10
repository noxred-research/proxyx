//! Keepalive and eviction of ready rotating sessions.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use common::types::{Kind, OrgId, Partition, Tier};
use store::{ExitIpClaim, Grant, Phase, SessionJob};

use super::support::{Harness, Setup, TestResult, evictions, harness, rotating_adapter, unix_now};

async fn start(drops_per_hour: u32) -> TestResult<Option<Harness>> {
    start_with(drops_per_hour, 10).await
}

async fn start_with(drops_per_hour: u32, changes_per_hour: u32) -> TestResult<Option<Harness>> {
    Harness::start(Setup::new(
        rotating_adapter,
        "min_ready = 1\nmax_ready = 1\nlow_watermark = 1\n",
        &format!(
            "[policy.rotating]\nrefill_concurrency = 1\n\
             [policy.rotating.stability]\ndrops_per_hour = {drops_per_hour}\n\
             changes_per_hour = {changes_per_hour}\n"
        ),
    ))
    .await
}

/// Create one ready session and return its job.
async fn one_session(h: &mut Harness) -> TestResult<SessionJob> {
    h.reconcile().await;
    current_job(h).await
}

async fn current_job(h: &mut Harness) -> TestResult<SessionJob> {
    let jobs = h.due_jobs().await?;
    assert_eq!(jobs.len(), 1, "one session, one job: {jobs:?}");
    Ok(SessionJob::parse(&jobs[0]).ok_or("job does not parse")?)
}

/// Run one keepalive step now and return the session's next job, if any.
async fn step(h: &mut Harness) -> TestResult<Option<SessionJob>> {
    h.make_due().await?;
    h.w.keepalive_tick().await;
    let jobs = h.due_jobs().await?;
    Ok(jobs.first().and_then(|j| SessionJob::parse(j)))
}

/// [`step`] for a session that must still have a job.
async fn next(h: &mut Harness) -> TestResult<SessionJob> {
    Ok(step(h).await?.ok_or("job vanished")?)
}

fn fails(job: &SessionJob) -> u32 {
    match job.phase {
        Phase::Keep { fails, .. } => fails,
        Phase::Drain { .. } => u32::MAX,
    }
}

fn changes(job: &SessionJob) -> u32 {
    match job.phase {
        Phase::Keep { changes, .. } => changes,
        Phase::Drain { .. } => u32::MAX,
    }
}

fn draining(job: &SessionJob) -> bool {
    matches!(job.phase, Phase::Drain { .. })
}

async fn ready(h: &Harness, p: &Partition, job: &SessionJob) -> TestResult<bool> {
    Ok(h.hot.is_ready(p, &job.session).await?)
}

async fn replace_job(h: &mut Harness, old: &SessionJob, new: &SessionJob) -> TestResult {
    h.replace_due(&old.encode(), &new.encode()).await
}

/// Lease the ready session as `acme`.
async fn lease_session(h: &Harness, p: &Partition) -> TestResult<Grant> {
    let ttl = Duration::from_secs(60);
    h.lease_free(p, Kind::Rotating, "acme", "s", ttl).await
}

/// Try to claim the exit IP for another session.
async fn claim(h: &Harness, ip: Ipv4Addr) -> TestResult<ExitIpClaim> {
    let ttl = Duration::from_secs(5);
    Ok(h.hot.claim_exit_ip(IpAddr::V4(ip), "other", ttl).await?)
}

/// The user name the fake provider knows a session by.
fn session_user(h: &Harness, job: &SessionJob) -> TestResult<String> {
    let p = &job.partition;
    let endpoint = crate::checks::rotating_endpoint(
        h.w.loaded().adapters.get(&p.provider).ok_or("adapter")?,
        &job.session,
        &p.region,
    )?;
    Ok(endpoint.username.expose().to_owned())
}

fn addr(n: u8) -> Ipv4Addr {
    Ipv4Addr::new(198, 51, 100, n)
}

#[tokio::test]
async fn three_failed_keepalives_in_a_row_drain_the_session() -> TestResult {
    let mut h = harness!(start(10));
    let p = h.partition("rot")?;
    let job = one_session(&mut h).await?;

    h.fake.set_echo_down(true);
    assert_eq!(fails(&next(&mut h).await?), 1);
    assert_eq!(fails(&next(&mut h).await?), 2);
    assert!(ready(&h, &p, &job).await?, "two failures keep the session");

    let third = next(&mut h).await?;
    assert!(draining(&third), "{third:?}");
    assert!(
        !ready(&h, &p, &job).await?,
        "the third failure stops leasing"
    );
    assert_eq!(evictions(&h, "keepalive"), 1);

    // No tunnel holds it: the next step forgets it and its exit IP claim.
    assert!(step(&mut h).await?.is_none(), "the job is done");
    assert_eq!(
        claim(&h, job.ip).await?,
        ExitIpClaim::Claimed,
        "the exit ip claim was released"
    );
    Ok(())
}

#[tokio::test]
async fn a_good_keepalive_resets_the_failure_count() -> TestResult {
    let mut h = harness!(start(10));
    one_session(&mut h).await?;
    h.fake.set_echo_down(true);
    assert_eq!(fails(&next(&mut h).await?), 1);
    assert_eq!(fails(&next(&mut h).await?), 2);
    h.fake.set_echo_down(false);
    assert_eq!(fails(&next(&mut h).await?), 0);
    h.fake.set_echo_down(true);
    assert_eq!(fails(&next(&mut h).await?), 1, "the count restarted");
    Ok(())
}

#[tokio::test]
async fn keepalive_only_touches_the_echo_endpoint() -> TestResult {
    let mut h = harness!(start(10));
    one_session(&mut h).await?;
    let (echo, probe, ipify) = (
        h.fake.hits("/echo"),
        h.fake.hits("/probe/ok"),
        h.fake.hits("/ipify"),
    );
    step(&mut h).await?;
    assert!(h.fake.hits("/echo") > echo, "the neutral request went out");
    assert_eq!(h.fake.hits("/probe/ok"), probe, "never a target");
    assert_eq!(h.fake.hits("/ipify"), ipify, "not the public quorum either");
    Ok(())
}

#[tokio::test]
async fn an_ip_change_within_the_limit_keeps_the_session_on_the_new_ip() -> TestResult {
    let mut h = harness!(start_with(10, 1));
    let p = h.partition("rot")?;
    let job = one_session(&mut h).await?;
    let user = session_user(&h, &job)?;

    h.fake.set_user_ip(&user, addr(99));
    let moved = next(&mut h).await?;
    assert!(
        !draining(&moved),
        "one change is within changes_per_hour = 1: {moved:?}"
    );
    assert_eq!(moved.ip, addr(99), "the job follows the session");
    assert_eq!(changes(&moved), 1);
    assert!(ready(&h, &p, &job).await?);
    assert_eq!(evictions(&h, "stability") + evictions(&h, "ip_changed"), 0);

    // The claim moved with the session: the new IP is taken, the old one free.
    assert_eq!(
        claim(&h, addr(99)).await?,
        ExitIpClaim::Duplicate {
            owner: job.session.clone()
        }
    );
    assert_eq!(
        claim(&h, job.ip).await?,
        ExitIpClaim::Claimed,
        "the old exit ip claim was released"
    );

    // The unit record carries the new IP, so the next lease reports it.
    let grant = lease_session(&h, &p).await?;
    assert_eq!(grant.ip, IpAddr::V4(addr(99)));
    assert_eq!(grant.unit, job.session);

    // A second change in the hour is over the limit.
    h.fake.set_user_ip(&user, addr(98));
    let last = next(&mut h).await?;
    assert!(draining(&last), "{last:?}");
    assert!(!ready(&h, &p, &job).await?);
    assert_eq!(evictions(&h, "stability"), 1);
    Ok(())
}

#[tokio::test]
async fn a_degraded_session_stays_degraded_on_a_new_exit_ip() -> TestResult {
    let mut h = harness!(start_with(10, 5));
    let p = h.partition("rot")?;
    let job = one_session(&mut h).await?;
    assert!(h.hot.set_tier(&p, &job.session, Tier::Degraded).await?);

    h.fake.set_user_ip(&session_user(&h, &job)?, addr(99));
    let moved = next(&mut h).await?;
    assert_eq!(moved.ip, addr(99), "the new ip is adopted");
    assert_eq!(
        h.hot.tier(&p, &job.session).await?,
        Tier::Degraded,
        "an unchecked new ip does not make a slow session normal"
    );
    Ok(())
}

#[tokio::test]
async fn the_hour_window_forgets_old_ip_changes() -> TestResult {
    let mut h = harness!(start_with(10, 1));
    let p = h.partition("rot")?;
    let job = one_session(&mut h).await?;
    let user = session_user(&h, &job)?;
    let stale = SessionJob {
        phase: Phase::Keep {
            fails: 0,
            drops: 0,
            changes: 5,
            window_start: unix_now() - 3601,
            last_recheck: unix_now(),
            warn_zone: false,
        },
        ..job.clone()
    };
    replace_job(&mut h, &job, &stale).await?;

    h.fake.set_user_ip(&user, addr(97));
    h.w.keepalive_tick().await;
    let moved = current_job(&mut h).await?;
    assert!(
        !draining(&moved),
        "the old changes are out of the window: {moved:?}"
    );
    assert_eq!(changes(&moved), 1);
    assert!(ready(&h, &p, &job).await?);
    Ok(())
}

#[tokio::test]
async fn a_new_ip_that_fails_its_checks_drains_the_session() -> TestResult {
    let mut h = harness!(start_with(10, 5));
    let p = h.partition("rot")?;
    let job = one_session(&mut h).await?;
    let user = session_user(&h, &job)?;
    h.fake.set_risk(addr(96), 90);
    h.fake.set_user_ip(&user, addr(96));

    assert!(draining(&next(&mut h).await?));
    assert!(!ready(&h, &p, &job).await?);
    assert_eq!(
        evictions(&h, "reputation"),
        1,
        "the reputation rule judged the new ip"
    );
    assert_eq!(
        claim(&h, addr(96)).await?,
        ExitIpClaim::Claimed,
        "the bad ip was never claimed"
    );
    Ok(())
}

#[tokio::test]
async fn a_new_ip_already_owned_by_another_session_is_a_duplicate() -> TestResult {
    let mut h = harness!(start_with(10, 5));
    let p = h.partition("rot")?;
    let job = one_session(&mut h).await?;
    let user = session_user(&h, &job)?;
    h.hot
        .claim_exit_ip(
            IpAddr::V4(addr(95)),
            "another-session",
            Duration::from_secs(60),
        )
        .await?;
    h.fake.set_user_ip(&user, addr(95));

    assert!(draining(&next(&mut h).await?));
    assert!(!ready(&h, &p, &job).await?);
    assert_eq!(evictions(&h, "duplicate"), 1);
    Ok(())
}

#[tokio::test]
async fn a_new_ip_that_cannot_be_verified_counts_as_a_drop_and_changes_nothing() -> TestResult {
    let mut h = harness!(start_with(10, 5));
    let p = h.partition("rot")?;
    let job = one_session(&mut h).await?;
    let user = session_user(&h, &job)?;
    h.fake.set_user_ip(&user, addr(94));
    h.fake.set_checks_down(true);

    let unverified = next(&mut h).await?;
    assert!(!draining(&unverified));
    assert_eq!(unverified.ip, job.ip, "the unverified ip is not adopted");
    assert_eq!((fails(&unverified), changes(&unverified)), (1, 0));
    assert!(ready(&h, &p, &job).await?);

    h.fake.set_checks_down(false);
    let later = next(&mut h).await?;
    assert_eq!(later.ip, addr(94), "verified at the next keepalive");
    assert_eq!((fails(&later), changes(&later)), (0, 1));
    Ok(())
}

#[tokio::test]
async fn drops_up_to_the_limit_keep_the_session() -> TestResult {
    let mut h = harness!(start_with(2, 10));
    let p = h.partition("rot")?;
    let job = one_session(&mut h).await?;
    for _ in 0..2 {
        h.fake.set_echo_down(true);
        step(&mut h).await?;
        h.fake.set_echo_down(false);
        assert_eq!(fails(&next(&mut h).await?), 0);
    }
    assert!(ready(&h, &p, &job).await?, "two drops equal the limit of 2");
    h.fake.set_echo_down(true);
    let over = next(&mut h).await?;
    assert!(draining(&over), "the third drop in the hour drains");
    assert_eq!(evictions(&h, "stability"), 1);
    Ok(())
}

#[tokio::test]
async fn too_many_drops_in_an_hour_drain_even_when_they_are_not_in_a_row() -> TestResult {
    let mut h = harness!(start(1));
    let p = h.partition("rot")?;
    let job = one_session(&mut h).await?;

    h.fake.set_echo_down(true);
    assert_eq!(fails(&next(&mut h).await?), 1);
    h.fake.set_echo_down(false);
    assert_eq!(fails(&next(&mut h).await?), 0);
    h.fake.set_echo_down(true);
    let over = next(&mut h).await?;
    assert!(draining(&over), "the second drop is over the limit of 1");
    assert!(!ready(&h, &p, &job).await?);
    assert_eq!(evictions(&h, "stability"), 1);
    Ok(())
}

#[tokio::test]
async fn a_session_drains_at_max_age_even_while_leased_but_its_tunnel_continues() -> TestResult {
    let mut h = harness!(start(10));
    let p = h.partition("rot")?;
    let job = one_session(&mut h).await?;
    let grant = lease_session(&h, &p).await?;

    let expired = SessionJob {
        expires: unix_now() - 1,
        ..job.clone()
    };
    replace_job(&mut h, &job, &expired).await?;
    h.w.keepalive_tick().await;
    let drain = current_job(&mut h).await?;
    assert!(draining(&drain), "{drain:?}");
    assert!(!ready(&h, &p, &job).await?, "leasing stopped");
    assert_eq!(evictions(&h, "max_age"), 1);

    // The tunnel is still open: the unit stays until it closes.
    assert!(draining(&next(&mut h).await?));
    assert_eq!(h.hot.unit_load(&p, &job.session).await?.tunnels, 1);

    h.hot.tunnel_close(&grant.tunnel).await?;
    assert!(
        step(&mut h).await?.is_none(),
        "forgotten once the tunnel ended"
    );
    assert_eq!(h.hot.unit_load(&p, &job.session).await?.leases, 0);
    Ok(())
}

#[tokio::test]
async fn a_drain_with_a_tunnel_that_never_ends_is_cut_after_the_cap() -> TestResult {
    let mut h = harness!(start(10));
    let p = h.partition("rot")?;
    let job = one_session(&mut h).await?;
    lease_session(&h, &p).await?;

    let recent = SessionJob {
        phase: Phase::Drain {
            since: unix_now() - 590,
        },
        ..job.clone()
    };
    replace_job(&mut h, &job, &recent).await?;
    h.w.keepalive_tick().await;
    assert!(
        current_job(&mut h).await.is_ok(),
        "just under 10 minutes: wait"
    );

    let old = SessionJob {
        phase: Phase::Drain {
            since: unix_now() - 601,
        },
        ..job.clone()
    };
    replace_job(&mut h, &recent, &old).await?;
    h.w.keepalive_tick().await;
    assert!(
        h.due_jobs().await?.is_empty(),
        "N5: over 10 minutes the unit is dropped"
    );
    assert_eq!(h.hot.unit_load(&p, &job.session).await?.tunnels, 0);
    Ok(())
}

#[tokio::test]
async fn an_idle_session_drains_at_ready_ttl_but_a_leased_one_does_not() -> TestResult {
    let mut h = harness!(start(10));
    let p = h.partition("rot")?;
    let job = one_session(&mut h).await?;
    let old = SessionJob {
        born: unix_now() - 31 * 60,
        ..job.clone()
    };
    let org: OrgId = "acme".parse()?;
    let grant = lease_session(&h, &p).await?;

    replace_job(&mut h, &job, &old).await?;
    h.w.keepalive_tick().await;
    assert!(
        ready(&h, &p, &job).await?,
        "in use: ready_ttl does not apply"
    );

    h.hot.tunnel_close(&grant.tunnel).await?;
    assert!(h.hot.release(&p, &org, "s", None).await?);
    assert!(draining(&next(&mut h).await?));
    assert_eq!(evictions(&h, "ready_ttl"), 1);
    Ok(())
}

#[tokio::test]
async fn a_session_drained_elsewhere_is_waited_out_not_kept_alive() -> TestResult {
    let mut h = harness!(start(10));
    let p = h.partition("rot")?;
    let job = one_session(&mut h).await?;
    // The API drains a route class by taking its units out of the ready set.
    assert!(h.hot.ready_take(&p, &job.session).await?);
    let echo = h.fake.hits("/echo");
    assert!(draining(&next(&mut h).await?));
    assert_eq!(
        h.fake.hits("/echo"),
        echo,
        "no keepalive for a drained session"
    );
    Ok(())
}
