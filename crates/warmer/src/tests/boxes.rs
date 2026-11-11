//! SIM box resets (`rotate_ip`), rate limits and recovery.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use common::types::{IpState, Kind, Subtype};
use store::Transition;
use time::OffsetDateTime;

use super::support::{Harness, RotateMode, Setup, TestResult, box_adapter, harness, unit};

const BOX: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 200);
const NEW_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 201);

async fn start(per_hour: u32, attempts: u32) -> TestResult<Option<Harness>> {
    Harness::start(Setup::new(
        box_adapter,
        "min_ready = 1\n",
        &format!(
            "[policy.mobile_box]\nrotate_attempts = {attempts}\nrotate_timeout = \"1s\"\n\
             rotate_min_interval = \"1s\"\nrotate_per_hour = {per_hour}\n\
             drain_wait = \"1s\"\noffline_after = \"1s\"\n"
        ),
    ))
    .await
}

/// A box that rests in quarantine, so the warmer may reset it.
async fn resting_box(h: &Harness) -> TestResult {
    h.add_inventory("bx", Subtype::MobileBox, BOX, Some("m1"))
        .await?;
    let retest = OffsetDateTime::now_utc() + time::Duration::hours(6);
    let change = Transition::to(IpState::Quarantined, "block signal").retest_at(retest);
    h.transition(BOX, change).await?;
    Ok(())
}

/// One box tick and the resets it started.
async fn reset(h: &Harness) {
    h.box_tick().await;
    h.settle().await;
}

fn outcome(h: &Harness, label: &str) -> u64 {
    h.metrics
        .rotate_total
        .with_label_values(&["bx", label])
        .get()
}

fn failed_resets(h: &Harness) -> Option<u32> {
    let memory = h.w.memory.lock();
    memory.failed_resets.get(&IpAddr::V4(BOX)).copied()
}

async fn state(h: &Harness) -> TestResult<IpState> {
    Ok(h.row(BOX).await?.state)
}

#[tokio::test]
async fn a_reset_that_changes_the_exit_ip_makes_the_box_a_candidate_with_the_new_ip() -> TestResult
{
    let h = harness!(start(6, 3));
    resting_box(&h).await?;
    h.fake.set_rotate(RotateMode::Change(NEW_IP));
    reset(&h).await;

    let row = h.row(BOX).await?;
    assert_eq!(
        row.state,
        IpState::Candidate,
        "only `changed` leads to Candidate"
    );
    assert_eq!(row.exit_ip, Some(IpAddr::V4(NEW_IP)));
    assert_eq!(outcome(&h, "changed"), 1);

    // The new IP passes the checks before any lease.
    h.static_tick().await;
    assert_eq!(state(&h).await?, IpState::Available);
    Ok(())
}

#[tokio::test]
async fn a_reset_that_leaves_the_ip_unchanged_quarantines_the_box() -> TestResult {
    let h = harness!(start(6, 3));
    resting_box(&h).await?;
    h.fake.set_rotate(RotateMode::Unchanged);
    reset(&h).await;
    assert_eq!(state(&h).await?, IpState::Quarantined);
    assert_eq!(outcome(&h, "unchanged"), 1);
    assert_eq!(failed_resets(&h), Some(1));
    Ok(())
}

#[tokio::test]
async fn a_box_that_goes_dark_after_a_reset_times_out() -> TestResult {
    let h = harness!(start(6, 3));
    resting_box(&h).await?;
    h.fake.set_rotate(RotateMode::GoDark);
    reset(&h).await;
    assert_eq!(state(&h).await?, IpState::Quarantined);
    assert_eq!(outcome(&h, "timeout"), 1);
    assert_eq!(outcome(&h, "unchanged"), 0, "no exit check ever answered");
    Ok(())
}

#[tokio::test]
async fn a_reset_call_that_hangs_times_out_and_one_that_fails_is_an_error() -> TestResult {
    let h = harness!(start(6, 5));
    resting_box(&h).await?;
    h.fake.set_rotate(RotateMode::Hang);
    reset(&h).await;
    assert_eq!(outcome(&h, "timeout"), 1);

    tokio::time::sleep(Duration::from_millis(1100)).await;
    h.fake.set_rotate(RotateMode::Fail);
    reset(&h).await;
    assert_eq!(outcome(&h, "error"), 1);
    assert_eq!(state(&h).await?, IpState::Quarantined);
    Ok(())
}

#[tokio::test]
async fn resets_are_limited_per_hour() -> TestResult {
    let h = harness!(start(1, 5));
    resting_box(&h).await?;
    h.fake.set_rotate(RotateMode::Unchanged);
    reset(&h).await;
    assert_eq!(outcome(&h, "unchanged"), 1);

    // rotate_min_interval (1 s) has passed, but rotate_per_hour is 1.
    reset(&h).await;
    assert_eq!(outcome(&h, "unchanged"), 1, "no second reset in the hour");
    Ok(())
}

#[tokio::test]
async fn resets_are_spaced_by_the_minimum_interval() -> TestResult {
    let h = harness!(start(6, 5));
    resting_box(&h).await?;
    h.fake.set_rotate(RotateMode::Fail);
    reset(&h).await;
    assert_eq!(outcome(&h, "error"), 1);
    // The failing call took a few ms: far inside the 1 s minimum interval.
    reset(&h).await;
    assert_eq!(outcome(&h, "error"), 1, "too soon for another reset");
    tokio::time::sleep(Duration::from_millis(1100)).await;
    reset(&h).await;
    assert_eq!(outcome(&h, "error"), 2);
    Ok(())
}

#[tokio::test]
async fn failed_resets_in_a_row_request_a_replacement() -> TestResult {
    let h = harness!(start(6, 2));
    resting_box(&h).await?;
    h.fake.set_rotate(RotateMode::Unchanged);
    reset(&h).await;
    assert_eq!(
        state(&h).await?,
        IpState::Quarantined,
        "one failure is not enough"
    );
    reset(&h).await;
    assert_eq!(
        state(&h).await?,
        IpState::ReplaceRequested,
        "rotate_attempts failed resets"
    );
    Ok(())
}

#[tokio::test]
async fn a_reset_waits_drain_wait_for_leases_to_end() -> TestResult {
    let h = harness!(start(6, 3));
    resting_box(&h).await?;
    let p = h.partition("bx")?;
    h.hot
        .ready_put(&p, &unit(&BOX.to_string(), IpAddr::V4(BOX)))
        .await?;
    let ttl = Duration::from_secs(60);
    h.lease_free(&p, Kind::Static, "acme", "s", ttl).await?;

    h.fake.set_rotate(RotateMode::Unchanged);
    h.box_tick().await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(
        state(&h).await?,
        IpState::Quarantined,
        "still waiting for the lease"
    );
    assert_eq!(outcome(&h, "unchanged"), 0);
    h.settle().await;
    assert_eq!(
        outcome(&h, "unchanged"),
        1,
        "after drain_wait the reset went ahead"
    );
    Ok(())
}

#[tokio::test]
async fn a_silent_box_goes_offline_and_returns_when_it_answers() -> TestResult {
    let h = harness!(start(6, 3));
    h.add_inventory("bx", Subtype::MobileBox, BOX, Some("m1"))
        .await?;
    h.static_tick().await;
    assert_eq!(state(&h).await?, IpState::Available);

    h.fake.set_down(true);
    h.make_stale(BOX).await?;
    h.static_tick().await;
    assert_eq!(
        state(&h).await?,
        IpState::Offline,
        "silent for longer than offline_after"
    );
    let p = h.partition("bx")?;
    assert!(
        h.hot.ready_ids(&p).await?.is_empty(),
        "an offline box is not leased"
    );

    h.fake.set_down(false);
    h.static_tick().await;
    assert_eq!(state(&h).await?, IpState::Candidate, "it answers again");
    h.static_tick().await;
    assert_eq!(state(&h).await?, IpState::Available);
    Ok(())
}

#[tokio::test]
async fn a_box_stuck_in_rotating_after_a_crash_is_quarantined() -> TestResult {
    let h = harness!(start(6, 3));
    resting_box(&h).await?;
    h.transition(BOX, Transition::to(IpState::Rotating, "box reset"))
        .await?;
    h.box_tick().await;
    assert_eq!(
        state(&h).await?,
        IpState::Rotating,
        "a reset may still be running"
    );

    // drain_wait + 2 x rotate_timeout = 3 s.
    tokio::time::sleep(Duration::from_millis(3200)).await;
    h.w.box_tick().await;
    assert_eq!(state(&h).await?, IpState::Quarantined);
    assert_eq!(failed_resets(&h), Some(1));
    Ok(())
}
