//! The static loop: checks, cooldown and quarantine retests, the
//! replacement rule and its report.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use common::types::{IpState, Kind, SignalSource, SignalType, Subtype, Tier};
use store::{ScoreRow, Transition};
use time::OffsetDateTime;

use super::support::{
    Harness, LogCapture, Setup, TestResult, UserMode, evictions, harness, static_adapter,
};

fn ip(n: u8) -> Ipv4Addr {
    Ipv4Addr::new(203, 0, 113, n)
}

fn setup(tables: &str) -> Setup {
    Setup::new(static_adapter, "min_ready = 2\n", tables)
}

async fn start(tables: &str) -> TestResult<Option<Harness>> {
    Harness::start(setup(tables)).await
}

/// The breaker's probe spacing shortened to 300 ms.
async fn start_probing(tables: &str) -> TestResult<Option<Harness>> {
    Harness::start(Setup {
        timing: |t| t.breaker.first_probe_after = Duration::from_millis(300),
        ..setup(tables)
    })
    .await
}

/// Both scorers, for the replacement rule.
async fn start_scored() -> TestResult<Option<Harness>> {
    Harness::start(Setup {
        two_scorers: true,
        ..setup("")
    })
    .await
}

/// An inventory entry that has passed its checks.
async fn available(h: &Harness, n: u8) -> TestResult {
    h.add_inventory("stat", Subtype::Isp, ip(n), None).await?;
    h.static_tick().await;
    assert_eq!(h.row(ip(n)).await?.state, IpState::Available);
    Ok(())
}

async fn leasable(h: &Harness, n: u8) -> TestResult<bool> {
    let p = h.partition("stat")?;
    Ok(h.hot.ready_ids(&p).await?.contains(&ip(n).to_string()))
}

fn in_the_past() -> OffsetDateTime {
    OffsetDateTime::now_utc() - time::Duration::seconds(5)
}

async fn to_cooldown(h: &Harness, n: u8, until: OffsetDateTime) -> TestResult {
    let p = h.partition("stat")?;
    let change = Transition::to(IpState::Cooldown, "test block").cooldown_until(until);
    h.transition(ip(n), change).await?;
    h.hot.ready_take(&p, &ip(n).to_string()).await?;
    Ok(())
}

/// Quarantined, with its retest far away.
async fn quarantine(h: &Harness, n: u8) -> TestResult {
    let retest = OffsetDateTime::now_utc() + time::Duration::hours(6);
    let change = Transition::to(IpState::Quarantined, "test").retest_at(retest);
    h.transition(ip(n), change).await?;
    Ok(())
}

async fn retire(h: &Harness, n: u8) -> TestResult {
    let change = Transition::to(IpState::Retired, "removed from the inventory");
    h.transition(ip(n), change).await?;
    Ok(())
}

/// Three checks of each of `sources`, all with this risk.
async fn seed_scores(h: &Harness, n: u8, sources: &[&str], risk: u8) -> TestResult {
    let now = OffsetDateTime::now_utc();
    for i in 1..=3 {
        for source in sources {
            h.db.record_score(&ScoreRow {
                ip: IpAddr::V4(ip(n)),
                source: (*source).to_owned(),
                risk,
                flags: vec![],
                checked_at: now + time::Duration::seconds(i),
            })
            .await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn a_candidate_that_passes_its_checks_becomes_available_and_leasable() -> TestResult {
    let h = harness!(start(""));
    h.add_inventory("stat", Subtype::Isp, ip(1), None).await?;
    assert_eq!(h.row(ip(1)).await?.state, IpState::Candidate);
    assert!(!leasable(&h, 1).await?, "a candidate is not leased");

    h.static_tick().await;
    let row = h.row(ip(1)).await?;
    assert_eq!(row.state, IpState::Available);
    assert!(row.last_check_at.is_some());
    assert_eq!(row.exit_ip, Some(IpAddr::V4(ip(1))));
    assert!(leasable(&h, 1).await?);
    assert_eq!(
        h.db.recent_scores(IpAddr::V4(ip(1)), 1).await?.len(),
        1,
        "the reputation check is recorded"
    );
    Ok(())
}

#[tokio::test]
async fn a_candidate_whose_exit_ip_differs_from_its_entry_is_quarantined() -> TestResult {
    let h = harness!(start(""));
    h.add_inventory("stat", Subtype::Isp, ip(2), None).await?;
    h.fake
        .set_user_ip("st-203-0-113-2", Ipv4Addr::new(198, 51, 100, 5));
    h.static_tick().await;
    let row = h.row(ip(2)).await?;
    assert_eq!(
        row.state,
        IpState::Quarantined,
        "inventory drift is found by the check"
    );
    assert!(row.retest_at.is_some());
    assert!(!leasable(&h, 2).await?);
    Ok(())
}

#[tokio::test]
async fn a_candidate_is_promoted_while_its_route_class_is_paused() -> TestResult {
    // A failed canary pauses a class that has only candidates (a new region):
    // the canary can only pass again through an IP that is back in service.
    let h = harness!(start(""));
    h.add_inventory("stat", Subtype::Isp, ip(3), None).await?;
    let p = h.partition("stat")?;
    h.hot.warm_pause(&p, Duration::from_secs(60)).await?;
    h.static_tick().await;
    assert_eq!(h.row(ip(3)).await?.state, IpState::Available);
    assert!(leasable(&h, 3).await?, "leasable although paused");
    assert!(
        h.hot.warm_paused(&p).await?,
        "only a canary lifts the pause"
    );
    Ok(())
}

#[tokio::test]
async fn a_cooled_ip_is_retested_while_its_route_class_is_paused() -> TestResult {
    // A failed canary drains the class and pauses warming; the canary can only
    // pass again through an IP that is back in service.
    let h = harness!(start(""));
    available(&h, 12).await?;
    to_cooldown(&h, 12, in_the_past()).await?;
    let p = h.partition("stat")?;
    h.hot.warm_pause(&p, Duration::from_secs(60)).await?;

    h.static_tick().await;
    assert_eq!(h.row(ip(12)).await?.state, IpState::Available);
    assert!(leasable(&h, 12).await?, "back in service although paused");
    assert!(
        h.hot.warm_paused(&p).await?,
        "only a canary lifts the pause"
    );
    Ok(())
}

#[tokio::test]
async fn a_cooled_ip_returns_to_available_after_a_passing_retest() -> TestResult {
    let h = harness!(start(""));
    available(&h, 10).await?;
    available(&h, 11).await?;
    to_cooldown(&h, 10, OffsetDateTime::now_utc() + time::Duration::hours(1)).await?;
    to_cooldown(&h, 11, in_the_past()).await?;

    h.static_tick().await;
    assert_eq!(
        h.row(ip(10)).await?.state,
        IpState::Cooldown,
        "the cooldown has not ended: no retest yet"
    );
    assert!(!leasable(&h, 10).await?);
    assert_eq!(
        h.row(ip(11)).await?.state,
        IpState::Available,
        "passing retest"
    );
    assert!(leasable(&h, 11).await?, "leasable again");
    Ok(())
}

/// N2-1: a gateway withdraws an IP for 60 s, again after the warmer returned it
/// (a provider blip). The second rest is retested when it ends, not only after
/// the 15 minute spacing of a failed retest.
#[tokio::test]
async fn an_ip_that_cools_again_is_retested_when_its_new_rest_ends() -> TestResult {
    let h = harness!(start(""));
    available(&h, 13).await?;
    to_cooldown(&h, 13, in_the_past()).await?;
    h.static_tick().await;
    assert_eq!(h.row(ip(13)).await?.state, IpState::Available, "first rest");

    to_cooldown(&h, 13, in_the_past()).await?;
    h.static_tick().await;
    assert_eq!(
        h.row(ip(13)).await?.state,
        IpState::Available,
        "a second rest, seconds after the first retest"
    );
    assert!(leasable(&h, 13).await?);
    Ok(())
}

/// A rest that was retested and failed is not retested every tick.
#[tokio::test]
async fn a_failed_retest_is_not_repeated_within_the_same_cooldown() -> TestResult {
    let h = harness!(start(""));
    available(&h, 14).await?;
    to_cooldown(&h, 14, in_the_past()).await?;
    h.fake.set_probe_status(403);
    h.static_tick().await;
    assert_eq!(h.row(ip(14)).await?.state, IpState::Cooldown);
    // The next tick would pass a retest, so a still-cooling IP shows there was none.
    h.fake.set_probe_status(200);
    h.static_tick().await;
    assert_eq!(h.row(ip(14)).await?.state, IpState::Cooldown, "spaced");
    Ok(())
}

#[tokio::test]
async fn repeated_blocks_send_a_cooled_ip_to_quarantine() -> TestResult {
    // One of two targets blocks: below replace_blocked_share, so the replacement rule stays out of it.
    let h = harness!(Harness::start(Setup {
        probe_targets: vec![
            "http://probe.test/probe/bad",
            "http://probe.test/probe/fine",
        ],
        ..setup("[policy.static]\ncooldown = \"1s\"\nquarantine_after = 3\n")
    }));
    available(&h, 20).await?;
    to_cooldown(&h, 20, in_the_past()).await?;
    h.db.record_block(
        IpAddr::V4(ip(20)),
        None,
        SignalSource::Operator,
        SignalType::Challenge,
        None,
    )
    .await?;
    h.fake.set_probe_status(403);

    h.static_tick().await;
    assert_eq!(
        h.row(ip(20)).await?.state,
        IpState::Cooldown,
        "two blocks in the hour are below quarantine_after"
    );
    tokio::time::sleep(Duration::from_millis(1100)).await;
    h.static_tick().await;
    let row = h.row(ip(20)).await?;
    assert_eq!(
        row.state,
        IpState::Quarantined,
        "the third block quarantines it"
    );
    assert!(row.retest_at.is_some());
    assert!(!leasable(&h, 20).await?);
    Ok(())
}

#[tokio::test]
async fn two_blocked_probes_in_a_row_request_a_replacement() -> TestResult {
    let h = harness!(start(
        "[policy.static]\ncooldown = \"1s\"\nquarantine_after = 9\n"
    ));
    available(&h, 25).await?;
    to_cooldown(&h, 25, in_the_past()).await?;
    h.fake.set_probe_status(403);

    h.static_tick().await;
    assert_eq!(
        h.row(ip(25)).await?.state,
        IpState::Cooldown,
        "one blocked probe is not enough"
    );
    tokio::time::sleep(Duration::from_millis(1100)).await;
    h.static_tick().await;
    assert_eq!(
        h.row(ip(25)).await?.state,
        IpState::ReplaceRequested,
        "every target blocked on two probes in a row"
    );
    assert!(!leasable(&h, 25).await?);
    Ok(())
}

/// A block page every IP gets is the target's doing. The pool rests,
/// but no IP is replaced for it.
#[tokio::test]
async fn a_block_page_on_every_ip_does_not_request_replacements() -> TestResult {
    let h = harness!(start(
        "[policy.static]\ncooldown = \"1s\"\nquarantine_after = 9\n"
    ));
    let ips = [26, 27, 28];
    for n in ips {
        available(&h, n).await?;
    }
    for n in ips {
        to_cooldown(&h, n, in_the_past()).await?;
    }
    h.fake.set_probe_status(403);

    for _ in 0..3 {
        h.static_tick().await;
        tokio::time::sleep(Duration::from_millis(1100)).await;
    }
    for n in ips {
        assert_eq!(
            h.row(ip(n)).await?.state,
            IpState::Cooldown,
            "{n}: blocked on every IP is not the IP's fault"
        );
    }
    Ok(())
}

#[tokio::test]
async fn a_quarantined_ip_is_retested_when_due_and_returns_when_it_passes() -> TestResult {
    let h = harness!(start(""));
    h.add_inventory("stat", Subtype::Isp, ip(30), None).await?;
    quarantine(&h, 30).await?;
    h.static_tick().await;
    assert_eq!(
        h.row(ip(30)).await?.state,
        IpState::Quarantined,
        "not due yet"
    );

    h.transition(ip(30), Transition::to(IpState::Candidate, "test"))
        .await?;
    let change = Transition::to(IpState::Quarantined, "test again").retest_at(in_the_past());
    h.transition(ip(30), change).await?;
    h.fake.set_probe_status(403);
    h.static_tick().await;
    assert_eq!(
        h.row(ip(30)).await?.state,
        IpState::Quarantined,
        "a blocked retest fails"
    );

    h.fake.set_probe_status(200);
    // The retest is spaced by retest_every, which is long: reset the memory of the attempt.
    h.w.memory.lock().attempts.clear();
    h.static_tick().await;
    assert_eq!(h.row(ip(30)).await?.state, IpState::Available);
    assert!(leasable(&h, 30).await?);
    Ok(())
}

#[tokio::test]
async fn a_bad_reputation_cools_an_available_ip() -> TestResult {
    let h = harness!(start(""));
    available(&h, 40).await?;
    h.fake.set_risk(ip(40), 90);
    h.make_stale(ip(40)).await?;
    h.static_tick().await;
    let row = h.row(ip(40)).await?;
    assert_eq!(row.state, IpState::Cooldown);
    assert!(
        row.cooldown_until
            .is_some_and(|t| t > OffsetDateTime::now_utc())
    );
    assert!(!leasable(&h, 40).await?);
    Ok(())
}

#[tokio::test]
async fn the_warn_zone_twice_in_a_row_cools_an_ip_but_once_does_not() -> TestResult {
    let h = harness!(start(""));
    available(&h, 50).await?;
    h.fake.set_risk(ip(50), 60);
    h.make_stale(ip(50)).await?;
    h.static_tick().await;
    assert_eq!(
        h.row(ip(50)).await?.state,
        IpState::Available,
        "one warning keeps the IP"
    );
    h.make_stale(ip(50)).await?;
    h.static_tick().await;
    assert_eq!(
        h.row(ip(50)).await?.state,
        IpState::Cooldown,
        "the second one drains it"
    );
    Ok(())
}

#[tokio::test]
async fn a_changed_exit_ip_sends_an_available_ip_back_to_candidate() -> TestResult {
    let h = harness!(start(""));
    available(&h, 60).await?;
    h.fake
        .set_user_ip("st-203-0-113-60", Ipv4Addr::new(198, 51, 100, 60));
    h.make_stale(ip(60)).await?;
    h.static_tick().await;
    assert_eq!(h.row(ip(60)).await?.state, IpState::Candidate);
    assert!(!leasable(&h, 60).await?);
    assert_eq!(evictions(&h, "ip_changed"), 1);
    Ok(())
}

#[tokio::test]
async fn the_replacement_rule_emits_one_report_per_ip_per_day() -> TestResult {
    let mut h = harness!(start_scored());
    let log = LogCapture::start();
    available(&h, 70).await?;
    seed_scores(&h, 70, &["ipqs", "abuseipdb"], 90).await?;
    h.static_tick().await;
    let row = h.row(ip(70)).await?;
    assert_eq!(row.state, IpState::ReplaceRequested);
    assert!(
        !leasable(&h, 70).await?,
        "a replace-requested IP leaves leasing"
    );

    let events = log.events("pool_replacement_report");
    assert_eq!(events.len(), 1, "{}", log.text());
    let e = &events[0];
    assert_eq!(e["provider"], "stat");
    assert_eq!(e["plan"], "test plan");
    assert_eq!(e["ip"], "203.0.113.70");
    assert_eq!(e["port"], u64::from(h.fake.port));
    assert!(
        e["reasons"]
            .as_str()
            .is_some_and(|r| r.contains("reputation")),
        "{e}"
    );
    assert!(
        e["scores"]
            .as_str()
            .is_some_and(|s| s.contains("\"risk\":90")),
        "{e}"
    );
    assert_eq!(e["rental_end"], "2030-01-01");
    assert!(
        !log.text().contains("st-203-0-113-70") && !log.text().contains(":pw"),
        "no credential in the event"
    );
    assert_eq!(
        h.metrics
            .replace_reports_total
            .with_label_values(&["stat"])
            .get(),
        1
    );
    assert!(
        h.metrics
            .inventory_rental_days_left
            .with_label_values(&["stat"])
            .get()
            > 0.0,
        "the rental gauge is set"
    );

    // Later passes within the day stay quiet.
    h.static_tick().await;
    h.static_tick().await;
    assert_eq!(log.events("pool_replacement_report").len(), 1);
    let ttl: i64 = redis::cmd("PTTL")
        .arg(format!(
            "once:replace:203.0.113.70:{}",
            row.state_since.unix_timestamp()
        ))
        .query_async(&mut h.raw)
        .await?;
    assert!(
        (23 * 3600 * 1000..=24 * 3600 * 1000).contains(&ttl),
        "the once-a-day slot holds 24 h: {ttl}"
    );

    // A Redis loss does not repeat the report inside the day: Postgres
    // remembers it.
    redis::cmd("FLUSHDB").query_async::<()>(&mut h.raw).await?;
    h.static_tick().await;
    assert_eq!(
        log.events("pool_replacement_report").len(),
        1,
        "{}",
        log.text()
    );

    // A day later the report repeats.
    let reasons = ["reputation".to_owned()];
    h.w.emit_report(
        &h.row(ip(70)).await?,
        &reasons,
        OffsetDateTime::now_utc() + time::Duration::hours(25),
    )
    .await?;
    assert_eq!(log.events("pool_replacement_report").len(), 2);

    // An IP that is replaced and comes back to ReplaceRequested is a new
    // stay: it is reported at once, not 24 h after the last stay.
    let mut again = h.row(ip(70)).await?;
    again.state_since += time::Duration::seconds(5);
    h.w.emit_report(&again, &reasons, OffsetDateTime::now_utc())
        .await?;
    assert_eq!(log.events("pool_replacement_report").len(), 3);
    Ok(())
}

#[tokio::test]
async fn a_failed_read_does_not_use_up_the_days_replacement_report() -> TestResult {
    // The failure is forced with a date PostgreSQL cannot store; SQLite keeps
    // microseconds in a 64-bit integer and MariaDB errors differently.
    if proxyx_db::testing::selected() != proxyx_db::Backend::Postgres {
        eprintln!("SKIP: forces a PostgreSQL-specific date range error");
        return Ok(());
    }
    let h = harness!(start(""));
    let log = LogCapture::start();
    h.add_inventory("stat", Subtype::Isp, ip(110), None).await?;
    let row = h
        .transition(ip(110), Transition::to(IpState::ReplaceRequested, "test"))
        .await?;
    let reasons = ["reputation".to_owned()];
    // A date Postgres cannot store makes the block query fail.
    let unreadable = OffsetDateTime::new_utc(
        time::Date::from_calendar_date(-9000, time::Month::January, 1)?,
        time::Time::MIDNIGHT,
    );
    assert!(h.w.emit_report(&row, &reasons, unreadable).await.is_err());
    assert!(log.events("pool_replacement_report").is_empty());

    h.w.emit_report(&row, &reasons, OffsetDateTime::now_utc())
        .await?;
    assert_eq!(
        log.events("pool_replacement_report").len(),
        1,
        "the retry still reports: {}",
        log.text()
    );
    Ok(())
}

#[tokio::test]
async fn one_noisy_service_does_not_replace_an_ip() -> TestResult {
    let h = harness!(start_scored());
    available(&h, 80).await?;
    seed_scores(&h, 80, &["ipqs"], 99).await?;
    h.static_tick().await;
    assert_eq!(h.row(ip(80)).await?.state, IpState::Available);
    Ok(())
}

#[tokio::test]
async fn a_long_quarantine_requests_a_replacement() -> TestResult {
    let h = harness!(start("[policy.static]\nreplace_quarantine_for = \"1s\"\n"));
    h.add_inventory("stat", Subtype::Isp, ip(90), None).await?;
    quarantine(&h, 90).await?;
    h.static_tick().await;
    assert_eq!(
        h.row(ip(90)).await?.state,
        IpState::Quarantined,
        "not long enough yet"
    );
    tokio::time::sleep(Duration::from_millis(1100)).await;
    h.static_tick().await;
    assert_eq!(h.row(ip(90)).await?.state, IpState::ReplaceRequested);
    Ok(())
}

/// The Redis write after a move to `Available` failed: the next tick puts the
/// IP back, and leaves the one that rests in cooldown out.
#[tokio::test]
async fn a_leasable_ip_missing_from_the_ready_set_is_put_back() -> TestResult {
    let h = harness!(start(""));
    available(&h, 200).await?;
    available(&h, 201).await?;
    to_cooldown(
        &h,
        201,
        OffsetDateTime::now_utc() + time::Duration::hours(1),
    )
    .await?;
    let p = h.partition("stat")?;
    h.hot.ready_take(&p, &ip(200).to_string()).await?;
    assert!(!leasable(&h, 200).await?);

    h.static_tick().await;
    assert!(leasable(&h, 200).await?, "the leasable ip is back");
    assert!(!leasable(&h, 201).await?, "the cooled ip stays out");
    Ok(())
}

#[tokio::test]
async fn a_retired_ip_leaves_leasing() -> TestResult {
    let h = harness!(start(""));
    available(&h, 100).await?;
    retire(&h, 100).await?;
    assert!(
        leasable(&h, 100).await?,
        "still in Redis until the loop runs"
    );
    h.static_tick().await;
    assert!(!leasable(&h, 100).await?);
    Ok(())
}

#[tokio::test]
async fn the_last_ip_of_a_partition_leaves_leasing_when_it_is_retired() -> TestResult {
    let h = harness!(start(""));
    available(&h, 101).await?;
    retire(&h, 101).await?;
    // The published snapshot now holds only a retired row for the partition:
    // the warmer must still lock it to withdraw the unit.
    h.reload().await?;
    h.static_tick().await;
    assert!(!leasable(&h, 101).await?);
    Ok(())
}

/// An IP whose upstream drops or refuses every check connection
/// left `Available` never; now it cools and leaves leasing. An IP whose check
/// services are merely down (they answer 503) stays.
#[tokio::test]
async fn a_dead_static_ip_cools_while_down_check_services_leave_it_alone() -> TestResult {
    let h = harness!(start("[policy.static]\nrecheck_every = \"1s\"\n"));
    for n in [120, 121, 122] {
        available(&h, n).await?;
    }
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    h.fake
        .set_user_mode("st-203-0-113-120", Some(UserMode::Drop));
    h.fake
        .set_user_mode("st-203-0-113-121", Some(UserMode::Auth));
    h.static_tick().await;
    for n in [120, 121] {
        assert_eq!(h.row(ip(n)).await?.state, IpState::Cooldown, "{n}");
        assert!(!leasable(&h, n).await?, "{n} leaves leasing");
    }
    assert_eq!(h.row(ip(122)).await?.state, IpState::Available);
    assert!(leasable(&h, 122).await?);

    // the check services go down behind a healthy upstream: no verdict
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    h.fake.set_checks_down(true);
    h.static_tick().await;
    assert_eq!(h.row(ip(122)).await?.state, IpState::Available);
    assert!(leasable(&h, 122).await?);
    Ok(())
}

/// A provider outage makes every retest fail the same way. They must not
/// count toward quarantine, or the whole pool rests 6 h after the provider is
/// back.
#[tokio::test]
async fn retests_that_fail_like_a_provider_outage_do_not_quarantine_the_pool() -> TestResult {
    let h = harness!(start_probing(
        "[policy.static]\ncooldown = \"1s\"\nquarantine_after = 1\n"
    ));
    for n in [130, 131, 132] {
        available(&h, n).await?;
    }
    for n in [130, 131, 132] {
        to_cooldown(&h, n, in_the_past()).await?;
        h.fake
            .set_user_mode(&format!("st-203-0-113-{n}"), Some(UserMode::Drop));
    }
    h.static_tick().await;
    for n in [130, 131, 132] {
        assert_eq!(
            h.row(ip(n)).await?.state,
            IpState::Cooldown,
            "{n}: a failed retest of the whole class is the provider's, not the IP's"
        );
        assert!(
            h.db.ip_wide_blocks_since(
                IpAddr::V4(ip(n)),
                OffsetDateTime::now_utc() - time::Duration::hours(1)
            )
            .await?
                == 0,
            "{n}: no block is recorded"
        );
    }

    // The provider is back: the next retest returns every IP.
    for n in [130, 131, 132] {
        h.fake.set_user_mode(&format!("st-203-0-113-{n}"), None);
    }
    tokio::time::sleep(Duration::from_millis(1100)).await;
    h.static_tick().await;
    for n in [130, 131, 132] {
        assert_eq!(h.row(ip(n)).await?.state, IpState::Available, "{n}");
        assert!(leasable(&h, n).await?, "{n}");
    }
    Ok(())
}

/// R3 keeps the rule for one IP that fails while the rest of the pool works.
#[tokio::test]
async fn a_retest_failing_for_one_ip_of_a_healthy_pool_still_counts() -> TestResult {
    let h = harness!(start(
        "[policy.static]\ncooldown = \"1s\"\nquarantine_after = 1\n"
    ));
    for n in [140, 141, 142] {
        available(&h, n).await?;
    }
    to_cooldown(&h, 140, in_the_past()).await?;
    h.fake
        .set_user_mode("st-203-0-113-140", Some(UserMode::Drop));
    h.static_tick().await;
    assert_eq!(
        h.row(ip(140)).await?.state,
        IpState::Quarantined,
        "one dead IP among healthy ones is that IP's fault"
    );
    Ok(())
}

/// While a route class is down, its cooled IPs are retested at the
/// breaker's probe spacing and not after the 1 h cooldown, so the pool is back
/// within a probe after the provider is.
#[tokio::test]
async fn a_down_route_class_is_retested_at_the_probe_spacing_not_the_cooldown() -> TestResult {
    let h = harness!(start_probing(
        "[policy.static]\ncooldown = \"1h\"\nrecheck_every = \"1s\"\n"
    ));
    for n in [160, 161, 162] {
        available(&h, n).await?;
    }
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    for n in [160, 161, 162] {
        h.fake
            .set_user_mode(&format!("st-203-0-113-{n}"), Some(UserMode::Drop));
    }
    // The rechecks cool the IPs for an hour; the next tick sees the class down.
    h.static_tick().await;
    h.static_tick().await;
    for n in [160, 161, 162] {
        assert_eq!(h.row(ip(n)).await?.state, IpState::Cooldown, "{n}");
    }

    // The provider is back; the IPs wait one probe spacing, not an hour.
    for n in [160, 161, 162] {
        h.fake.set_user_mode(&format!("st-203-0-113-{n}"), None);
    }
    tokio::time::sleep(Duration::from_millis(400)).await;
    h.static_tick().await;
    for n in [160, 161, 162] {
        assert_eq!(h.row(ip(n)).await?.state, IpState::Available, "{n}");
        assert!(leasable(&h, n).await?, "{n}");
    }
    Ok(())
}

/// D4 does not touch single-IP failures: one cooled IP of a healthy pool waits
/// for its cooldown, even when its upstream works again.
#[tokio::test]
async fn one_cooled_ip_of_a_healthy_pool_waits_for_its_cooldown() -> TestResult {
    let h = harness!(start_probing("[policy.static]\ncooldown = \"1h\"\n"));
    for n in [170, 171, 172] {
        available(&h, n).await?;
    }
    to_cooldown(
        &h,
        170,
        OffsetDateTime::now_utc() + time::Duration::hours(1),
    )
    .await?;
    h.static_tick().await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    h.static_tick().await;
    assert_eq!(h.row(ip(170)).await?.state, IpState::Cooldown);
    Ok(())
}

/// D4 is for outages only: IPs cooled by blocks wait out their cooldown even
/// when most of the route class rests.
#[tokio::test]
async fn block_cooled_ips_of_a_mostly_cooled_pool_still_wait_for_their_cooldown() -> TestResult {
    let h = harness!(start_probing("[policy.static]\ncooldown = \"1h\"\n"));
    for n in [190, 191, 192] {
        available(&h, n).await?;
        to_cooldown(&h, n, OffsetDateTime::now_utc() + time::Duration::hours(1)).await?;
    }
    h.static_tick().await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    h.static_tick().await;
    for n in [190, 191, 192] {
        assert_eq!(h.row(ip(n)).await?.state, IpState::Cooldown, "{n}");
    }
    Ok(())
}

const SLOW_CRITERIA: &str = "[policy.criteria]\nmax_ttfb_ms = 100\nbrowser_sample = 0.0\n";

async fn tier_of(h: &Harness, n: u8) -> TestResult<Tier> {
    let p = h.partition("stat")?;
    Ok(h.hot.tier(&p, &ip(n).to_string()).await?)
}

/// Clean answers over the TTFB limit make a candidate `Degraded`, not a
/// quarantined one.
#[tokio::test]
async fn a_slow_candidate_is_leasable_in_the_degraded_tier() -> TestResult {
    let h = harness!(start(SLOW_CRITERIA));
    h.fake.set_probe_delay(300);
    h.add_inventory("stat", Subtype::Isp, ip(150), None).await?;
    h.static_tick().await;
    assert_eq!(h.row(ip(150)).await?.state, IpState::Degraded);
    assert!(leasable(&h, 150).await?);
    assert_eq!(tier_of(&h, 150).await?, Tier::Degraded);
    Ok(())
}

/// A recheck that finds an IP slow degrades it, a later one at full speed
/// returns it, and blocks or errors still cool it.
#[tokio::test]
async fn a_recheck_degrades_a_slow_ip_and_a_fast_one_returns_it_but_blocks_still_cool() -> TestResult
{
    let h = harness!(start(SLOW_CRITERIA));
    available(&h, 151).await?;
    assert_eq!(tier_of(&h, 151).await?, Tier::Normal);

    h.fake.set_probe_delay(300);
    h.make_stale(ip(151)).await?;
    h.static_tick().await;
    assert_eq!(h.row(ip(151)).await?.state, IpState::Degraded);
    assert!(leasable(&h, 151).await?, "a slow IP keeps serving");
    assert_eq!(tier_of(&h, 151).await?, Tier::Degraded);

    h.fake.set_probe_delay(0);
    h.make_stale(ip(151)).await?;
    h.static_tick().await;
    assert_eq!(h.row(ip(151)).await?.state, IpState::Available);
    assert_eq!(tier_of(&h, 151).await?, Tier::Normal);

    // Slow, then blocked: a block cools it even from the degraded tier.
    h.fake.set_probe_delay(300);
    h.make_stale(ip(151)).await?;
    h.static_tick().await;
    assert_eq!(h.row(ip(151)).await?.state, IpState::Degraded);
    h.fake.set_probe_status(403);
    h.make_stale(ip(151)).await?;
    h.static_tick().await;
    assert_eq!(h.row(ip(151)).await?.state, IpState::Cooldown);
    assert!(!leasable(&h, 151).await?);
    Ok(())
}

/// A leased degraded IP counts as `leased` only, not as `degraded` too.
#[tokio::test]
async fn a_leased_degraded_ip_is_counted_once_in_the_inventory_gauge() -> TestResult {
    let h = harness!(start(SLOW_CRITERIA));
    h.fake.set_probe_delay(300);
    for n in [180, 181] {
        h.add_inventory("stat", Subtype::Isp, ip(n), None).await?;
    }
    h.static_tick().await;
    let ips = |state: &str| {
        h.metrics
            .inventory_ips
            .with_label_values(&["stat", state])
            .get()
    };
    h.w.gauges_tick().await;
    assert_eq!((ips("degraded"), ips("leased")), (2, 0));

    let p = h.partition("stat")?;
    h.lease_free(&p, Kind::Static, "acme", "s", Duration::from_secs(60))
        .await?;
    h.w.gauges_tick().await;
    assert_eq!(
        (ips("available"), ips("degraded"), ips("leased")),
        (0, 1, 1),
        "two IPs: one leased, one free and degraded"
    );
    Ok(())
}
