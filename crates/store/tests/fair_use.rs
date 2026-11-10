//! Monthly fair-use traffic of a static IP: warn at 80%, no new lease at
//! 100% until the UTC month changes.

#[macro_use]
mod support;

use proxyx_store::{FairUse, LeaseOutcome};
use support::{TestResult, grant, ip, lease_static, org, partition, seed_static, seeded_partition};
use time::{Date, Month, OffsetDateTime};

const LIMIT: u64 = 1_000;

fn in_month(m: Month, day: u8) -> OffsetDateTime {
    Date::from_calendar_date(2031, m, day)
        .expect("date")
        .with_hms(12, 0, 0)
        .expect("time")
        .assume_utc()
}

/// The report of a call that crosses no threshold.
fn quiet(used: u64) -> FairUse {
    FairUse {
        used,
        warned: false,
        stopped: false,
    }
}

#[tokio::test]
async fn warns_at_eighty_percent_and_stops_new_leases_at_the_limit_until_next_month() -> TestResult
{
    let hot = hot_or_skip!();
    let p = seeded_partition(&hot, &[1]).await?;
    let now = OffsetDateTime::now_utc();

    // below the limit the IP is leasable; org a holds it
    let (a, b, c) = (org("a")?, org("b")?, org("c")?);
    let ga = lease_static(&hot, &p, &a, "s").await?;
    assert!(matches!(ga, LeaseOutcome::Free(_)));
    assert_eq!(grant(&ga)?.ip, ip(1));
    seed_static(&hot, &p, &[2]).await?;

    let add = |bytes, at| hot.fair_use_add(&p, ip(1), bytes, LIMIT, at);
    assert_eq!(add(799, now).await?, quiet(799));
    assert_eq!(
        add(1, now).await?,
        FairUse {
            used: 800,
            warned: true,
            stopped: false
        },
        "80% exactly warns, once"
    );
    assert_eq!(add(100, now).await?, quiet(900));

    assert_eq!(
        add(100, now).await?,
        FairUse {
            used: 1_000,
            warned: false,
            stopped: true
        },
        "the limit stops the IP"
    );
    assert_eq!(
        add(5, now).await?,
        quiet(1_005),
        "only the crossing call reports"
    );

    // a new lease never gets the stopped IP, whichever it would have picked
    let gb = lease_static(&hot, &p, &b, "s").await?;
    let gc = lease_static(&hot, &p, &c, "s").await?;
    for g in [&gb, &gc] {
        assert_eq!(grant(g)?.ip, ip(2), "{g:?}");
    }
    // a lease the stopped IP already holds is renewed
    let held = grant(&ga)?.unit.clone();
    let again = lease_static(&hot, &p, &a, "s").await?;
    assert_eq!(grant(&again)?.unit, held);
    assert!(matches!(again, LeaseOutcome::Hit(_)), "{again:?}");

    // with the other IP stopped too, the stop is the last limit to break
    hot.fair_use_add(&p, ip(2), 2_000, LIMIT, now).await?;
    let d = org("d")?;
    let last = lease_static(&hot, &p, &d, "s").await?;
    assert_eq!(grant(&last)?.broke, Some("fair_use"), "{last:?}");
    Ok(())
}

#[tokio::test]
async fn a_new_month_counts_from_zero_and_a_zero_limit_only_counts() -> TestResult {
    let hot = hot_or_skip!();
    let p = partition()?;
    let (oct, nov) = (in_month(Month::October, 31), in_month(Month::November, 1));
    hot.fair_use_add(&p, ip(7), 600, LIMIT, oct).await?;
    let oct_used = hot.fair_use_add(&p, ip(7), 0, LIMIT, oct).await?.used;
    let nov_used = hot.fair_use_add(&p, ip(7), 0, LIMIT, nov).await?.used;
    assert_eq!(oct_used, 600);
    assert_eq!(nov_used, 0, "November has its own counter");

    let unlimited = hot.fair_use_add(&p, ip(8), 10_000_000, 0, oct).await?;
    assert_eq!(unlimited, quiet(10_000_000));
    seed_static(&hot, &p, &[8]).await?;
    let o = org("o")?;
    assert!(matches!(
        lease_static(&hot, &p, &o, "s").await?,
        LeaseOutcome::Free(_)
    ));
    Ok(())
}

#[tokio::test]
async fn the_stop_key_ends_with_the_month() -> TestResult {
    let hot = hot_or_skip!();
    let p = seeded_partition(&hot, &[3]).await?;
    // The month of `at` has ~1 s left, so the stop key expires almost at once.
    let last_second = {
        let now = OffsetDateTime::now_utc();
        let (y, m) = (now.year(), now.month());
        let next = if m == Month::December {
            Date::from_calendar_date(y + 1, Month::January, 1)
        } else {
            Date::from_calendar_date(y, m.next(), 1)
        }?;
        next.midnight().assume_utc() - time::Duration::milliseconds(300)
    };
    let o = org("o")?;
    let f = hot
        .fair_use_add(&p, ip(3), LIMIT, LIMIT, last_second)
        .await?;
    assert!(f.stopped);
    // the only IP is stopped: it is leased all the same, the stop broken
    let last = lease_static(&hot, &p, &o, "s").await?;
    assert_eq!(grant(&last)?.broke, Some("fair_use"), "{last:?}");
    hot.release(&p, &o, "s", None).await?;
    hot.tunnel_close(&grant(&last)?.tunnel).await?;
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let after = lease_static(&hot, &p, &org("p")?, "s").await?;
    assert!(
        matches!(after, LeaseOutcome::Free(_)) && grant(&after)?.broke.is_none(),
        "the IP is leasable again once the stop key's month is over: {after:?}"
    );
    Ok(())
}
