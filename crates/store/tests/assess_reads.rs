//! The pool-wide reads `proxyx assess pool` uses: latest risk per IP and the
//! block summary of a window.

#[macro_use]
mod support;

use common::types::{SignalSource, SignalType};
use proxyx_store::ScoreRow;
use support::{TestResult, fresh_db, uniq_ip};
use time::OffsetDateTime;

#[tokio::test]
async fn the_latest_risk_per_ip_takes_the_newest_check_of_each_source() -> TestResult {
    let Some((db, _raw)) = fresh_db("assess_reads").await? else {
        return Ok(());
    };
    let (a, b) = (uniq_ip(), uniq_ip());
    let now = OffsetDateTime::now_utc();
    let rows = [
        // a: ipqs got better (90 then 20); abuse says 35 -> highest of the latest is 35.
        (a, "ipqs", 90, -3),
        (a, "ipqs", 20, -1),
        (a, "abuse", 35, -2),
        // b: one check.
        (b, "ipqs", 60, -1),
    ];
    for (ip, source, risk, minutes) in rows {
        db.record_score(&ScoreRow {
            ip,
            source: source.into(),
            risk,
            flags: vec![],
            checked_at: now + time::Duration::minutes(minutes),
        })
        .await?;
    }
    let mut got = db.latest_risks().await?;
    got.sort();
    let mut want = vec![(a, 35), (b, 60)];
    want.sort();
    assert_eq!(got, want);
    Ok(())
}

#[tokio::test]
async fn the_block_summary_counts_signals_and_distinct_ips_inside_the_window() -> TestResult {
    let Some((db, raw)) = fresh_db("assess_reads_blocks").await? else {
        return Ok(());
    };
    let (a, b, old) = (uniq_ip(), uniq_ip(), uniq_ip());
    let now = OffsetDateTime::now_utc();
    let until = now + time::Duration::minutes(30);
    db.record_block(
        a,
        Some("x.example"),
        SignalSource::Client,
        SignalType::RateLimited,
        Some(until),
    )
    .await?;
    db.record_block(
        a,
        Some("y.example"),
        SignalSource::Client,
        SignalType::RateLimited,
        Some(until),
    )
    .await?;
    db.record_block(b, None, SignalSource::Operator, SignalType::Forbidden, None)
        .await?;
    let stale = db
        .record_block(
            old,
            None,
            SignalSource::Operator,
            SignalType::Challenge,
            None,
        )
        .await?;
    raw.execute(
        "UPDATE ip_blocks SET created_at = ? WHERE id = ?",
        &[(now - time::Duration::hours(5)).into(), stale.id.into()],
    )
    .await?;

    let hour = db
        .block_summary_since(now - time::Duration::hours(1))
        .await?;
    assert_eq!(hour.signals, 3);
    assert_eq!(hour.ips, 2);
    assert_eq!(
        hour.by_type,
        vec![("forbidden".to_owned(), 1), ("rate_limited".to_owned(), 2)]
    );
    let day = db
        .block_summary_since(now - time::Duration::hours(24))
        .await?;
    assert_eq!((day.signals, day.ips), (4, 3));
    let none = db
        .block_summary_since(now + time::Duration::hours(1))
        .await?;
    assert_eq!((none.signals, none.ips, none.by_type.len()), (0, 0, 0));
    Ok(())
}
