//! The replacement report: one WARN
//! event, `pool_replacement_report`, when an IP enters *ReplaceRequested*
//! and again once per 24 h while it stays there. It has no credential. It is
//! the only log line that may hold a static IP. A developer replaces the IP
//! in the provider panel and edits the inventory.
//!
//! The once-per-day rule lives in two places: Redis (`Hot::claim_once`) so two
//! replicas do not both report, and an audit row in Postgres so a restart or
//! a Redis loss does not repeat the event inside the window.

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::Context as _;
use common::types::IpState;
use serde_json::json;
use store::InventoryRow;
use time::{Date, Month, OffsetDateTime};

use crate::state::Warmer;
use crate::statics::time_duration;

/// The event repeats at most this often per IP.
const REPORT_EVERY: Duration = Duration::from_secs(24 * 3600);

impl Warmer {
    /// Emit the report unless one went out in the last 24 h.
    pub(crate) async fn emit_report(
        &self,
        row: &InventoryRow,
        reasons: &[String],
        now: OffsetDateTime,
    ) -> anyhow::Result<()> {
        let ip = row.entry.ip;
        let window = time_duration(REPORT_EVERY);
        let scores: Vec<_> = self
            .db
            .recent_scores(ip, 1)
            .await
            .context("failed to read scores for a replacement report")?
            .into_iter()
            .map(|s| {
                json!({
                    "service": s.source,
                    "risk": s.risk,
                    "flags": s.flags,
                    "checked_at_unix": s.checked_at.unix_timestamp(),
                })
            })
            .collect();
        let mut blocks_by_target: BTreeMap<String, u64> = BTreeMap::new();
        for block in self
            .db
            .blocks_since(ip, now - window)
            .await
            .context("failed to read blocks for a replacement report")?
        {
            *blocks_by_target
                .entry(block.target.unwrap_or_else(|| "*".to_owned()))
                .or_default() += 1;
        }
        let last_probes: Vec<_> = self
            .memory
            .lock()
            .probes
            .get(&ip)
            .map(|rounds| {
                rounds
                    .iter()
                    .map(|r| json!({ "blocked": r.blocked, "total": r.total }))
                    .collect()
            })
            .unwrap_or_default();

        // Postgres remembers the last report: Redis alone would repeat it
        // after a Redis loss (nothing that must survive one lives only
        // there). Read before the claim, so a failed read cannot use up the day.
        // one subject per stay in ReplaceRequested: a replaced IP that later
        // returns there reports again at once
        let subject = format!("replace-report:{ip}:{}", row.state_since.unix_timestamp());
        let last = self
            .db
            .audit_for(&subject, 1)
            .await
            .context("failed to read the last replacement report")?;
        if last.first().is_some_and(|prev| now - prev.at < window) {
            return Ok(());
        }
        // Claimed last: a failed read above must not use up the day's report.
        // Redis settles which replica reports when several get here together;
        // the key names the stay (as the audit subject does), so an IP that
        // is replaced and returns to ReplaceRequested is reported at once.
        let first_today = self
            .hot
            .claim_once(
                &format!("replace:{ip}:{}", row.state_since.unix_timestamp()),
                REPORT_EVERY,
            )
            .await
            .context("failed to claim the daily replacement report")?;
        if !first_today {
            return Ok(());
        }

        tracing::warn!(
            provider = %row.entry.provider,
            plan = %row.entry.plan,
            %ip,
            port = row.entry.port,
            state_since_unix = row.state_since.unix_timestamp(),
            reasons = %reasons.join(","),
            scores = %json!(scores),
            blocks_by_target = %json!(blocks_by_target),
            last_probes = %json!(last_probes),
            rental_end = row.entry.rental_end.as_deref().unwrap_or(""),
            "pool_replacement_report"
        );
        self.metrics
            .replace_reports_total
            .with_label_values(&[row.entry.provider.as_str()])
            .inc();
        if let Err(error) = self
            .db
            .audit(
                "warmer",
                "inventory.replacement_report",
                &subject,
                json!({ "reasons": reasons }),
            )
            .await
        {
            tracing::warn!(%error, "failed to record a replacement report");
        }
        Ok(())
    }

    /// `inventory_rental_days_left{provider}`: the fewest days left among the
    /// provider's IPs that are not retired and have a valid `rental_end`. A
    /// provider without one has no series, so the alert cannot fire on a
    /// value a renewal or a retirement left behind.
    pub(crate) fn publish_rental_days(&self, rows: &[InventoryRow]) {
        self.metrics.inventory_rental_days_left.reset();
        let today = OffsetDateTime::now_utc().date();
        let mut fewest: BTreeMap<&str, i64> = BTreeMap::new();
        for row in rows {
            if row.state == IpState::Retired {
                continue;
            }
            let Some(end) = row.entry.rental_end.as_deref().and_then(parse_date) else {
                continue;
            };
            let days = (end - today).whole_days();
            fewest
                .entry(row.entry.provider.as_str())
                .and_modify(|d| *d = (*d).min(days))
                .or_insert(days);
        }
        for (provider, days) in fewest {
            // Day counts are small; the conversion is exact.
            self.metrics
                .inventory_rental_days_left
                .with_label_values(&[provider])
                .set(days as f64);
        }
    }
}

/// `YYYY-MM-DD`.
fn parse_date(text: &str) -> Option<Date> {
    let mut parts = text.split('-');
    let year: i32 = parts.next()?.parse().ok()?;
    let month: u8 = parts.next()?.parse().ok()?;
    let day: u8 = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Date::from_calendar_date(year, Month::try_from(month).ok()?, day).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rental_end_dates_parse_strictly() {
        assert_eq!(
            parse_date("2026-11-03"),
            Date::from_calendar_date(2026, Month::November, 3).ok()
        );
        for bad in [
            "",
            "2026-13-01",
            "2026-02-30",
            "2026-11",
            "2026-11-03-01",
            "soon",
        ] {
            assert_eq!(parse_date(bad), None, "{bad:?}");
        }
    }
}
