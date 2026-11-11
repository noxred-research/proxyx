//! The state of one rotating session after it became ready.
//!
//! It lives in the `due` set as the job text itself, so any replica can run
//! the next step and a Redis loss forgets only the sessions it also forgot
//!. Every step
//! writes the next job before it removes the old one, so a crash repeats a
//! step and never loses the session.
//!
//! The warmer creates sessions ahead of demand and the gateway creates them
//! on demand (`on_empty = create`); both schedule the same job before the
//! session becomes ready, and the warmer's keepalive loop runs it.

use std::net::Ipv4Addr;

use common::types::{Partition, ProviderId, Region};

const TAG: &str = "s1";

/// What the next step of a session is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Phase {
    /// Ready or leased: keepalive, re-check, and the eviction rules.
    Keep {
        /// Keepalives that failed in a row.
        fails: u32,
        /// Failed keepalives in the current hour window.
        drops: u32,
        /// Exit IP changes in the current hour window.
        changes: u32,
        /// Start of the hour window of `drops` and `changes` (unix seconds).
        window_start: i64,
        /// Last reputation re-check (unix seconds).
        last_recheck: i64,
        /// The last re-check was in the warn zone (a second one drains).
        warn_zone: bool,
    },
    /// Not leasable any more; waits for its tunnels to end.
    Drain {
        /// When the drain began (unix seconds), for the drain cap.
        since: i64,
    },
}

impl Phase {
    /// The first phase of a session that just became ready.
    pub fn fresh(now: i64) -> Self {
        Phase::Keep {
            fails: 0,
            drops: 0,
            changes: 0,
            window_start: now,
            last_recheck: now,
            warn_zone: false,
        }
    }
}

/// One rotating session in the `due` set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionJob {
    pub partition: Partition,
    pub session: String,
    /// The exit IP the session was verified with.
    pub ip: Ipv4Addr,
    /// When it became ready (unix seconds), for `ready_ttl`.
    pub born: i64,
    /// End of life (unix seconds): `max_age`.
    pub expires: i64,
    pub phase: Phase,
}

impl SessionJob {
    pub fn encode(&self) -> String {
        let head = format!(
            "{TAG}|{}|{}|{}|{}|{}|{}",
            self.partition.provider,
            self.partition.region,
            self.session,
            self.ip,
            self.born,
            self.expires
        );
        match &self.phase {
            Phase::Keep {
                fails,
                drops,
                changes,
                window_start,
                last_recheck,
                warn_zone,
            } => format!(
                "{head}|K|{fails}|{drops}|{changes}|{window_start}|{last_recheck}|{}",
                u8::from(*warn_zone)
            ),
            Phase::Drain { since } => format!("{head}|D|{since}"),
        }
    }

    /// `None` for text that is not a session job (another component's job,
    /// or a corrupt one): the caller leaves it alone.
    pub fn parse(text: &str) -> Option<Self> {
        let mut f = text.split('|');
        if f.next()? != TAG {
            return None;
        }
        let provider: ProviderId = f.next()?.parse().ok()?;
        let region: Region = f.next()?.parse().ok()?;
        let session = f.next()?.to_owned();
        let ip: Ipv4Addr = f.next()?.parse().ok()?;
        let born: i64 = f.next()?.parse().ok()?;
        let expires: i64 = f.next()?.parse().ok()?;
        let phase = match f.next()? {
            "K" => Phase::Keep {
                fails: f.next()?.parse().ok()?,
                drops: f.next()?.parse().ok()?,
                changes: f.next()?.parse().ok()?,
                window_start: f.next()?.parse().ok()?,
                last_recheck: f.next()?.parse().ok()?,
                warn_zone: match f.next()? {
                    "0" => false,
                    "1" => true,
                    _ => return None,
                },
            },
            "D" => Phase::Drain {
                since: f.next()?.parse().ok()?,
            },
            _ => return None,
        };
        if f.next().is_some() || session.is_empty() {
            return None;
        }
        Some(Self {
            partition: Partition { provider, region },
            session,
            ip,
            born,
            expires,
            phase,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job(phase: Phase) -> SessionJob {
        SessionJob {
            partition: Partition {
                provider: "res_user_suffix".parse().expect("provider"),
                region: "fr/paris".parse().expect("region"),
            },
            session: "AbC123xyz".into(),
            ip: Ipv4Addr::new(203, 0, 113, 9),
            born: 1_000,
            expires: 5_000,
            phase,
        }
    }

    #[test]
    fn both_phases_round_trip() {
        for phase in [
            Phase::fresh(1_000),
            Phase::Keep {
                fails: 2,
                drops: 3,
                changes: 1,
                window_start: 900,
                last_recheck: 950,
                warn_zone: true,
            },
            Phase::Drain { since: 4_000 },
        ] {
            let j = job(phase);
            assert_eq!(SessionJob::parse(&j.encode()), Some(j));
        }
    }

    #[test]
    fn foreign_and_corrupt_jobs_are_not_ours() {
        let good = job(Phase::fresh(1)).encode();
        assert!(SessionJob::parse(&good).is_some());
        for bad in [
            "",
            "recheck|1.2.3.4",
            &good.replace("s1|", "s2|"),
            &format!("{good}|extra"),
            &good.replace("|K|", "|X|"),
            &good[..good.len() - 2],
            &good.replace("203.0.113.9", "2001:db8::1"),
        ] {
            assert_eq!(SessionJob::parse(bad), None, "{bad:?}");
        }
    }
}
