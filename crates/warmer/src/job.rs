//! Browser-sample watches in the `due` set.
//!
//! Like a session job ([`store::SessionJob`]), a watch lives in the `due` set
//! as its own text, so any replica can poll it.

use common::types::{Partition, ProviderId, Region};

/// What a browser-sample watch concerns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Subject {
    /// A rotating session; the unit is its id.
    Rotating,
    /// A static IP; the unit is the IP as text.
    Static,
}

/// A browser sample that was queued for the prober and waits for its
/// verdict. It lives in the `due` set like a session job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SampleWatch {
    pub job_id: String,
    pub subject: Subject,
    pub partition: Partition,
    pub unit: String,
    /// The sticky key under which the unit is reserved for the probe org.
    pub sid: String,
    /// When the sample was queued (unix seconds).
    pub created: i64,
}

const WATCH_TAG: &str = "w1";

impl SampleWatch {
    pub(crate) fn encode(&self) -> String {
        format!(
            "{WATCH_TAG}|{}|{}|{}|{}|{}|{}|{}",
            self.job_id,
            match self.subject {
                Subject::Rotating => "r",
                Subject::Static => "s",
            },
            self.partition.provider,
            self.partition.region,
            self.unit,
            self.sid,
            self.created
        )
    }

    /// `None` for text that is not a sample watch.
    pub(crate) fn parse(text: &str) -> Option<Self> {
        let mut f = text.split('|');
        if f.next()? != WATCH_TAG {
            return None;
        }
        let job_id = f.next()?.to_owned();
        let subject = match f.next()? {
            "r" => Subject::Rotating,
            "s" => Subject::Static,
            _ => return None,
        };
        let provider: ProviderId = f.next()?.parse().ok()?;
        let region: Region = f.next()?.parse().ok()?;
        let unit = f.next()?.to_owned();
        let sid = f.next()?.to_owned();
        let created: i64 = f.next()?.parse().ok()?;
        if f.next().is_some() || job_id.is_empty() || unit.is_empty() || sid.is_empty() {
            return None;
        }
        Some(Self {
            job_id,
            subject,
            partition: Partition { provider, region },
            unit,
            sid,
            created,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use store::{Phase, SessionJob};

    use super::*;

    #[test]
    fn sample_watches_round_trip_and_are_not_session_jobs() {
        for subject in [Subject::Rotating, Subject::Static] {
            let w = SampleWatch {
                job_id: "0b9f4c1e".into(),
                subject,
                partition: Partition {
                    provider: "oxylabs_isp".parse().expect("provider"),
                    region: "fr".parse().expect("region"),
                },
                unit: "203.0.113.9".into(),
                sid: "smp1234abcd".into(),
                created: 1_700,
            };
            let text = w.encode();
            assert_eq!(SampleWatch::parse(&text), Some(w));
            assert_eq!(SessionJob::parse(&text), None);
            assert_eq!(SampleWatch::parse(&format!("{text}|x")), None);
            assert_eq!(
                SampleWatch::parse(&text.replace("|r|", "|x|").replace("|s|", "|x|")),
                None
            );
        }
        let session = SessionJob {
            partition: Partition {
                provider: "oxylabs_isp".parse().expect("provider"),
                region: "fr".parse().expect("region"),
            },
            session: "AbC123xyz".into(),
            ip: Ipv4Addr::new(203, 0, 113, 9),
            born: 1,
            expires: 2,
            phase: Phase::fresh(1),
        };
        assert_eq!(SampleWatch::parse(&session.encode()), None);
    }
}
