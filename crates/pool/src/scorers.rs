//! Reputation scorers from the secrets directory.
//!
//! A scorer is on when its key file exists in `secrets_dir`. With none on,
//! `Reputation` has no slots and the policy's `on_score_unavailable` applies.
//! Each scorer calls the vendor origin unless `ipqs_base_url`,
//! `abuseipdb_base_url` or `scamalytics_base_url` points it at a stand-in.
//! Scamalytics also needs `scamalytics_customer`, its account name.

use anyhow::Context as _;
use common::Secret;
use common::config::Settings;
use verify::{Scorer, ScorerAccount, ScorerSlot};

const IPQS_KEY_FILE: &str = "ipqs_api_key";
const ABUSEIPDB_KEY_FILE: &str = "abuseipdb_api_key";
const SCAMALYTICS_KEY_FILE: &str = "scamalytics_api_key";

/// Lookups per UTC day, kept under the free plans of both services.
/// Assumption: IPQS free is about 1000 a month, AbuseIPDB free 1000 a day.
const IPQS_DAILY_BUDGET: u32 = 30;
const ABUSEIPDB_DAILY_BUDGET: u32 = 900;
/// Assumption: the Scamalytics entry plan is about 500 lookups a month.
const SCAMALYTICS_DAILY_BUDGET: u32 = 15;

/// The scorers whose key file is present.
///
/// Fails when a key file exists but cannot be read or is empty: a broken secret
/// is a startup error, not a silently missing scorer.
pub(crate) fn slots(settings: &Settings) -> anyhow::Result<Vec<ScorerSlot>> {
    let mut slots = Vec::new();
    if let Some(key) = key(settings, IPQS_KEY_FILE)? {
        slots.push(ScorerSlot {
            scorer: Scorer::Ipqs(ScorerAccount {
                base_url: settings.ipqs_base_url.clone(),
                key,
            }),
            daily_budget: IPQS_DAILY_BUDGET,
        });
    }
    if let Some(key) = key(settings, ABUSEIPDB_KEY_FILE)? {
        slots.push(ScorerSlot {
            scorer: Scorer::AbuseIpdb(ScorerAccount {
                base_url: settings.abuseipdb_base_url.clone(),
                key,
            }),
            daily_budget: ABUSEIPDB_DAILY_BUDGET,
        });
    }
    if let Some(key) = key(settings, SCAMALYTICS_KEY_FILE)? {
        let customer = settings
            .scamalytics_customer
            .as_deref()
            .filter(|name| !name.is_empty())
            .context("scamalytics_api_key exists but scamalytics_customer is not set")?;
        slots.push(ScorerSlot {
            scorer: Scorer::Scamalytics {
                account: ScorerAccount {
                    base_url: settings.scamalytics_base_url.clone(),
                    key,
                },
                customer: customer.to_owned(),
            },
            daily_budget: SCAMALYTICS_DAILY_BUDGET,
        });
    }
    Ok(slots)
}

fn key(settings: &Settings, file: &str) -> anyhow::Result<Option<Secret>> {
    if !settings.secrets_dir.join(file).try_exists()? {
        return Ok(None);
    }
    settings.read_secret(file).map(Some)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use verify::ScorerKind;

    use super::*;

    fn settings_with(files: &[(&str, &str)]) -> (Settings, PathBuf) {
        let dir = std::env::temp_dir().join(format!("proxyx-scorers-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("create secrets dir");
        for (name, content) in files {
            std::fs::write(dir.join(name), content).expect("write secret");
        }
        let settings = Settings {
            secrets_dir: dir.clone(),
            ..Settings::default()
        };
        (settings, dir)
    }

    #[test]
    fn only_scorers_with_a_key_file_are_on() {
        let (settings, dir) = settings_with(&[("abuseipdb_api_key", "k\n")]);
        let kinds: Vec<_> = slots(&settings)
            .expect("slots")
            .iter()
            .map(|s| s.scorer.kind())
            .collect();
        std::fs::remove_dir_all(dir).expect("clean up");
        assert_eq!(kinds, [ScorerKind::AbuseIpdb]);
    }

    #[test]
    fn no_key_files_means_no_scorer() {
        let (settings, dir) = settings_with(&[]);
        let got = slots(&settings).expect("slots");
        std::fs::remove_dir_all(dir).expect("clean up");
        assert!(got.is_empty());
    }

    #[test]
    fn an_empty_key_file_is_a_startup_error() {
        let (settings, dir) = settings_with(&[("ipqs_api_key", "\n")]);
        let got = slots(&settings);
        std::fs::remove_dir_all(dir).expect("clean up");
        assert!(got.is_err());
    }

    fn base_urls(settings: &Settings) -> Vec<String> {
        slots(settings)
            .expect("slots")
            .into_iter()
            .map(|slot| match slot.scorer {
                Scorer::Ipqs(account) | Scorer::AbuseIpdb(account) => account.base_url,
                Scorer::Scamalytics { account, .. } => account.base_url,
            })
            .collect()
    }

    #[test]
    fn scorers_call_the_vendors_unless_an_origin_is_configured() {
        let (mut settings, dir) =
            settings_with(&[("ipqs_api_key", "k1\n"), ("abuseipdb_api_key", "k2\n")]);
        let default = base_urls(&settings);
        settings.ipqs_base_url = "http://127.0.0.1:9".to_owned();
        settings.abuseipdb_base_url = "http://stand-in.test".to_owned();
        let configured = base_urls(&settings);
        std::fs::remove_dir_all(dir).expect("clean up");

        assert_eq!(
            default,
            ["https://ipqualityscore.com", "https://api.abuseipdb.com"]
        );
        assert_eq!(configured, ["http://127.0.0.1:9", "http://stand-in.test"]);
    }

    /// `check=scamalytics` used to be impossible to produce.
    #[test]
    fn scamalytics_is_on_with_a_key_file_and_a_customer() {
        let (mut settings, dir) = settings_with(&[("scamalytics_api_key", "k3\n")]);
        settings.scamalytics_customer = Some("acme".to_owned());
        let default = slots(&settings).expect("slots");
        settings.scamalytics_base_url = "http://127.0.0.1:9".to_owned();
        let configured = slots(&settings).expect("slots");
        std::fs::remove_dir_all(dir).expect("clean up");

        let parts = |slots: Vec<ScorerSlot>| {
            slots
                .into_iter()
                .map(|slot| match slot.scorer {
                    Scorer::Scamalytics { account, customer } => (account.base_url, customer),
                    other => panic!("not a Scamalytics slot: {:?}", other.kind()),
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(
            parts(default),
            [(
                "https://api12.scamalytics.com".to_owned(),
                "acme".to_owned()
            )]
        );
        assert_eq!(
            parts(configured),
            [("http://127.0.0.1:9".to_owned(), "acme".to_owned())]
        );
    }

    #[test]
    fn a_scamalytics_key_without_a_customer_is_a_startup_error() {
        let (settings, dir) = settings_with(&[("scamalytics_api_key", "k3\n")]);
        let got = slots(&settings);
        std::fs::remove_dir_all(dir).expect("clean up");
        let error = format!("{:#}", got.expect_err("no customer"));
        assert!(error.contains("scamalytics_customer"), "{error}");
    }

    #[tokio::test]
    async fn a_scorer_can_be_tested_against_a_stand_in() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let stand_in = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind stand-in");
        let origin = format!("http://{}", stand_in.local_addr().expect("addr"));
        let server = tokio::spawn(async move {
            let (mut stream, _) = stand_in.accept().await.expect("accept");
            let mut head = [0u8; 1024];
            let read = stream.read(&mut head).await.expect("read request");
            let body = r#"{"success":true,"message":"Success","fraud_score":42}"#;
            let reply = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(reply.as_bytes()).await.expect("reply");
            String::from_utf8_lossy(&head[..read]).into_owned()
        });

        let (mut settings, dir) = settings_with(&[("ipqs_api_key", "stand-in-key\n")]);
        settings.ipqs_base_url = origin;
        let slot = slots(&settings).expect("slots").remove(0);
        std::fs::remove_dir_all(dir).expect("clean up");
        let score = slot
            .scorer
            .score(&reqwest::Client::new(), "203.0.113.7".parse().expect("ip"))
            .await
            .expect("score from the stand-in");

        assert_eq!(score.risk, 42);
        let request = server.await.expect("stand-in task");
        assert!(
            request.starts_with("GET /api/json/ip/stand-in-key/203.0.113.7 "),
            "{request}"
        );
    }
}
