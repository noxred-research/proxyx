//! `proxyx assess pool` against a real pool: its own Postgres database and
//! Valkey database 12, seeded through the store's own write calls, and a canned
//! gateway ops server. Skips when `PROXYX_TEST_DATABASE_URL` or
//! `PROXYX_TEST_REDIS_URL` is unset.

use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use common::Secret;
use common::config::Settings;
use common::types::{IpState, Partition};
use proxyx_ops::assess::{Assessment, Level, PoolAssessArgs, assess_pool};
use sqlx::PgPool;
use store::{Db, Hot, ScoreRow, Transition, UnitRecord};
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const REDIS_DB: &str = "12";

fn redis_url() -> Option<String> {
    let base = std::env::var("PROXYX_TEST_REDIS_URL").ok()?;
    let authority = base.trim_end_matches('/');
    let authority = authority
        .rsplit_once('/')
        .filter(|(h, _)| h.contains("://"))
        .map_or(authority, |(h, _)| h);
    Some(format!("{authority}/{REDIS_DB}"))
}

fn slug() -> String {
    Uuid::new_v4().simple().to_string()[..8].to_owned()
}

struct Fixture {
    dir: PathBuf,
    settings: Settings,
    db: Db,
    hot: Hot,
    pg: PgPool,
    rot: String,
    isp: String,
    ips: Vec<IpAddr>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Fixture {
    /// A pool with a rotating provider (min_ready 4, so the low watermark is 2)
    /// and a static one with four IPs, all in region `fr`; nothing is ready yet.
    async fn new(
        db_name: &str,
        rental_end: Option<&str>,
    ) -> Result<Option<Self>, Box<dyn std::error::Error>> {
        let (Ok(base), Some(redis)) = (std::env::var("PROXYX_TEST_DATABASE_URL"), redis_url())
        else {
            eprintln!("SKIP: PROXYX_TEST_DATABASE_URL or PROXYX_TEST_REDIS_URL is not set");
            return Ok(None);
        };
        let url = store::testing::database(&base, db_name, true).await?;
        let db = Db::connect(&url).await?;
        db.migrate().await?;
        let pg = PgPool::connect(&url).await?;
        let hot = Hot::connect(&redis).await?;

        let (tag, rot, isp) = (slug(), format!("rot{}", slug()), format!("isp{}", slug()));
        let dir = std::env::temp_dir().join(format!("proxyx-ops-assess-{tag}"));
        for sub in ["data/adapters", "data/policies", "secrets"] {
            std::fs::create_dir_all(dir.join(sub))?;
        }
        for file in [
            format!("{rot}_user"),
            format!("{rot}_pass"),
            format!("{isp}_user"),
            format!("{isp}_pass"),
        ] {
            std::fs::write(dir.join("secrets").join(file), "secret\n")?;
        }
        std::fs::write(
            dir.join("data/adapters/adapters.toml"),
            format!(
                "[[adapter]]\nid = \"{rot}\"\nkind = \"rotating\"\nsubtype = \"residential\"\nscheme = \"http\"\n\
                 host = \"rot.example\"\nport = 12321\nuser_file = \"{rot}_user\"\npass_file = \"{rot}_pass\"\n\
                 user = \"{{base_user}}\"\npass = \"{{base_pass}}{{opts}}\"\nmax_session_minutes = 10080\n\n\
                 [[adapter.option]]\nname = \"country\"\nto = \"pass\"\nfrag = \"_country-{{v}}\"\ncase = \"lower\"\n\n\
                 [[adapter.option]]\nname = \"sid\"\nto = \"pass\"\nfrag = \"_session-{{v}}\"\ncharset = \"alnum\"\nlen = 8\n\n\
                 [[adapter.option]]\nname = \"ttl\"\nto = \"pass\"\nfrag = \"_lifetime-{{v}}m\"\nunit = \"min\"\nmax = 10080\n\n\
                 [[adapter]]\nid = \"{isp}\"\nkind = \"static\"\nsubtype = \"isp\"\nscheme = \"http\"\n\
                 host = \"isp.example\"\nuser_file = \"{isp}_user\"\npass_file = \"{isp}_pass\"\n\
                 user = \"{{base_user}}\"\npass = \"{{base_pass}}\"\n"
            ),
        )?;
        let settings = Settings {
            database_url: Secret::new(url),
            redis_url: Secret::new(redis),
            data_dir: dir.join("data"),
            secrets_dir: dir.join("secrets"),
            ..Settings::default()
        };

        let doc: policy::PolicyDoc = toml::from_str(
            "name = \"global\"\nregions = [\"fr\"]\nmin_ready = 4\nmax_ready = 8\n\n[cost]\nmax_gb_per_day = 5\nmax_creates_per_hour = 120\n",
        )?;
        db.put_policies(&[doc], "test").await?;

        let ips: Vec<IpAddr> = (1..=4).map(|n| IpAddr::from([198, 51, 100, n])).collect();
        let entries = ips
            .iter()
            .enumerate()
            .map(|(i, ip)| {
                let rental = if i == 0 {
                    rental_end.map(|d| format!("rental_end = \"{d}\"\n")).unwrap_or_default()
                } else {
                    String::new()
                };
                toml::from_str(&format!(
                    "provider = \"{isp}\"\nsubtype = \"isp\"\nip = \"{ip}\"\nhost = \"isp.example\"\nport = {}\nregion = \"fr\"\n{rental}",
                    8000 + i
                ))
            })
            .collect::<Result<Vec<common::types::InventoryEntry>, _>>()?;
        db.replace_inventory(&isp.parse()?, &entries, "test")
            .await?;
        Ok(Some(Self {
            dir,
            settings,
            db,
            hot,
            pg,
            rot,
            isp,
            ips,
        }))
    }

    fn rot_partition(&self) -> Result<Partition, Box<dyn std::error::Error>> {
        Ok(Partition {
            provider: self.rot.parse()?,
            region: "fr".parse()?,
        })
    }

    fn isp_partition(&self) -> Result<Partition, Box<dyn std::error::Error>> {
        Ok(Partition {
            provider: self.isp.parse()?,
            region: "fr".parse()?,
        })
    }

    /// `n` free ready rotating sessions.
    async fn ready_sessions(&self, n: u8) -> TestResult {
        let p = self.rot_partition()?;
        for i in 0..n {
            self.hot
                .ready_put(
                    &p,
                    &UnitRecord {
                        id: format!("s{i}"),
                        ip: IpAddr::from([192, 0, 2, i + 1]),
                        expires_at: Some(OffsetDateTime::now_utc() + time::Duration::hours(1)),
                        ttl: Some(Duration::from_secs(4000)),
                        owner: None,
                    },
                )
                .await?;
        }
        Ok(())
    }

    /// Every static IP available, checked `minutes` ago, and leasable in Redis.
    async fn healthy_statics(&self, minutes: i64) -> TestResult {
        let p = self.isp_partition()?;
        for ip in &self.ips {
            self.db
                .transition_ip(
                    *ip,
                    &Transition::to(IpState::Available, "checks passed"),
                    "test",
                )
                .await?;
            self.db
                .record_check(
                    *ip,
                    Some(*ip),
                    OffsetDateTime::now_utc() - time::Duration::minutes(minutes),
                )
                .await?;
            self.hot.ready_put(&p, &UnitRecord::static_ip(*ip)).await?;
        }
        Ok(())
    }

    async fn assess(
        &self,
        gateway: Option<String>,
    ) -> Result<Assessment, Box<dyn std::error::Error>> {
        let args = PoolAssessArgs {
            config: None,
            json: false,
            strict: false,
            window: Duration::from_secs(3600),
            no_gateway: gateway.is_none(),
            ops_url: gateway,
            timeout: Duration::from_secs(3),
        };
        Ok(assess_pool(&self.settings, &args).await?)
    }
}

fn level(a: &Assessment, section: &str, subject_part: &str) -> Level {
    let s = a
        .sections
        .iter()
        .find(|s| s.name == section)
        .expect("section");
    s.findings
        .iter()
        .find(|f| f.subject.contains(subject_part))
        .unwrap_or_else(|| panic!("no finding for {subject_part} in {s:#?}"))
        .level
}

#[tokio::test]
async fn a_healthy_pool_is_all_ok() -> TestResult {
    let Some(f) = Fixture::new("proxyx_ops_doctor_assess_ok", None).await? else {
        return Ok(());
    };
    f.ready_sessions(4).await?;
    f.healthy_statics(10).await?;
    let a = f.assess(None).await?;
    assert_eq!(a.overall(false), Level::Ok, "{}", a.render(false));
    assert_eq!(a.exit_code(false), 0);
    assert_eq!(level(&a, "capacity", &f.rot), Level::Ok);
    assert_eq!(level(&a, "capacity", &f.isp), Level::Ok);
    assert_eq!(level(&a, "checks", &f.isp), Level::Ok);
    assert_eq!(level(&a, "breakers", &f.rot), Level::Ok);
    assert_eq!(level(&a, "budget", &f.rot), Level::Ok);
    let cap = &a.sections[0].findings;
    assert!(
        cap.iter()
            .any(|x| x.message.contains("4 ready, min_ready 4, low watermark 2")),
        "{cap:#?}"
    );
    Ok(())
}

#[tokio::test]
async fn a_partition_under_min_ready_is_critical_and_the_exit_code_says_so() -> TestResult {
    let Some(f) = Fixture::new("proxyx_ops_doctor_assess_low", None).await? else {
        return Ok(());
    };
    f.ready_sessions(1).await?; // watermark 2
    f.healthy_statics(10).await?;
    let a = f.assess(None).await?;
    assert_eq!(
        level(&a, "capacity", &f.rot),
        Level::Crit,
        "{}",
        a.render(false)
    );
    assert_eq!(a.exit_code(false), 1);
    f.ready_sessions(3).await?; // 3 ready: under min_ready (4), over the watermark
    let a = f.assess(None).await?;
    assert_eq!(level(&a, "capacity", &f.rot), Level::Warn);
    assert_eq!(a.exit_code(false), 2);
    f.ready_sessions(4).await?;
    assert_eq!(f.assess(None).await?.exit_code(false), 0);
    Ok(())
}

#[tokio::test]
async fn an_open_breaker_warns_and_a_paused_partition_warns() -> TestResult {
    let Some(f) = Fixture::new("proxyx_ops_doctor_assess_breaker", None).await? else {
        return Ok(());
    };
    f.ready_sessions(4).await?;
    f.healthy_statics(10).await?;
    let p = f.rot_partition()?;
    let cfg = common::retry::BreakerConfig::default();
    for _ in 0..cfg.failures_to_open {
        f.hot.breaker_failure(&p, &cfg).await?;
    }
    let a = f.assess(None).await?;
    assert_eq!(
        level(&a, "breakers", &f.rot),
        Level::Warn,
        "{}",
        a.render(false)
    );
    assert_eq!(level(&a, "breakers", &f.isp), Level::Ok);
    assert_eq!(a.overall(false), Level::Warn);
    assert_eq!(a.exit_code(false), 2);

    f.hot
        .warm_pause(&f.isp_partition()?, Duration::from_secs(60))
        .await?;
    let a = f.assess(None).await?;
    assert!(
        a.sections[0]
            .findings
            .iter()
            .any(|x| x.level == Level::Warn && x.message.contains("paused")),
        "{}",
        a.render(false)
    );
    Ok(())
}

#[tokio::test]
async fn a_stale_exit_ip_check_warns() -> TestResult {
    let Some(f) = Fixture::new("proxyx_ops_doctor_assess_stale", None).await? else {
        return Ok(());
    };
    f.ready_sessions(4).await?;
    f.healthy_statics(10).await?;
    assert_eq!(level(&f.assess(None).await?, "checks", &f.isp), Level::Ok);
    // recheck_every is 30 m by default: 3 x 30 m is the limit.
    f.db.record_check(
        f.ips[0],
        Some(f.ips[0]),
        OffsetDateTime::now_utc() - time::Duration::hours(3),
    )
    .await?;
    let a = f.assess(None).await?;
    assert_eq!(
        level(&a, "checks", &f.isp),
        Level::Warn,
        "{}",
        a.render(false)
    );
    let message = &a.sections[3].findings[0].message;
    assert!(message.starts_with("1 of 4 IPs not checked"), "{message}");
    assert_eq!(a.exit_code(false), 2);
    Ok(())
}

#[tokio::test]
async fn rentals_scores_blocks_budget_and_leases_are_read_from_the_stores() -> TestResult {
    let in_ten_days = (OffsetDateTime::now_utc() + time::Duration::days(10))
        .date()
        .to_string();
    let Some(f) = Fixture::new("proxyx_ops_doctor_assess_misc", Some(&in_ten_days)).await? else {
        return Ok(());
    };
    f.ready_sessions(4).await?;
    f.healthy_statics(10).await?;

    // Reputation: three of four static IPs over the default limit of 75.
    let now = OffsetDateTime::now_utc();
    for (ip, risk) in f.ips.iter().zip([90u8, 80, 85, 10]) {
        f.db.record_score(&ScoreRow {
            ip: *ip,
            source: "ipqs".into(),
            risk,
            flags: vec![],
            checked_at: now,
        })
        .await?;
    }
    // Block signals: IP-wide on two IPs inside the window, one older.
    for ip in &f.ips[..2] {
        f.db.record_block(
            *ip,
            None,
            common::types::SignalSource::Operator,
            common::types::SignalType::Forbidden,
            None,
        )
        .await?;
    }
    // Budget: 95% of the hourly creates (the default limit is 120).
    f.hot.cost_add(&f.rot.parse()?, 0, 114, now).await?;
    // Leases: a tunnel-carrying unit is not needed; the free/leased counts come from Redis.
    let a = f.assess(None).await?;
    let text = a.render(false);
    assert_eq!(level(&a, "rentals", &f.isp), Level::Crit, "{text}");
    assert!(
        a.sections[7].findings[0]
            .message
            .contains("fewest days left: 9")
            || a.sections[7].findings[0]
                .message
                .contains("fewest days left: 10"),
        "{text}"
    );
    assert_eq!(level(&a, "reputation", &f.isp), Level::Crit, "{text}");
    assert_eq!(
        level(&a, "blocks", "pool"),
        Level::Crit,
        "2 of 4 IPs: {text}"
    );
    assert_eq!(level(&a, "budget", &f.rot), Level::Crit, "{text}");
    assert_eq!(a.exit_code(false), 1);

    // An old block is outside the window.
    sqlx::query("UPDATE ip_blocks SET created_at = now() - interval '3 hours'")
        .execute(&f.pg)
        .await?;
    let a = f.assess(None).await?;
    assert_eq!(level(&a, "blocks", "pool"), Level::Ok);
    Ok(())
}

/// A server that answers every request with `status` and the body of its path.
async fn canned_gateway(
    ready_status: u16,
    ready_body: &'static str,
    metrics: &'static str,
) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let n = s.read(&mut buf).await.unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]).into_owned();
                let (status, body) = if head.starts_with("GET /readyz") {
                    (ready_status, ready_body)
                } else if head.starts_with("GET /metrics") {
                    (200, metrics)
                } else {
                    (404, "")
                };
                let reply = format!(
                    "HTTP/1.1 {status} X\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(reply.as_bytes()).await;
            });
        }
    });
    format!("http://{addr}")
}

#[tokio::test]
async fn the_gateway_ops_server_is_asked() -> TestResult {
    let Some(f) = Fixture::new("proxyx_ops_doctor_assess_gateway", None).await? else {
        return Ok(());
    };
    f.ready_sessions(4).await?;
    f.healthy_statics(10).await?;

    let ok = canned_gateway(
        200,
        "ok",
        "proxyx_pool_redis_down 0\nproxyx_pool_postgres_down 0\n",
    )
    .await;
    let a = f.assess(Some(ok)).await?;
    assert_eq!(a.overall(false), Level::Ok, "{}", a.render(false));

    let down = canned_gateway(503, "redis unavailable", "proxyx_pool_redis_down 1\n").await;
    let a = f.assess(Some(down)).await?;
    let gw = &a.sections[9].findings;
    assert!(
        gw.iter()
            .any(|x| x.level == Level::Crit && x.message.contains("redis unavailable")),
        "{gw:#?}"
    );
    assert!(
        gw.iter()
            .any(|x| x.level == Level::Crit && x.message.contains("Redis down")),
        "{gw:#?}"
    );
    assert_eq!(a.exit_code(false), 1);

    // Nothing listens there: a warning, not a crash.
    let closed = {
        let l = std::net::TcpListener::bind("127.0.0.1:0")?;
        format!("http://{}", l.local_addr()?)
    };
    let a = f.assess(Some(closed)).await?;
    assert_eq!(
        a.sections[9].findings[0].level,
        Level::Warn,
        "{}",
        a.render(false)
    );
    Ok(())
}
