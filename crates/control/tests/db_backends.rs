//! The control plane's relational store on every configured backend: the
//! migrations, orgs, the session lifecycle (the partial unique active slot,
//! reference counting, the reapers), traffic view jobs and API keys.
//!
//! Each test runs against every backend whose test variable is set:
//! `PROXYX_TEST_DATABASE_URL` (PostgreSQL), `PROXYX_TEST_MARIADB_URL` and
//! `PROXYX_TEST_SQLITE_DIR`. With none set the tests skip with a message.

use std::collections::HashSet;
use std::time::Duration;

use proxyx_control::db::{Db, OrgSettingsWrite, SessionInsert};
use proxyx_control::keys::{KeyKind, KeyStore};
use proxyx_db::Backend;
use proxyx_db::testing::{self, Raw};
use time::OffsetDateTime;
use uuid::Uuid;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn uniq(prefix: &str) -> String {
    format!("{prefix}{}", &Uuid::new_v4().simple().to_string()[..10])
}

/// Create (once) a database for `name` on `backend`, migrate it, and open it.
async fn open(
    backend: Backend,
    name: &str,
    fresh: bool,
) -> Result<Option<(Db, Raw)>, Box<dyn std::error::Error>> {
    let Some(url) =
        testing::database(backend, &format!("proxyx_control_{name}_test"), fresh).await?
    else {
        return Ok(None);
    };
    let db = Db::connect(&url, 8).await?;
    db.migrate().await?;
    Ok(Some((db, Raw::connect(&url).await?)))
}

/// Run `body` on every configured backend.
macro_rules! on_every_backend {
    ($name:literal, |$db:ident, $raw:ident| $body:expr) => {{
        let backends = testing::configured();
        if backends.is_empty() {
            eprintln!(
                "SKIP: no test database is configured (see crates/control/tests/db_backends.rs)"
            );
        }
        for backend in backends {
            let Some(($db, $raw)) = open(backend, $name, false).await? else {
                continue;
            };
            eprintln!("-- {backend}");
            #[allow(clippy::redundant_closure_call)]
            (|| async { $body })().await?;
        }
        Ok(())
    }};
}

const VERSIONS: usize = 16;

#[tokio::test]
async fn migrations_apply_once_race_safely_and_are_reported() -> TestResult {
    for backend in testing::configured() {
        eprintln!("-- {backend}");
        let Some(url) = testing::database(backend, "proxyx_control_migrate_test", true).await?
        else {
            continue;
        };
        let db = Db::connect(&url, 8).await?;
        let raw = Raw::connect(&url).await?;
        let pending = db.pending_migrations().await?;
        assert_eq!(pending.len(), VERSIONS, "{pending:?}");
        assert!(pending[0].ends_with("_create orgs"), "{pending:?}");
        // Asking twice changes nothing.
        assert_eq!(db.pending_migrations().await?, pending);
        assert!(!raw.pool().table_exists("orgs").await?);

        let (a, b, c) = tokio::join!(db.migrate(), db.migrate(), db.migrate());
        a?;
        b?;
        c?;
        assert!(db.pending_migrations().await?.is_empty());
        assert_eq!(
            raw.int("SELECT count(*) FROM _sqlx_migrations", &[])
                .await?,
            VERSIONS as i64
        );
        for table in ["orgs", "session_lifecycle", "traffic_view_jobs", "api_keys"] {
            assert!(raw.pool().table_exists(table).await?, "table {table}");
        }
        // The vestigial capture table is gone on every backend.
        assert!(!raw.pool().table_exists("http_captures").await?);
        db.migrate().await?;
        assert!(db.ping().await.is_ok());
        assert!(!db.server_version().await?.is_empty());
    }
    Ok(())
}

#[tokio::test]
async fn orgs_keep_rate_limits_and_the_egress_proxy() -> TestResult {
    on_every_backend!("orgs", |db, _raw| {
        let org = uniq("org-");
        assert_eq!(db.org_rate_limit(&org).await?, None);
        assert_eq!(db.clear_org_proxy(&org).await?, 0, "no such org");

        db.create_org(&org, Some(60), None).await?;
        assert!(
            db.create_org(&org, Some(1), Some(1)).await.is_err(),
            "an org id is created once"
        );
        assert_eq!(db.org_rate_limit(&org).await?, Some((Some(60), None)));

        db.set_org_rate_limit(&org, Some(120), Some(30)).await?;
        assert_eq!(db.org_rate_limit(&org).await?, Some((Some(120), Some(30))));

        db.set_org_proxy(&org, "socks5", "10.0.0.1:1080", Some("u"), None)
            .await?;
        let proxy = db.org_proxy(&org).await?.ok_or("proxy")?;
        assert_eq!(
            proxy,
            (
                Some("socks5".to_owned()),
                Some("10.0.0.1:1080".to_owned()),
                Some("u".to_owned()),
                None
            )
        );
        assert_eq!(
            db.org_rate_limit(&org).await?,
            Some((Some(120), Some(30))),
            "a proxy change keeps the limits"
        );

        // An upsert creates a missing org.
        let fresh = uniq("org-");
        db.set_org_rate_limit(&fresh, None, None).await?;
        assert_eq!(db.org_rate_limit(&fresh).await?, Some((None, None)));

        let settings = uniq("org-");
        let full = OrgSettingsWrite {
            id: &settings,
            rpm: Some(5),
            burst: Some(6),
            proxy_type: Some("http"),
            proxy_address: Some("h:8080"),
            proxy_username: Some("user"),
            proxy_password: Some("pass"),
        };
        db.set_org_settings(&full).await?;
        db.set_org_settings(&OrgSettingsWrite {
            rpm: Some(7),
            burst: Some(8),
            proxy_type: None,
            proxy_address: None,
            proxy_username: None,
            proxy_password: None,
            ..full
        })
        .await?;
        let s = db.org_settings(&settings).await?.ok_or("settings")?;
        assert_eq!((s.rate_limit_rpm, s.rate_limit_burst), (Some(7), Some(8)));
        assert_eq!(s.proxy_type, None);

        assert_eq!(db.clear_org_proxy(&org).await?, 1);
        assert_eq!(
            db.org_proxy(&org).await?,
            Some((None, None, None, None)),
            "the proxy is cleared, the org stays"
        );
        assert_eq!(db.delete_org(&org).await?, 1);
        assert_eq!(db.delete_org(&org).await?, 0);
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}

async fn insert(
    db: &Db,
    org: &str,
    source: &str,
    source_id: &str,
    expires_in: time::Duration,
) -> Result<(Uuid, SessionInsert), Box<dyn std::error::Error>> {
    let id = Uuid::new_v4();
    let outcome = db
        .insert_session(
            id,
            org,
            source,
            source_id,
            OffsetDateTime::now_utc() + expires_in,
        )
        .await?;
    Ok((id, outcome))
}

#[tokio::test]
async fn one_active_session_holds_a_slot_and_a_released_slot_is_free_again() -> TestResult {
    on_every_backend!("sessions", |db, _raw| {
        let (org, source_id) = (uniq("org-"), uniq("src-"));
        let hour = time::Duration::hours(1);

        let (first, outcome) = insert(&db, &org, "crawler", &source_id, hour).await?;
        assert_eq!(outcome, SessionInsert::Inserted);
        assert_eq!(
            db.active_session(&org, "crawler", &source_id).await?,
            Some(first)
        );
        assert_eq!(db.session_state(first).await?.as_deref(), Some("active"));

        // The same triple is refused while the first is active; another
        // source or source id is its own slot.
        let (_, again) = insert(&db, &org, "crawler", &source_id, hour).await?;
        assert_eq!(again, SessionInsert::AlreadyActive);
        let (_, other_source) = insert(&db, &org, "scanner", &source_id, hour).await?;
        assert_eq!(other_source, SessionInsert::Inserted);
        let (_, other_id) = insert(&db, &org, "crawler", &uniq("src-"), hour).await?;
        assert_eq!(other_id, SessionInsert::Inserted);

        // A second reference keeps the session; the last one ends it.
        let later = OffsetDateTime::now_utc() + time::Duration::hours(3);
        let effective = db.attach_session(first, later).await?.ok_or("attached")?;
        assert_eq!(effective / 1000, later.unix_timestamp());
        let sooner = OffsetDateTime::now_utc() + time::Duration::hours(2);
        let kept = db.attach_session(first, sooner).await?.ok_or("attached")?;
        assert_eq!(kept, effective, "an attach never shortens the expiry");

        assert_eq!(db.release_session(first).await?, Some(2));
        assert_eq!(db.release_session(first).await?, Some(1));
        assert_eq!(db.session_state(first).await?.as_deref(), Some("active"));
        assert_eq!(db.release_session(first).await?, Some(0));
        assert_eq!(db.session_state(first).await?.as_deref(), Some("consuming"));
        assert_eq!(db.release_session(first).await?, None, "no longer active");
        assert_eq!(db.attach_session(first, later).await?, None);

        // The slot is free: a new session of the triple is accepted, and the
        // old one is still there for the consumer to finish.
        let (second, outcome) = insert(&db, &org, "crawler", &source_id, hour).await?;
        assert_eq!(outcome, SessionInsert::Inserted);
        assert_eq!(
            db.active_session(&org, "crawler", &source_id).await?,
            Some(second)
        );

        assert!(!db.source_has_closed_session(&org, &source_id).await?);
        db.close_session(first).await?;
        assert!(db.source_has_closed_session(&org, &source_id).await?);
        assert!(
            !db.source_has_closed_session("other-org", &source_id)
                .await?
        );
        let status = db.session_status(first).await?.ok_or("status")?;
        assert_eq!(status.state, "closed");
        assert_eq!(status.org_id, org);
        assert!(status.closing_at().is_some() && status.closed_at().is_some());
        assert!(db.session_status(Uuid::new_v4()).await?.is_none());

        db.abandon_active_session(second).await?;
        assert_eq!(
            db.session_state(second).await?.as_deref(),
            Some("consuming")
        );
        db.set_session_expiry(second, OffsetDateTime::now_utc())
            .await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}

#[tokio::test]
async fn concurrent_creates_of_one_session_leave_exactly_one() -> TestResult {
    on_every_backend!("sessions_race", |db, _raw| {
        let (org, source_id) = (uniq("org-"), uniq("src-"));
        let tasks: Vec<_> = (0..12)
            .map(|_| {
                let (db, org, source_id) = (db.clone(), org.clone(), source_id.clone());
                tokio::spawn(async move {
                    insert(&db, &org, "crawler", &source_id, time::Duration::hours(1))
                        .await
                        .map(|(_, outcome)| outcome)
                        .map_err(|e| e.to_string())
                })
            })
            .collect();
        let mut inserted = 0;
        for task in tasks {
            if task.await?? == SessionInsert::Inserted {
                inserted += 1;
            }
        }
        assert_eq!(
            inserted, 1,
            "one active session per (org, source, source id)"
        );

        // Concurrent attaches count every reference.
        let id = db
            .active_session(&org, "crawler", &source_id)
            .await?
            .ok_or("active")?;
        let attaches: Vec<_> = (0..10)
            .map(|_| {
                let db = db.clone();
                tokio::spawn(async move {
                    db.attach_session(id, OffsetDateTime::now_utc() + time::Duration::hours(1))
                        .await
                })
            })
            .collect();
        for task in attaches {
            task.await??.ok_or("attached")?;
        }
        let mut left = None;
        for _ in 0..11 {
            left = db.release_session(id).await?;
        }
        assert_eq!(left, Some(0), "1 creator + 10 attaches = 11 references");
        assert_eq!(db.session_state(id).await?.as_deref(), Some("consuming"));
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}

#[tokio::test]
async fn the_reapers_claim_each_expired_session_once_across_replicas() -> TestResult {
    on_every_backend!("reaper", |db, raw| {
        let org = uniq("reap-");
        // Twenty sessions that expired a minute ago, and one that did not.
        let mut expired = HashSet::new();
        for n in 0..20 {
            let (id, outcome) = insert(
                &db,
                &org,
                "crawler",
                &format!("src-{n}"),
                -time::Duration::minutes(1) - time::Duration::seconds(n),
            )
            .await?;
            assert_eq!(outcome, SessionInsert::Inserted);
            expired.insert(id);
        }
        let (live, _) = insert(&db, &org, "crawler", "src-live", time::Duration::hours(1)).await?;
        let cutoff = OffsetDateTime::now_utc();

        // Four replicas claim at once: no session is claimed twice, none is missed.
        let claims: Vec<_> = (0..4)
            .map(|_| {
                let db = db.clone();
                tokio::spawn(async move { db.claim_expired_sessions(cutoff, 8).await })
            })
            .collect();
        let mut claimed = Vec::new();
        for claim in claims {
            claimed.extend(claim.await??);
        }
        let mut again = db.claim_expired_sessions(cutoff, 100).await?;
        claimed.append(&mut again);
        let mine: Vec<_> = claimed.iter().filter(|(_, o, ..)| *o == org).collect();
        let ids: HashSet<Uuid> = mine.iter().map(|(id, ..)| *id).collect();
        assert_eq!(mine.len(), ids.len(), "no session is claimed twice");
        assert_eq!(ids, expired, "every expired session is claimed");
        assert!(mine.iter().all(|(_, _, source, source_id)| {
            source == "crawler" && source_id.as_deref().is_some_and(|s| s.starts_with("src-"))
        }));
        for id in &expired {
            assert_eq!(db.session_state(*id).await?.as_deref(), Some("consuming"));
        }
        assert_eq!(db.session_state(live).await?.as_deref(), Some("active"));

        // Stuck in `consuming`: claimed once per lease, oldest first, and a claim
        // gives the row a new lease.
        let old = OffsetDateTime::now_utc() - time::Duration::hours(2);
        for id in &expired {
            raw.execute(
                "UPDATE session_lifecycle SET closing_at = ? WHERE session_id = ?",
                &[old.into(), (*id).into()],
            )
            .await?;
        }
        let cutoff = OffsetDateTime::now_utc() - time::Duration::hours(1);
        let first = db.claim_stuck_sessions(cutoff, 1000).await?;
        let first: HashSet<Uuid> = first
            .iter()
            .filter(|(_, o, ..)| *o == org)
            .map(|(id, ..)| *id)
            .collect();
        assert_eq!(first, expired);
        let second = db.claim_stuck_sessions(cutoff, 1000).await?;
        assert!(
            second.iter().all(|(_, o, ..)| *o != org),
            "a claimed session has a fresh lease"
        );
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}

#[tokio::test]
async fn source_windows_span_the_sessions_of_a_source() -> TestResult {
    on_every_backend!("windows", |db, raw| {
        let org = uniq("win-");
        let (open_src, closed_src, none_src) = (uniq("a-"), uniq("b-"), uniq("c-"));
        let (a, _) = insert(&db, &org, "s", &open_src, time::Duration::hours(1)).await?;
        let (b1, _) = insert(&db, &org, "s", &closed_src, time::Duration::hours(1)).await?;
        db.release_session(b1).await?;
        db.close_session(b1).await?;
        let (b2, _) = insert(&db, &org, "s", &closed_src, time::Duration::hours(1)).await?;
        db.release_session(b2).await?;
        db.close_session(b2).await?;
        let started = OffsetDateTime::now_utc() - time::Duration::hours(3);
        raw.execute(
            "UPDATE session_lifecycle SET opened_at = ? WHERE session_id = ?",
            &[started.into(), b1.into()],
        )
        .await?;

        let windows = db
            .source_windows(&[&open_src, &closed_src, &none_src])
            .await?;
        let of = |id: &str| windows.iter().find(|(s, _)| s == id).map(|(_, w)| *w);
        assert!(of(&none_src).is_none(), "no session, no window");
        let open = of(&open_src).ok_or("open window")?;
        assert!(open.end.is_none(), "an open session has no end");
        let closed = of(&closed_src).ok_or("closed window")?;
        assert!(
            closed.end.is_some(),
            "every session of the source is closed"
        );
        assert!(
            (closed.start - started).abs() < time::Duration::milliseconds(2),
            "the window starts with the earliest session: {:?}",
            closed.start
        );
        assert!(db.source_windows(&[]).await?.is_empty());
        let _ = a;
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}

#[tokio::test]
async fn view_jobs_are_claimed_once_and_failed_ones_are_reclaimed() -> TestResult {
    on_every_backend!("views", |db, raw| {
        let (view, org) = (Uuid::new_v4(), uniq("org-"));
        let created = db.upsert_view_job(view, &org, "q1").await?;
        assert_eq!(created.status, "pending");

        // Two tasks race to claim; one wins.
        let (x, y) = tokio::join!(db.claim_view_job(view), db.claim_view_job(view));
        assert_eq!([x?, y?].iter().filter(|won| **won).count(), 1);
        let again = db.upsert_view_job(view, &org, "q2").await?;
        assert_eq!(
            again.status, "running",
            "an upsert leaves a running job alone"
        );
        assert_eq!(
            db.view_job(view, &org)
                .await?
                .ok_or("job")?
                .query_id
                .as_deref(),
            Some("q2")
        );
        assert!(db.view_job(view, "someone-else").await?.is_none());

        db.set_view_progress(view, 10, 5, 100).await?;
        let job = db.view_job(view, &org).await?.ok_or("job")?;
        assert_eq!(
            (job.read_rows, job.written_rows, job.total_rows),
            (Some(10), Some(5), Some(100))
        );
        assert!(job.last_checked_at().is_none());
        db.touch_view_job(view).await?;
        assert!(
            db.view_job(view, &org)
                .await?
                .ok_or("job")?
                .last_checked_at()
                .is_some()
        );

        // A failed job comes back as pending with its error and key cleared.
        raw.execute(
            "UPDATE traffic_view_jobs SET status = 'failed', error = 'boom', s3_key = 'k'
             WHERE view_id = ?",
            &[view.into()],
        )
        .await?;
        let reclaimed = db.upsert_view_job(view, &org, "q3").await?;
        assert_eq!(
            (reclaimed.status.as_str(), reclaimed.error, reclaimed.s3_key),
            ("pending", None, None)
        );

        db.complete_view_job(view, "exports/a.parquet").await?;
        let done = db.upsert_view_job(view, &org, "q4").await?;
        assert_eq!(
            (done.status.as_str(), done.s3_key.as_deref()),
            ("completed", Some("exports/a.parquet"))
        );

        // Expiry looks at `completed_at`.
        let now = OffsetDateTime::now_utc();
        let future = now + time::Duration::hours(1);
        let due = db.expired_view_jobs(future, 500).await?;
        assert!(
            due.iter()
                .any(|(id, key)| *id == view && key.as_deref() == Some("exports/a.parquet"))
        );
        assert!(
            !db.expired_view_jobs(now - time::Duration::hours(1), 500)
                .await?
                .iter()
                .any(|(id, _)| *id == view)
        );
        db.delete_expired_view_job(view, now - time::Duration::hours(1))
            .await?;
        assert!(
            db.view_job(view, &org).await?.is_some(),
            "a younger job stays"
        );
        db.delete_expired_view_job(view, future).await?;
        assert!(db.view_job(view, &org).await?.is_none());

        db.upsert_view_job(view, &org, "q5").await?;
        db.delete_view_job(view).await?;
        assert!(db.view_job(view, &org).await?.is_none());
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}

#[tokio::test]
async fn api_keys_authenticate_list_and_disable() -> TestResult {
    on_every_backend!("keys", |db, raw| {
        let org = uniq("org-");
        let keys = KeyStore::new(db.clone());
        let service = keys.create(KeyKind::Service, Some(&org), "crawler").await?;
        let admin = keys.create(KeyKind::Admin, None, &uniq("ops")).await?;
        assert!(service.starts_with("pxk_") && service != admin);
        assert!(keys.create(KeyKind::Admin, Some(&org), "x").await.is_err());
        assert!(keys.create(KeyKind::User, None, "x").await.is_err());
        assert!(
            keys.create(KeyKind::User, Some(&org), "bad name!")
                .await
                .is_err()
        );

        assert!(keys.authenticate(&service).await?.is_some());
        assert!(keys.authenticate(&admin).await?.is_some());
        assert!(keys.authenticate("pxk_unknown").await?.is_none());

        // The key is not stored, only its hash: no column holds it.
        let leaked = raw
            .int(
                "SELECT count(*) FROM api_keys WHERE name LIKE ? OR org_id LIKE ?",
                &[format!("%{service}%").into(), format!("%{service}%").into()],
            )
            .await?;
        assert_eq!(leaked, 0);

        let listed = keys.list(Some(&org)).await?;
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].kind, "service");
        assert!(!listed[0].disabled);
        assert!(keys.list(None).await?.len() >= 2);

        // Disabling by id; a fresh store (no cache) refuses the key.
        let id = listed[0].id.clone();
        assert_eq!(id.len(), 16);
        assert!(keys.disable(&id).await?);
        assert!(!keys.disable(&id).await?, "already disabled");
        assert!(!keys.disable("0000000000000000").await?);
        let fresh = KeyStore::new(db.clone());
        assert!(fresh.authenticate(&service).await?.is_none());
        assert!(fresh.authenticate(&admin).await?.is_some());
        assert!(keys.list(Some(&org)).await?[0].disabled);
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}

#[tokio::test]
async fn a_slow_database_does_not_hang_the_pool_forever() -> TestResult {
    for backend in testing::configured() {
        let Some((db, _)) = open(backend, "ping", false).await? else {
            continue;
        };
        tokio::time::timeout(Duration::from_secs(5), db.ping()).await??;
    }
    Ok(())
}
