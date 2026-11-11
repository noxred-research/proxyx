//! The generic checks against the local Postgres and Valkey
//! (`PROXYX_TEST_DATABASE_URL`, `PROXYX_TEST_REDIS_URL`; a test skips with a
//! message when its variable is unset) and against ports where nothing listens.

use std::time::{Duration, Instant};

use proxyx_diag::db::database as postgres;
use proxyx_diag::redis_checks::{RedisOptions, redis_server, redis_stream};
use proxyx_diag::{Check, Status};
use sqlx::{AssertSqlSafe, Connection as _};

const T: Duration = Duration::from_secs(5);
/// Redis database index of the doctor tests (contract: doctor 12).
const REDIS_DB: &str = "12";

fn status(checks: &[Check], id: &str) -> Status {
    checks
        .iter()
        .find(|c| c.id == id)
        .unwrap_or_else(|| panic!("no {id} in {checks:?}"))
        .status
}

fn redis_url() -> Option<String> {
    let Ok(base) = std::env::var("PROXYX_TEST_REDIS_URL") else {
        eprintln!("SKIP: PROXYX_TEST_REDIS_URL is not set");
        return None;
    };
    let authority = base.trim_end_matches('/');
    let authority = authority
        .rsplit_once('/')
        .filter(|(h, _)| h.contains("://"))
        .map_or(authority, |(h, _)| h);
    Some(format!("{authority}/{REDIS_DB}"))
}

/// A database of this test binary on the test server, created empty.
async fn database(name: &'static str) -> Option<String> {
    let Ok(base) = std::env::var("PROXYX_TEST_DATABASE_URL") else {
        eprintln!("SKIP: PROXYX_TEST_DATABASE_URL is not set");
        return None;
    };
    let mut admin = sqlx::PgConnection::connect(&base).await.expect("connect");
    // The only caller supplies the fixed identifier `proxyx_ops_doctor_diag`.
    sqlx::query(AssertSqlSafe(format!(
        "DROP DATABASE IF EXISTS {name} WITH (FORCE)"
    )))
    .execute(&mut admin)
    .await
    .expect("drop");
    // `name` is the same fixed test identifier.
    sqlx::query(AssertSqlSafe(format!("CREATE DATABASE {name}")))
        .execute(&mut admin)
        .await
        .expect("create");
    let (prefix, _) = base.rsplit_once('/').expect("database url has a path");
    Some(format!("{prefix}/{name}"))
}

#[tokio::test]
async fn postgres_passes_once_the_schema_exists() {
    let Some(url) = database("proxyx_ops_doctor_diag").await else {
        return;
    };

    // Reachable, but nothing was ever migrated.
    let checks = postgres(&url, T).await;
    assert_eq!(
        status(&checks, "postgres.reachable"),
        Status::Pass,
        "{checks:?}"
    );
    assert_eq!(
        status(&checks, "postgres.version"),
        Status::Pass,
        "{checks:?}"
    );
    assert_eq!(
        status(&checks, "postgres.migrations"),
        Status::Fail,
        "{checks:?}"
    );
    let reachable = checks
        .iter()
        .find(|c| c.id == "postgres.reachable")
        .expect("check");
    assert!(reachable.elapsed_ms.is_some());

    let mut conn = sqlx::PgConnection::connect(&url).await.expect("connect");
    sqlx::query(
        "CREATE TABLE _sqlx_migrations (version BIGINT PRIMARY KEY, description TEXT NOT NULL, \
         installed_on TIMESTAMPTZ NOT NULL DEFAULT now(), success BOOLEAN NOT NULL, \
         checksum BYTEA NOT NULL, execution_time BIGINT NOT NULL)",
    )
    .execute(&mut conn)
    .await
    .expect("create table");
    sqlx::query("INSERT INTO _sqlx_migrations VALUES (1, 'init', now(), true, '\\x00', 1)")
        .execute(&mut conn)
        .await
        .expect("insert");
    let checks = postgres(&url, T).await;
    assert_eq!(
        status(&checks, "postgres.migrations"),
        Status::Pass,
        "{checks:?}"
    );
}

#[tokio::test]
async fn a_wrong_password_or_database_fails_with_the_target_named() {
    let Ok(base) = std::env::var("PROXYX_TEST_DATABASE_URL") else {
        eprintln!("SKIP: PROXYX_TEST_DATABASE_URL is not set");
        return;
    };
    let (prefix, _) = base.rsplit_once('/').expect("url");
    let checks = postgres(&format!("{prefix}/proxyx_ops_no_such_database"), T).await;
    assert_eq!(checks.len(), 1);
    assert_eq!(checks[0].status, Status::Fail, "{checks:?}");
    assert!(
        checks[0].message.contains("proxyx_ops_no_such_database"),
        "{checks:?}"
    );
}

#[tokio::test]
async fn redis_passes_against_the_local_valkey() {
    let Some(url) = redis_url() else { return };
    let checks = redis_server(&url, RedisOptions::new(T)).await;
    assert_eq!(
        status(&checks, "redis.reachable"),
        Status::Pass,
        "{checks:?}"
    );
    assert_eq!(
        status(&checks, "redis.clock_skew"),
        Status::Pass,
        "{checks:?}"
    );
    let mut ids: Vec<&str> = checks.iter().map(|c| c.id.as_str()).collect();
    ids.sort_unstable();
    assert_eq!(
        ids,
        [
            "redis.clock_skew",
            "redis.memory_policy",
            "redis.persistence",
            "redis.reachable"
        ]
    );
}

#[tokio::test]
async fn redis_streams_are_measured_against_their_cap() {
    let Some(url) = redis_url() else { return };
    let key = format!("proxyx_ops_doctor:stream:{}", std::process::id());
    assert_eq!(redis_stream(&url, &key, 10, T).await.status, Status::Pass);
    let client = redis::Client::open(url.as_str()).expect("client");
    let mut conn = client
        .get_multiplexed_async_connection()
        .await
        .expect("connect");
    for i in 0..9 {
        let _: String = redis::cmd("XADD")
            .arg(&key)
            .arg("*")
            .arg("n")
            .arg(i)
            .query_async(&mut conn)
            .await
            .expect("xadd");
    }
    let near = redis_stream(&url, &key, 10, T).await;
    assert_eq!(near.status, Status::Warn, "{near:?}");
    assert_eq!(redis_stream(&url, &key, 1000, T).await.status, Status::Pass);
    let _: i64 = redis::cmd("DEL")
        .arg(&key)
        .query_async(&mut conn)
        .await
        .expect("del");
}

#[tokio::test]
async fn a_closed_port_fails_fast_and_a_black_hole_is_bounded_by_the_timeout() {
    let start = Instant::now();
    let checks = postgres(
        "postgres://postgres@127.0.0.1:1/postgres",
        Duration::from_secs(2),
    )
    .await;
    assert_eq!(checks[0].status, Status::Fail, "{checks:?}");
    let checks = redis_server(
        "redis://127.0.0.1:1",
        RedisOptions::new(Duration::from_secs(2)),
    )
    .await;
    assert_eq!(checks[0].status, Status::Fail, "{checks:?}");
    assert!(
        start.elapsed() < Duration::from_secs(3),
        "{:?}",
        start.elapsed()
    );

    // 192.0.2.0/24 is documentation space: packets go nowhere.
    let bound = Duration::from_millis(500);
    let start = Instant::now();
    let checks = postgres("postgres://postgres@192.0.2.1:5432/postgres", bound).await;
    assert_eq!(checks[0].status, Status::Fail, "{checks:?}");
    let checks = redis_server("redis://192.0.2.1:6379", RedisOptions::new(bound)).await;
    assert_eq!(checks[0].status, Status::Fail, "{checks:?}");
    assert!(
        start.elapsed() < Duration::from_secs(4),
        "{:?}",
        start.elapsed()
    );
}
