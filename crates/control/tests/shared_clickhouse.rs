//! Two ProxyX namespaces (two ClickHouse databases) on one server.
//!
//! Needs `PROXYX_TEST_CLICKHOUSE_URL` and `PROXYX_CONTROL_CLICKHOUSE__LOCAL_SINGLE_NODE`
//! (a single-node server); skips without them.

use proxyx_control::migrations;
use proxyx_control::pipeline::clickhouse::ClickHouseConfig;
use proxyx_control::runtime::{clickhouse_client, ensure_clickhouse_database};
use uuid::Uuid;

fn config(url: &str, database: &str) -> ClickHouseConfig {
    ClickHouseConfig {
        url: url.to_owned(),
        database: Some(database.to_owned()),
        user: std::env::var("PROXYX_TEST_CLICKHOUSE_USER").ok(),
        password: std::env::var("PROXYX_TEST_CLICKHOUSE_PASSWORD").ok(),
        table: None,
        bulk_size: 500,
        flush_interval_secs: 1,
        max_buffer_bytes: 256 * 1024 * 1024,
        circuit_breaker_threshold: 5,
        circuit_breaker_reset_secs: 60,
    }
}

async fn count(client: &clickhouse::Client, sql: &str) -> u64 {
    client.query(sql).fetch_one::<u64>().await.expect("count")
}

#[tokio::test]
async fn migrate_creates_each_database_and_keeps_their_history_apart() {
    let Ok(url) = std::env::var("PROXYX_TEST_CLICKHOUSE_URL") else {
        eprintln!("SKIP: PROXYX_TEST_CLICKHOUSE_URL is not set");
        return;
    };
    if std::env::var_os("PROXYX_CONTROL_CLICKHOUSE__LOCAL_SINGLE_NODE").is_none() {
        eprintln!("SKIP: PROXYX_CONTROL_CLICKHOUSE__LOCAL_SINGLE_NODE is not set");
        return;
    }
    let suffix = &Uuid::new_v4().simple().to_string()[..10];
    let (a, b) = (format!("pxa_{suffix}"), format!("pxb_{suffix}"));
    let admin = clickhouse_client(&ClickHouseConfig {
        database: None,
        ..config(&url, "default")
    });

    // a bad name is refused before anything is sent
    let bad = ensure_clickhouse_database(&config(&url, "x`; DROP DATABASE default; --")).await;
    assert!(bad.is_err());

    for database in [&a, &b] {
        let cfg = config(&url, database);
        ensure_clickhouse_database(&cfg)
            .await
            .expect("create the database");
        ensure_clickhouse_database(&cfg)
            .await
            .expect("repeating is harmless");
        let client = clickhouse_client(&cfg);
        migrations::run_clickhouse(&client).await.expect("migrate");
        migrations::verify_clickhouse(&client)
            .await
            .expect("up to date");
    }

    for database in [&a, &b] {
        let tables = count(
            &admin,
            &format!("SELECT count() FROM system.tables WHERE database = '{database}' AND name IN ('http_captures', '_ch_migrations')"),
        )
        .await;
        assert_eq!(
            tables, 2,
            "{database} has its own tables and its own migration history"
        );
    }
    let applied = |database: &str| format!("SELECT count() FROM `{database}`._ch_migrations FINAL");
    assert_eq!(
        count(&admin, &applied(&a)).await,
        count(&admin, &applied(&b)).await
    );
    assert!(count(&admin, &applied(&a)).await > 0);

    // a row in one namespace is invisible in the other
    admin
        .query(&format!(
            "INSERT INTO `{a}`._ch_migrations (name) VALUES ('only_in_a')"
        ))
        .execute()
        .await
        .expect("insert");
    assert_eq!(
        count(
            &admin,
            &format!("SELECT count() FROM `{a}`._ch_migrations FINAL WHERE name = 'only_in_a'")
        )
        .await,
        1
    );
    assert_eq!(
        count(
            &admin,
            &format!("SELECT count() FROM `{b}`._ch_migrations FINAL WHERE name = 'only_in_a'")
        )
        .await,
        0
    );
    // verify in b still passes: its history is its own
    migrations::verify_clickhouse(&clickhouse_client(&config(&url, &b)))
        .await
        .expect("b unaffected");

    for database in [&a, &b] {
        admin
            .query(&format!("DROP DATABASE `{database}`"))
            .execute()
            .await
            .expect("drop");
    }
}
