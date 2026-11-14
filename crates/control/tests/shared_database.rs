//! Several products, or both ProxyX planes, in one PostgreSQL database: each
//! `database_schema` owns its tables and its migration history.
//!
//! Needs `PROXYX_TEST_DATABASE_URL`; skips without it.

use proxyx_control::config::ControlConfig;
use proxyx_control::db::Db;
use proxyx_db::testing::{self, Arg, Raw};
use proxyx_db::{Backend, url_with_schema};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[tokio::test]
async fn two_schemas_in_one_database_keep_separate_tables_and_migration_history() -> TestResult {
    let Some(url) = testing::database(Backend::Postgres, "proxyx_shared_schema_test", true).await?
    else {
        return Ok(());
    };
    let raw = Raw::connect(&url).await?;
    // a neighbour that is not ProxyX: its schema and its table must survive everything below
    raw.execute("CREATE SCHEMA neighbour", &[]).await?;
    raw.execute("CREATE TABLE neighbour.orgs (note text)", &[])
        .await?;
    raw.execute("INSERT INTO neighbour.orgs VALUES ('mine')", &[])
        .await?;

    let mine = Db::connect(&url_with_schema(&url, "proxyx_a")?, 4).await?;
    let other = Db::connect(&url_with_schema(&url, "proxyx_b")?, 4).await?;
    assert_eq!(
        mine.pending_migrations().await?.len(),
        16,
        "nothing is applied yet"
    );

    mine.migrate().await?;
    assert!(mine.pending_migrations().await?.is_empty());
    assert_eq!(
        other.pending_migrations().await?.len(),
        16,
        "another schema's migrations are its own"
    );
    other.migrate().await?;
    mine.migrate().await?; // safe to repeat

    // each schema holds its own tables and its own migration table
    for schema in ["proxyx_a", "proxyx_b"] {
        for table in ["orgs", "api_keys", "session_lifecycle", "_sqlx_migrations"] {
            let n = raw
                .int(
                    "SELECT count(*) FROM information_schema.tables WHERE table_schema = $1 AND table_name = $2",
                    &[Arg::Text(schema.into()), Arg::Text(table.into())],
                )
                .await?;
            assert_eq!(n, 1, "{schema}.{table}");
        }
    }
    let in_public = raw
        .int(
            "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public'",
            &[],
        )
        .await?;
    assert_eq!(in_public, 0, "no ProxyX table leaked into public");

    // a row written through one namespace is invisible through the other
    raw.execute("INSERT INTO proxyx_a.orgs (id) VALUES ('acme')", &[])
        .await?;
    assert_eq!(raw.int("SELECT count(*) FROM proxyx_a.orgs", &[]).await?, 1);
    assert_eq!(raw.int("SELECT count(*) FROM proxyx_b.orgs", &[]).await?, 0);
    assert_eq!(
        raw.int("SELECT count(*) FROM neighbour.orgs", &[]).await?,
        1,
        "the neighbour's table is untouched"
    );
    let through_other = Raw::connect(&url_with_schema(&url, "proxyx_b")?).await?;
    assert_eq!(
        through_other.int("SELECT count(*) FROM orgs", &[]).await?,
        0
    );
    let through_mine = Raw::connect(&url_with_schema(&url, "proxyx_a")?).await?;
    assert_eq!(through_mine.int("SELECT count(*) FROM orgs", &[]).await?, 1);
    Ok(())
}

/// SHA-384 of the two PostgreSQL migrations as release 0.1.0 shipped them.
const RELEASED_CHECKSUMS: [(i64, &str); 2] = [
    (
        20250425000002,
        "5d9dd3b8590c047ff4a5179db890bd31d1439593b561d8e66d4830733100d21299e517a0915b109ee1589a6380322ff1",
    ),
    (
        20260703000001,
        "9f337569854ae15f5172ef614265e74378c7e365440ad74ee38bb91b782c46c781a31f72db87f4e089765f8ecebe483b",
    ),
];

async fn recorded_checksum(raw: &Raw, version: i64) -> Result<String, sqlx::Error> {
    raw.text(
        "SELECT encode(checksum, 'hex') FROM _sqlx_migrations WHERE version = $1",
        &[Arg::Int(version)],
    )
    .await
}

/// A database that applied the migrations of release 0.1.0 holds the old
/// checksum of the two rewritten ones. `migrate` records the new checksum, for
/// exactly the released checksum, and still refuses any other.
#[tokio::test]
async fn a_database_from_release_0_1_0_is_repaired_and_a_tampered_one_is_refused() -> TestResult {
    let Some(url) = testing::database(Backend::Postgres, "proxyx_rewritten_test", true).await?
    else {
        return Ok(());
    };
    let pinned = url_with_schema(&url, "proxyx_a")?;
    let db = Db::connect(&pinned, 4).await?;
    db.migrate().await?;
    let raw = Raw::connect(&pinned).await?;
    let mut current = Vec::new();
    for (version, released) in RELEASED_CHECKSUMS {
        let now = recorded_checksum(&raw, version).await?;
        assert_ne!(now, released, "{version} changed after the release");
        current.push(now);
    }

    // what release 0.1.0 left in the table
    for (version, released) in RELEASED_CHECKSUMS {
        raw.execute(
            "UPDATE _sqlx_migrations SET checksum = decode($1, 'hex') WHERE version = $2",
            &[Arg::Text(released.into()), Arg::Int(version)],
        )
        .await?;
    }
    db.migrate().await?;
    for ((version, _), now) in RELEASED_CHECKSUMS.iter().zip(&current) {
        assert_eq!(&recorded_checksum(&raw, *version).await?, now, "{version}");
    }
    db.migrate().await?; // nothing left to repair

    // a checksum that no release ever had stays an error
    raw.execute(
        "UPDATE _sqlx_migrations SET checksum = decode(repeat('ab', 48), 'hex') WHERE version = $1",
        &[Arg::Int(RELEASED_CHECKSUMS[0].0)],
    )
    .await?;
    let error = db.migrate().await.expect_err("a tampered checksum");
    assert!(
        matches!(error, sqlx::migrate::MigrateError::VersionMismatch(v) if v == RELEASED_CHECKSUMS[0].0),
        "{error:?}"
    );
    Ok(())
}

/// ProxyX migrations touch only ProxyX's schema: a neighbour's extension (here
/// `pg_trgm` in its own schema, outside the search path), `partman` and `cron`
/// schemas, their rows and cron jobs survive, and the migration does not need
/// the extension at all.
#[tokio::test]
async fn migrations_leave_the_extensions_schemas_and_jobs_of_neighbours_alone() -> TestResult {
    let Some(url) = testing::database(Backend::Postgres, "proxyx_neighbour_ext_test", true).await?
    else {
        return Ok(());
    };
    let raw = Raw::connect(&url).await?;
    for statement in [
        "CREATE SCHEMA extensions",
        "CREATE EXTENSION pg_trgm SCHEMA extensions",
        "CREATE SCHEMA partman",
        "CREATE TABLE partman.part_config (parent_table text)",
        "INSERT INTO partman.part_config VALUES ('public.http_captures'), \
            ('neighbour.http_captures'), ('proxyx_a.http_captures'), ('proxyx_a.other')",
        "CREATE SCHEMA cron",
        "CREATE TABLE cron.job (jobname text)",
        "INSERT INTO cron.job VALUES ('partman-maintenance'), ('neighbour-nightly-vacuum')",
    ] {
        raw.execute(statement, &[]).await?;
    }
    let extensions_before = raw.int("SELECT count(*) FROM pg_extension", &[]).await?;

    for schema in ["proxyx_a", "proxyx_b"] {
        Db::connect(&url_with_schema(&url, schema)?, 4)
            .await?
            .migrate()
            .await?;
    }

    assert_eq!(
        raw.int("SELECT count(*) FROM pg_extension", &[]).await?,
        extensions_before,
        "no extension was created or dropped"
    );
    assert_eq!(
        raw.int(
            "SELECT count(*) FROM pg_extension e JOIN pg_namespace n ON n.oid = e.extnamespace \
             WHERE e.extname = 'pg_trgm' AND n.nspname = 'extensions'",
            &[],
        )
        .await?,
        1,
        "the neighbour's pg_trgm is where it was"
    );
    assert_eq!(
        raw.int("SELECT count(*) FROM cron.job", &[]).await?,
        2,
        "no cron job was unscheduled"
    );
    assert_eq!(
        raw.int("SELECT count(*) FROM information_schema.schemata WHERE schema_name IN ('partman', 'cron', 'extensions')", &[])
            .await?,
        3
    );
    // only the row of a schema's own http_captures is removed
    assert_eq!(
        raw.int(
            "SELECT count(*) FROM partman.part_config WHERE parent_table IN \
             ('public.http_captures', 'neighbour.http_captures', 'proxyx_a.other')",
            &[],
        )
        .await?,
        3
    );
    assert_eq!(
        raw.int(
            "SELECT count(*) FROM partman.part_config WHERE parent_table = 'proxyx_a.http_captures'",
            &[],
        )
        .await?,
        0
    );
    Ok(())
}

#[test]
fn the_schema_setting_is_applied_and_refused_where_it_cannot_work() {
    let load = |toml: &str| -> anyhow::Result<ControlConfig> {
        use figment::Figment;
        use figment::providers::{Format as _, Toml};
        let mut config: ControlConfig = Figment::new().merge(Toml::string(toml)).extract()?;
        config.apply_database_schema()?;
        Ok(config)
    };
    let config =
        load("database_url = \"postgres://u@h/d\"\ndatabase_schema = \"proxyx\"").expect("pg");
    assert_eq!(
        config.database_url,
        "postgres://u@h/d?options=-c%20search_path%3Dproxyx%2Cpublic"
    );
    for (toml, why) in [
        (
            "database_url = \"mariadb://u@h/d\"\ndatabase_schema = \"proxyx\"",
            "PostgreSQL only",
        ),
        (
            "database_url = \"sqlite:///x.db?mode=rwc\"\ndatabase_schema = \"proxyx\"",
            "PostgreSQL only",
        ),
        (
            "database_url = \"postgres://u@h/d\"\ndatabase_schema = \"Bad Name\"",
            "lowercase",
        ),
        (
            "database_url = \"postgres://u@h/d\"\ndatabase_schema = \"public\"",
            "public",
        ),
    ] {
        let error = load(toml).expect_err(toml);
        assert!(format!("{error:#}").contains(why), "{toml}: {error:#}");
    }
    assert_eq!(
        load("database_url = \"mariadb://u@h/d\"")
            .expect("no schema")
            .database_url,
        "mariadb://u@h/d",
        "without a schema the URL is used as it always was"
    );
}
