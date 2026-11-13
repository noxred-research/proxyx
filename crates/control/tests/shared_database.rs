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
