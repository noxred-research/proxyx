//! The pool store in its own PostgreSQL schema, next to another product's.
//!
//! Needs `PROXYX_TEST_DATABASE_URL`; skips without it.

use proxyx_db::testing::{self, Arg, Raw};
use proxyx_db::{Backend, url_with_schema};
use proxyx_store::Db;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[tokio::test]
async fn the_pool_store_migrates_into_its_own_schema() -> TestResult {
    let Some(url) = testing::database(Backend::Postgres, "proxyx_pool_schema_test", true).await?
    else {
        return Ok(());
    };
    let raw = Raw::connect(&url).await?;
    raw.execute("CREATE SCHEMA other_product", &[]).await?;
    raw.execute("CREATE TABLE other_product.audit (note text)", &[])
        .await?;

    let pool_url = url_with_schema(&url, "proxyx_pool")?;
    let db = Db::connect(&pool_url).await?;
    assert!(!db.pending_migrations().await?.is_empty());
    db.migrate().await?;
    assert!(db.pending_migrations().await?.is_empty());
    for table in ["audit", "_sqlx_migrations"] {
        let n = raw
            .int(
                "SELECT count(*) FROM information_schema.tables WHERE table_schema = $1 AND table_name = $2",
                &[Arg::Text("proxyx_pool".into()), Arg::Text(table.into())],
            )
            .await?;
        assert_eq!(n, 1, "proxyx_pool.{table}");
    }
    // the other product's table has the name of ours and is left alone
    assert_eq!(
        raw.int("SELECT count(*) FROM other_product.audit", &[])
            .await?,
        0
    );
    assert_eq!(
        raw.int(
            "SELECT count(*) FROM information_schema.columns WHERE table_schema = 'other_product' AND table_name = 'audit'",
            &[]
        )
        .await?,
        1
    );
    assert_eq!(
        raw.int(
            "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public'",
            &[]
        )
        .await?,
        0
    );
    Ok(())
}
