//! Test support shared by the integration tests of every crate.

use sqlx::{AssertSqlSafe, Connection as _};

/// The row MariaDB locks for the changes of one org's blocks. Two orgs may
/// share one: a test that needs two independent orgs picks until the names differ.
pub fn mariadb_org_lock_name(org: &str) -> String {
    crate::db::org_lock_name(org)
}

/// Serialises the database creation of all test binaries on one server.
const CREATE_LOCK: i64 = 70001;

/// Create the database `name` on the backend the suite runs on
/// (`PROXYX_TEST_BACKEND`, PostgreSQL when unset; its server comes from that
/// backend's test variable) and return its URL, or `None` (after a message on
/// stderr) when the variable is unset. `fresh` drops it first.
pub async fn backend_database(name: &str, fresh: bool) -> Result<Option<String>, sqlx::Error> {
    proxyx_db::testing::database(proxyx_db::testing::selected(), name, fresh).await
}

/// Create the database `name` on the PostgreSQL server `base` names (a URL ending in a
/// database) if it is missing, and return its URL. `fresh` drops it first.
/// Callers supply a test or benchmark identifier, not external input.
pub async fn database(base: &str, name: &str, fresh: bool) -> Result<String, sqlx::Error> {
    let mut admin = sqlx::PgConnection::connect(base).await?;
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(CREATE_LOCK)
        .execute(&mut admin)
        .await?;
    if fresh {
        // Callers use fixed test names or identifiers generated from test names.
        sqlx::query(AssertSqlSafe(format!(
            "DROP DATABASE IF EXISTS {name} WITH (FORCE)"
        )))
        .execute(&mut admin)
        .await?;
    }
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)")
            .bind(name)
            .fetch_one(&mut admin)
            .await?;
    if !exists {
        // `name` is the same caller-controlled test or benchmark identifier.
        sqlx::query(AssertSqlSafe(format!("CREATE DATABASE {name}")))
            .execute(&mut admin)
            .await?;
    }
    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(CREATE_LOCK)
        .execute(&mut admin)
        .await?;
    let (prefix, _) = base
        .rsplit_once('/')
        .ok_or_else(|| sqlx::Error::Configuration("database url has no path".into()))?;
    Ok(format!("{prefix}/{name}"))
}
