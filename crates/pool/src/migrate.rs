//! `proxyx migrate [--check]`: apply the embedded migrations of the configured database (PostgreSQL, MariaDB or SQLite), or
//! report the pending ones without applying them.

use std::time::Duration;

use anyhow::Context as _;
use common::config::Settings;
use store::Db;

/// A migration job that cannot reach the database fails instead of waiting
/// forever like a serving role does.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(60);

/// Apply the migrations, or with `check` list the pending ones and fail when
/// there are any.
///
/// Fails when the database is unreachable, a migration fails, or `check` finds
/// pending migrations.
pub async fn run(settings: &Settings, check: bool) -> anyhow::Result<()> {
    let db = tokio::time::timeout(CONNECT_TIMEOUT, Db::connect(settings.database_url.expose()))
        .await
        .context("failed to connect to the database in time")?
        .context("failed to connect to the database")?;

    if check {
        let pending = db
            .pending_migrations()
            .await
            .context("failed to list pending migrations")?;
        for name in &pending {
            println!("pending: {name}");
        }
        anyhow::ensure!(pending.is_empty(), "{} migration(s) pending", pending.len());
        println!("no pending migrations");
    } else {
        db.migrate().await.context("failed to apply migrations")?;
        println!("migrations applied");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::Secret;

    #[tokio::test]
    async fn invalid_database_configuration_fails_without_retrying() {
        for url in ["sqlite::memory:", "unsupported://host/database"] {
            let settings = Settings {
                database_url: Secret::new(url),
                ..Settings::default()
            };
            let error = tokio::time::timeout(Duration::from_secs(2), run(&settings, false))
                .await
                .expect("invalid configuration must fail immediately")
                .expect_err("invalid configuration cannot migrate");
            let message = format!("{error:#}");
            assert!(
                message.contains("failed to connect to the database"),
                "{message}"
            );
            assert!(!message.contains("deadline has elapsed"), "{message}");
        }
    }
}
