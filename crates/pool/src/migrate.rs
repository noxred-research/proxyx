//! `proxyx migrate [--check]`: apply the embedded migrations of the configured database (PostgreSQL, MariaDB or SQLite), or
//! report the pending ones without applying them.

use std::time::Duration;

use anyhow::Context as _;
use common::config::Settings;
use tokio_util::sync::CancellationToken;

/// A migration job that cannot reach the database fails instead of waiting
/// forever like a serving role does.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(60);

/// Apply the migrations, or with `check` list the pending ones and fail when
/// there are any.
///
/// Fails when the database is unreachable, a migration fails, or `check` finds
/// pending migrations.
pub async fn run(settings: &Settings, check: bool) -> anyhow::Result<()> {
    let db = tokio::time::timeout(
        CONNECT_TIMEOUT,
        crate::connect::db(&settings.database_url, &CancellationToken::new()),
    )
    .await
    .context("failed to connect to the database in time")??;

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
