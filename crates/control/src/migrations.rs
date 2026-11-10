use anyhow::{Context, Result};
use include_dir::{Dir, include_dir};

const CLICKHOUSE_SCHEMA_FILES: &[(&str, &str)] = &[
    ("init.sql", include_str!("../clickhouse/init.sql")),
    ("ws_init.sql", include_str!("../clickhouse/ws_init.sql")),
    ("indexes.sql", include_str!("../clickhouse/indexes.sql")),
    (
        "ws_indexes.sql",
        include_str!("../clickhouse/ws_indexes.sql"),
    ),
];

static CLICKHOUSE_MIGRATIONS_DIR: Dir<'_> =
    include_dir!("$CARGO_MANIFEST_DIR/clickhouse/migrations");

/// Return `(name, sql)` pairs sorted by filename. Migration files must be
/// `*.sql` and are ordered lexicographically — the `YYYYMMDD_NNN_` prefix
/// guarantees chronological execution.
fn clickhouse_migrations() -> Vec<(&'static str, &'static str)> {
    let mut entries: Vec<(&str, &str)> = CLICKHOUSE_MIGRATIONS_DIR
        .files()
        .filter_map(|f| {
            let name = f.path().file_stem()?.to_str()?;
            let contents = f.contents_utf8()?;
            Some((name, contents))
        })
        .collect();
    entries.sort_by_key(|(name, _)| *name);
    entries
}

/// Apply the relational migrations of the backend `db` talks to.
pub async fn run_database(db: &crate::db::Db) -> Result<()> {
    db.migrate().await?;
    tracing::info!(backend = %db.backend(), "database migrations applied");
    Ok(())
}

pub async fn run_clickhouse(ch_client: &clickhouse::Client) -> Result<()> {
    apply_clickhouse_schema(ch_client).await?;
    apply_clickhouse_migrations(ch_client).await?;
    tracing::info!("ClickHouse schema initialized");
    Ok(())
}

/// Fail when the database has migrations to apply.
pub async fn verify_database(db: &crate::db::Db) -> Result<()> {
    let pending = db
        .pending_migrations()
        .await
        .context("failed to read the applied database migrations")?;
    if !pending.is_empty() {
        anyhow::bail!(
            "pending {} migrations not applied (run `migrate` first): {:?}",
            db.backend(),
            pending
        );
    }
    tracing::info!(backend = %db.backend(), "database schema up to date");
    Ok(())
}

pub async fn verify_clickhouse(ch_client: &clickhouse::Client) -> Result<()> {
    let applied: Vec<String> = ch_client
        .query("SELECT name FROM _ch_migrations FINAL")
        .fetch_all()
        .await
        .context("failed to read ClickHouse migration state (run `migrate` first)")?;

    let migrations = clickhouse_migrations();
    let pending: Vec<&str> = migrations
        .iter()
        .map(|(name, _)| *name)
        .filter(|name| !applied.iter().any(|applied| applied == name))
        .collect();
    if !pending.is_empty() {
        anyhow::bail!(
            "pending ClickHouse migrations not applied (run `migrate` first): {:?}",
            pending
        );
    }
    tracing::info!("ClickHouse schema up to date");
    Ok(())
}

fn local_clickhouse_statement(stmt: &str) -> Option<String> {
    if std::env::var_os("PROXYX_CONTROL_CLICKHOUSE__LOCAL_SINGLE_NODE").is_none() {
        return Some(stmt.to_owned());
    }
    single_node_statement(stmt)
}

fn single_node_statement(stmt: &str) -> Option<String> {
    // Single-node local ClickHouse has no ClickHouse Keeper and no tiered
    // storage policy, so the prod DDL is rewritten in place: Replicated* engines
    // collapse to their non-replicated form, the `tiered` storage policy setting
    // is dropped, and TTL "move to cold volume" actions are removed (the
    // INTERVAL ... DELETE retention entry, when present, is preserved).
    // `SYSTEM SYNC REPLICA` fails on non-replicated tables and is skipped. Prod
    // is untouched; this only runs when LOCAL_SINGLE_NODE is set.
    if effective_sql(stmt).starts_with("SYSTEM SYNC REPLICA") {
        return None;
    }
    let stmt = stmt
        .replace("ReplicatedReplacingMergeTree", "ReplacingMergeTree")
        .replace("ReplicatedSummingMergeTree", "SummingMergeTree")
        .replace("ReplicatedMergeTree", "MergeTree");

    let raw: Vec<&str> = stmt.lines().collect();
    let mut out: Vec<String> = Vec::new();
    let mut i = 0;
    while i < raw.len() {
        let line = raw[i];
        let trimmed = line.trim();
        if trimmed == "TTL" {
            // Collect the TTL entries (one per line until SETTINGS/ENGINE/end),
            // dropping any "TO VOLUME" tier moves. Emit the clause only if at
            // least one retention entry survives.
            let mut entries: Vec<&str> = Vec::new();
            let mut j = i + 1;
            while j < raw.len() {
                let entry = raw[j].trim();
                if entry.is_empty()
                    || entry.starts_with("SETTINGS")
                    || entry.starts_with("ENGINE")
                    || entry.starts_with("AS ")
                {
                    break;
                }
                if !entry.contains("TO VOLUME") {
                    entries.push(entry.trim_end_matches(','));
                }
                j += 1;
            }
            if !entries.is_empty() {
                out.push("TTL".to_owned());
                let last = entries.len() - 1;
                for (k, entry) in entries.iter().enumerate() {
                    let sep = if k == last { "" } else { "," };
                    out.push(format!("    {entry}{sep}"));
                }
            }
            i = j;
            continue;
        }
        if trimmed == "SETTINGS" {
            // Collect SETTINGS entries, dropping the tiered storage policy. Emit
            // the clause only if at least one setting survives.
            let mut entries: Vec<&str> = Vec::new();
            let mut j = i + 1;
            while j < raw.len() {
                let entry = raw[j].trim();
                if entry.is_empty()
                    || entry.starts_with("TTL")
                    || entry.starts_with("ENGINE")
                    || entry.starts_with("AS ")
                {
                    break;
                }
                if !entry.contains("storage_policy") {
                    entries.push(entry.trim_end_matches(','));
                }
                j += 1;
            }
            if !entries.is_empty() {
                out.push("SETTINGS".to_owned());
                let last = entries.len() - 1;
                for (k, entry) in entries.iter().enumerate() {
                    let sep = if k == last { "" } else { "," };
                    out.push(format!("    {entry}{sep}"));
                }
            }
            i = j;
            continue;
        }
        out.push(line.to_owned());
        i += 1;
    }
    Some(out.join("\n"))
}

async fn apply_clickhouse_schema(ch_client: &clickhouse::Client) -> Result<()> {
    for (name, contents) in CLICKHOUSE_SCHEMA_FILES {
        for stmt in statements(contents) {
            let Some(stmt) = local_clickhouse_statement(stmt) else {
                continue;
            };
            ch_client
                .query(&stmt)
                .execute()
                .await
                .with_context(|| format!("ClickHouse schema file {name} failed"))?;
        }
    }
    Ok(())
}

async fn apply_clickhouse_migrations(ch_client: &clickhouse::Client) -> Result<()> {
    for (name, contents) in clickhouse_migrations() {
        let applied: u64 = ch_client
            .query("SELECT count() FROM _ch_migrations FINAL WHERE name = ?")
            .bind(name)
            .fetch_one()
            .await
            .context("failed to query _ch_migrations")?;

        if applied > 0 {
            tracing::info!(
                migration = name,
                "ClickHouse migration already applied, skipping"
            );
            continue;
        }

        for stmt in statements(contents) {
            let Some(stmt) = local_clickhouse_statement(stmt) else {
                continue;
            };
            ch_client
                .query(&stmt)
                .execute()
                .await
                .with_context(|| format!("ClickHouse migration {name} failed"))?;
        }

        ch_client
            .query("INSERT INTO _ch_migrations (name) VALUES (?)")
            .bind(name)
            .execute()
            .await
            .with_context(|| format!("failed to record ClickHouse migration {name}"))?;

        tracing::info!(migration = name, "applied ClickHouse migration");
    }
    Ok(())
}

fn statements(contents: &'static str) -> impl Iterator<Item = &'static str> {
    contents.split(";\n").filter_map(|stmt| {
        let stmt = stmt.trim().trim_end_matches(';').trim();
        if effective_sql(stmt).is_empty() {
            None
        } else {
            Some(stmt)
        }
    })
}

fn effective_sql(stmt: &str) -> String {
    stmt.lines()
        .skip_while(|line| {
            let trimmed = line.trim();
            trimmed.is_empty() || trimmed.starts_with("--")
        })
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUEST_COUNTS_REPLICATED: &str = "20261019_001_request_counts_per_minute_replicated";

    fn migration_statements(name: &str) -> Vec<&'static str> {
        let (_, contents) = clickhouse_migrations()
            .into_iter()
            .find(|(n, _)| *n == name)
            .expect("migration exists");
        statements(contents).collect()
    }

    #[test]
    fn single_node_rewrites_replicated_summing_mv() {
        let create = migration_statements(REQUEST_COUNTS_REPLICATED)
            .into_iter()
            .find(|s| effective_sql(s).starts_with("CREATE MATERIALIZED VIEW"))
            .expect("CREATE statement");
        assert!(create.contains("ReplicatedSummingMergeTree"));

        let local = single_node_statement(create).expect("CREATE is kept");
        assert!(local.contains("ENGINE = SummingMergeTree"));
        assert!(!local.contains("Replicated"));
        assert!(!local.contains("TO VOLUME"));
        assert!(!local.contains("storage_policy"));
        assert!(local.contains("GROUP BY org_id, minute"));
    }

    #[test]
    fn single_node_skips_sync_replica() {
        let sync = migration_statements(REQUEST_COUNTS_REPLICATED)
            .into_iter()
            .find(|s| effective_sql(s).starts_with("SYSTEM SYNC REPLICA"))
            .expect("SYNC REPLICA statement");
        assert_eq!(single_node_statement(sync), None);
    }
}
