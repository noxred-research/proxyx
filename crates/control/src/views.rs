//! Async traffic view export: the capture store writes directly to object
//! storage (S3 or Azure Blob, see [`crate::view_store`]) as Parquet. Only the
//! ClickHouse store can: it does so with a native table function. Other
//! stores have no [`ViewExporter`] and answer exports with 501.
//!
//! # Architecture
//!
//! Exports are **fire-and-forget**: `create_view` submits the INSERT query
//! to ClickHouse with `wait_end_of_query=0` (returns immediately) and a
//! deterministic `query_id` derived from the `view_id`. ClickHouse
//! continues the query independently of the proxyx process lifetime.
//! The ClickHouse specifics live behind [`ViewExporter`].
//!
//! All state reconciliation happens in `poll_view_status`, called by the
//! `GET /rpc/views/{view_id}` handler. It checks, in order:
//!
//! 1. Postgres `traffic_view_jobs` row for cached status.
//! 2. `system.processes` on every replica for in-flight progress (read_rows, total_rows).
//! 3. `system.query_log` on every replica for completion/failure of a finished query.
//! 4. Object store existence check to confirm the Parquet file landed.
//!
//! External checks (ClickHouse, object store) are debounced via
//! `last_checked_at` to avoid overwhelming backends when callers poll
//! aggressively.
//!
//! # Expiry
//!
//! Completed exports live for `traffic_views_ttl_secs` after `completed_at`.
//! [`expire_completed_views`] (run by the API reaper loop) deletes the object
//! first and the job row second, so a failed delete is retried on the next
//! pass instead of leaving an orphaned object with no row.

use crate::db::Db;
use anyhow::{Context, Result};
use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::config::ControlConfig;
use crate::query::{QueryBranch, TrafficQuery};
use crate::view_store::ViewStore;

/// Namespace UUID for traffic view identifiers (UUID v5).
const VIEW_NS: Uuid = uuid::uuid!("c7a8e2f4-4b1d-5a9c-8e3f-1d2b4c6a8e0f");

/// Minimum interval between external checks (ClickHouse / object store) in seconds.
const DEBOUNCE_SECS: i64 = 3;

#[derive(Serialize)]
struct ViewKey<'a> {
    org_id: &'a str,
    branches: &'a [QueryBranch],
}

/// Compute the deterministic view identifier for a query.
pub(crate) fn compute_view_id(org_id: &str, branches: &[QueryBranch]) -> Uuid {
    let canonical =
        serde_json::to_vec(&ViewKey { org_id, branches }).expect("ViewKey is infallible");
    Uuid::new_v5(&VIEW_NS, &canonical)
}

pub(crate) fn s3_key(org_id: &str, view_id: Uuid) -> String {
    format!("traffic-views/{org_id}/{view_id}.parquet")
}

/// ClickHouse query_id for a view export. Deterministic so we can find
/// the query in `system.processes` / `system.query_log` without storing
/// extra state.
fn ch_query_id(view_id: Uuid) -> String {
    format!("proxyx-export-{view_id}")
}

/// Progress of a running export.
pub struct ExportProgress {
    pub read_rows: i64,
    pub written_rows: i64,
    pub total_rows: i64,
}

/// How a finished export ended.
pub enum ExportOutcome {
    Finished,
    Failed(String),
}

/// The part of a capture store that writes Parquet exports to object
/// storage. Exports are identified by an export id (the ClickHouse
/// `query_id`) that is derived from the view id, so progress and outcome can
/// be found again without storing more state.
#[async_trait::async_trait]
pub trait ViewExporter: Send + Sync {
    /// Start writing the export of `query` to `key` in `store` and return
    /// without waiting for it to finish.
    async fn submit(
        &self,
        config: &ControlConfig,
        store: &ViewStore,
        query: &TrafficQuery,
        export_id: &str,
        key: &str,
    ) -> Result<()>;

    /// Progress of the running export, `None` when it is not running.
    async fn progress(&self, export_id: &str) -> Result<Option<ExportProgress>>;

    /// How the export ended, `None` when the store has no record of it.
    async fn outcome(&self, export_id: &str) -> Result<Option<ExportOutcome>>;
}

/// Returned by `create_view` — the initial job state after upsert + fire.
pub(crate) struct ViewJobResult {
    pub view_id: Uuid,
    pub status: String,
    pub s3_key: Option<String>,
    pub error: Option<String>,
}

/// Returned by `poll_view_status` — full state including progress.
pub(crate) struct ViewPollResult {
    pub view_id: Uuid,
    pub status: String,
    pub s3_key: Option<String>,
    pub error: Option<String>,
    pub read_rows: Option<i64>,
    pub written_rows: Option<i64>,
    pub total_rows: Option<i64>,
}

/// Upsert a view job row and fire the ClickHouse export query.
///
/// The export query is submitted with `wait_end_of_query=0` so ClickHouse
/// accepts it and returns immediately. Status is reconciled lazily via
/// [`poll_view_status`].
pub(crate) async fn create_view(
    config: &ControlConfig,
    store: &ViewStore,
    exporter: &dyn ViewExporter,
    db: &Db,
    org_id: &str,
    query: TrafficQuery,
) -> Result<ViewJobResult> {
    let view_id = compute_view_id(org_id, &query.branches.0);
    let qid = ch_query_id(view_id);
    let key = s3_key(org_id, view_id);

    // Upsert: insert or reclaim failed rows.
    let row = db
        .upsert_view_job(view_id, org_id, &qid)
        .await
        .context("failed to upsert view job")?;

    // If already completed, just return.
    if row.status == "completed" {
        return Ok(ViewJobResult {
            view_id,
            status: row.status,
            s3_key: row.s3_key,
            error: row.error,
        });
    }

    // If pending (new or reclaimed), fire the export. Bound it before the
    // claim, so a failed lookup leaves the job pending for the next create.
    if row.status == "pending" {
        let mut query = query;
        crate::query::bound_to_sessions(db, &mut query).await?;
        fire_export(config, store, exporter, db, view_id, &query, &qid, &key).await?;
    }

    // For "running" — a previous create already fired; the caller should poll.
    Ok(ViewJobResult {
        view_id,
        status: row.status,
        s3_key: row.s3_key,
        error: row.error,
    })
}

/// Claim the job and submit the export to the capture store; returns
/// immediately. The export continues in the store independently.
#[allow(clippy::too_many_arguments)]
async fn fire_export(
    config: &ControlConfig,
    store: &ViewStore,
    exporter: &dyn ViewExporter,
    db: &Db,
    view_id: Uuid,
    query: &TrafficQuery,
    qid: &str,
    key: &str,
) -> Result<()> {
    // Claim: pending → running. If another task already claimed it, bail.
    let claimed = db
        .claim_view_job(view_id)
        .await
        .context("failed to claim export job")?;

    if !claimed {
        tracing::debug!(%view_id, "export job already claimed, skipping fire");
        return Ok(());
    }

    exporter.submit(config, store, query, qid, key).await?;

    tracing::info!(%view_id, %qid, "export query fired (fire-and-forget)");
    Ok(())
}

/// Poll the current state of a view export job.
///
/// Reconciles Postgres, ClickHouse (`system.processes` / `system.query_log`),
/// and the object store to return an accurate, up-to-date status. External
/// checks are debounced to at most once every [`DEBOUNCE_SECS`].
pub(crate) async fn poll_view_status(
    store: &ViewStore,
    exporter: &dyn ViewExporter,
    db: &Db,
    org_id: &str,
    view_id: Uuid,
) -> Result<Option<ViewPollResult>> {
    let row = db.view_job(view_id, org_id).await?;

    let row = match row {
        Some(r) => r,
        None => return Ok(None),
    };

    // ── completed: verify the object still exists ──────────────────────
    if row.status == "completed" {
        let key = row.s3_key.as_deref().unwrap_or_default();
        if should_check_external(&row.last_checked_at()) {
            touch_last_checked(db, view_id).await;
            if !store.exists(key).await {
                tracing::info!(%view_id, key, "parquet missing from object store, deleting job");
                delete_job(db, view_id).await;
                return Ok(Some(ViewPollResult {
                    view_id,
                    status: "pending".into(),
                    s3_key: None,
                    error: None,
                    read_rows: None,
                    written_rows: None,
                    total_rows: None,
                }));
            }
        }
        return Ok(Some(ViewPollResult {
            view_id,
            status: "completed".into(),
            s3_key: row.s3_key,
            error: None,
            read_rows: row.read_rows,
            written_rows: row.written_rows,
            total_rows: row.total_rows,
        }));
    }

    // ── pending / running: check ClickHouse ─────────────────────────────
    let qid = row.query_id.as_deref().unwrap_or("");

    if qid.is_empty() {
        // Legacy row without query_id — can't track. Reset to pending so
        // the next create_view fires a new export with a query_id.
        delete_job(db, view_id).await;
        return Ok(Some(ViewPollResult {
            view_id,
            status: "pending".into(),
            s3_key: None,
            error: None,
            read_rows: None,
            written_rows: None,
            total_rows: None,
        }));
    }

    if !should_check_external(&row.last_checked_at()) {
        // Return cached progress without hitting ClickHouse.
        return Ok(Some(ViewPollResult {
            view_id,
            status: row.status,
            s3_key: row.s3_key,
            error: row.error,
            read_rows: row.read_rows,
            written_rows: row.written_rows,
            total_rows: row.total_rows,
        }));
    }
    touch_last_checked(db, view_id).await;

    // Check system.processes for in-flight query.
    if let Some(progress) = exporter.progress(qid).await? {
        // Query is running — update cached progress.
        db.set_view_progress(
            view_id,
            progress.read_rows,
            progress.written_rows,
            progress.total_rows,
        )
        .await
        .ok();

        return Ok(Some(ViewPollResult {
            view_id,
            status: "running".into(),
            s3_key: None,
            error: None,
            read_rows: Some(progress.read_rows),
            written_rows: Some(progress.written_rows),
            total_rows: Some(progress.total_rows),
        }));
    }

    // Query not in system.processes — check query_log for outcome.
    let outcome = exporter.outcome(qid).await?;
    let key = s3_key(org_id, view_id);

    match outcome {
        Some(ExportOutcome::Finished) => {
            // Verify the file landed.
            if store.exists(&key).await {
                db.complete_view_job(view_id, &key).await.ok();

                tracing::info!(%view_id, %key, "export completed (discovered via poll)");
                return Ok(Some(ViewPollResult {
                    view_id,
                    status: "completed".into(),
                    s3_key: Some(key),
                    error: None,
                    read_rows: row.read_rows,
                    written_rows: row.written_rows,
                    total_rows: row.total_rows,
                }));
            }
            // Query finished but file missing — something went wrong.
            let msg =
                "export query finished but parquet file not found in object store".to_string();
            tracing::warn!(%view_id, %key, "{}", msg);
            delete_job(db, view_id).await;
            Ok(Some(ViewPollResult {
                view_id,
                status: "failed".into(),
                s3_key: None,
                error: Some(msg),
                read_rows: None,
                written_rows: None,
                total_rows: None,
            }))
        }
        Some(ExportOutcome::Failed(exception)) => {
            tracing::warn!(%view_id, %exception, "export query failed in ClickHouse");
            delete_job(db, view_id).await;
            Ok(Some(ViewPollResult {
                view_id,
                status: "failed".into(),
                s3_key: None,
                error: Some(exception),
                read_rows: None,
                written_rows: None,
                total_rows: None,
            }))
        }
        None => {
            // No log entry — query may not have started, or was lost.
            // Check the object store as a last resort (maybe a previous run succeeded).
            if store.exists(&key).await {
                db.complete_view_job(view_id, &key).await.ok();

                return Ok(Some(ViewPollResult {
                    view_id,
                    status: "completed".into(),
                    s3_key: Some(key),
                    error: None,
                    read_rows: None,
                    written_rows: None,
                    total_rows: None,
                }));
            }
            // Truly lost. Delete so next create_view retries.
            tracing::info!(%view_id, "query not found in CH processes or log, resetting");
            delete_job(db, view_id).await;
            Ok(Some(ViewPollResult {
                view_id,
                status: "pending".into(),
                s3_key: None,
                error: None,
                read_rows: None,
                written_rows: None,
                total_rows: None,
            }))
        }
    }
}

async fn delete_job(db: &Db, view_id: Uuid) {
    db.delete_view_job(view_id).await.ok();
}

async fn touch_last_checked(db: &Db, view_id: Uuid) {
    db.touch_view_job(view_id).await.ok();
}

fn should_check_external(last_checked: &Option<OffsetDateTime>) -> bool {
    match last_checked {
        None => true,
        Some(ts) => {
            let now = OffsetDateTime::now_utc();
            (now - *ts).whole_seconds() >= DEBOUNCE_SECS
        }
    }
}

/// Expired exports removed per reaper pass; the next pass takes the rest.
const EXPIRE_BATCH: i64 = 500;

/// Delete completed exports whose `completed_at` is older than `ttl`.
///
/// The object is deleted before the row. If the object delete fails, the
/// row stays and the next pass retries; deleting the row first would leave
/// an orphaned object nothing points at. Between the two deletes a caller
/// can still be handed a URL to the removed object; it gets a 404 and the
/// next create re-exports.
///
/// Returns the number of exports removed.
pub async fn expire_completed_views(
    store: &ViewStore,
    db: &Db,
    ttl: std::time::Duration,
) -> Result<usize> {
    let cutoff = OffsetDateTime::now_utc() - ttl;
    let rows = db
        .expired_view_jobs(cutoff, EXPIRE_BATCH)
        .await
        .context("failed to select expired traffic views")?;

    let mut expired = 0;
    for (view_id, key) in rows {
        if let Some(key) = key.as_deref()
            && let Err(e) = store.delete(key).await
        {
            tracing::warn!(%view_id, key, error = %e, "traffic view object delete failed; retrying next pass");
            continue;
        }
        // Re-check the expiry condition so a row re-created since the SELECT
        // is not removed.
        db.delete_expired_view_job(view_id, cutoff)
            .await
            .context("failed to delete expired traffic view job")?;
        expired += 1;
    }
    if expired > 0 {
        tracing::info!(expired, "expired traffic view exports");
    }
    Ok(expired)
}
