//! Traffic view export jobs (`traffic_view_jobs`).

use proxyx_db::Ts;
use sqlx::FromRow;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::db::DbResult;

instances!("impls/views.rs");

/// What [`Db::upsert_view_job`] left in the row.
#[derive(Debug, Clone, FromRow)]
pub struct ViewJobUpsert {
    pub status: String,
    pub s3_key: Option<String>,
    pub error: Option<String>,
}

/// One export job, for the status poll.
#[derive(Debug, Clone, FromRow)]
pub struct ViewJobRow {
    pub status: String,
    pub s3_key: Option<String>,
    pub error: Option<String>,
    pub query_id: Option<String>,
    pub read_rows: Option<i64>,
    pub written_rows: Option<i64>,
    pub total_rows: Option<i64>,
    last_checked_at: Option<Ts>,
}

impl ViewJobRow {
    /// When the capture store and the object store were last asked.
    pub fn last_checked_at(&self) -> Option<OffsetDateTime> {
        self.last_checked_at.map(|t| t.0)
    }
}

delegate! {
    /// Create the job of `view_id`, or reclaim a failed one (it becomes
    /// `pending` again). Any other state is left as it is.
    pub async fn upsert_view_job(&self, view_id: Uuid, org_id: &str, query_id: &str) -> DbResult<ViewJobUpsert>;

    /// Move a `pending` job to `running`. Whether this call did it (false:
    /// another task claimed it first).
    pub async fn claim_view_job(&self, view_id: Uuid) -> DbResult<bool>;

    /// The job of `view_id` of `org_id`.
    pub async fn view_job(&self, view_id: Uuid, org_id: &str) -> DbResult<Option<ViewJobRow>>;

    /// Record the progress of a running export.
    pub async fn set_view_progress(
        &self,
        view_id: Uuid,
        read_rows: i64,
        written_rows: i64,
        total_rows: i64,
    ) -> DbResult<()>;

    /// Mark the export `completed`, with the object key.
    pub async fn complete_view_job(&self, view_id: Uuid, s3_key: &str) -> DbResult<()>;

    /// Delete the job, so the next create starts it again.
    pub async fn delete_view_job(&self, view_id: Uuid) -> DbResult<()>;

    /// Note that the external stores were just asked.
    pub async fn touch_view_job(&self, view_id: Uuid) -> DbResult<()>;

    /// Up to `limit` completed jobs completed before `cutoff`, oldest first.
    pub async fn expired_view_jobs(&self, cutoff: OffsetDateTime, limit: i64) -> DbResult<Vec<(Uuid, Option<String>)>>;

    /// Delete a completed job that is still completed before `cutoff`.
    pub async fn delete_expired_view_job(&self, view_id: Uuid, cutoff: OffsetDateTime) -> DbResult<()>;
}
