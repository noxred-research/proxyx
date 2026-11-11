//! Session lifecycle rows: the source of truth of which session is active.

use sqlx::FromRow;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::db::DbResult;
use proxyx_db::Ts;

instances!("impls/sessions.rs");

/// What [`Db::insert_session`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionInsert {
    /// The row was created.
    Inserted,
    /// Another active session holds the `(org, source, source_id)` slot.
    AlreadyActive,
}

/// A session a reaper pass took over: id, org, source, source id.
pub type SessionClaim = (Uuid, String, String, Option<String>);

/// The lifecycle of one session, for `GET /sessions/{id}/status`.
#[derive(FromRow)]
pub struct SessionStatusRow {
    pub state: String,
    opened_at: Ts,
    closing_at: Option<Ts>,
    closed_at: Option<Ts>,
    pub org_id: String,
}

impl SessionStatusRow {
    pub fn opened_at(&self) -> OffsetDateTime {
        self.opened_at.0
    }

    pub fn closing_at(&self) -> Option<OffsetDateTime> {
        self.closing_at.map(|t| t.0)
    }

    pub fn closed_at(&self) -> Option<OffsetDateTime> {
        self.closed_at.map(|t| t.0)
    }
}

/// The span the sessions of one source id were open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceWindow {
    /// The earliest `opened_at`.
    pub start: OffsetDateTime,
    /// The latest `closed_at`, when every session of the source is closed.
    pub end: Option<OffsetDateTime>,
}

delegate! {
    /// Create the lifecycle row of a new active session. The slot of
    /// `(org, source, source_id)` is unique among active rows, so a concurrent
    /// create that lost the race gets [`SessionInsert::AlreadyActive`].
    pub async fn insert_session(
        &self,
        session_id: Uuid,
        org_id: &str,
        source: &str,
        source_id: &str,
        expires_at: OffsetDateTime,
    ) -> DbResult<SessionInsert>;

    /// The active session of `(org, source, source_id)`, if any.
    pub async fn active_session(
        &self,
        org_id: &str,
        source: &str,
        source_id: &str,
    ) -> DbResult<Option<Uuid>>;

    /// The state of a session (`active`, `consuming`, `closed`); `None` for
    /// an unknown session.
    pub async fn session_state(&self, session_id: Uuid) -> DbResult<Option<String>>;

    /// The lifecycle of a session.
    pub async fn session_status(&self, session_id: Uuid) -> DbResult<Option<SessionStatusRow>>;

    /// Whether any session of `(org, source_id)` is closed, meaning the
    /// consumer has drained its captures.
    pub async fn source_has_closed_session(&self, org_id: &str, source_id: &str) -> DbResult<bool>;

    /// Move an active session to `consuming` at once, dropping its references:
    /// its Redis key is gone, so it must not hold the active slot.
    pub async fn abandon_active_session(&self, session_id: Uuid) -> DbResult<()>;

    /// Add one reference to an active session and move its expiry out to
    /// `expires_at` when that is later. Returns the effective expiry in
    /// milliseconds since the epoch, or `None` when the session is not active.
    pub async fn attach_session(
        &self,
        session_id: Uuid,
        expires_at: OffsetDateTime,
    ) -> DbResult<Option<i64>>;

    /// Drop one reference of an active session; the last one moves it to
    /// `consuming`. Returns the references left, or `None` when the session
    /// is not active.
    pub async fn release_session(&self, session_id: Uuid) -> DbResult<Option<i32>>;

    /// Set the expiry of a session.
    pub async fn set_session_expiry(&self, session_id: Uuid, expires_at: OffsetDateTime) -> DbResult<()>;

    /// Mark a session `closed`, once the captures read before its end are stored.
    pub async fn close_session(&self, session_id: Uuid) -> DbResult<()>;

    /// Take over up to `limit` active sessions that expired before `cutoff`:
    /// they become `consuming`, oldest first. Replicas never take the same row
    /// (PostgreSQL and MariaDB `SKIP LOCKED`; SQLite has one writer).
    pub async fn claim_expired_sessions(&self, cutoff: OffsetDateTime, limit: i64) -> DbResult<Vec<SessionClaim>>;

    /// Take over up to `limit` sessions stuck in `consuming` since before
    /// `cutoff`, giving each a new lease (`closing_at` becomes now).
    pub async fn claim_stuck_sessions(&self, cutoff: OffsetDateTime, limit: i64) -> DbResult<Vec<SessionClaim>>;

    /// The open span of each of `source_ids` that has a session row.
    pub async fn source_windows(&self, source_ids: &[&str]) -> DbResult<Vec<(String, SourceWindow)>>;
}
