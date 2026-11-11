// Session lifecycle: the queries of one backend. See `db/sessions.rs`.

use proxyx_db::Ts;
use sqlx::types::Json;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{SessionClaim, SessionInsert, SessionStatusRow, SourceWindow};
use crate::db::DbResult;

pub(crate) async fn insert_session(
    pool: &d::Pool,
    session_id: Uuid,
    org_id: &str,
    source: &str,
    source_id: &str,
    expires_at: OffsetDateTime,
) -> DbResult<SessionInsert> {
    let inserted = sqlx::query(d::sql!(
        "INSERT INTO session_lifecycle (session_id, org_id, source, source_id, state, expires_at)
         VALUES (?, ?, ?, ?, 'active', ?)"
    ))
    .bind(session_id)
    .bind(org_id)
    .bind(source)
    .bind(source_id)
    .bind(Ts(expires_at))
    .execute(pool)
    .await;
    match inserted {
        Ok(_) => Ok(SessionInsert::Inserted),
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => Ok(SessionInsert::AlreadyActive),
        Err(e) => Err(e),
    }
}

pub(crate) async fn active_session(
    pool: &d::Pool,
    org_id: &str,
    source: &str,
    source_id: &str,
) -> DbResult<Option<Uuid>> {
    sqlx::query_scalar(d::sql!(
        "SELECT session_id FROM session_lifecycle
         WHERE org_id = ? AND source = ? AND source_id = ? AND state = 'active'"
    ))
    .bind(org_id)
    .bind(source)
    .bind(source_id)
    .fetch_optional(pool)
    .await
}

pub(crate) async fn session_state(pool: &d::Pool, session_id: Uuid) -> DbResult<Option<String>> {
    sqlx::query_scalar(d::sql!(
        "SELECT state FROM session_lifecycle WHERE session_id = ?"
    ))
    .bind(session_id)
    .fetch_optional(pool)
    .await
}

pub(crate) async fn session_status(
    pool: &d::Pool,
    session_id: Uuid,
) -> DbResult<Option<SessionStatusRow>> {
    sqlx::query_as(d::sql!(
        "SELECT state, opened_at, closing_at, closed_at, org_id
         FROM session_lifecycle WHERE session_id = ?"
    ))
    .bind(session_id)
    .fetch_optional(pool)
    .await
}

pub(crate) async fn source_has_closed_session(
    pool: &d::Pool,
    org_id: &str,
    source_id: &str,
) -> DbResult<bool> {
    let n: i64 = sqlx::query_scalar(d::sql!(
        "SELECT count(*) FROM (
             SELECT 1 FROM session_lifecycle
             WHERE org_id = ? AND source_id = ? AND state = 'closed' LIMIT 1) closed"
    ))
    .bind(org_id)
    .bind(source_id)
    .fetch_one(pool)
    .await?;
    Ok(n > 0)
}

pub(crate) async fn abandon_active_session(pool: &d::Pool, session_id: Uuid) -> DbResult<()> {
    sqlx::query(d::sql!(concat!(
        "UPDATE session_lifecycle SET state = 'consuming', closing_at = ",
        d::now!(),
        ", ref_count = 0 WHERE session_id = ? AND state = 'active'"
    )))
    .bind(session_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// The reference count and expiry of an active session, locked for the
/// transaction.
async fn lock_active(
    conn: &mut d::Conn,
    session_id: Uuid,
) -> DbResult<Option<(i32, Ts)>> {
    sqlx::query_as(d::sql!(concat!(
        "SELECT ref_count, expires_at FROM session_lifecycle
         WHERE session_id = ? AND state = 'active'",
        d::for_update!()
    )))
    .bind(session_id)
    .fetch_optional(conn)
    .await
}

pub(crate) async fn attach_session(
    pool: &d::Pool,
    session_id: Uuid,
    expires_at: OffsetDateTime,
) -> DbResult<Option<i64>> {
    let mut tx = d::begin_write(pool).await?;
    let Some((ref_count, current)) = lock_active(&mut tx, session_id).await? else {
        return Ok(None);
    };
    let effective = current.max(Ts(expires_at));
    sqlx::query(d::sql!(
        "UPDATE session_lifecycle SET ref_count = ?, expires_at = ? WHERE session_id = ?"
    ))
    .bind(ref_count + 1)
    .bind(effective)
    .bind(session_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Some(effective.unix_micros().div_euclid(1_000_000) * 1000))
}

pub(crate) async fn release_session(pool: &d::Pool, session_id: Uuid) -> DbResult<Option<i32>> {
    let mut tx = d::begin_write(pool).await?;
    let Some((ref_count, _)) = lock_active(&mut tx, session_id).await? else {
        return Ok(None);
    };
    let left = (ref_count - 1).max(0);
    if ref_count <= 1 {
        sqlx::query(d::sql!(concat!(
            "UPDATE session_lifecycle SET ref_count = ?, state = 'consuming', closing_at = ",
            d::now!(),
            " WHERE session_id = ?"
        )))
        .bind(left)
        .bind(session_id)
        .execute(&mut *tx)
        .await?;
    } else {
        sqlx::query(d::sql!(
            "UPDATE session_lifecycle SET ref_count = ? WHERE session_id = ?"
        ))
        .bind(left)
        .bind(session_id)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(Some(left))
}

pub(crate) async fn set_session_expiry(
    pool: &d::Pool,
    session_id: Uuid,
    expires_at: OffsetDateTime,
) -> DbResult<()> {
    sqlx::query(d::sql!(
        "UPDATE session_lifecycle SET expires_at = ? WHERE session_id = ?"
    ))
    .bind(Ts(expires_at))
    .bind(session_id)
    .execute(pool)
    .await?;
    Ok(())
}

pub(crate) async fn close_session(pool: &d::Pool, session_id: Uuid) -> DbResult<()> {
    sqlx::query(d::sql!(concat!(
        "UPDATE session_lifecycle SET state = 'closed', closed_at = ",
        d::now!(),
        " WHERE session_id = ? AND state <> 'closed'"
    )))
    .bind(session_id)
    .execute(pool)
    .await?;
    Ok(())
}

pub(crate) async fn claim_expired_sessions(
    pool: &d::Pool,
    cutoff: OffsetDateTime,
    limit: i64,
) -> DbResult<Vec<SessionClaim>> {
    let mut tx = d::begin_write(pool).await?;
    let rows: Vec<SessionClaim> = sqlx::query_as(d::sql!(concat!(
        "SELECT session_id, org_id, source, source_id FROM session_lifecycle
         WHERE state = 'active' AND expires_at < ? ORDER BY expires_at ASC LIMIT ?",
        d::for_update_skip_locked!()
    )))
    .bind(Ts(cutoff))
    .bind(limit)
    .fetch_all(&mut *tx)
    .await?;
    for (session_id, ..) in &rows {
        sqlx::query(d::sql!(concat!(
            "UPDATE session_lifecycle SET state = 'consuming', closing_at = ",
            d::now!(),
            " WHERE session_id = ?"
        )))
        .bind(session_id)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(rows)
}

pub(crate) async fn claim_stuck_sessions(
    pool: &d::Pool,
    cutoff: OffsetDateTime,
    limit: i64,
) -> DbResult<Vec<SessionClaim>> {
    let mut tx = d::begin_write(pool).await?;
    let rows: Vec<SessionClaim> = sqlx::query_as(d::sql!(concat!(
        "SELECT session_id, org_id, source, source_id FROM session_lifecycle
         WHERE state = 'consuming' AND closing_at < ? ORDER BY closing_at ASC LIMIT ?",
        d::for_update_skip_locked!()
    )))
    .bind(Ts(cutoff))
    .bind(limit)
    .fetch_all(&mut *tx)
    .await?;
    for (session_id, ..) in &rows {
        sqlx::query(d::sql!(concat!(
            "UPDATE session_lifecycle SET closing_at = ",
            d::now!(),
            " WHERE session_id = ?"
        )))
        .bind(session_id)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(rows)
}

pub(crate) async fn source_windows(
    pool: &d::Pool,
    source_ids: &[&str],
) -> DbResult<Vec<(String, SourceWindow)>> {
    let rows: Vec<(String, Ts, Option<Ts>)> = sqlx::query_as(d::sql!(concat!(
        "SELECT source_id, min(opened_at),
                CASE WHEN min(CASE WHEN state = 'closed' THEN 1 ELSE 0 END) = 1
                     THEN max(closed_at) END
         FROM session_lifecycle
         WHERE source_id IN ",
        d::in_json_array!(),
        " GROUP BY source_id"
    )))
    .bind(Json(source_ids))
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, start, end)| {
            (
                id,
                SourceWindow {
                    start: start.0,
                    end: end.map(|t| t.0),
                },
            )
        })
        .collect())
}
