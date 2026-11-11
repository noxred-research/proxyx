// Traffic view jobs: the queries of one backend. See `db/views.rs`.

use proxyx_db::Ts;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{ViewJobRow, ViewJobUpsert};
use crate::db::DbResult;

pub(crate) async fn upsert_view_job(
    pool: &d::Pool,
    view_id: Uuid,
    org_id: &str,
    query_id: &str,
) -> DbResult<ViewJobUpsert> {
    let mut tx = d::begin_write(pool).await?;
    sqlx::query(d::sql!(d::view_job_upsert!()))
        .bind(view_id)
        .bind(org_id)
        .bind(query_id)
        .execute(&mut *tx)
        .await?;
    let row = sqlx::query_as(d::sql!(
        "SELECT status, s3_key, error, query_id FROM traffic_view_jobs WHERE view_id = ?"
    ))
    .bind(view_id)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row)
}

pub(crate) async fn claim_view_job(pool: &d::Pool, view_id: Uuid) -> DbResult<bool> {
    let claimed = sqlx::query(d::sql!(concat!(
        "UPDATE traffic_view_jobs SET status = 'running', updated_at = ",
        d::now!(),
        " WHERE view_id = ? AND status = 'pending'"
    )))
    .bind(view_id)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(claimed > 0)
}

pub(crate) async fn view_job(
    pool: &d::Pool,
    view_id: Uuid,
    org_id: &str,
) -> DbResult<Option<ViewJobRow>> {
    sqlx::query_as(d::sql!(
        "SELECT status, s3_key, error, query_id, read_rows, written_rows, total_rows,
                last_checked_at
         FROM traffic_view_jobs WHERE view_id = ? AND org_id = ?"
    ))
    .bind(view_id)
    .bind(org_id)
    .fetch_optional(pool)
    .await
}

pub(crate) async fn set_view_progress(
    pool: &d::Pool,
    view_id: Uuid,
    read_rows: i64,
    written_rows: i64,
    total_rows: i64,
) -> DbResult<()> {
    sqlx::query(d::sql!(concat!(
        "UPDATE traffic_view_jobs SET status = 'running', read_rows = ?, written_rows = ?,
             total_rows = ?, updated_at = ",
        d::now!(),
        " WHERE view_id = ?"
    )))
    .bind(read_rows)
    .bind(written_rows)
    .bind(total_rows)
    .bind(view_id)
    .execute(pool)
    .await?;
    Ok(())
}

pub(crate) async fn complete_view_job(pool: &d::Pool, view_id: Uuid, s3_key: &str) -> DbResult<()> {
    sqlx::query(d::sql!(concat!(
        "UPDATE traffic_view_jobs SET status = 'completed', s3_key = ?, error = NULL,
             completed_at = ",
        d::now!(),
        ", updated_at = ",
        d::now!(),
        " WHERE view_id = ?"
    )))
    .bind(s3_key)
    .bind(view_id)
    .execute(pool)
    .await?;
    Ok(())
}

pub(crate) async fn fail_view_job(
    pool: &d::Pool,
    view_id: Uuid,
    query_id: &str,
    error: &str,
) -> DbResult<bool> {
    let failed = sqlx::query(d::sql!(concat!(
        "UPDATE traffic_view_jobs SET status = 'failed', error = ?, updated_at = ",
        d::now!(),
        " WHERE view_id = ? AND query_id = ? AND status IN ('pending', 'running')"
    )))
    .bind(error)
    .bind(view_id)
    .bind(query_id)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(failed > 0)
}

pub(crate) async fn delete_view_job(pool: &d::Pool, view_id: Uuid) -> DbResult<()> {
    sqlx::query(d::sql!("DELETE FROM traffic_view_jobs WHERE view_id = ?"))
        .bind(view_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub(crate) async fn touch_view_job(pool: &d::Pool, view_id: Uuid) -> DbResult<()> {
    sqlx::query(d::sql!(concat!(
        "UPDATE traffic_view_jobs SET last_checked_at = ",
        d::now!(),
        " WHERE view_id = ?"
    )))
    .bind(view_id)
    .execute(pool)
    .await?;
    Ok(())
}

pub(crate) async fn expired_view_jobs(
    pool: &d::Pool,
    cutoff: OffsetDateTime,
    limit: i64,
) -> DbResult<Vec<(Uuid, Option<String>)>> {
    sqlx::query_as(d::sql!(
        "SELECT view_id, s3_key FROM traffic_view_jobs
         WHERE status = 'completed' AND completed_at < ?
         ORDER BY completed_at LIMIT ?"
    ))
    .bind(Ts(cutoff))
    .bind(limit)
    .fetch_all(pool)
    .await
}

pub(crate) async fn delete_expired_view_job(
    pool: &d::Pool,
    view_id: Uuid,
    cutoff: OffsetDateTime,
) -> DbResult<()> {
    sqlx::query(d::sql!(
        "DELETE FROM traffic_view_jobs
         WHERE view_id = ? AND status = 'completed' AND completed_at < ?"
    ))
    .bind(view_id)
    .bind(Ts(cutoff))
    .execute(pool)
    .await?;
    Ok(())
}
