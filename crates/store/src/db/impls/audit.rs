// Audit rows: the queries of one backend. See `db/audit.rs`.

use serde_json::Value;
use sqlx::types::Json;

use crate::db::audit::{
    AUDIT_KEEP_DAYS, AuditRow, BLOCKS_KEEP_DAYS, PRUNE_CHUNK, Pruned, RawAudit, SCORES_KEEP_DAYS,
    audit_columns,
};
use crate::error::Result;

/// Add one audit row inside the caller's transaction.
pub(crate) async fn append_audit(
    conn: &mut d::Conn,
    actor: &str,
    action: &str,
    subject: &str,
    detail: Value,
) -> Result<()> {
    sqlx::query(d::sql!(
        "INSERT INTO audit (actor, action, subject, detail) VALUES (?, ?, ?, ?)"
    ))
    .bind(actor)
    .bind(action)
    .bind(subject)
    .bind(Json(detail))
    .execute(conn)
    .await?;
    Ok(())
}

pub(crate) async fn audit(
    pool: &d::Pool,
    actor: &str,
    action: &str,
    subject: &str,
    detail: Value,
) -> Result<()> {
    let mut conn = pool.acquire().await?;
    append_audit(&mut conn, actor, action, subject, detail).await
}

pub(crate) async fn audit_for(pool: &d::Pool, subject: &str, limit: i64) -> Result<Vec<AuditRow>> {
    let rows: Vec<RawAudit> = sqlx::query_as(d::sql!(concat!(
        "SELECT ",
        audit_columns!(),
        " FROM audit WHERE subject = ? ORDER BY id DESC LIMIT ?"
    )))
    .bind(subject)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(AuditRow::from).collect())
}

pub(crate) async fn last_transition(pool: &d::Pool, ip: &str) -> Result<Option<AuditRow>> {
    let row: Option<RawAudit> = sqlx::query_as(d::sql!(concat!(
        "SELECT ",
        audit_columns!(),
        " FROM audit WHERE subject = ? AND action = 'inventory.transition'
         ORDER BY id DESC LIMIT 1"
    )))
    .bind(ip)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(AuditRow::from))
}

/// Delete the rows of `$table` that match `$cond` (one `?`: an age in
/// seconds), a chunk at a time: the first prune of a long-lived table must
/// stay inside the statement timeout. The inner query names the first
/// `PRUNE_CHUNK` rows by id; the outer one deletes the matching rows up to
/// the last of them, which are exactly those.
macro_rules! delete_old {
    ($pool:expr, $table:literal, $cond:expr, $days:expr) => {{
        let sql = d::sql!(concat!(
            "DELETE FROM ",
            $table,
            " WHERE ",
            $cond,
            " AND id <= (SELECT max(id) FROM (SELECT id FROM ",
            $table,
            " WHERE ",
            $cond,
            " ORDER BY id LIMIT ?) chunk)"
        ));
        let age = f64::from($days) * 86_400.0;
        let mut total = 0_u64;
        loop {
            let n = sqlx::query(sql)
                .bind(age)
                .bind(age)
                .bind(PRUNE_CHUNK)
                .execute($pool)
                .await?
                .rows_affected();
            total += n;
            if n < PRUNE_CHUNK.unsigned_abs() {
                break total;
            }
        }
    }};
}

pub(crate) async fn prune_history(pool: &d::Pool) -> Result<Pruned> {
    let scores = delete_old!(
        pool,
        "ip_scores",
        concat!("checked_at < ", d::now_minus_secs!()),
        SCORES_KEEP_DAYS
    );
    let blocks = delete_old!(
        pool,
        "ip_blocks",
        concat!(
            "created_at < ",
            d::now_minus_secs!(),
            " AND (expires_at IS NULL OR expires_at < ",
            d::now!(),
            ")"
        ),
        BLOCKS_KEEP_DAYS
    );
    let audit = delete_old!(
        pool,
        "audit",
        concat!(
            "at < ",
            d::now_minus_secs!(),
            " AND action IN ('inventory.transition', 'ip.rotate_requested',
                              'inventory.replacement_report')"
        ),
        AUDIT_KEEP_DAYS
    );
    Ok(Pruned {
        scores,
        blocks,
        audit,
    })
}
