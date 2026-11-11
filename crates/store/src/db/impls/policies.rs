// Policies: the queries of one backend. See `db/policies.rs`.

use std::collections::HashMap;

use policy::PolicyDoc;
use serde_json::{Value, json};
use sqlx::types::Json;

use crate::db::policies::{
    MAX_POLICY_VERSIONS, PolicyPut, PolicyRecord, RawPolicy, canonical_policy_doc, policy_columns,
};
use crate::error::Result;

pub(crate) async fn current_policies_in(conn: &mut d::Conn) -> Result<Vec<PolicyRecord>> {
    let rows: Vec<RawPolicy> = sqlx::query_as(concat!(
        "SELECT ",
        policy_columns!(),
        " FROM policies WHERE current ORDER BY scope, name"
    ))
    .fetch_all(conn)
    .await?;
    Ok(rows.into_iter().map(PolicyRecord::from).collect())
}

/// `(scope, name, version)` of every current policy, in the order of
/// [`current_policies_in`]. The version of one policy only goes up, so the
/// same list means the same documents.
pub(crate) async fn current_policy_versions_in(
    conn: &mut d::Conn,
) -> Result<Vec<(String, String, i32)>> {
    Ok(sqlx::query_as(
        "SELECT scope, name, version FROM policies WHERE current ORDER BY scope, name",
    )
    .fetch_all(conn)
    .await?)
}

pub(crate) async fn put_policies(
    pool: &d::Pool,
    docs: &[PolicyDoc],
    actor: &str,
) -> Result<PolicyPut> {
    let mut out = PolicyPut::default();
    let mut tx = d::begin_write(pool).await?;
    d::lock_table(&mut tx, "policies").await?;
    for doc in docs {
        let scope = doc.scope.to_string();
        let value = canonical_policy_doc(doc)?;
        let current: Option<(i32, Json<Value>, String)> = sqlx::query_as(d::sql!(
            "SELECT version, doc, actor FROM policies
             WHERE scope = ? AND name = ? AND current"
        ))
        .bind(&scope)
        .bind(&doc.name)
        .fetch_optional(&mut *tx)
        .await?;
        // A document equal to the current one changes nothing, except
        // that git's own copy of what an operator wrote becomes git's
        // version: `latest_policy_docs_by(gitops)` must name what
        // git last applied, or a later unrelated git change would read
        // the operator's next edit as git's and replace it.
        if current.as_ref().is_some_and(|(_, old, by)| {
            old.0 == value && (by == actor || actor != crate::loaded::GITOPS_ACTOR)
        }) {
            out.unchanged += 1;
            continue;
        }
        let latest: Option<i32> = sqlx::query_scalar(d::sql!(
            "SELECT max(version) FROM policies WHERE scope = ? AND name = ?"
        ))
        .bind(&scope)
        .bind(&doc.name)
        .fetch_one(&mut *tx)
        .await?;
        let version = latest.unwrap_or(0) + 1;
        sqlx::query(d::sql!(
            "UPDATE policies SET current = FALSE WHERE scope = ? AND name = ? AND current"
        ))
        .bind(&scope)
        .bind(&doc.name)
        .execute(&mut *tx)
        .await?;
        sqlx::query(d::sql!(
            "INSERT INTO policies (scope, name, target, version, doc, actor)
             VALUES (?, ?, ?, ?, ?, ?)"
        ))
        .bind(&scope)
        .bind(&doc.name)
        .bind(&doc.target)
        .bind(version)
        .bind(Json(&value))
        .bind(actor)
        .execute(&mut *tx)
        .await?;
        // The newest versions stay for audit and rollback; a policy that
        // is written in a loop must not grow the table without end.
        sqlx::query(d::sql!(
            "DELETE FROM policies WHERE scope = ? AND name = ? AND version <= ?"
        ))
        .bind(&scope)
        .bind(&doc.name)
        .bind(version - MAX_POLICY_VERSIONS)
        .execute(&mut *tx)
        .await?;
        let subject = format!("{scope}/{}", doc.name);
        d::append_audit(
            &mut tx,
            actor,
            "policy.put",
            &subject,
            // A change of hand shows who was replaced: an operator's API
            // change that git overwrites must not vanish silently.
            match current.as_ref().filter(|(_, _, by)| by != actor) {
                Some((old_version, _, by)) => json!({
                    "version": version,
                    "replaced": { "actor": by, "version": old_version },
                }),
                None => json!({ "version": version }),
            },
        )
        .await?;
        out.stored.push(subject);
    }
    tx.commit().await?;
    Ok(out)
}

pub(crate) async fn current_policy_versions(pool: &d::Pool) -> Result<Vec<(String, String, i32)>> {
    let mut conn = pool.acquire().await?;
    current_policy_versions_in(&mut conn).await
}

pub(crate) async fn latest_policy_docs_by(
    pool: &d::Pool,
    actor: &str,
) -> Result<HashMap<(String, String), Value>> {
    let rows: Vec<(String, String, Json<Value>)> = sqlx::query_as(d::sql!(
        "SELECT scope, name, doc FROM (
             SELECT scope, name, doc, row_number() OVER (
                 PARTITION BY scope, name ORDER BY version DESC) AS n
             FROM policies WHERE actor = ?
         ) latest WHERE n = 1 ORDER BY scope, name"
    ))
    .bind(actor)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(scope, name, doc)| ((scope, name), doc.0))
        .collect())
}

pub(crate) async fn deactivate_policy(
    pool: &d::Pool,
    scope: &str,
    name: &str,
    actor: &str,
) -> Result<bool> {
    let mut tx = d::begin_write(pool).await?;
    d::lock_table(&mut tx, "policies").await?;
    let n = sqlx::query(d::sql!(
        "UPDATE policies SET current = FALSE WHERE scope = ? AND name = ? AND current"
    ))
    .bind(scope)
    .bind(name)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if n > 0 {
        d::append_audit(
            &mut tx,
            actor,
            "policy.deactivate",
            &format!("{scope}/{name}"),
            json!({}),
        )
        .await?;
    }
    tx.commit().await?;
    Ok(n > 0)
}

pub(crate) async fn current_policies(pool: &d::Pool) -> Result<Vec<PolicyRecord>> {
    let mut conn = pool.acquire().await?;
    current_policies_in(&mut conn).await
}

pub(crate) async fn policy_versions(
    pool: &d::Pool,
    scope: &str,
    name: &str,
) -> Result<Vec<PolicyRecord>> {
    let rows: Vec<RawPolicy> = sqlx::query_as(d::sql!(concat!(
        "SELECT ",
        policy_columns!(),
        " FROM policies WHERE scope = ? AND name = ? ORDER BY version DESC"
    )))
    .bind(scope)
    .bind(name)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(PolicyRecord::from).collect())
}
