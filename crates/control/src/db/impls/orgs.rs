// Orgs: the queries of one backend. See `db/orgs.rs`.

use super::{OrgSettingsRow, OrgSettingsWrite, ProxyColumns};
use crate::db::DbResult;
use crate::session::OrgRow;

pub(crate) async fn org(pool: &d::Pool, id: &str) -> DbResult<Option<OrgRow>> {
    sqlx::query_as(d::sql!(
        "SELECT id, rate_limit_rpm, rate_limit_burst, proxy_type, proxy_address, proxy_username,
                proxy_password
         FROM orgs WHERE id = ?"
    ))
    .bind(id)
    .fetch_optional(pool)
    .await
}

pub(crate) async fn create_org(
    pool: &d::Pool,
    id: &str,
    rpm: Option<i32>,
    burst: Option<i32>,
) -> DbResult<()> {
    sqlx::query(d::sql!(
        "INSERT INTO orgs (id, rate_limit_rpm, rate_limit_burst) VALUES (?, ?, ?)"
    ))
    .bind(id)
    .bind(rpm)
    .bind(burst)
    .execute(pool)
    .await?;
    Ok(())
}

pub(crate) async fn delete_org(pool: &d::Pool, id: &str) -> DbResult<u64> {
    Ok(sqlx::query(d::sql!("DELETE FROM orgs WHERE id = ?"))
        .bind(id)
        .execute(pool)
        .await?
        .rows_affected())
}

pub(crate) async fn org_rate_limit(
    pool: &d::Pool,
    id: &str,
) -> DbResult<Option<(Option<i32>, Option<i32>)>> {
    sqlx::query_as(d::sql!(
        "SELECT rate_limit_rpm, rate_limit_burst FROM orgs WHERE id = ?"
    ))
    .bind(id)
    .fetch_optional(pool)
    .await
}

pub(crate) async fn set_org_rate_limit(
    pool: &d::Pool,
    id: &str,
    rpm: Option<i32>,
    burst: Option<i32>,
) -> DbResult<()> {
    sqlx::query(d::sql!(d::org_rate_limit_upsert!()))
        .bind(id)
        .bind(rpm)
        .bind(burst)
        .execute(pool)
        .await?;
    Ok(())
}

pub(crate) async fn org_proxy(pool: &d::Pool, id: &str) -> DbResult<Option<ProxyColumns>> {
    sqlx::query_as(d::sql!(
        "SELECT proxy_type, proxy_address, proxy_username, proxy_password FROM orgs WHERE id = ?"
    ))
    .bind(id)
    .fetch_optional(pool)
    .await
}

pub(crate) async fn set_org_proxy(
    pool: &d::Pool,
    id: &str,
    proxy_type: &str,
    address: &str,
    username: Option<&str>,
    password: Option<&str>,
) -> DbResult<()> {
    sqlx::query(d::sql!(d::org_proxy_upsert!()))
        .bind(id)
        .bind(proxy_type)
        .bind(address)
        .bind(username)
        .bind(password)
        .execute(pool)
        .await?;
    Ok(())
}

pub(crate) async fn clear_org_proxy(pool: &d::Pool, id: &str) -> DbResult<u64> {
    Ok(sqlx::query(d::sql!(concat!(
        "UPDATE orgs SET proxy_type = NULL, proxy_address = NULL, proxy_username = NULL,
             proxy_password = NULL, updated_at = ",
        d::now!(),
        " WHERE id = ?"
    )))
    .bind(id)
    .execute(pool)
    .await?
    .rows_affected())
}

pub(crate) async fn org_settings(pool: &d::Pool, id: &str) -> DbResult<Option<OrgSettingsRow>> {
    sqlx::query_as(d::sql!(
        "SELECT rate_limit_rpm, rate_limit_burst, proxy_type, proxy_address FROM orgs WHERE id = ?"
    ))
    .bind(id)
    .fetch_optional(pool)
    .await
}

pub(crate) async fn set_org_settings(pool: &d::Pool, settings: &OrgSettingsWrite<'_>) -> DbResult<()> {
    sqlx::query(d::sql!(d::org_settings_upsert!()))
        .bind(settings.id)
        .bind(settings.rpm)
        .bind(settings.burst)
        .bind(settings.proxy_type)
        .bind(settings.proxy_address)
        .bind(settings.proxy_username)
        .bind(settings.proxy_password)
        .execute(pool)
        .await?;
    Ok(())
}
