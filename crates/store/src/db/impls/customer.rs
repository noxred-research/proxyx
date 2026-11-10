// Customer upstreams: the queries of one backend. See `db/customer.rs`.

use std::collections::HashMap;
use std::net::IpAddr;

use common::types::{InventoryEntry, IpState, Kind, OrgId};
use serde_json::json;
use sqlx::types::Json;

use crate::db::customer::{CustomerLogin, CustomerSet, CustomerUnit, RawVersioned};
use crate::db::inventory::{InventoryRow, RawRow, inventory_columns};
use crate::db::{enum_text, to_json};
use crate::error::{Result, StoreError};

/// Every customer login, by org.
pub(crate) async fn customer_logins_in(
    conn: &mut d::Conn,
) -> Result<HashMap<OrgId, CustomerLogin>> {
    let rows: Vec<(String, String, String)> =
        sqlx::query_as("SELECT org, username, password FROM customer_credentials")
            .fetch_all(conn)
            .await?;
    rows.into_iter()
        .map(|(org, username, password)| {
            let org = OrgId::try_from(org).map_err(|e| StoreError::decode("org id", e))?;
            Ok((org, CustomerLogin::new(username, password)))
        })
        .collect()
}

/// The org's live unit, locked. With `expected`, a unit of another version is
/// [`StoreError::Stale`]: a change committed since the caller read it.
async fn live_unit_in(
    conn: &mut d::Conn,
    org: &OrgId,
    expected: Option<i64>,
) -> Result<Option<CustomerUnit>> {
    let raw: Option<RawVersioned> = sqlx::query_as(d::sql!(concat!(
        "SELECT ",
        inventory_columns!(),
        ", upstream_version FROM inventory WHERE ",
        d::live_unit!(),
        d::for_update!()
    )))
    .bind(org.as_str())
    .fetch_optional(conn)
    .await?;
    let unit = raw.map(CustomerUnit::try_from).transpose()?;
    match (&unit, expected) {
        (Some(u), Some(version)) if u.version != version => Err(StoreError::Stale {
            what: "customer upstream",
        }),
        _ => Ok(unit),
    }
}

async fn retire_in(conn: &mut d::Conn, ip: IpAddr) -> Result<()> {
    d::bump_version(conn).await?;
    sqlx::query(d::sql!(concat!(
        "UPDATE inventory SET state = 'retired', state_since = ",
        d::now!(),
        ", cooldown_until = NULL,
             quarantined_at = NULL, retest_at = NULL, offline_since = NULL, updated_at = ",
        d::now!(),
        ", upstream_version = ",
        d::next_version!(),
        " WHERE ip = ?"
    )))
    .bind(ip.to_string())
    .execute(conn)
    .await?;
    Ok(())
}

async fn bump_version_in(conn: &mut d::Conn, ip: IpAddr) -> Result<()> {
    d::bump_version(conn).await?;
    sqlx::query(d::sql!(concat!(
        "UPDATE inventory SET upstream_version = ",
        d::next_version!(),
        " WHERE ip = ?"
    )))
    .bind(ip.to_string())
    .execute(conn)
    .await?;
    Ok(())
}

async fn store_login_in(conn: &mut d::Conn, org: &OrgId, login: &CustomerLogin) -> Result<()> {
    sqlx::query(d::sql!(d::login_upsert!()))
        .bind(org.as_str())
        .bind(login.username.expose())
        .bind(login.password.expose())
        .execute(conn)
        .await?;
    Ok(())
}

async fn delete_login_in(conn: &mut d::Conn, org: &OrgId) -> Result<()> {
    sqlx::query(d::sql!("DELETE FROM customer_credentials WHERE org = ?"))
        .bind(org.as_str())
        .execute(conn)
        .await?;
    Ok(())
}

pub(crate) async fn set_customer_upstream(
    pool: &d::Pool,
    org: &OrgId,
    entry: &InventoryEntry,
    login: Option<&CustomerLogin>,
    actor: &str,
) -> Result<CustomerSet> {
    if entry.subtype.kind() != Kind::Static {
        return Err(StoreError::Invalid(format!(
            "a {} subtype is not a static unit",
            entry.subtype.as_str()
        )));
    }
    let ip = entry.ip.to_string();
    let value = to_json(entry)?;
    let region = entry.region.to_string();
    let subtype = enum_text(&entry.subtype)?;

    let mut tx = d::begin_write(pool).await?;
    d::lock_table(&mut tx, "inventory").await?;
    let taken: Option<(String, Option<String>)> = sqlx::query_as(d::sql!(concat!(
        "SELECT state, owner_org FROM inventory WHERE ip = ?",
        d::for_update!()
    )))
    .bind(&ip)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some((state, owner)) = &taken
        && state != IpState::Retired.as_str()
        && owner.as_deref() != Some(org.as_str())
    {
        return Err(StoreError::Conflict {
            what: "inventory ip",
        });
    }
    let replaced = live_unit_in(&mut tx, org, None).await?.map(|u| u.row);
    if let Some(old) = replaced.as_ref().filter(|r| r.entry.ip != entry.ip) {
        retire_in(&mut tx, old.entry.ip).await?;
    }
    d::bump_version(&mut tx).await?;
    if taken.is_some() {
        sqlx::query(d::sql!(concat!(
            "UPDATE inventory SET provider = ?, region = ?, subtype = ?, entry = ?,
                 owner_org = ?, state = 'candidate', state_since = ",
            d::now!(),
            ", cooldown_until = NULL,
                 quarantined_at = NULL, retest_at = NULL, offline_since = NULL,
                 last_check_at = NULL, exit_ip = NULL, updated_at = ",
            d::now!(),
            ", upstream_version = ",
            d::next_version!(),
            " WHERE ip = ?"
        )))
        .bind(entry.provider.as_str())
        .bind(&region)
        .bind(&subtype)
        .bind(Json(&value))
        .bind(org.as_str())
        .bind(&ip)
        .execute(&mut *tx)
        .await?;
    } else {
        sqlx::query(d::sql!(concat!(
            "INSERT INTO inventory (ip, provider, region, subtype, entry, owner_org, upstream_version)
             VALUES (?, ?, ?, ?, ?, ?, ",
            d::next_version!(),
            ")"
        )))
        .bind(&ip)
        .bind(entry.provider.as_str())
        .bind(&region)
        .bind(&subtype)
        .bind(Json(&value))
        .bind(org.as_str())
        .execute(&mut *tx)
        .await?;
    }
    match login {
        Some(login) => store_login_in(&mut tx, org, login).await?,
        None => delete_login_in(&mut tx, org).await?,
    }
    d::append_audit(
        &mut tx,
        actor,
        "customer.set",
        org.as_str(),
        json!({
            "provider": entry.provider.as_str(),
            "region": region,
            "host": entry.host,
            "port": entry.port,
            "login": login.is_some(),
            "replaced": replaced.as_ref().map(|r| r.entry.ip.to_string()),
        }),
    )
    .await?;
    let raw: RawRow = sqlx::query_as(d::sql!(concat!(
        "SELECT ",
        inventory_columns!(),
        " FROM inventory WHERE ip = ?"
    )))
    .bind(&ip)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(CustomerSet {
        row: raw.try_into()?,
        replaced,
    })
}

pub(crate) async fn last_customer_setter(pool: &d::Pool, org: &OrgId) -> Result<Option<String>> {
    Ok(sqlx::query_scalar(d::sql!(
        "SELECT actor FROM audit WHERE subject = ? AND action = 'customer.set'
         ORDER BY id DESC LIMIT 1"
    ))
    .bind(org.as_str())
    .fetch_optional(pool)
    .await?)
}

pub(crate) async fn clear_customer_upstream(
    pool: &d::Pool,
    org: &OrgId,
    actor: &str,
) -> Result<InventoryRow> {
    let mut tx = d::begin_write(pool).await?;
    d::lock_table(&mut tx, "inventory").await?;
    let Some(CustomerUnit { row: unit, .. }) = live_unit_in(&mut tx, org, None).await? else {
        return Err(StoreError::NotFound {
            what: "customer upstream",
        });
    };
    retire_in(&mut tx, unit.entry.ip).await?;
    delete_login_in(&mut tx, org).await?;
    d::append_audit(
        &mut tx,
        actor,
        "customer.clear",
        org.as_str(),
        json!({ "ip": unit.entry.ip.to_string(), "state": unit.state.as_str() }),
    )
    .await?;
    tx.commit().await?;
    Ok(unit)
}

pub(crate) async fn rotate_customer_login(
    pool: &d::Pool,
    org: &OrgId,
    version: i64,
    login: &CustomerLogin,
    actor: &str,
) -> Result<()> {
    let mut tx = d::begin_write(pool).await?;
    d::lock_table(&mut tx, "inventory").await?;
    let Some(unit) = live_unit_in(&mut tx, org, Some(version)).await? else {
        return Err(StoreError::NotFound {
            what: "customer upstream",
        });
    };
    bump_version_in(&mut tx, unit.row.entry.ip).await?;
    store_login_in(&mut tx, org, login).await?;
    d::append_audit(&mut tx, actor, "customer.rotate", org.as_str(), json!({})).await?;
    tx.commit().await?;
    Ok(())
}

pub(crate) async fn customer_upstream(
    pool: &d::Pool,
    org: &OrgId,
) -> Result<Option<CustomerUnit>> {
    let raw: Option<RawVersioned> = sqlx::query_as(d::sql!(concat!(
        "SELECT ",
        inventory_columns!(),
        ", upstream_version FROM inventory WHERE ",
        d::live_unit!()
    )))
    .bind(org.as_str())
    .fetch_optional(pool)
    .await?;
    raw.map(CustomerUnit::try_from).transpose()
}

pub(crate) async fn customer_login(pool: &d::Pool, org: &OrgId) -> Result<Option<CustomerLogin>> {
    let row: Option<(String, String)> = sqlx::query_as(d::sql!(
        "SELECT username, password FROM customer_credentials WHERE org = ?"
    ))
    .bind(org.as_str())
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(username, password)| CustomerLogin::new(username, password)))
}

pub(crate) async fn customer_validated(
    pool: &d::Pool,
    org: &OrgId,
    version: i64,
    exit_ip: IpAddr,
    actor: &str,
) -> Result<InventoryRow> {
    let mut tx = d::begin_write(pool).await?;
    d::lock_table(&mut tx, "inventory").await?;
    let Some(CustomerUnit { row: unit, .. }) = live_unit_in(&mut tx, org, Some(version)).await?
    else {
        return Err(StoreError::NotFound {
            what: "customer upstream",
        });
    };
    if !matches!(
        unit.state,
        IpState::Candidate
            | IpState::Available
            | IpState::Leased
            | IpState::Cooldown
            | IpState::Quarantined
            | IpState::Offline
    ) {
        return Err(StoreError::InvalidTransition {
            from: unit.state,
            to: IpState::Available,
        });
    }
    // `state_since` before `state`: MariaDB evaluates the assignments left to
    // right, and `state_since` must see the state the row had.
    let key = unit.entry.ip.to_string();
    sqlx::query(d::sql!(concat!(
        "UPDATE inventory SET
             state_since = CASE WHEN state IN ('available', 'leased')
                                THEN state_since ELSE ",
        d::now!(),
        " END,
             state = CASE WHEN state IN ('available', 'leased') THEN state ELSE 'available' END,
             cooldown_until = NULL, quarantined_at = NULL, retest_at = NULL,
             offline_since = NULL, last_check_at = ",
        d::now!(),
        ", exit_ip = ?, updated_at = ",
        d::now!(),
        " WHERE ip = ?"
    )))
    .bind(exit_ip.to_string())
    .bind(&key)
    .execute(&mut *tx)
    .await?;
    let raw: RawRow = sqlx::query_as(d::sql!(concat!(
        "SELECT ",
        inventory_columns!(),
        " FROM inventory WHERE ip = ?"
    )))
    .bind(&key)
    .fetch_one(&mut *tx)
    .await?;
    d::append_audit(
        &mut tx,
        actor,
        "customer.validate",
        org.as_str(),
        json!({ "ok": true, "from": unit.state.as_str(), "exit_ip": exit_ip.to_string() }),
    )
    .await?;
    tx.commit().await?;
    raw.try_into()
}
