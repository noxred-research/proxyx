// Inventory: the queries of one backend. See `db/inventory.rs`.

use std::collections::HashSet;
use std::net::IpAddr;

use common::types::{InventoryEntry, IpState, Partition, ProviderId};
use proxyx_db::Ts;
use serde_json::{Value, json};
use sqlx::types::Json;
use time::OffsetDateTime;

use crate::db::inventory::{
    InventoryRow, InventorySync, RawRow, Transition, Upserted, UpsertOutcome, can_transition,
    check_rental_end, inventory_columns,
};
use crate::db::{enum_text, parse_enum, to_json};
use crate::error::{Result, StoreError};

/// Rows of one provider and/or state (`None`: any), ordered by IP.
pub(crate) async fn list_inventory_in(
    conn: &mut d::Conn,
    provider: Option<&ProviderId>,
    state: Option<IpState>,
) -> Result<Vec<InventoryRow>> {
    let raw: Vec<RawRow> = sqlx::query_as(d::sql!(concat!(
        "SELECT ",
        inventory_columns!(),
        " FROM inventory WHERE provider = COALESCE(?, provider) AND state = COALESCE(?, state)
         ORDER BY ip"
    )))
    .bind(provider.map(ProviderId::as_str))
    .bind(state.map(IpState::as_str))
    .fetch_all(conn)
    .await?;
    raw.into_iter().map(InventoryRow::try_from).collect()
}

/// Whether the two entries name another upstream behind the same IP: a new
/// host, port or credentials file. The next static tick then checks it
/// instead of waiting for `recheck_every`.
fn upstream_changed(old: &Value, new: &Value) -> bool {
    ["host", "port", "credentials"]
        .iter()
        .any(|key| old.get(key) != new.get(key))
}

async fn upsert_in(conn: &mut d::Conn, entry: &InventoryEntry, actor: &str) -> Result<Upserted> {
    check_rental_end(entry)?;
    let ip = entry.ip.to_string();
    let value = to_json(entry)?;
    let region = entry.region.to_string();
    let subtype = enum_text(&entry.subtype)?;
    let existing: Option<(Json<Value>, String, Option<String>)> = sqlx::query_as(d::sql!(concat!(
        "SELECT entry, state, owner_org FROM inventory WHERE ip = ?",
        d::for_update!()
    )))
    .bind(&ip)
    .fetch_optional(&mut *conn)
    .await?;
    if let Some((_, state, Some(_))) = &existing
        && state != IpState::Retired.as_str()
    {
        return Err(StoreError::Conflict {
            what: "org-owned inventory ip",
        });
    }
    let moved_from = existing
        .as_ref()
        .filter(|(_, state, _)| state != IpState::Retired.as_str())
        .and_then(|(old, _, _)| serde_json::from_value::<InventoryEntry>(old.0.clone()).ok())
        .filter(|old| old.provider != entry.provider || old.region != entry.region)
        .map(|old| Partition {
            provider: old.provider,
            region: old.region,
        });
    let (outcome, action) = match existing {
        None => {
            sqlx::query(d::sql!(
                "INSERT INTO inventory (ip, provider, region, subtype, entry)
                 VALUES (?, ?, ?, ?, ?)"
            ))
            .bind(&ip)
            .bind(entry.provider.as_str())
            .bind(&region)
            .bind(&subtype)
            .bind(Json(&value))
            .execute(&mut *conn)
            .await?;
            (UpsertOutcome::Added, "inventory.add")
        }
        Some((_, state, _)) if state == IpState::Retired.as_str() => {
            sqlx::query(d::sql!(concat!(
                "UPDATE inventory SET provider = ?, region = ?, subtype = ?, entry = ?,
                     state = 'candidate', state_since = ",
                d::now!(),
                ", cooldown_until = NULL, owner_org = NULL,
                     quarantined_at = NULL, retest_at = NULL, offline_since = NULL,
                     updated_at = ",
                d::now!(),
                " WHERE ip = ?"
            )))
            .bind(entry.provider.as_str())
            .bind(&region)
            .bind(&subtype)
            .bind(Json(&value))
            .bind(&ip)
            .execute(&mut *conn)
            .await?;
            (UpsertOutcome::Revived, "inventory.revive")
        }
        Some((old, _, _)) if old.0 == value => return Ok((UpsertOutcome::Unchanged, None)),
        Some((old, _, _)) => {
            sqlx::query(d::sql!(concat!(
                "UPDATE inventory SET provider = ?, region = ?, subtype = ?, entry = ?,
                     last_check_at = CASE WHEN ? THEN NULL ELSE last_check_at END,
                     updated_at = ",
                d::now!(),
                " WHERE ip = ?"
            )))
            .bind(entry.provider.as_str())
            .bind(&region)
            .bind(&subtype)
            .bind(Json(&value))
            .bind(upstream_changed(&old.0, &value))
            .bind(&ip)
            .execute(&mut *conn)
            .await?;
            (UpsertOutcome::Updated, "inventory.update")
        }
    };
    d::append_audit(
        conn,
        actor,
        action,
        &ip,
        json!({ "provider": entry.provider.as_str(), "region": region }),
    )
    .await?;
    Ok((outcome, moved_from))
}

pub(crate) async fn upsert_inventory_entry(
    pool: &d::Pool,
    entry: &InventoryEntry,
    actor: &str,
) -> Result<UpsertOutcome> {
    let mut tx = d::begin_write(pool).await?;
    d::lock_table(&mut tx, "inventory").await?;
    let (outcome, _) = upsert_in(&mut tx, entry, actor).await?;
    tx.commit().await?;
    Ok(outcome)
}

pub(crate) async fn replace_inventory(
    pool: &d::Pool,
    provider: &ProviderId,
    entries: &[InventoryEntry],
    actor: &str,
) -> Result<InventorySync> {
    let mut seen = HashSet::new();
    for e in entries {
        if e.provider != *provider {
            return Err(StoreError::Invalid(format!(
                "entry {} belongs to provider {}, not {provider}",
                e.ip, e.provider
            )));
        }
        if !seen.insert(e.ip) {
            return Err(StoreError::Invalid(format!(
                "duplicate inventory ip {}",
                e.ip
            )));
        }
    }
    let mut out = InventorySync::default();
    let mut tx = d::begin_write(pool).await?;
    d::lock_table(&mut tx, "inventory").await?;
    for e in entries {
        let (outcome, moved_from) = upsert_in(&mut tx, e, actor).await?;
        if let Some(from) = moved_from {
            out.moved.push((e.ip, from));
        }
        match outcome {
            UpsertOutcome::Added => out.added.push(e.ip),
            UpsertOutcome::Updated => out.updated.push(e.ip),
            UpsertOutcome::Revived => out.revived.push(e.ip),
            UpsertOutcome::Unchanged => out.unchanged += 1,
        }
    }
    let keep: HashSet<String> = entries.iter().map(|e| e.ip.to_string()).collect();
    let live: Vec<String> = sqlx::query_scalar(d::sql!(concat!(
        "SELECT ip FROM inventory
         WHERE provider = ? AND state <> 'retired' AND owner_org IS NULL ORDER BY ip",
        d::for_update!()
    )))
    .bind(provider.as_str())
    .fetch_all(&mut *tx)
    .await?;
    for ip in live.into_iter().filter(|ip| !keep.contains(ip)) {
        sqlx::query(d::sql!(concat!(
            "UPDATE inventory SET state = 'retired', state_since = ",
            d::now!(),
            ", cooldown_until = NULL,
                 quarantined_at = NULL, retest_at = NULL, offline_since = NULL, updated_at = ",
            d::now!(),
            " WHERE ip = ?"
        )))
        .bind(&ip)
        .execute(&mut *tx)
        .await?;
        d::append_audit(
            &mut tx,
            actor,
            "inventory.retire",
            &ip,
            json!({ "reason": "removed from inventory" }),
        )
        .await?;
        out.retired
            .push(ip.parse().map_err(|e| StoreError::decode("ip", e))?);
    }
    tx.commit().await?;
    Ok(out)
}

pub(crate) async fn inventory_row(pool: &d::Pool, ip: IpAddr) -> Result<Option<InventoryRow>> {
    let raw: Option<RawRow> = sqlx::query_as(d::sql!(concat!(
        "SELECT ",
        inventory_columns!(),
        " FROM inventory WHERE ip = ?"
    )))
    .bind(ip.to_string())
    .fetch_optional(pool)
    .await?;
    raw.map(InventoryRow::try_from).transpose()
}

pub(crate) async fn list_inventory(
    pool: &d::Pool,
    provider: Option<&ProviderId>,
    state: Option<IpState>,
) -> Result<Vec<InventoryRow>> {
    let mut conn = pool.acquire().await?;
    list_inventory_in(&mut conn, provider, state).await
}

pub(crate) async fn transition_ip(
    pool: &d::Pool,
    ip: IpAddr,
    change: &Transition,
    actor: &str,
) -> Result<InventoryRow> {
    change.validate()?;
    let key = ip.to_string();
    let mut tx = d::begin_write(pool).await?;
    let from: Option<String> = sqlx::query_scalar(d::sql!(concat!(
        "SELECT state FROM inventory WHERE ip = ?",
        d::for_update!()
    )))
    .bind(&key)
    .fetch_optional(&mut *tx)
    .await?;
    let from: IpState = parse_enum(
        "ip state",
        &from.ok_or(StoreError::NotFound {
            what: "inventory ip",
        })?,
    )?;
    if change.from.is_some_and(|expected| expected != from) || !can_transition(from, change.to) {
        return Err(StoreError::InvalidTransition {
            from,
            to: change.to,
        });
    }
    // `validate` made the two deadlines present exactly for their states.
    sqlx::query(d::sql!(concat!(
        "UPDATE inventory SET state = ?, state_since = ",
        d::now!(),
        ", cooldown_until = ?,
             quarantined_at = CASE WHEN ? THEN ",
        d::now!(),
        " WHEN ? THEN quarantined_at END,
             retest_at = ?,
             offline_since = CASE WHEN ? THEN ",
        d::now!(),
        " WHEN ? THEN offline_since END,
             updated_at = ",
        d::now!(),
        " WHERE ip = ?"
    )))
    .bind(change.to.as_str())
    .bind(change.cooldown_until.map(Ts))
    .bind(change.to == IpState::Quarantined)
    .bind(change.to == IpState::ReplaceRequested)
    .bind(change.retest_at.map(Ts))
    .bind(change.to == IpState::Offline)
    .bind(change.to == IpState::ReplaceRequested)
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
        "inventory.transition",
        &key,
        json!({ "from": from.as_str(), "to": change.to.as_str(), "reason": change.reason }),
    )
    .await?;
    tx.commit().await?;
    raw.try_into()
}

pub(crate) async fn record_check(
    pool: &d::Pool,
    ip: IpAddr,
    exit_ip: Option<IpAddr>,
    at: OffsetDateTime,
) -> Result<()> {
    let n = sqlx::query(d::sql!(concat!(
        "UPDATE inventory SET last_check_at = ?, exit_ip = ?, updated_at = ",
        d::now!(),
        " WHERE ip = ?"
    )))
    .bind(Ts(at))
    .bind(exit_ip.map(|e| e.to_string()))
    .bind(ip.to_string())
    .execute(pool)
    .await?
    .rows_affected();
    if n == 0 {
        return Err(StoreError::NotFound {
            what: "inventory ip",
        });
    }
    Ok(())
}

pub(crate) async fn providers_written_by(pool: &d::Pool, actor: &str) -> Result<Vec<ProviderId>> {
    let names: Vec<String> = sqlx::query_scalar(d::sql!(
        "SELECT DISTINCT i.provider FROM inventory i
         WHERE i.state <> 'retired' AND i.owner_org IS NULL
           AND EXISTS (
               SELECT 1 FROM audit a
               WHERE a.subject = i.ip AND a.actor = ?
                 AND a.action IN ('inventory.add', 'inventory.update', 'inventory.revive'))
         ORDER BY i.provider"
    ))
    .bind(actor)
    .fetch_all(pool)
    .await?;
    names
        .into_iter()
        .map(|n| n.parse().map_err(|e| StoreError::decode("provider", e)))
        .collect()
}
