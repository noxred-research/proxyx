//! The inventory table: IP entries with their state machine and
//! deadlines. The database is the source of truth; Redis only caches what leasing needs.

use std::net::IpAddr;

use common::types::{InventoryEntry, IpState, OrgId, Partition, ProviderId};
use proxyx_db::Ts;
use serde_json::Value;
use sqlx::FromRow;
use sqlx::types::Json;
use time::OffsetDateTime;

use super::parse_enum;
use crate::error::{Result, StoreError};

instances!("impls/inventory.rs");

macro_rules! inventory_columns {
    () => {
        "entry, state, state_since, cooldown_until, quarantined_at, retest_at, offline_since, \
         last_check_at, exit_ip, owner_org"
    };
}
pub(super) use inventory_columns;

/// One inventory entry with its state and deadlines. Postgres holds
/// the deadlines, so a Redis loss cannot return a banned IP to leasing.
#[derive(Debug, Clone, PartialEq)]
pub struct InventoryRow {
    pub entry: InventoryEntry,
    pub state: IpState,
    pub state_since: OffsetDateTime,
    /// Set in `Cooldown`: the IP is retested after this time.
    pub cooldown_until: Option<OffsetDateTime>,
    /// Set in `Quarantined` (and kept in `ReplaceRequested`).
    pub quarantined_at: Option<OffsetDateTime>,
    /// Set in `Quarantined`: back to `Candidate` after this time.
    pub retest_at: Option<OffsetDateTime>,
    /// Set in `Offline` (and kept in `ReplaceRequested`).
    pub offline_since: Option<OffsetDateTime>,
    pub last_check_at: Option<OffsetDateTime>,
    /// Exit IP seen by the last check. A `mobile_box` changes it.
    pub exit_ip: Option<IpAddr>,
    /// The org that owns this unit (a customer upstream); only it may lease
    /// the unit. `None`: a shared provider IP.
    pub owner: Option<OrgId>,
}

impl InventoryRow {
    /// The Redis partition this IP belongs to.
    pub fn partition(&self) -> Partition {
        Partition {
            provider: self.entry.provider.clone(),
            region: self.entry.region.clone(),
        }
    }

    /// The address the unit record of this row carries: the exit IP the last
    /// check saw (a SIM box's address after a reset, a customer upstream's
    /// exit), the entry IP before the first check.
    pub fn unit_ip(&self) -> IpAddr {
        self.exit_ip.unwrap_or(self.entry.ip)
    }
}

#[derive(FromRow)]
pub(super) struct RawRow {
    entry: Json<Value>,
    state: String,
    state_since: Ts,
    cooldown_until: Option<Ts>,
    quarantined_at: Option<Ts>,
    retest_at: Option<Ts>,
    offline_since: Option<Ts>,
    last_check_at: Option<Ts>,
    exit_ip: Option<String>,
    owner_org: Option<String>,
}

impl TryFrom<RawRow> for InventoryRow {
    type Error = StoreError;

    fn try_from(r: RawRow) -> Result<Self> {
        Ok(Self {
            entry: serde_json::from_value(r.entry.0)
                .map_err(|e| StoreError::decode("inventory entry", e))?,
            state: parse_enum("ip state", &r.state)?,
            state_since: r.state_since.0,
            cooldown_until: r.cooldown_until.map(|t| t.0),
            quarantined_at: r.quarantined_at.map(|t| t.0),
            retest_at: r.retest_at.map(|t| t.0),
            offline_since: r.offline_since.map(|t| t.0),
            last_check_at: r.last_check_at.map(|t| t.0),
            exit_ip: r
                .exit_ip
                .map(|s| s.parse().map_err(|e| StoreError::decode("exit ip", e)))
                .transpose()?,
            owner: r
                .owner_org
                .map(|s| OrgId::try_from(s).map_err(|e| StoreError::decode("owner org", e)))
                .transpose()?,
        })
    }
}
/// What [`Db::replace_inventory`] changed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InventorySync {
    pub added: Vec<IpAddr>,
    pub updated: Vec<IpAddr>,
    /// Retired IPs that the list brought back as `Candidate`.
    pub revived: Vec<IpAddr>,
    /// IPs missing from the list, now `Retired`.
    pub retired: Vec<IpAddr>,
    /// IPs whose provider or region changed, with the partition they were
    /// listed in before: their unit has to leave that partition's ready set.
    pub moved: Vec<(IpAddr, Partition)>,
    pub unchanged: usize,
}

/// What [`Db::upsert_inventory_entry`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpsertOutcome {
    Added,
    Updated,
    Revived,
    Unchanged,
}

/// A requested state change with the deadline its target state needs.
#[derive(Debug, Clone)]
pub struct Transition {
    pub to: IpState,
    pub reason: String,
    /// Required for `Cooldown`, refused elsewhere.
    pub cooldown_until: Option<OffsetDateTime>,
    /// Required for `Quarantined`, refused elsewhere.
    pub retest_at: Option<OffsetDateTime>,
    /// The state the caller saw the IP in; the move is refused when the IP
    /// is in another state by now (the caller worked from a snapshot, and a
    /// parallel signal or check moved it).
    pub from: Option<IpState>,
}

impl Transition {
    pub fn to(state: IpState, reason: impl Into<String>) -> Self {
        Self {
            to: state,
            reason: reason.into(),
            cooldown_until: None,
            retest_at: None,
            from: None,
        }
    }

    #[must_use]
    pub fn cooldown_until(mut self, at: OffsetDateTime) -> Self {
        self.cooldown_until = Some(at);
        self
    }

    #[must_use]
    pub fn retest_at(mut self, at: OffsetDateTime) -> Self {
        self.retest_at = Some(at);
        self
    }

    /// Move only when the IP is still in `state`; otherwise
    /// [`StoreError::InvalidTransition`], as for a forbidden move.
    #[must_use]
    pub fn expecting(mut self, state: IpState) -> Self {
        self.from = Some(state);
        self
    }

    pub(super) fn validate(&self) -> Result<()> {
        let (needs_cooldown, needs_retest) = (
            self.to == IpState::Cooldown,
            self.to == IpState::Quarantined,
        );
        if needs_cooldown != self.cooldown_until.is_some() {
            return Err(StoreError::Invalid(format!(
                "cooldown_until is required for cooldown and refused elsewhere (to {})",
                self.to.as_str()
            )));
        }
        if needs_retest != self.retest_at.is_some() {
            return Err(StoreError::Invalid(format!(
                "retest_at is required for quarantined and refused elsewhere (to {})",
                self.to.as_str()
            )));
        }
        Ok(())
    }
}

/// The allowed state moves. `Retired` is final; any other
/// state may go to `ReplaceRequested` (a replacement rule holds) or `Retired`
/// (the entry was removed). `Degraded` is `Available` and slow: it is entered
/// from where an IP becomes leasable, and left for `Available` (a check passes
/// at full speed) or where `Available` can go.
pub(crate) fn can_transition(from: IpState, to: IpState) -> bool {
    use IpState::{
        Available, Candidate, Cooldown, Degraded, Leased, Offline, Quarantined, ReplaceRequested,
        Retired, Rotating,
    };
    match (from, to) {
        (Retired, _) => false,
        (_, Retired) => true,
        (_, ReplaceRequested) => from != ReplaceRequested,
        (Candidate, Available | Quarantined | Degraded)
        | (Available, Leased | Cooldown | Candidate | Offline | Degraded)
        | (Leased, Available | Cooldown | Candidate | Degraded)
        | (Degraded, Available | Cooldown | Candidate | Offline)
        | (Cooldown, Available | Quarantined | Rotating | Degraded)
        | (Quarantined, Rotating | Candidate)
        | (Rotating, Candidate | Quarantined)
        | (Offline, Candidate) => true,
        _ => false,
    }
}
/// `rental_end` is a real calendar day, `YYYY-MM-DD`: the warmer reads it as
/// one and skips what it cannot parse, which would blind the rental alert.
pub(crate) fn check_rental_end(entry: &InventoryEntry) -> Result<()> {
    let Some(text) = entry.rental_end.as_deref() else {
        return Ok(());
    };
    let bad = || {
        StoreError::Invalid(format!(
            "{}: rental_end {text:?} is not a date, YYYY-MM-DD",
            entry.ip
        ))
    };
    let mut parts = text.split('-');
    let (Some(y), Some(m), Some(d), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(bad());
    };
    let digits = |s: &str, len: usize| s.len() == len && s.bytes().all(|b| b.is_ascii_digit());
    if !(digits(y, 4) && digits(m, 2) && digits(d, 2)) {
        return Err(bad());
    }
    let month = time::Month::try_from(m.parse::<u8>().map_err(|_| bad())?).map_err(|_| bad())?;
    let (year, day) = (y.parse().map_err(|_| bad())?, d.parse().map_err(|_| bad())?);
    time::Date::from_calendar_date(year, month, day).map_err(|_| bad())?;
    Ok(())
}

pub(super) type Upserted = (UpsertOutcome, Option<Partition>);

delegate! {
    /// Insert an entry as `Candidate`, or update the entry of an existing IP
    /// and keep its state. A retired IP comes back as `Candidate`.
    pub async fn upsert_inventory_entry(&self, entry: &InventoryEntry, actor: &str) -> Result<UpsertOutcome>;

    /// Make the inventory of one provider equal to `entries` (the git file):
    /// upsert each IP, keep the state of known IPs, and mark every other
    /// non-retired IP of the provider `Retired`. All or nothing.
    ///
    /// Fails with [`StoreError::Invalid`] when an entry names another provider
    /// or an IP appears twice.
    pub async fn replace_inventory(
        &self,
        provider: &ProviderId,
        entries: &[InventoryEntry],
        actor: &str,
    ) -> Result<InventorySync>;

    /// One inventory row.
    pub async fn inventory_row(&self, ip: IpAddr) -> Result<Option<InventoryRow>>;

    /// Rows of one provider and/or state, ordered by IP.
    pub async fn list_inventory(
        &self,
        provider: Option<&ProviderId>,
        state: Option<IpState>,
    ) -> Result<Vec<InventoryRow>>;

    /// Move an IP to another state, setting and clearing its deadlines.
    ///
    /// Fails with [`StoreError::NotFound`] for an unknown IP,
    /// [`StoreError::InvalidTransition`] for a move the state machine forbids,
    /// [`StoreError::Invalid`] for a missing or stray deadline.
    pub async fn transition_ip(&self, ip: IpAddr, change: &Transition, actor: &str) -> Result<InventoryRow>;

    /// Record the result of an exit-IP check (no audit row: it is a
    /// measurement, taken every few minutes per IP).
    ///
    /// Fails with [`StoreError::NotFound`] for an unknown IP.
    pub async fn record_check(&self, ip: IpAddr, exit_ip: Option<IpAddr>, at: OffsetDateTime) -> Result<()>;

    /// Providers with at least one non-retired IP whose inventory the git
    /// sync (`actor`) has written: the providers a deleted git file leaves
    /// behind.
    pub async fn providers_written_by(&self, actor: &str) -> Result<Vec<ProviderId>>;
}

#[cfg(test)]
mod tests {
    use IpState::{
        Available, Candidate, Cooldown, Degraded, Leased, Offline, Quarantined, ReplaceRequested,
        Retired, Rotating,
    };

    use super::*;

    #[test]
    fn ip_state_machine_follows_the_diagram() {
        // Allowed edges (plus "removed" and "replace
        // rule holds", which may start from any live state).
        let edges = [
            (Candidate, Available),
            (Candidate, Quarantined),
            (Available, Leased),
            (Leased, Available),
            (Available, Cooldown),
            (Leased, Cooldown),
            (Cooldown, Available),
            (Cooldown, Quarantined),
            (Cooldown, Rotating),
            (Quarantined, Rotating),
            (Rotating, Candidate),
            (Rotating, Quarantined),
            (Available, Candidate),
            (Leased, Candidate),
            (Available, Offline),
            (Offline, Candidate),
            (Quarantined, Candidate),
            (Candidate, Degraded),
            (Available, Degraded),
            (Leased, Degraded),
            (Cooldown, Degraded),
            (Degraded, Available),
            (Degraded, Cooldown),
            (Degraded, Candidate),
            (Degraded, Offline),
        ];
        for from in IpState::ALL {
            for to in IpState::ALL {
                let expected = if from == Retired {
                    false
                } else if to == Retired {
                    true
                } else if to == ReplaceRequested {
                    from != ReplaceRequested
                } else {
                    edges.contains(&(from, to))
                };
                assert_eq!(can_transition(from, to), expected, "{from:?} -> {to:?}");
            }
        }
    }

    #[test]
    fn a_deadline_is_required_where_it_belongs_and_refused_elsewhere() {
        let at = OffsetDateTime::UNIX_EPOCH;
        for (change, ok) in [
            (Transition::to(Cooldown, "x").cooldown_until(at), true),
            (Transition::to(Cooldown, "x"), false),
            (
                Transition::to(Cooldown, "x")
                    .cooldown_until(at)
                    .retest_at(at),
                false,
            ),
            (Transition::to(Quarantined, "x").retest_at(at), true),
            (Transition::to(Quarantined, "x"), false),
            (Transition::to(Offline, "x").retest_at(at), false),
            (Transition::to(Available, "x").cooldown_until(at), false),
            (Transition::to(Available, "x"), true),
        ] {
            assert_eq!(change.validate().is_ok(), ok, "{change:?}");
        }
    }

    #[test]
    fn rental_end_must_be_a_real_calendar_day() {
        let with = |rental_end: Option<&str>| InventoryEntry {
            provider: "oxy".parse().expect("provider"),
            subtype: common::types::Subtype::Isp,
            plan: String::new(),
            ip: "203.0.113.7".parse().expect("ip"),
            host: "h.example".into(),
            port: 1,
            region: "fr".parse().expect("region"),
            asn: None,
            credentials: None,
            box_handle: None,
            rental_end: rental_end.map(str::to_owned),
        };
        for ok in [None, Some("2026-10-30"), Some("2028-02-29")] {
            assert!(check_rental_end(&with(ok)).is_ok(), "{ok:?}");
        }
        for bad in [
            "",
            "soon",
            "2026-02-30",
            "2027-02-29",
            "2026-13-01",
            "2026-1-1",
            "26-01-01",
            "2026-01-01-01",
        ] {
            assert!(check_rental_end(&with(Some(bad))).is_err(), "{bad:?}");
        }
    }
}
