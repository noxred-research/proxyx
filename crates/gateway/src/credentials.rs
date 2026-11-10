//! Cooldowns of a unit whose login changed.
//!
//! A tunnel that fails on a unit cools it for its target for a few seconds
//! and keeps the cause, so a client whose upstream login is wrong hears
//! `provider_auth` at once ([`crate::acquire`]). When the owner then rotates
//! the login, that answer is stale: the new login has not failed yet. Each
//! snapshot reload is compared with the previous one, and the cooldowns a
//! failed tunnel set on the units of an org whose login changed are removed.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use common::types::{OrgId, Partition};
use store::{CustomerLogin, InventoryRow};
use tokio_util::sync::CancellationToken;

use crate::gateway::Gateway;

/// The units whose owner's login differs between `previous` and `now`: the
/// inventory IP of each, and the exit IP the gateway cools them under.
fn units_with_new_login(
    previous: &HashMap<OrgId, CustomerLogin>,
    now: &HashMap<OrgId, CustomerLogin>,
    inventory: &[InventoryRow],
) -> Vec<(Partition, IpAddr)> {
    let mut units = Vec::new();
    for row in inventory {
        let Some(owner) = &row.owner else { continue };
        let Some(login) = now.get(owner) else {
            continue;
        };
        if previous.get(owner).is_none_or(|old| old == login) {
            continue;
        }
        let partition = row.partition();
        units.push((partition.clone(), row.entry.ip));
        if let Some(exit) = row.exit_ip.filter(|exit| *exit != row.entry.ip) {
            units.push((partition, exit));
        }
    }
    units
}

/// Watch the snapshot until `cancel` fires and forget the failure cooldowns of
/// every unit whose login changed.
pub(crate) async fn forget_cooldowns_of_new_logins(gw: Arc<Gateway>, cancel: CancellationToken) {
    let mut loaded = gw.loaded.clone();
    let mut previous = Arc::clone(&loaded.borrow_and_update());
    loop {
        tokio::select! {
            () = cancel.cancelled() => return,
            changed = loaded.changed() => {
                if changed.is_err() {
                    return;
                }
            }
        }
        let now = Arc::clone(&loaded.borrow_and_update());
        let units = units_with_new_login(
            &previous.snapshot.customer_logins,
            &now.snapshot.customer_logins,
            &now.snapshot.inventory,
        );
        for (partition, ip) in units {
            match gw.hot.cool_clear_failed(&partition, ip).await {
                Ok(0) => {}
                Ok(n) => {
                    tracing::info!(%partition, cleared = n, "forgot the failures of a unit whose login changed")
                }
                Err(error) => {
                    tracing::warn!(%partition, %error, "failed to forget the failures of a unit whose login changed");
                }
            }
        }
        previous = now;
    }
}

#[cfg(test)]
mod tests {
    use common::Secret;
    use common::types::{InventoryEntry, IpState, Subtype};
    use time::OffsetDateTime;

    use super::*;

    fn login(pass: &str) -> CustomerLogin {
        CustomerLogin {
            username: Secret::new("u"),
            password: Secret::new(pass),
        }
    }

    fn row(ip: [u8; 4], owner: Option<&str>) -> InventoryRow {
        let now = OffsetDateTime::now_utc();
        InventoryRow {
            entry: InventoryEntry {
                provider: "p".parse().expect("provider"),
                subtype: Subtype::Isp,
                plan: "t".into(),
                ip: IpAddr::from(ip),
                host: "127.0.0.1".into(),
                port: 1,
                region: "fr".parse().expect("region"),
                asn: None,
                credentials: None,
                box_handle: None,
                rental_end: None,
            },
            state: IpState::Available,
            state_since: now,
            cooldown_until: None,
            quarantined_at: None,
            retest_at: None,
            offline_since: None,
            last_check_at: None,
            exit_ip: None,
            owner: owner.map(|o| o.parse().expect("org")),
        }
    }

    #[test]
    fn only_units_of_an_org_whose_login_changed_are_named() {
        let (a, b): (OrgId, OrgId) = ("a".parse().expect("org"), "b".parse().expect("org"));
        let before = HashMap::from([(a.clone(), login("old")), (b.clone(), login("same"))]);
        let after = HashMap::from([(a, login("new")), (b, login("same"))]);
        let inventory = [
            row([10, 0, 0, 1], Some("a")),
            row([10, 0, 0, 2], Some("b")),
            row([10, 0, 0, 3], None),
        ];
        let units = units_with_new_login(&before, &after, &inventory);
        assert_eq!(units.len(), 1);
        assert_eq!(units[0].1, IpAddr::from([10, 0, 0, 1]));
        // a first login (nothing before) is not a change
        assert!(units_with_new_login(&HashMap::new(), &after, &inventory).is_empty());
    }
}
