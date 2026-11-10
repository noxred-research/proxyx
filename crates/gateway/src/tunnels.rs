//! Registry of the tunnels this pod has open.
//!
//! The gateway registers every tunnel under its `X-ProxyX-Pool-Session` id before
//! it answers `200`. The control API uses the registry to close tunnels when
//! an operator blocks an org (`close_org_scope`), and the drain deadline uses
//! it to close what is left (`close_all`).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use common::types::{OrgId, Partition};
use parking_lot::Mutex;
use policy::Pool;
use store::BlockScope;
use tokio_util::sync::CancellationToken;

/// What the registry knows about one open tunnel.
pub(crate) struct TunnelInfo {
    pub org: OrgId,
    pub partition: Partition,
    pub ip: IpAddr,
    pub pool: Pool,
}

impl TunnelInfo {
    fn in_scope(&self, scope: &BlockScope) -> bool {
        match scope {
            BlockScope::Ip(ip) => self.ip == *ip,
            BlockScope::Provider(p) => self.partition.provider == *p,
            BlockScope::RouteClass(p) => self.partition == *p,
            BlockScope::Pool(pool) => self.pool == *pool,
        }
    }
}

struct Entry {
    info: TunnelInfo,
    close: CancellationToken,
}

/// Open tunnels of this pod. Cheap to clone; every clone sees the same set.
#[derive(Clone, Default)]
pub struct Tunnels(Arc<Mutex<HashMap<String, Entry>>>);

/// Keeps a tunnel in the registry. Dropping it removes the entry.
pub(crate) struct Registration {
    tunnels: Tunnels,
    id: String,
    close: CancellationToken,
}

impl Registration {
    /// Fires when the registry asks this tunnel to close.
    pub(crate) fn closed(&self) -> &CancellationToken {
        &self.close
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        self.tunnels.0.lock().remove(&self.id);
    }
}

impl Tunnels {
    /// Number of open tunnels.
    pub(crate) fn count(&self) -> usize {
        self.0.lock().len()
    }

    /// Close every open tunnel of `org` that runs in `scope`. Returns how many
    /// were asked to close.
    pub fn close_org_scope(&self, org: &OrgId, scope: &BlockScope) -> usize {
        self.0
            .lock()
            .values()
            .filter(|e| e.info.org == *org && e.info.in_scope(scope))
            .inspect(|e| e.close.cancel())
            .count()
    }

    pub(crate) fn register(&self, id: String, info: TunnelInfo) -> Registration {
        let close = CancellationToken::new();
        self.0.lock().insert(
            id.clone(),
            Entry {
                info,
                close: close.clone(),
            },
        );
        Registration {
            tunnels: self.clone(),
            id,
            close,
        }
    }

    /// Ask every open tunnel to close (the drain deadline passed).
    pub(crate) fn close_all(&self) {
        for entry in self.0.lock().values() {
            entry.close.cancel();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(org: &str, provider: &str, region: &str, ip: &str, pool: Pool) -> TunnelInfo {
        TunnelInfo {
            org: org.parse().expect("org"),
            partition: Partition {
                provider: provider.parse().expect("provider"),
                region: region.parse().expect("region"),
            },
            ip: ip.parse().expect("ip"),
            pool,
        }
    }

    #[test]
    fn scopes_close_only_the_orgs_matching_tunnels() {
        let tunnels = Tunnels::default();
        let a_fr = tunnels.register("s1".into(), info("a", "p1", "fr", "1.1.1.1", Pool::Shared));
        let a_de = tunnels.register("s2".into(), info("a", "p1", "de", "2.2.2.2", Pool::Shared));
        let a_p2 = tunnels.register("s3".into(), info("a", "p2", "fr", "3.3.3.3", Pool::Private));
        let b_fr = tunnels.register("s4".into(), info("b", "p1", "fr", "1.1.1.1", Pool::Shared));
        let org: OrgId = "a".parse().expect("org");
        let route = |p: &str, r: &str| {
            BlockScope::RouteClass(Partition {
                provider: p.parse().expect("provider"),
                region: r.parse().expect("region"),
            })
        };

        assert_eq!(tunnels.count(), 4);
        assert_eq!(
            tunnels.close_org_scope(&org, &BlockScope::Ip("1.1.1.1".parse().expect("ip"))),
            1
        );
        assert!(a_fr.closed().is_cancelled() && !b_fr.closed().is_cancelled());
        assert_eq!(
            tunnels.close_org_scope(&org, &BlockScope::Provider("p1".parse().expect("p"))),
            2,
            "both p1 tunnels of org a, one of them already asked to close"
        );
        assert!(a_de.closed().is_cancelled());
        assert!(!a_p2.closed().is_cancelled());
        assert_eq!(tunnels.close_org_scope(&org, &route("p2", "de")), 0);
        assert_eq!(tunnels.close_org_scope(&org, &route("p2", "fr")), 1);
        assert!(a_p2.closed().is_cancelled());
        assert!(!b_fr.closed().is_cancelled(), "other orgs are untouched");
        assert_eq!(
            tunnels.close_org_scope(&org, &BlockScope::Pool(Pool::Private)),
            1
        );
    }

    #[test]
    fn close_all_asks_every_tunnel_and_a_dropped_registration_leaves_the_count() {
        let tunnels = Tunnels::default();
        let a = tunnels.register("s1".into(), info("a", "p1", "fr", "1.1.1.1", Pool::Shared));
        let b = tunnels.register("s2".into(), info("b", "p2", "de", "2.2.2.2", Pool::Private));
        tunnels.close_all();
        assert!(a.closed().is_cancelled() && b.closed().is_cancelled());
        assert_eq!(tunnels.count(), 2, "still open until its task ends");
        drop(a);
        assert_eq!(tunnels.count(), 1);
    }
}
