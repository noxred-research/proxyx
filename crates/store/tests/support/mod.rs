//! Shared helpers of the integration tests. They need the local Redis and
//! a database (`PROXYX_TEST_REDIS_URL` and `PROXYX_TEST_DATABASE_URL`, or the
//! variable of the backend `PROXYX_TEST_BACKEND` selects) and skip with a message
//! when the variables are unset.
#![allow(dead_code)] // shared by several test binaries; each uses a part

use std::net::IpAddr;
use std::num::NonZeroU32;
use std::time::Duration;

use common::types::{InventoryEntry, Kind, OrgId, Partition, Subtype, Target};
use policy::Pool;
use proxyx_db::Backend;
use proxyx_db::testing::{self, Raw};
use proxyx_store::{Db, Grant, Hot, LeaseLimits, LeaseOutcome, LeaseRequest, UnitRecord};
use redis::AsyncCommands;
use time::OffsetDateTime;
use uuid::Uuid;

pub type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Redis DB index of this crate (contract: store 1) unless the URL names one.
const REDIS_DB: &str = "1";

fn redis_url() -> Option<String> {
    let base = std::env::var("PROXYX_TEST_REDIS_URL").ok()?;
    let (scheme, rest) = base.split_once("://")?;
    let authority = rest.split('/').next().unwrap_or(rest);
    let db = rest
        .split_once('/')
        .map(|(_, db)| db)
        .filter(|db| !db.is_empty())
        .unwrap_or(REDIS_DB);
    Some(format!("{scheme}://{authority}/{db}"))
}

pub async fn hot() -> Result<Option<Hot>, Box<dyn std::error::Error>> {
    let Some(url) = redis_url() else {
        eprintln!("SKIP: PROXYX_TEST_REDIS_URL is not set");
        return Ok(None);
    };
    Ok(Some(Hot::connect(&url).await?))
}

/// The Redis handle of a test; the test returns early when Redis is not
/// configured. Needs `#[macro_use] mod support;`.
#[allow(unused_macros)]
macro_rules! hot_or_skip {
    () => {
        match $crate::support::hot().await? {
            Some(hot) => hot,
            None => return Ok(()),
        }
    };
}

pub type RawRedis = redis::aio::MultiplexedConnection;

/// A raw Redis connection for assertions on keys and TTLs.
pub async fn raw_redis() -> Result<RawRedis, Box<dyn std::error::Error>> {
    let url = redis_url().ok_or("PROXYX_TEST_REDIS_URL is not set")?;
    Ok(redis::Client::open(url)?
        .get_multiplexed_async_connection()
        .await?)
}

/// Assert that `key` expires, and within `max`.
pub async fn assert_ttl(raw: &mut RawRedis, key: &str, max: Duration) -> TestResult {
    let ttl: i64 = raw.pttl(key).await?;
    assert!(
        ttl > 0 && u128::from(ttl.unsigned_abs()) <= max.as_millis(),
        "{key}: pttl {ttl}"
    );
    Ok(())
}

/// Assert that `key` expires at some point.
pub async fn assert_has_ttl(raw: &mut RawRedis, key: &str) -> TestResult {
    let ttl: i64 = raw.pttl(key).await?;
    assert!(ttl > 0, "{key}: pttl {ttl}");
    Ok(())
}

/// The backend the suite runs on: `PROXYX_TEST_BACKEND` (`postgres`,
/// `mariadb`, `sqlite`; PostgreSQL when unset). The database of each backend
/// comes from its own variable, see `proxyx_db::testing`.
pub fn backend() -> Backend {
    testing::selected()
}

/// Create the database `proxyx_store_<name>_test` on `backend` if missing, and
/// return its URL. `fresh` drops it first. `None` (skip) when the backend is not
/// configured.
pub async fn database_url_on(
    backend: Backend,
    name: &str,
    fresh: bool,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let name = format!("proxyx_store_{name}_test");
    Ok(testing::database(backend, &name, fresh).await?)
}

async fn database_url(
    name: &str,
    fresh: bool,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    database_url_on(backend(), name, fresh).await
}

/// The database of a test: the repository and raw SQL access.
pub type TestDb = (Db, Raw);

/// Create (once) and migrate the database `proxyx_store_<name>_test`.
/// Data of earlier runs stays, so tests use unique ids.
pub async fn db(name: &str) -> Result<Option<TestDb>, Box<dyn std::error::Error>> {
    open(name, false).await
}

/// Like [`db`], but starts from an empty database.
pub async fn fresh_db(name: &str) -> Result<Option<TestDb>, Box<dyn std::error::Error>> {
    open(name, true).await
}

/// [`db`] on a given backend, for the tests that run on all of them.
pub async fn db_on(
    backend: Backend,
    name: &str,
    fresh: bool,
) -> Result<Option<TestDb>, Box<dyn std::error::Error>> {
    let Some(url) = database_url_on(backend, name, fresh).await? else {
        return Ok(None);
    };
    let db = Db::connect(&url).await?;
    db.migrate().await?;
    Ok(Some((db, Raw::connect(&url).await?)))
}

/// An empty database that is not migrated.
pub async fn unmigrated_db(name: &str) -> Result<Option<Db>, Box<dyn std::error::Error>> {
    let Some(url) = database_url(name, true).await? else {
        return Ok(None);
    };
    Ok(Some(Db::connect(&url).await?))
}

async fn open(name: &str, fresh: bool) -> Result<Option<TestDb>, Box<dyn std::error::Error>> {
    db_on(backend(), name, fresh).await
}

/// An address no other test or run uses (10.x.y.z from a random id).
pub fn uniq_ip() -> IpAddr {
    let b = Uuid::new_v4();
    let b = b.as_bytes();
    IpAddr::from([10, b[0], b[1], b[2]])
}

pub fn uniq(prefix: &str) -> String {
    format!("{prefix}{}", &Uuid::new_v4().simple().to_string()[..10])
}

/// A partition no other test uses.
pub fn partition() -> Result<Partition, Box<dyn std::error::Error>> {
    let id = Uuid::new_v4().simple().to_string();
    Ok(Partition {
        provider: format!("p{}", &id[..12]).parse()?,
        region: "fr".parse()?,
    })
}

pub fn org(name: &str) -> Result<OrgId, Box<dyn std::error::Error>> {
    Ok(name.parse()?)
}

pub fn uniq_org(prefix: &str) -> Result<OrgId, Box<dyn std::error::Error>> {
    org(&uniq(prefix))
}

pub fn target(host: &str) -> Target {
    Target {
        host: host.to_owned(),
        port: 443,
    }
}

pub fn ip(n: u8) -> IpAddr {
    IpAddr::from([198, 51, 100, n])
}

pub fn limits() -> LeaseLimits {
    LeaseLimits {
        lease_ttl: Duration::from_secs(60),
        tunnel_ttl: Duration::from_secs(60),
        orgs_hard: None,
        max_conns_per_ip: None,
        provider_conns_per_ip: None,
        rest_after_release: Duration::ZERO,
        min_remaining: Duration::ZERO,
        allow_create: false,
    }
}

pub fn nz(n: u32) -> Option<NonZeroU32> {
    NonZeroU32::new(n)
}

pub async fn seed_static(
    hot: &Hot,
    p: &Partition,
    ips: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    for n in ips {
        hot.ready_put(p, &UnitRecord::static_ip(ip(*n))).await?;
    }
    Ok(())
}

/// A new partition with static units at `ips`.
pub async fn seeded_partition(
    hot: &Hot,
    ips: &[u8],
) -> Result<Partition, Box<dyn std::error::Error>> {
    let p = partition()?;
    seed_static(hot, &p, ips).await?;
    Ok(p)
}

pub struct Call<'a> {
    pub kind: Kind,
    pub p: &'a Partition,
    pub org: &'a OrgId,
    pub sticky: &'a str,
    pub host: &'a str,
    pub limits: LeaseLimits,
}

/// A lease of a static unit by `org` on `sticky` for example.com, with the
/// default limits. Tests override single fields with `Call { host, ..}`.
pub fn static_call<'a>(p: &'a Partition, org: &'a OrgId, sticky: &'a str) -> Call<'a> {
    Call {
        kind: Kind::Static,
        p,
        org,
        sticky,
        host: "example.com",
        limits: limits(),
    }
}

fn request<'a>(c: &'a Call<'a>, target: &'a Target, tunnel: Uuid) -> LeaseRequest<'a> {
    LeaseRequest {
        partition: c.p,
        kind: c.kind,
        org: c.org,
        sticky: c.sticky,
        target,
        tunnel,
        pool: Pool::Shared,
        limits: c.limits.clone(),
    }
}

pub async fn lease(hot: &Hot, c: &Call<'_>) -> Result<LeaseOutcome, Box<dyn std::error::Error>> {
    lease_as(hot, c, Uuid::new_v4()).await
}

/// Like [`lease`], with the id of the tunnel the lease opens.
pub async fn lease_as(
    hot: &Hot,
    c: &Call<'_>,
    tunnel: Uuid,
) -> Result<LeaseOutcome, Box<dyn std::error::Error>> {
    let target = target(c.host);
    Ok(hot
        .lease_ranked(&request(c, &target, tunnel), &[], proxyx_store::MAX_RANK)
        .await?)
}

/// Renew the lease of `c` without opening a tunnel.
pub async fn renew(hot: &Hot, c: &Call<'_>) -> Result<Option<Grant>, Box<dyn std::error::Error>> {
    let target = target(c.host);
    Ok(hot.renew(&request(c, &target, Uuid::new_v4())).await?)
}

/// Lease a static unit with default limits.
pub async fn lease_static(
    hot: &Hot,
    p: &Partition,
    org: &OrgId,
    sticky: &str,
) -> Result<LeaseOutcome, Box<dyn std::error::Error>> {
    lease(hot, &static_call(p, org, sticky)).await
}

/// The grant of a lease that must succeed.
pub async fn granted(hot: &Hot, c: &Call<'_>) -> Result<Grant, Box<dyn std::error::Error>> {
    Ok(grant(&lease(hot, c).await?)?.clone())
}

/// The grant of a static lease with default limits.
pub async fn static_grant(
    hot: &Hot,
    p: &Partition,
    org: &OrgId,
    sticky: &str,
) -> Result<Grant, Box<dyn std::error::Error>> {
    granted(hot, &static_call(p, org, sticky)).await
}

pub fn grant(outcome: &LeaseOutcome) -> Result<&Grant, Box<dyn std::error::Error>> {
    match outcome {
        LeaseOutcome::Hit(g) | LeaseOutcome::Free(g) | LeaseOutcome::Shared(g) => Ok(g),
        other => Err(format!("expected a grant, got {other:?}").into()),
    }
}

pub fn entry_at(provider: &str, ip: IpAddr) -> Result<InventoryEntry, Box<dyn std::error::Error>> {
    Ok(InventoryEntry {
        provider: provider.parse()?,
        subtype: Subtype::Isp,
        plan: "test".into(),
        ip,
        host: ip.to_string(),
        port: 8000,
        region: "fr".parse()?,
        asn: None,
        credentials: None,
        box_handle: None,
        rental_end: None,
    })
}

/// A rotating session of the ready set.
pub fn session_unit(
    id: &str,
    ip: IpAddr,
    expires_at: Option<OffsetDateTime>,
    ttl: Duration,
) -> UnitRecord {
    UnitRecord {
        id: id.into(),
        ip,
        expires_at,
        ttl: Some(ttl),
        owner: None,
    }
}

/// A lock another process holds on one org's block changes, until released.
pub enum PeerLock {
    Postgres(sqlx::Transaction<'static, sqlx::Postgres>),
    MariaDb(sqlx::Transaction<'static, sqlx::MySql>),
}

impl PeerLock {
    pub async fn release(self) -> Result<(), sqlx::Error> {
        match self {
            Self::Postgres(tx) => tx.commit().await,
            Self::MariaDb(tx) => tx.commit().await,
        }
    }
}

/// Take the lock the repository takes for the block changes of `org`, in a
/// transaction of this test. Not for SQLite.
pub async fn hold_org_lock(raw: &Raw, org: &str) -> Result<PeerLock, Box<dyn std::error::Error>> {
    match raw.pool() {
        proxyx_db::Pool::Postgres(pool) => {
            let mut tx = pool.begin().await?;
            sqlx::query(
                "SELECT pg_advisory_xact_lock(hashtextextended('org_block:' || $1::text, 0))",
            )
            .bind(org)
            .execute(&mut *tx)
            .await?;
            Ok(PeerLock::Postgres(tx))
        }
        proxyx_db::Pool::MariaDb(pool) => {
            let mut tx = pool.begin().await?;
            sqlx::query("SELECT name FROM advisory_locks WHERE name = ? FOR UPDATE")
                .bind(proxyx_store::testing::mariadb_org_lock_name(org))
                .execute(&mut *tx)
                .await?;
            Ok(PeerLock::MariaDb(tx))
        }
        proxyx_db::Pool::Sqlite(_) => Err("SQLite has no per-org lock".into()),
    }
}
