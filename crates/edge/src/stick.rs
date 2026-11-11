//! Finite-lifetime affinity claims. Redis claims are authoritative across replicas.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::sync::OnceCell;

use crate::config::StickConfig;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mapping {
    pub parents: Vec<String>,
    pub egress: Option<IpAddr>,
}

struct Entry {
    value: Mapping,
    expires: Instant,
    order: u64,
}
#[derive(Default)]
struct Local {
    entries: HashMap<String, Entry>,
    expiry: BTreeMap<(Instant, u64), String>,
    serial: u64,
}

pub struct StickMap {
    cfg: StickConfig,
    local: Mutex<Local>,
    client: Option<redis::Client>,
    connection: OnceCell<redis::aio::ConnectionManager>,
}

impl StickMap {
    pub fn new(cfg: &StickConfig) -> Result<Self, String> {
        if cfg.capacity == 0
            || cfg.ttl.is_zero()
            || cfg.ttl.as_millis() > u128::from(u64::MAX)
            || Instant::now().checked_add(cfg.ttl).is_none()
        {
            return Err("stick.capacity and finite stick.ttl must be above zero".to_owned());
        }
        let client = cfg
            .redis
            .as_ref()
            .map(|r| {
                let ttl = r.ttl.unwrap_or(cfg.ttl);
                if r.key_prefix.is_empty()
                    || r.timeout.is_zero()
                    || ttl.is_zero()
                    || ttl.as_millis() > u128::from(u64::MAX)
                    || Instant::now().checked_add(ttl).is_none()
                {
                    return Err(
                        "stick.redis requires nonempty key_prefix and positive finite ttl/timeout"
                            .to_owned(),
                    );
                }
                redis::Client::open(r.url.expose()).map_err(|e| format!("stick.redis: {e}"))
            })
            .transpose()?;
        Ok(Self {
            cfg: cfg.clone(),
            local: Mutex::new(Local::default()),
            client,
            connection: OnceCell::new(),
        })
    }

    fn remember(&self, key: &str, value: Mapping, ttl: Duration) -> Result<(), String> {
        let now = Instant::now();
        let mut local = self.local.lock();
        if let Some(old) = local.entries.remove(key) {
            local.expiry.remove(&(old.expires, old.order));
        }
        while let Some((&(expires, order), _)) = local.expiry.first_key_value() {
            if expires > now && local.entries.len() < self.cfg.capacity {
                break;
            }
            if let Some(key) = local.expiry.remove(&(expires, order)) {
                local.entries.remove(&key);
            }
        }
        local.serial = local.serial.wrapping_add(1);
        let order = local.serial;
        let expires = now
            .checked_add(ttl.min(self.cfg.ttl))
            .ok_or("stick TTL exceeds clock range")?;
        local.expiry.insert((expires, order), key.to_owned());
        local.entries.insert(
            key.to_owned(),
            Entry {
                value,
                expires,
                order,
            },
        );
        Ok(())
    }

    /// Claims once, never extends a healthy claim's TTL. Invalid claims are replaced atomically.
    /// Redis failure returns an error: a replica must not invent a competing mapping.
    pub async fn claim(
        &self,
        key: &str,
        proposal: Mapping,
        valid: impl Fn(&Mapping) -> bool,
    ) -> Result<Mapping, String> {
        if let (Some(client), Some(cfg)) = (&self.client, &self.cfg.redis) {
            let work = async {
                let connection = self
                    .connection
                    .get_or_try_init(|| redis::aio::ConnectionManager::new(client.clone()))
                    .await
                    .map_err(|e| format!("stick.redis connect: {e}"))?;
                let mut connection = connection.clone();
                let proposal_json = serde_json::to_string(&proposal).map_err(|e| e.to_string())?;
                let redis_key = format!("{}:claim:{}", cfg.key_prefix, key);
                let expiry_key = format!("{}:expiry", cfg.key_prefix);
                let script = redis::Script::new(
                    r#"
local clock = redis.call('TIME')
local now = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
local expired = redis.call('ZRANGEBYSCORE', KEYS[2], '-inf', now, 'LIMIT', 0, 64)
for _, key in ipairs(expired) do
  redis.call('DEL', key)
  redis.call('ZREM', KEYS[2], key)
end
local capacity = tonumber(ARGV[4])
local indexed = redis.call('ZSCORE', KEYS[2], KEYS[1])
local target = capacity
if not indexed then target = capacity - 1 end
for _ = 1, 64 do
  if redis.call('ZCARD', KEYS[2]) <= target then break end
  local victims = redis.call('ZRANGE', KEYS[2], 0, 1)
  local victim = victims[1]
  if victim == KEYS[1] then victim = victims[2] end
  if not victim then break end
  redis.call('DEL', victim)
  redis.call('ZREM', KEYS[2], victim)
end
if redis.call('ZCARD', KEYS[2]) > target then
  return redis.error_reply('stick capacity shrink requires more bounded cleanup')
end
local old = redis.call('GET', KEYS[1])
local remaining = redis.call('PTTL', KEYS[1])
if not old or remaining <= 0 or (ARGV[3] ~= '' and old == ARGV[3]) then
  redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])
  old = ARGV[1]
  remaining = tonumber(ARGV[2])
end
redis.call('ZADD', KEYS[2], now + remaining, KEYS[1])
local index_ttl = redis.call('PTTL', KEYS[2])
if index_ttl < remaining then redis.call('PEXPIRE', KEYS[2], remaining) end
return {old, remaining}
"#,
                );
                let mut replace = String::new();
                // A finite bound prevents churn from turning affinity into an unbounded loop.
                for _ in 0..8 {
                    let (raw, ttl): (String, i64) = script
                        .key(&redis_key)
                        .key(&expiry_key)
                        .arg(&proposal_json)
                        .arg(
                            u64::try_from(cfg.ttl.unwrap_or(self.cfg.ttl).as_millis())
                                .map_err(|e| e.to_string())?
                                .max(1),
                        )
                        .arg(&replace)
                        .arg(self.cfg.capacity)
                        .invoke_async(&mut connection)
                        .await
                        .map_err(|e| format!("stick.redis claim: {e}"))?;
                    let mapping = serde_json::from_str::<Mapping>(&raw);
                    if let Ok(mapping) = mapping
                        && ttl > 0
                        && valid(&mapping)
                    {
                        self.remember(
                            key,
                            mapping.clone(),
                            Duration::from_millis(ttl.unsigned_abs()),
                        )?;
                        return Ok(mapping);
                    }
                    replace = raw;
                }
                Err("stick.redis claim changed too often or has no finite TTL".to_owned())
            };
            return tokio::time::timeout(cfg.timeout, work)
                .await
                .map_err(|_| "stick.redis claim timed out".to_owned())?;
        }
        let now = Instant::now();
        {
            let local = self.local.lock();
            if let Some(entry) = local.entries.get(key)
                && entry.expires > now
                && valid(&entry.value)
            {
                return Ok(entry.value.clone());
            }
        }
        // Serialize local claim creation; no await occurs while this lock is held.
        let mut local = self.local.lock();
        if let Some(entry) = local.entries.get(key)
            && entry.expires > now
            && valid(&entry.value)
        {
            return Ok(entry.value.clone());
        }
        if let Some(old) = local.entries.remove(key) {
            local.expiry.remove(&(old.expires, old.order));
        }
        while let Some((&(expires, order), _)) = local.expiry.first_key_value() {
            if expires > now && local.entries.len() < self.cfg.capacity {
                break;
            }
            if let Some(key) = local.expiry.remove(&(expires, order)) {
                local.entries.remove(&key);
            }
        }
        local.serial = local.serial.wrapping_add(1);
        let order = local.serial;
        let expires = now
            .checked_add(self.cfg.ttl)
            .ok_or("stick TTL exceeds clock range")?;
        local.expiry.insert((expires, order), key.to_owned());
        local.entries.insert(
            key.to_owned(),
            Entry {
                value: proposal.clone(),
                expires,
                order,
            },
        );
        Ok(proposal)
    }

    pub fn len(&self) -> usize {
        let now = Instant::now();
        self.local
            .lock()
            .entries
            .values()
            .filter(|e| e.expires > now)
            .count()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mapping(name: &str) -> Mapping {
        Mapping {
            parents: vec![name.to_owned()],
            egress: None,
        }
    }

    #[tokio::test]
    async fn ttl_is_finite_capacity_is_bounded_and_claims_do_not_refresh() {
        let map = StickMap::new(&StickConfig {
            capacity: 2,
            ttl: Duration::from_millis(50),
            redis: None,
        })
        .expect("valid stick config");
        assert_eq!(
            map.claim("a", mapping("one"), |_| true)
                .await
                .expect("initial affinity claim"),
            mapping("one")
        );
        assert_eq!(
            map.claim("a", mapping("two"), |_| true)
                .await
                .expect("existing claim retained"),
            mapping("one")
        );
        map.claim("b", mapping("two"), |_| true)
            .await
            .expect("second affinity claim");
        map.claim("c", mapping("three"), |_| true)
            .await
            .expect("capacity eviction claim");
        assert_eq!(map.len(), 2);
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(map.is_empty());
        assert_eq!(
            map.claim("c", mapping("new"), |_| true)
                .await
                .expect("expired affinity claim"),
            mapping("new")
        );
    }

    #[tokio::test]
    async fn unhealthy_mapping_can_be_replaced() {
        let map = StickMap::new(&StickConfig::default()).expect("valid stick config");
        map.claim("a", mapping("dead"), |_| true)
            .await
            .expect("initial affinity claim");
        assert_eq!(
            map.claim("a", mapping("live"), |m| m.parents[0] != "dead")
                .await
                .expect("replacement claim"),
            mapping("live")
        );
    }
}
