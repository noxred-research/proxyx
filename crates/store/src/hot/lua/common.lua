-- Helpers every script gets in front of its own text. Keys of one partition
-- all contain the hash tag T (for example "{isp_static_port:fr}"):
--   ready:T            set of leasable unit ids
--   unit:T:id          hash: ip, expires_at, last_org, last_used, held_until; tier is
--                      'degraded' for a slow unit (absent or 'normal': normal tier);
--                      strikes, penalty_until (ms) after a tunnel failed on the unit at
--                      IP level: it is leased last until penalty_until (unit_strike.lua)
--   ulz:T:id, uorgs:T:id   live leases of a unit, see holders() below
--   lease:T:org:sticky string: unit id, PX lease_ttl
--   since:T:org:sticky string, PX min_dwell (60 s): the lease came to its unit that recently;
--                      its absence lets the lease move (lease.lua, "Moving a lease")
--   tun:T:id           zset: "org|tunnel" -> deadline (ms)
--   tunx:T:org|tunnel  string, PX CLOSED_MARK_TTL: the tunnel was closed (blocks a late touch)
--   traf:T:id          hash: minute -> bytes
--   prev:T:org         string: the unit this org held last (static)
--   cool:T:ip:host     string, PX target_cooldown
--   creating:T, reserve:T   zsets: id -> deadline (ms)
--   reclaimed:T        hash: sessions | reservations | leases -> state dropped by any
--                      script since the last sweep (see reclaimed() below)
-- Times are milliseconds from the Redis clock, so replicas agree.
-- A partition script gets KEYS[1] = ready:T only to name the cluster slot:
-- every key it touches carries the same hash tag T.

local function now_ms()
  local t = redis.call('TIME')
  return tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
end

-- Raise the TTL of a key to at least ms.
local function extend(key, ms)
  if redis.call('PTTL', key) < ms then
    redis.call('PEXPIRE', key, ms)
  end
end

-- Every script that drops expired state (counts, holders, the leasing scripts,
-- the sweep itself) books it here, so the sweeper's metric counts what was
-- reclaimed by whoever got to it first. The sweep takes the book and clears
-- it. The TTL only bounds the key when no sweeper runs.
local RECLAIMED_TTL_MS = 3600000
local function reclaimed(T, kind, n)
  if n > 0 then
    local key = 'reclaimed:' .. T
    redis.call('HINCRBY', key, kind, n)
    extend(key, RECLAIMED_TTL_MS)
  end
end

-- Live leases of a unit are indexed twice, so reading them costs the number
-- of leases that EXPIRED since the last read, not the number that exist (a
-- fresh sticky key per request leaves thousands of live leases per unit):
--   ulz:T:id    zset: "org:sticky" -> lease expiry (ms)
--   uorgs:T:id  hash: org -> number of live "org:sticky" members of ulz
local function lease_org(field)
  return string.match(field, '^([^:]*):')
end

-- Take one member out of the index of a unit (`ok` is its uorgs key).
local function lease_uncount(ok, field)
  local org = lease_org(field)
  if redis.call('HINCRBY', ok, org, -1) <= 0 then
    redis.call('HDEL', ok, org)
  end
end

-- Both index keys outlive their last lease by LEASE_INDEX_MARGIN_MS, so the
-- sweeper (every 30 s) still finds the expired members of a unit whose last
-- lease ended and counts them; without it the keys expired together with
-- that lease and the leak of a killed gateway was invisible.
local LEASE_INDEX_MARGIN_MS = 120000

-- Add or renew the lease of "org:sticky" on a unit until `expiry`.
local function lease_set(T, id, field, expiry, ttl)
  local zk, ok = 'ulz:' .. T .. ':' .. id, 'uorgs:' .. T .. ':' .. id
  if redis.call('ZADD', zk, expiry, field) == 1 then
    redis.call('HINCRBY', ok, lease_org(field), 1)
  end
  extend(zk, ttl + LEASE_INDEX_MARGIN_MS)
  extend(ok, ttl + LEASE_INDEX_MARGIN_MS)
end

-- End the lease of "org:sticky" on a unit.
local function lease_drop(T, id, field)
  if redis.call('ZREM', 'ulz:' .. T .. ':' .. id, field) == 1 then
    lease_uncount('uorgs:' .. T .. ':' .. id, field)
  end
end

-- Forget the leases of a unit that expired. Only a per-connection lease
-- ("org:conn:<tunnel>") counts as reclaimed: the gateway releases it when its
-- tunnel ends, so one that expired was leaked by a gateway that died. A sticky
-- lease (sid, org, target scope) has no release call and ends by expiry
-- whenever its client stops asking: booking those would page on normal traffic.
local function lease_expire(T, id, now)
  local zk = 'ulz:' .. T .. ':' .. id
  local dead = redis.call('ZRANGEBYSCORE', zk, '-inf', now)
  if #dead > 0 then
    local ok = 'uorgs:' .. T .. ':' .. id
    local leaked = 0
    for _, field in ipairs(dead) do
      lease_uncount(ok, field)
      if string.find(field, '^[^:]*:conn:') then
        leaked = leaked + 1
      end
    end
    redis.call('ZREMRANGEBYSCORE', zk, '-inf', now)
    reclaimed(T, 'leases', leaked)
  end
end

-- Live holders of a unit. Drops expired leases and tunnels on the way.
-- Returns: the key of the hash org -> live leases (HEXISTS tells whether an
-- org holds the unit), number of orgs, number of live leases, number of
-- open tunnels.
local function holders(T, id, now)
  lease_expire(T, id, now)
  local ok = 'uorgs:' .. T .. ':' .. id
  local n_leases = redis.call('ZCARD', 'ulz:' .. T .. ':' .. id)
  local n_orgs = 0
  if n_leases > 0 then
    n_orgs = redis.call('HLEN', ok)
  else
    redis.call('DEL', ok)
  end
  local tk = 'tun:' .. T .. ':' .. id
  redis.call('ZREMRANGEBYSCORE', tk, '-inf', now)
  return ok, n_orgs, n_leases, redis.call('ZCARD', tk)
end

-- Counts of one partition: free ready units, leased ready units, creates in
-- flight and reservations, and how many of the free units are degraded.
-- Expired in-flight entries are dropped first.
local function counts(T, now)
  local free, leased, degraded = 0, 0, 0
  local ready = 'ready:' .. T
  for _, id in ipairs(redis.call('SMEMBERS', ready)) do
    local h = redis.call('HMGET', 'unit:' .. T .. ':' .. id, 'ip', 'expires_at', 'tier')
    if not h[1] then
      redis.call('SREM', ready, id)
      reclaimed(T, 'sessions', 1)
    else
      local exp = tonumber(h[2]) or 0
      if exp == 0 or exp > now then
        local _, _, n_leases, n_tunnels = holders(T, id, now)
        if n_leases == 0 and n_tunnels == 0 then
          free = free + 1
          if h[3] == 'degraded' then
            degraded = degraded + 1
          end
        else
          leased = leased + 1
        end
      end
    end
  end
  reclaimed(T, 'sessions', redis.call('ZREMRANGEBYSCORE', 'creating:' .. T, '-inf', now))
  reclaimed(T, 'reservations', redis.call('ZREMRANGEBYSCORE', 'reserve:' .. T, '-inf', now))
  return free, leased, redis.call('ZCARD', 'creating:' .. T), redis.call('ZCARD', 'reserve:' .. T), degraded
end

-- A rotating unit that lost its last lease and tunnel (policy
-- rotating.after_release). `mode`: 'drain' takes the session out of the ready
-- set, 'same_org' reserves it for the org that used it. Does nothing for a
-- unit that was never leased (a pin or a fresh candidate) and for one the
-- probe org used last: a browser sample must not burn the session it tested.
local function released(T, id, mode, probe_org, now)
  local uk = 'unit:' .. T .. ':' .. id
  local last = redis.call('HGET', uk, 'last_org')
  if not last or last == '' or last == probe_org then
    return
  end
  local _, _, n_leases, n_tunnels = holders(T, id, now)
  if n_leases > 0 or n_tunnels > 0 then
    return
  end
  if mode == 'drain' then
    redis.call('SREM', 'ready:' .. T, id)
  elseif mode == 'same_org' then
    redis.call('HSET', uk, 'reserved', last)
  end
end

-- A unit that lost its last lease and tunnel starts resting now. Does nothing
-- for a unit whose record is gone.
local function rest_if_idle(T, id, now)
  local uk = 'unit:' .. T .. ':' .. id
  if redis.call('EXISTS', uk) == 0 then
    return
  end
  local _, _, n_leases, n_tunnels = holders(T, id, now)
  if n_leases == 0 and n_tunnels == 0 then
    redis.call('HSET', uk, 'held_until', now)
  end
end

-- A lease left a unit (release or rebind to another unit). A unit with no
-- lease and no tunnel starts resting now. A unit that keeps other leases is
-- held only until the last of them ends, not until the expiry of the lease
-- that left (which may have been far longer). Does nothing for a unit whose
-- record is gone.
local function lease_ended(T, id, now)
  local uk = 'unit:' .. T .. ':' .. id
  if redis.call('EXISTS', uk) == 0 then
    return
  end
  local _, _, n_leases, n_tunnels = holders(T, id, now)
  if n_leases > 0 then
    local last = redis.call('ZREVRANGE', 'ulz:' .. T .. ':' .. id, 0, 0, 'WITHSCORES')
    redis.call('HSET', uk, 'held_until', math.max(now, tonumber(last[2])))
  elseif n_tunnels == 0 then
    redis.call('HSET', uk, 'held_until', now)
  end
end
