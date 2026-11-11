-- Lease or renew one (org, sticky key) in one partition, atomically
--. ARGV[1] is JSON:
--   mode: "lease" | "renew"      tag, org, sticky, host, tunnel, kind
--   lease_ttl, tunnel_ttl, prev_ttl, rest, min_remaining, min_dwell   (ms)
--   orgs_hard, max_conns, conns_ceiling   (0 = no limit)
--   allow_create           (bool)
--   blocked_ips            (units on these exit IPs are blocked for the org)
--   skip                   (units this call leaves out; nothing is withdrawn)
--   max_rank               how low a unit this call may take (see Ranks)
-- A unit with an `owner` field is invisible to every other org: it is neither
-- leased, shared, nor counted as blocked or busy for them.
-- Returns {outcome, unit, ip, orgs, tunnels, expires_at, limit, struck, fresh}, or
-- {outcome} for NONE (renew without lease), CREATE, EMPTY and BLOCKED, or
-- {'COOLED', cause} when the only thing between the org and a unit is that
-- every unit is cooled for this target (`cool:T:ip:host` holds the cause code
-- of the tunnel failure; a cooldown a block signal set holds "1" and answers
-- no_healthy_ip (static) or cache_empty (rotating)) and no create is under way
-- that could bring another one: waiting would only delay the answer. `limit` names the soft limit a SHARED or FREE lease broke
-- (see Last resort); it is '' when none was. `struck` is '1' when the unit
-- holds strikes (see Failed units), else ''. `fresh` is '1' when this call
-- bound the lease to the unit (new, or moved from another one) and so set its
-- `since` key, else ''.
-- {'LOWER', rank} when units exist that only a higher max_rank may take (see
-- Ranks).
--
-- Tiers. A unit whose hash holds tier = 'degraded' is slow but
-- clean: it is leased only when no normal unit can take the lease.
--
-- Ranks. The gateway walks several partitions (providers,
-- regions) and applies the tiers and limits across all of them: it asks every
-- partition for rank 0 first, then for the lowest rank any of them reported,
-- and so on. A call takes the best unit of rank <= max_rank:
--   0      a normal unit within the limits
--   1      a degraded unit within the limits
--   2..5   a normal unit breaking rest, orgs_hard, max_conns, fair_use (Last resort)
--   6..9   a degraded unit breaking the same
--   10     a unit that failed a tunnel at IP level a moment ago (see Failed units),
--          whatever its tier or limit
-- A lease on a degraded unit older than `min_dwell` is not renewed at rank 0:
-- it moves to a normal unit, or the answer is LOWER. 10 is "no limit".
--
-- Failed units. A tunnel that failed on a unit at IP level
-- (unit_strike.lua) leaves the unit `strikes` and a `penalty_until`, which the
-- gateway sets to 10 s and doubles on every further failure, up to 5 min; it
-- expires by itself, and a tunnel the unit serves clears it (the reply flags a
-- unit with strikes). Until then the unit is ranked below every other one,
-- for new leases and for the retry of a tunnel that failed, but it is not
-- withdrawn: it takes a lease when nothing else can. An existing lease stays
-- on it (it is cooled for the target that failed). Limits and tiers apply
-- among the failed units as among the others.
--
-- Org IP cap (static partitions). A new sticky key of an org
-- that holds `cap` static IPs already (a live lease on each) does not take
-- another IP: it reuses the org's least-loaded one. `cap` is
-- max(1, ceil(IPs of the partition / orgs holding leases in it)), the org
-- itself counted, so an org alone may use every IP and three orgs on ten IPs
-- hold 4 at most, not sharing an IP while the pool lasts. Only IPs this call
-- can use count (not cooled for the target, blocked for the org or skipped).
-- When an org holds more than its cap (it took the pool while alone) and none
-- is free, an org below its cap takes its next IP from the IPs of such an org,
-- until it holds `cap`; otherwise, and at its cap, it reuses its own
-- least-loaded IP. The cap does not touch a customer's own upstream, or a
-- rotating partition (sessions are created on demand).
--
-- Moving a lease. A lease that would renew on its unit in `lease`
-- mode (never in `renew`, the cheap traffic renewal) moves to another unit
-- instead when it is older than `min_dwell` and either
--   - its unit is degraded and a normal unit takes the lease, or
--   - the org holds more IPs than its cap, another org shares the unit, and the
--     org holds an IP that no other org shares.
-- Open tunnels are never cut: they stay on the old unit.
--
-- Last resort. A unit that only a soft limit keeps from the org is kept
-- back while any unit is free of limits, and leased when none is left, the
-- one that breaks the lowest limit first: (1) the rest of a free unit another
-- org held last, (2) `orgs_hard`, (3) `max_conns`, (4) the monthly fair-use
-- stop. A normal unit goes before a degraded one. The reply names the limit.
-- Only `max_conns` has a ceiling: a unit that holds `conns_ceiling` tunnels,
-- twice `max_conns` but never more than the provider allows per IP, is not
-- leased at all; with every unit there, the answer is
-- EMPTY and the caller waits as for any other lack of units.
local p = cjson.decode(ARGV[1])
local T = p.tag
local now = now_ms()
local ready = 'ready:' .. T
local lease_key = 'lease:' .. T .. ':' .. p.org .. ':' .. p.sticky
local since_key = 'since:' .. T .. ':' .. p.org .. ':' .. p.sticky
local field = p.org .. ':' .. p.sticky
local renew_only = p.mode == 'renew'

local LIMITS = { 'rest', 'orgs_hard', 'max_conns', 'fair_use' }
-- the rank of a unit that failed a tunnel lately: after every other unit
local WEAK_RANK = 10

local blocked = {}
for _, ip in ipairs(p.blocked_ips) do
  blocked[ip] = true
end

local skipped = {}
for _, id in ipairs(p.skip) do
  skipped[id] = true
end

local function inspect(id)
  local h = redis.call('HMGET', 'unit:' .. T .. ':' .. id,
    'ip', 'expires_at', 'last_org', 'last_used', 'held_until', 'owner', 'reserved', 'tier',
    'strikes', 'penalty_until')
  if not h[1] then
    redis.call('SREM', ready, id)
    reclaimed(T, 'sessions', 1)
    return nil
  end
  local orgs_key, n_orgs, n_leases, n_tunnels = holders(T, id, now)
  local has_org = n_orgs > 0 and redis.call('HEXISTS', orgs_key, p.org) == 1
  return {
    id = id,
    ip = h[1],
    expires_at = tonumber(h[2]) or 0,
    last_org = h[3] or '',
    last_used = tonumber(h[4]) or 0,
    held_until = tonumber(h[5]) or 0,
    owner = h[6] or '',
    reserved = h[7] or '',
    degraded = h[8] == 'degraded',
    struck = (tonumber(h[9]) or 0) > 0,
    penalized = (tonumber(h[10]) or 0) > now,
    has_org = has_org,
    orgs_key = orgs_key,
    n_orgs = n_orgs,
    n_leases = n_leases,
    tunnels = n_tunnels,
  }
end

local function alive(u)
  return u.expires_at == 0 or u.expires_at > now
end

local function mine(u)
  return u.owner == '' or u.owner == p.org
end

local function cooled(u)
  return redis.call('EXISTS', 'cool:' .. T .. ':' .. u.ip .. ':' .. p.host) == 1
end

-- What the units cooled for this target say, for the COOLED answer: how many
-- and the cause of the latest tunnel failure (the cooldown with the most time
-- left; a block signal's cooldown holds "1", no cause).
local cooled_n, cooled_cause, cooled_left = 0, nil, -1
local function note_cooled(u)
  local key = 'cool:' .. T .. ':' .. u.ip .. ':' .. p.host
  local why = redis.call('GET', key)
  cooled_n = cooled_n + 1
  if why == '1' then
    return
  end
  local left = redis.call('PTTL', key)
  if left > cooled_left then
    cooled_left, cooled_cause = left, why
  end
end

-- A static IP that used up its monthly fair-use traffic gets no NEW lease
-- until the month ends (Hot::fair_use_add). A lease it holds is renewed in
-- step 1 and goes on.
local function fair_stopped(u)
  return redis.call('EXISTS', 'fairstop:' .. T .. ':' .. u.ip) == 1
end

local function full(u)
  return p.max_conns > 0 and u.tunnels >= p.max_conns
end

local function at_ceiling(u)
  return p.conns_ceiling > 0 and u.tunnels >= p.conns_ceiling
end

local function over_orgs(u)
  return p.orgs_hard > 0 and not u.has_org and u.n_orgs >= p.orgs_hard
end

local cur = redis.call('GET', lease_key)

local function bind(u, outcome, limit)
  local expiry = now + p.lease_ttl
  redis.call('SET', lease_key, u.id, 'PX', p.lease_ttl)
  lease_set(T, u.id, field, expiry, p.lease_ttl)
  redis.call('HSET', 'unit:' .. T .. ':' .. u.id,
    'last_org', p.org, 'last_used', now, 'held_until', math.max(u.held_until, expiry))
  local tunnels = u.tunnels
  if not renew_only then
    local tk = 'tun:' .. T .. ':' .. u.id
    redis.call('ZADD', tk, now + p.tunnel_ttl, p.org .. '|' .. p.tunnel)
    extend(tk, p.tunnel_ttl)
    tunnels = tunnels + 1
    if p.kind == 'static' then
      redis.call('SET', 'prev:' .. T .. ':' .. p.org, u.id, 'PX', p.prev_ttl)
    end
  end
  if cur ~= u.id then
    -- the key exists for `min_dwell` after the lease came to this unit
    if p.min_dwell > 0 then
      redis.call('SET', since_key, 1, 'PX', p.min_dwell)
    end
    if cur then
      lease_drop(T, cur, field)
      lease_ended(T, cur, now)
    end
  end
  local orgs = u.n_orgs
  if not u.has_org then
    orgs = orgs + 1
  end
  local reply = {
    outcome, u.id, u.ip,
    string.format('%d', orgs), string.format('%d', tunnels), string.format('%d', u.expires_at),
    limit or '', u.struck and '1' or '', cur ~= u.id and '1' or '',
  }
  return reply
end

-- Classify every leasable unit (step 2). `moving` is the unit of the lease
-- that may move: it counts for the cap but is not offered.
-- free, shared    units no limit keeps from the org, by tier
-- strained        units only a soft limit keeps from the org (see Last resort)
-- A unit that failed a tunnel at IP level a moment ago (`penalized`, see Ranks)
-- is kept in a set of its own, leased only when the other set has no unit.
local function new_set()
  return {
    normal = { free = {}, shared = {} },
    slow = { free = {}, shared = {} },
    strained = {},
  }
end
local good, weak = new_set(), new_set()
local blocked_n, other_n = 0, 0
-- the static IPs of the partition the org cap counts (those this call can
-- use), and how many of them the org holds a lease on
local pool, held_n = {}, 0

local function classify(moving)
  for _, id in ipairs(redis.call('SMEMBERS', ready)) do
    local u = inspect(id)
    if u and mine(u) and alive(u) then
      if blocked[u.ip] then
        blocked_n = blocked_n + 1
      elseif skipped[u.id] then
        other_n = other_n + 1
      elseif u.expires_at ~= 0 and u.expires_at - now < p.min_remaining then
        other_n = other_n + 1
      elseif at_ceiling(u) then
        other_n = other_n + 1
      elseif cooled(u) then
        other_n = other_n + 1
        note_cooled(u)
      else
        if p.kind == 'static' and u.owner == '' then
          pool[#pool + 1] = u
          if u.has_org then
            held_n = held_n + 1
          end
        end
        local is_free = u.n_leases == 0 and u.tunnels == 0
        local lvl = 0
        if full(u) then
          lvl = 3
        end
        if fair_stopped(u) then
          lvl = 4
        end
        if u.id == moving then
          -- not offered
        elseif is_free and u.reserved ~= '' and u.reserved ~= p.org then
          -- a session kept for its org (after_release) is no one else's
          other_n = other_n + 1
        else
          if is_free then
            -- A unit that another org held last must rest before this org gets it.
            if u.last_org ~= '' and u.last_org ~= p.org and now < u.held_until + p.rest then
              lvl = math.max(lvl, 1)
            end
          elseif over_orgs(u) then
            lvl = math.max(lvl, 2)
          end
          local set = u.penalized and weak or good
          if lvl > 0 then
            u.lvl = lvl
            set.strained[#set.strained + 1] = u
            other_n = other_n + 1
          else
            local tier = u.degraded and set.slow or set.normal
            if is_free then
              tier.free[#tier.free + 1] = u
            else
              tier.shared[#tier.shared + 1] = u
            end
          end
        end
      end
    end
  end
end

local cap_cache, held_cache
-- Org IP cap: ceil(IPs of the partition / orgs holding a lease in it, this
-- one included), at least 1; and how many IPs each org holds.
local function org_cap()
  if cap_cache then
    return cap_cache, held_cache
  end
  local held, orgs = {}, 0
  for _, u in ipairs(pool) do
    if u.n_orgs > 0 then
      for _, org in ipairs(redis.call('HKEYS', u.orgs_key)) do
        if not held[org] then
          held[org] = 0
          orgs = orgs + 1
        end
        held[org] = held[org] + 1
      end
    end
  end
  if not held[p.org] then
    orgs = orgs + 1
  end
  cap_cache, held_cache = math.max(1, math.ceil(#pool / orgs)), held
  return cap_cache, held_cache
end

local function traffic(id)
  local all = redis.call('HGETALL', 'traf:' .. T .. ':' .. id)
  local minute = math.floor(now / 60000)
  local sum = 0
  for i = 1, #all, 2 do
    if minute - tonumber(all[i]) < 5 then
      sum = sum + tonumber(all[i + 1])
    end
  end
  return sum
end

-- Fewest orgs, then a unit an org over its cap holds, then fewest live leases
-- (so sessions spread even when tunnels close at once), then fewest tunnels,
-- then least traffic in the last 5 minutes.
local function lighter(u, b)
  if u.n_orgs ~= b.n_orgs then
    return u.n_orgs < b.n_orgs
  elseif (u.over or false) ~= (b.over or false) then
    return u.over or false
  elseif u.n_leases ~= b.n_leases then
    return u.n_leases < b.n_leases
  elseif u.tunnels ~= b.tunnels then
    return u.tunnels < b.tunnels
  end
  return u.traffic < b.traffic
end

local function least_loaded(units)
  local best
  for _, u in ipairs(units) do
    u.traffic = traffic(u.id)
    if not best or lighter(u, best) then
      best = u
    end
  end
  return best
end

-- Prefer a free unit. Static: this org's previous IP, else the least
-- recently used. Rotating: the least life left (min_remaining already holds).
local function pick_free(free)
  local best, best_key
  local prev = false
  if p.kind == 'static' then
    prev = redis.call('GET', 'prev:' .. T .. ':' .. p.org)
  end
  for _, u in ipairs(free) do
    if u.id == prev then
      return u
    end
    local key
    if p.kind == 'static' then
      key = u.last_used
    elseif u.expires_at == 0 then
      key = math.huge
    else
      key = u.expires_at - now
    end
    if not best or key < best_key then
      best, best_key = u, key
    end
  end
  return best
end

-- Steps 3 to 5 over the units of one tier: the unit and the outcome, or nil
-- and 'CREATE' (rotating: ask the caller to create a session).
local function pick(tier, may_create)
  local free, shared = tier.free, tier.shared
  -- 3. A static org at its IP cap takes no further free IP: this sticky key
  -- reuses the org's least-loaded one (when one can take it).
  local own = {}
  if held_n > 0 then
    for _, u in ipairs(shared) do
      if u.has_org then
        own[#own + 1] = u
      end
    end
    if #own > 0 and held_n >= org_cap() then
      return least_loaded(own), 'SHARED'
    end
  end

  local f = pick_free(free)
  if f then
    return f, 'FREE'
  end

  -- 4. Rotating: ask the caller to create a session.
  if may_create then
    return nil, 'CREATE'
  end

  -- 5. Share. Mark the IPs an org over its cap holds (it took the pool while
  -- alone). An org below its cap takes its next IP from those; with none it
  -- reuses its own. Orgs all within their cap never take each other's IPs.
  local cands = shared
  if p.kind == 'static' and #shared > 0 then
    local cap, held = org_cap()
    for _, u in ipairs(shared) do
      if u.n_orgs > 0 then
        for _, org in ipairs(redis.call('HKEYS', u.orgs_key)) do
          if (held[org] or 0) > cap then
            u.over = true
          end
        end
      end
    end
  end
  if #own > 0 then
    cands = {}
    for _, u in ipairs(shared) do
      if u.over and not u.has_org then
        cands[#cands + 1] = u
      end
    end
    if #cands == 0 then
      cands = own
    end
  end
  return least_loaded(cands), 'SHARED'
end

-- Last resort: the unit of `strained` that breaks the lowest limit, a normal
-- one before a degraded one. Returns the unit, its outcome, the limit broken
-- and its rank.
local function pick_strained(strained)
  for _, want_degraded in ipairs({ false, true }) do
    local lvl = 5
    for _, u in ipairs(strained) do
      if u.degraded == want_degraded and u.lvl < lvl then
        lvl = u.lvl
      end
    end
    local cands = {}
    for _, u in ipairs(strained) do
      if u.degraded == want_degraded and u.lvl == lvl then
        cands[#cands + 1] = u
      end
    end
    local best = least_loaded(cands)
    if best then
      local outcome = (best.n_leases == 0 and best.tunnels == 0) and 'FREE' or 'SHARED'
      return best, outcome, LIMITS[lvl], (want_degraded and 5 or 1) + lvl
    end
  end
end

-- Steps 3 to 5 over the normal units of a set, then the degraded ones, then
-- the last resort. Returns the unit, outcome, limit broken and rank of the
-- unit, or nil and 'CREATE' when a session is to be created, or nil.
local function choose_in(set, may_create)
  local u, outcome = pick(set.normal, may_create)
  if u or outcome == 'CREATE' then
    return u, outcome, nil, 0
  end
  u, outcome = pick(set.slow, false)
  if u then
    return u, outcome, nil, 1
  end
  return pick_strained(set.strained)
end

-- The units that did not fail a tunnel lately go first, whatever their tier or
-- limit; the others take the lease at WEAK_RANK, with the same order inside.
-- A rotating session is never created for the others: the create comes first.
local function choose()
  local u, outcome, limit, rank = choose_in(good, p.kind == 'rotating' and p.allow_create)
  if u or outcome == 'CREATE' then
    return u, outcome, limit, rank
  end
  u, outcome, limit = choose_in(weak, false)
  if u then
    return u, outcome, limit, WEAK_RANK
  end
end

-- The unit a lease on `cur_u` moves to, if it does (see Moving a lease).
local function move_target(cur_u)
  classify(cur_u.id)
  local b, outcome, limit, rank = choose()
  if not b or limit or b.penalized or rank > p.max_rank then
    return nil
  end
  if cur_u.penalized or (cur_u.degraded and not b.degraded) then
    return b, outcome
  end
  if p.kind == 'static' and cur_u.n_orgs > 1 and b.has_org and b.n_orgs == 1
      and held_n > org_cap() then
    return b, outcome
  end
end

-- 1. The existing lease renews unless its unit is gone, cooled for this
-- target, blocked, full or past its life. A lease older than the dwell on a
-- degraded or failed unit is left for step 2 by a call that may not take such
-- a unit (rank 0, or below WEAK_RANK): it moves to a better unit, or the
-- answer is LOWER.
if cur and redis.call('SISMEMBER', ready, cur) == 1 then
  local u = inspect(cur)
  if u and mine(u) and alive(u) and not blocked[u.ip] and not skipped[u.id] and not cooled(u)
      and not over_orgs(u)
      and (renew_only or not full(u)) then
    local movable = not renew_only and u.owner == ''
      and (u.degraded or u.penalized or (p.kind == 'static' and u.n_orgs > 1))
      and redis.call('EXISTS', since_key) == 0
    if not (movable and ((u.degraded and p.max_rank < 1) or (u.penalized and p.max_rank < WEAK_RANK))) then
      if movable then
        local b, outcome = move_target(u)
        if b then
          return bind(b, outcome)
        end
      end
      return bind(u, 'HIT')
    end
  end
end
if renew_only then
  return { 'NONE' }
end

-- 2. Classify every leasable unit, then pick.
classify(nil)
local u, outcome, limit, rank = choose()
if u then
  if rank > p.max_rank then
    return { 'LOWER', string.format('%d', rank) }
  end
  return bind(u, outcome, limit)
end
if outcome == 'CREATE' then
  return { 'CREATE' }
end

if blocked_n > 0 and other_n == 0 then
  return { 'BLOCKED' }
end
if blocked_n == 0 and cooled_n > 0 and cooled_n == other_n
    and redis.call('ZCOUNT', 'creating:' .. T, string.format('(%d', now), '+inf') == 0
    and redis.call('ZCOUNT', 'reserve:' .. T, string.format('(%d', now), '+inf') == 0 then
  if cooled_cause then
    return { 'COOLED', cooled_cause }
  end
  return { 'COOLED', p.kind == 'static' and 'no_healthy_ip' or 'cache_empty' }
end
return { 'EMPTY' }
