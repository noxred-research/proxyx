-- KEYS[1] breaker hash; the failure zset is KEYS[1] .. ':fails' (same hash
-- tag). ARGV[1] JSON: op (peek | claim | success | failure), the config in ms,
-- idle ttl in ms. Returns {state, verdict}: state 0 closed, 1 half-open, 2
-- open; verdict 0 go (closed), 1 probe, 2 blocked. Only `claim` takes the
-- probe lease.
local p = cjson.decode(ARGV[1])
local h = KEYS[1]
local z = h .. ':fails'
local now = now_ms()
local s = redis.call('HMGET', h, 'state', 'opened', 'probe_after', 'passes', 'probe_until')
local state = tonumber(s[1]) or 0
local opened = tonumber(s[2]) or 0
local probe_after = tonumber(s[3]) or p.first
local passes = tonumber(s[4]) or 0
local probe_until = tonumber(s[5]) or 0

local function save()
  redis.call('HSET', h, 'state', state, 'opened', opened, 'probe_after', probe_after,
    'passes', passes, 'probe_until', probe_until)
  redis.call('PEXPIRE', h, p.idle)
end

local function open()
  state = 2
  opened = now
  probe_until = 0
  redis.call('DEL', z)
  save()
end

if p.op == 'peek' or p.op == 'claim' then
  if state == 0 then
    return { 0, 0 }
  end
  local probe_due
  if state == 2 then
    probe_due = now - opened >= probe_after
  else
    probe_due = probe_until <= now
  end
  if not probe_due then
    return { state, 2 }
  end
  if p.op == 'claim' then
    if state == 2 then
      state = 1
      passes = 0
    end
    probe_until = now + p.first
    save()
  end
  return { state, 1 }
elseif p.op == 'success' then
  if state == 1 then
    probe_until = 0
    passes = passes + 1
    if passes >= p.close_after then
      redis.call('DEL', h, z)
      return { 0, 0 }
    end
    save()
  end
  return { state, 0 }
else
  if state == 0 then
    redis.call('ZADD', z, now, now .. ':' .. redis.call('HINCRBY', h, 'seq', 1))
    redis.call('ZREMRANGEBYSCORE', z, '-inf', now - p.window)
    redis.call('PEXPIRE', z, p.idle)
    if redis.call('ZCARD', z) >= p.open_after then
      open()
    else
      redis.call('PEXPIRE', h, p.idle)
    end
  elseif state == 1 then
    probe_after = math.min(probe_after * 2, p.max)
    open()
  end
  return { state, 0 }
end
