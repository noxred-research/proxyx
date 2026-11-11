-- A tunnel failed on a unit at IP level (op 'fail'), or the unit served one
-- (op 'ok'); never creates a unit record. ARGV[1] JSON: tag, id, op, base,
-- max (ms). A failure puts the unit at the back of the leasing order until
-- `penalty_until` (lease.lua, Failed units): `base`, doubled for every
-- failure that follows within `max` of the last penalty ending, up to `max`.
-- `strikes` and `penalty_until` are fields of the unit hash, so nothing needs
-- a timer: both are read against the clock. Returns the penalty set, in ms,
-- or 0.
local p = cjson.decode(ARGV[1])
local uk = 'unit:' .. p.tag .. ':' .. p.id
if redis.call('EXISTS', uk) == 0 then
  return 0
end
if p.op == 'ok' then
  redis.call('HDEL', uk, 'strikes', 'penalty_until')
  return 0
end
local now = now_ms()
local h = redis.call('HMGET', uk, 'strikes', 'penalty_until')
local strikes = tonumber(h[1]) or 0
if (tonumber(h[2]) or 0) + p.max <= now then
  strikes = 0
end
strikes = math.min(strikes + 1, 30)
local penalty = math.min(p.base * 2 ^ (strikes - 1), p.max)
redis.call('HSET', uk, 'strikes', strikes, 'penalty_until', string.format('%d', now + penalty))
return math.floor(penalty)
