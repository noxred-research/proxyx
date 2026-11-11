-- An org's open tunnels on one provider (route class): what a route class's
-- max_tunnels_per_org is compared with. The org-wide count
-- (org_tunnel_open.lua) stays the cap on the org's tunnels in total.
-- KEYS[1] zset tunnel id -> deadline (ms), one per org and provider.
-- ARGV: op, tunnel id, ttl (ms), cap.
--   open   count the tunnel unless the org holds `cap` tunnels on the provider
--          already (a counted tunnel only refreshes); returns 1 when counted
--   touch  push the deadline of a counted tunnel; a tunnel that is not counted
--          (closed, or forgotten) stays out, so a touch in flight when the
--          tunnel closed does not bring it back
--   close  stop counting it
local now = now_ms()
local op = ARGV[1]
if op == 'close' then
  return redis.call('ZREM', KEYS[1], ARGV[2])
end
local known = redis.call('ZSCORE', KEYS[1], ARGV[2]) ~= false
if op == 'touch' then
  if not known then
    return 0
  end
else
  redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now)
  if not known and redis.call('ZCARD', KEYS[1]) >= tonumber(ARGV[4]) then
    return 0
  end
end
local ttl = tonumber(ARGV[3])
redis.call('ZADD', KEYS[1], now + ttl, ARGV[2])
extend(KEYS[1], ttl)
return 1
