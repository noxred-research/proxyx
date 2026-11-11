-- Count an open tunnel of an org against max_tunnels_per_org.
-- KEYS[1] zset, ARGV: tunnel id, cap (0 = none), ttl (ms). Returns 1 when counted.
local now = now_ms()
local ttl = tonumber(ARGV[3])
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now)
local known = redis.call('ZSCORE', KEYS[1], ARGV[1]) ~= false
local cap = tonumber(ARGV[2])
if not known and cap > 0 and redis.call('ZCARD', KEYS[1]) >= cap then
  return 0
end
redis.call('ZADD', KEYS[1], now + ttl, ARGV[1])
extend(KEYS[1], ttl)
return 1
