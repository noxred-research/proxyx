-- Reserve one create when ready (free + leased) + in flight + reserved < max_ready.
-- ARGV[1] JSON: tag, id, max_ready, ttl (ms). Returns 1 when granted.
local p = cjson.decode(ARGV[1])
local now = now_ms()
local free, leased, creating, reserved = counts(p.tag, now)
if free + leased + creating + reserved >= p.max_ready then
  return 0
end
local rk = 'reserve:' .. p.tag
redis.call('ZADD', rk, now + p.ttl, p.id)
extend(rk, p.ttl)
return 1
