-- Add traffic bytes to the 1-minute bucket of a unit and drop old buckets.
-- ARGV[1] JSON: tag, unit, bytes.
local p = cjson.decode(ARGV[1])
local now = now_ms()
local tk = 'traf:' .. p.tag .. ':' .. p.unit
local minute = math.floor(now / 60000)
redis.call('HINCRBY', tk, minute, p.bytes)
for _, f in ipairs(redis.call('HKEYS', tk)) do
  if minute - tonumber(f) >= 10 then
    redis.call('HDEL', tk, f)
  end
end
redis.call('PEXPIRE', tk, 600000)
local uk = 'unit:' .. p.tag .. ':' .. p.unit
if redis.call('EXISTS', uk) == 1 then
  redis.call('HSET', uk, 'last_used', now)
end
return 1
