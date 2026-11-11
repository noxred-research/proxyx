-- Bind a ready unit to an org's sticky key without opening a tunnel.
-- ARGV[1] JSON: tag, org, sticky, unit, ttl (ms). Returns 1 when the unit is
-- in the ready set and now carries the org's lease for the sticky key.
local p = cjson.decode(ARGV[1])
local T = p.tag
if redis.call('SISMEMBER', 'ready:' .. T, p.unit) == 0 then
  return 0
end
local expiry = now_ms() + p.ttl
redis.call('SET', 'lease:' .. T .. ':' .. p.org .. ':' .. p.sticky, p.unit, 'PX', p.ttl)
lease_set(T, p.unit, p.org .. ':' .. p.sticky, expiry, p.ttl)
return 1
