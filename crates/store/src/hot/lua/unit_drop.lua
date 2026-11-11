-- Forget a unit. Leases that point at it fail their next renew.
-- ARGV[1] JSON: tag, id.
local p = cjson.decode(ARGV[1])
local T = p.tag
local removed = redis.call('SREM', 'ready:' .. T, p.id)
redis.call('DEL', 'unit:' .. T .. ':' .. p.id, 'ulz:' .. T .. ':' .. p.id,
  'uorgs:' .. T .. ':' .. p.id, 'tun:' .. T .. ':' .. p.id, 'traf:' .. T .. ':' .. p.id)
return removed
