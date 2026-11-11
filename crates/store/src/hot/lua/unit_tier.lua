-- Set the tier of a unit that has a record; never creates one.
-- ARGV[1] JSON: tag, id, degraded (true: leased only when no normal unit is
-- left). Returns 1 when the unit has a record, else 0.
local p = cjson.decode(ARGV[1])
local uk = 'unit:' .. p.tag .. ':' .. p.id
if redis.call('EXISTS', uk) == 0 then
  return 0
end
if p.degraded then
  redis.call('HSET', uk, 'tier', 'degraded')
else
  redis.call('HDEL', uk, 'tier')
end
return 1
