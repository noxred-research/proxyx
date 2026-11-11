-- Make a unit leasable. Keeps the lease history of an existing unit.
-- ARGV[1] JSON: tag, id, ip, expires_at (ms, 0 = none), ttl (ms, 0 = none),
-- owner ("" = any org may lease the unit; otherwise only that org),
-- degraded (true: the unit is leased only when no normal unit is left),
-- if_ready (true: change nothing unless the unit is leasable now).
-- Returns 1 when the unit was written, 0 when `if_ready` refused it.
local p = cjson.decode(ARGV[1])
if p.if_ready and redis.call('SISMEMBER', 'ready:' .. p.tag, p.id) == 0 then
  return 0
end
local uk = 'unit:' .. p.tag .. ':' .. p.id
redis.call('HSET', uk, 'ip', p.ip, 'expires_at', p.expires_at, 'owner', p.owner)
if p.degraded then
  redis.call('HSET', uk, 'tier', 'degraded')
else
  redis.call('HDEL', uk, 'tier')
end
if p.ttl > 0 then
  redis.call('PEXPIRE', uk, p.ttl)
else
  redis.call('PERSIST', uk)
end
redis.call('SADD', 'ready:' .. p.tag, p.id)
redis.call('ZREM', 'creating:' .. p.tag, p.id)
return 1
