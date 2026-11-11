-- Record that the dial through one unit failed and say how many distinct units
-- of the partition failed one within the window. ARGV[1] JSON: tag, unit,
-- window (ms). Returns that number, this unit included. The gateway withdraws
-- a unit only while it is one of few: when several units of a route class
-- fail at once the provider failed, not the units.
local p = cjson.decode(ARGV[1])
local z = 'dialfail:' .. p.tag
local now = now_ms()
redis.call('ZADD', z, now, p.unit)
redis.call('ZREMRANGEBYSCORE', z, '-inf', now - p.window)
redis.call('PEXPIRE', z, p.window)
return redis.call('ZCARD', z)
