-- Turn a reservation into an in-flight create. The total stays the same.
-- ARGV[1] JSON: tag, reservation, session, ttl (ms).
-- Returns 1 when the reservation was still live. A reservation that expired
-- (or was given back) starts nothing: the caller does not spawn the create,
-- so an in-flight entry would only hold a slot until its own deadline.
local p = cjson.decode(ARGV[1])
local now = now_ms()
local held = redis.call('ZREM', 'reserve:' .. p.tag, p.reservation)
if held == 1 then
  local ck = 'creating:' .. p.tag
  redis.call('ZADD', ck, now + p.ttl, p.session)
  extend(ck, p.ttl)
end
return held
