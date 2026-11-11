-- ARGV[1] JSON: tag, and for rotating partitions after (drain | same_org) with
-- probe_org. Returns {sessions, reservations, leases} reclaimed.
-- Expired in-flight creates and reservations are dropped, expired lease
-- fields are removed, and a ready id whose unit record expired is forgotten.
-- The result is the book of everything dropped since the last sweep, by this
-- script or by any other that got there first (see reclaimed() in common.lua).
-- With `after`, a session that was leased and has no lease and no tunnel left
-- (its leases expired) is drained or kept for its org: a lease hash expires
-- with its last field, so the idle session itself is the signal.
local p = cjson.decode(ARGV[1])
local T = p.tag
local now = now_ms()
reclaimed(T, 'sessions', redis.call('ZREMRANGEBYSCORE', 'creating:' .. T, '-inf', now))
reclaimed(T, 'reservations', redis.call('ZREMRANGEBYSCORE', 'reserve:' .. T, '-inf', now))
for _, id in ipairs(redis.call('SMEMBERS', 'ready:' .. T)) do
  lease_expire(T, id, now)
  if type(p.after) == 'string' then
    released(T, id, p.after, p.probe_org, now)
  end
  if redis.call('EXISTS', 'unit:' .. T .. ':' .. id) == 0 then
    redis.call('SREM', 'ready:' .. T, id)
    reclaimed(T, 'sessions', 1)
  end
end
local book = redis.call('HMGET', 'reclaimed:' .. T, 'sessions', 'reservations', 'leases')
redis.call('DEL', 'reclaimed:' .. T)
return { tonumber(book[1]) or 0, tonumber(book[2]) or 0, tonumber(book[3]) or 0 }
