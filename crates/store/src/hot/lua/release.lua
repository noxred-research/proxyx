-- End one lease. ARGV[1] JSON: tag, org, sticky, and for a rotating unit
-- after (null | "drain" | "same_org") with probe_org. With `unit` set the
-- lease ends only while it is on that unit, and its dwell key goes too: the
-- tunnel that bound it there was not served, so the lease never settled.
-- Returns 1 when a lease existed. A unit left with no lease and no tunnel
-- starts resting now, and `after` decides what becomes of a rotating session.
local p = cjson.decode(ARGV[1])
local T = p.tag
local now = now_ms()
local key = 'lease:' .. T .. ':' .. p.org .. ':' .. p.sticky
local cur = redis.call('GET', key)
if not cur or (p.unit and p.unit ~= cur) then
  return 0
end
redis.call('DEL', key)
if p.unit then
  redis.call('DEL', 'since:' .. T .. ':' .. p.org .. ':' .. p.sticky)
end
lease_drop(T, cur, p.org .. ':' .. p.sticky)
lease_ended(T, cur, now)
if type(p.after) == 'string' then
  released(T, cur, p.after, p.probe_org, now)
end
return 1
