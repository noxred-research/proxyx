-- Close one tunnel. ARGV[1] JSON: tag, unit, member ("org|tunnel"), mark_ttl (ms).
-- A unit left with no lease and no tunnel starts resting now. The closed
-- marker makes a touch already in flight when the tunnel closed a no-op
-- (see tunnel_touch.lua); it is set even when the counter had forgotten the
-- tunnel.
local p = cjson.decode(ARGV[1])
redis.call('SET', 'tunx:' .. p.tag .. ':' .. p.member, 1, 'PX', p.mark_ttl)
local removed = redis.call('ZREM', 'tun:' .. p.tag .. ':' .. p.unit, p.member)
if removed == 1 then
  rest_if_idle(p.tag, p.unit, now_ms())
end
return removed
