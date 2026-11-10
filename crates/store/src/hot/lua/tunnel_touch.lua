-- Extend one tunnel deadline, and count the tunnel again when the counter
-- forgot it (Redis lost its data, or was out for longer than the tunnel TTL).
-- A tunnel that tunnel_close ended is not counted again: its marker blocks a
-- touch that was already in flight when the tunnel closed.
-- ARGV[1] JSON: tag, unit, member, ttl. Returns 1 when the tunnel is counted,
-- 0 when it was closed.
local p = cjson.decode(ARGV[1])
local tk = 'tun:' .. p.tag .. ':' .. p.unit
if redis.call('ZSCORE', tk, p.member) == false
    and redis.call('EXISTS', 'tunx:' .. p.tag .. ':' .. p.member) == 1 then
  return 0
end
redis.call('ZADD', tk, now_ms() + p.ttl, p.member)
extend(tk, p.ttl)
return 1
