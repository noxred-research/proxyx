-- Claim due jobs: return up to ARGV[1] members whose time has come and push
-- each ARGV[2] ms ahead, so a crashed claimer's job comes back.
-- KEYS[1] zset of job -> due time (ms).
local now = now_ms()
local n, vis = tonumber(ARGV[1]), tonumber(ARGV[2])
local due = redis.call('ZRANGEBYSCORE', KEYS[1], '-inf', now, 'LIMIT', 0, n)
for _, m in ipairs(due) do
  redis.call('ZADD', KEYS[1], now + vis, m)
end
return due
