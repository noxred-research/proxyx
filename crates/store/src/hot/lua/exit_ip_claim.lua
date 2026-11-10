-- Claim an exit IP for one session. KEYS[1] ip key, ARGV[1] owner, ARGV[2] ms.
-- Returns "" when claimed (or already ours), else the other owner.
local cur = redis.call('GET', KEYS[1])
if not cur then
  redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])
  return ''
end
if cur == ARGV[1] then
  redis.call('PEXPIRE', KEYS[1], ARGV[2])
  return ''
end
return cur
