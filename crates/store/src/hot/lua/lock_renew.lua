-- Extend a lock only for its holder. KEYS[1] lock, ARGV[1] holder, ARGV[2] ms.
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('PEXPIRE', KEYS[1], ARGV[2])
end
return 0
