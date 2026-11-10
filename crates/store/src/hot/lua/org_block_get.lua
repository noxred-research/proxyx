-- Live org-block fields of one org. KEYS[1] hash of field -> expiry (ms, 0 = never).
local now = now_ms()
local live = {}
local all = redis.call('HGETALL', KEYS[1])
for i = 1, #all, 2 do
  local exp = tonumber(all[i + 1])
  if exp == 0 or exp > now then
    live[#live + 1] = all[i]
  else
    redis.call('HDEL', KEYS[1], all[i])
  end
end
return live
