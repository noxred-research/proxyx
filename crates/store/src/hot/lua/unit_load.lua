-- ARGV[1] JSON: tag, id, and optionally skip_leases_of (an org whose leases
-- are not counted: the probe org's sample pin). Returns {orgs, leases,
-- tunnels}; tunnels always count every org's.
local p = cjson.decode(ARGV[1])
local ok, n_orgs, n_leases, n_tunnels = holders(p.tag, p.id, now_ms())
if p.skip_leases_of and n_leases > 0 then
  local skipped = tonumber(redis.call('HGET', ok, p.skip_leases_of)) or 0
  if skipped > 0 then
    n_orgs = n_orgs - 1
    n_leases = n_leases - skipped
  end
end
return { n_orgs, n_leases, n_tunnels }
