# Edge proxy: ProxyX on a machine with many IP addresses

`proxyx edge` turns one machine into a proxy gateway over its own IP addresses. Install it on a host that has several IPv4 or IPv6 addresses (or a whole routed IPv6 block), and clients reach the internet through the proxy with the source address you choose: fixed per listener, per user, per rule, round robin, random, least busy, or sticky per session.

It needs no database: one TOML file ([`examples/edge.toml`](../examples/edge.toml)), one process. Redis is optional for shared affinity between replicas. For the pool gateway, which leases rented and rotating IPs from many providers with Postgres and Redis behind it, see [gateway.md](gateway.md); the two can be combined, see [Using the machine's addresses from the pool gateway](#using-the-machines-addresses-from-the-pool-gateway).

| | `proxyx edge` | `proxyx gateway` |
|---|---|---|
| State | one TOML file, SIGHUP reload | Postgres (truth), Redis (hot state) |
| Exit IPs | the machine's own addresses | upstream providers, rented IPs, SIM boxes |
| Clients | HTTP proxy, `CONNECT`, SOCKS4/4a/5 (TCP, BIND and UDP), optional TLS | `CONNECT` and SOCKS5 |
| Accounts | static users, htpasswd file, login options | org keys, policies, budgets |
| Scale | one host | a fleet |

## Quick start

```sh
cargo build --release -p proxyx
proxyx edge --check --config examples/edge-loopback.toml     # validates, prints the pools
proxyx edge --config examples/edge-loopback.toml &
```

[`examples/edge-loopback.toml`](../examples/edge-loopback.toml) runs on any Linux machine: all of `127.0.0.0/8` is local, so `127.0.0.2`, `127.0.0.3` and `127.0.0.4` stand in for three public addresses. Start any server on `127.0.0.1:8080` that prints the address that connected to it (the sticky session below shows the same address every time, a new session id picks another):

```sh
$ curl -s -x http://alice-sid-job1:wonderland@127.0.0.1:3128 http://origin.test:8080/ip
127.0.0.3
$ curl -s -x http://alice-sid-job1:wonderland@127.0.0.1:3128 http://origin.test:8080/ip
127.0.0.3
$ curl -s -x http://alice-sid-job2:wonderland@127.0.0.1:3128 http://origin.test:8080/ip
127.0.0.4
$ curl -s -x socks5h://alice-sid-job1:wonderland@127.0.0.1:3128 http://origin.test:8080/ip
127.0.0.3
```

## Installing on a multi-IP host

1. **Put the addresses on the machine.** The proxy only connects *from* addresses the host owns; it never configures the network. Add an address with `ip addr add 192.0.2.11/24 dev eth0` (a secondary address on the interface that already has the subnet) and `ip -6 addr add 2001:db8::11/64 dev eth0` for IPv6. Make them permanent with the tool that configures the interface (netplan `addresses:`, NetworkManager, `systemd-networkd` `Address=`, `/etc/network/interfaces`). Cloud hosts usually need the address attached to the instance's network interface in the provider's console first. Check with `ip -brief addr`.
2. **A whole IPv6 block** (a routed /64 or /48): do not add every address. Route the block to the host instead, `ip route add local 2001:db8:1234::/64 dev lo`, and name it in a pool as `prefixes = ["2001:db8:1234::/64"]`. Every connection then draws its source address from the block.
3. **Reverse path filtering and the firewall.** Replies to a secondary address return on the interface that owns it, so default `rp_filter` works; if you use `rp_filter = 1` with several interfaces, route each source address out of the interface it lives on (`ip rule add from 192.0.2.11 lookup 100`). Allow the listener ports (`3128`, `1080`) inbound and nothing else.
4. **Install the binary and the unit.** Copy `proxyx` to `/usr/local/bin`, `deploy/systemd/proxyx-edge.sysusers.conf` to `/etc/sysusers.d/proxyx.conf` (`systemd-sysusers`), and `deploy/systemd/proxyx-edge.service` to `/etc/systemd/system/`. Put the configuration in `/etc/proxyx/edge.toml` (`chown root:proxyx`, mode `0640`, and the htpasswd file likewise): the unit runs `proxyx edge --check` before every start, reloads on `systemctl reload proxyx-edge`, and runs as the unprivileged `proxyx` user with only `CAP_NET_BIND_SERVICE` (needed only for a listener below port 1024).
5. **Check, then start.** `proxyx edge --check --config /etc/proxyx/edge.toml` fails when a listed address is not assigned to the host or cannot be bound, when a rule names a user or pool that does not exist, when a password hash format is not supported, and on any misspelled key. `systemctl enable --now proxyx-edge`.
6. **Rotate the access log** with `logrotate` and `postrotate systemctl reload proxyx-edge` (SIGHUP reopens the file).

## Listeners

Each `[[listener]]` is a port with a name. `protocol = "auto"` (the default) serves the HTTP proxy, `CONNECT`, SOCKS4, SOCKS4a and SOCKS5 on one port, told apart by the first byte; `http` or `socks` restricts it. A listener is a security boundary: `auth = "users"` (the default) requires a login, `auth = "none"` relies on the access rules (use a source-address rule and bind a private interface).

```toml
[[listener]]
name = "public"
listen = "0.0.0.0:3128"
auth = "users"
udp = true                      # SOCKS5 UDP ASSOCIATE

[[listener]]
name = "fixed-exit"
listen = "192.0.2.10:3129"
auth = "none"
pool = "primary"                # everything on this port leaves from the pool "primary"
```

Behind a TCP load balancer set `proxy_protocol = "optional"` or `"required"` and `trusted_proxies = ["10.0.0.0/8"]`: the PROXY protocol v1 or v2 header sets the client address for the rules, limits and access log, and only the listed peers are believed (a header from anyone else is ignored, or the connection is closed when the header is `required`). The edge can also send the header to a [parent](#parent-proxies) (`send_proxy_protocol = "v1"` or `"v2"` on the parent), so the parent sees the client's address.

Add `tls = { cert = "/etc/proxyx/tls/edge.pem", key = "/etc/proxyx/tls/edge-key.pem" }`
to wrap the listener in TLS. PEM certificates and private keys are read and validated before
the listener starts; reload replaces credentials for new connections. A mixed TLS listener
accepts HTTPS proxy requests and SOCKS5-over-TLS after decryption. Clients must verify the
proxy certificate. TLS protects proxy credentials in transit; Basic and RFC 1929 alone do not.
PROXY protocol, when configured, precedes the TLS handshake and remains restricted to trusted peers.
TLS encrypts the SOCKS5 UDP association's control connection only. UDP relay datagrams
remain unencrypted; use a separately secured network when UDP payload confidentiality matters.

SOCKS5 `BIND` sends the listening address in its first success reply, then the accepted peer
address in its second. Only a resolved requested peer IP and its nonzero requested port may
connect; port zero allows any source port for that checked IP. Wildcard destination addresses
are refused. Acceptance is bounded by `timeouts.connect` and 64 unexpected peers. BIND uses
direct local egress, not a reverse tunnel through parents. Authorize it with `method = ["BIND"]`;
normal private-destination protection still applies.
The expected peer must be able to reach the returned ephemeral port on the chosen egress
address. Configure the host firewall accordingly; a NAT address is not automatically published
or mapped by the proxy. Keep BIND disabled through ACLs unless reverse connections are needed.

HTTP-capable TLS listeners advertise ALPN `h2` and `http/1.1`. HTTP/2 supports ordinary
authority-form CONNECT streams, not RFC 8441 extended CONNECT or HTTP/3. Each stream passes
the same authentication, destination ACLs, egress selection and shaping as HTTP/1.1 tunnels.

## Egress addresses: pools

A `[[pool]]` is a set of local addresses with a strategy. Give it addresses (`addresses = [...]`), an interface to discover them from (`interface = "eth0"`, minus loopback, link-local and multicast addresses, minus `exclude = [...]`), or a routed block (`prefixes = [...]`, at most one per IP family, not mixed with explicit addresses of the same family).

| `strategy` | Picks |
|---|---|
| `first` | the first address (3proxy `-e`) |
| `round_robin` (default) | the next address, per pool |
| `random` | a random address (a random address of the block for `prefixes`) |
| `least_connections` | the address with the fewest open connections |
| `sticky` | by a hash of the session id (`-sid-`), else the user name, else the client address: the same key keeps the same address while the address set stays, and removing an address moves only the keys that were on it |

`fifo` is an explicit spelling for first-healthy-in-order selection. `hash` chooses a stable
address using `hash_key = "client_ip" | "target_host" | "user" | "session_id"`; absent user
or session values fall back to client IP. `userhash` and `sourcehash` select those attributes
directly. `carp` uses rendezvous hashing, so adding or removing one address only remaps keys
owned by that address. `race` dials available candidates concurrently and keeps the first success.
`latency` prefers measured fast paths and retains the current address within `latency_tolerance`
(default `50ms`). Prefix pools retain their documented per-prefix strategy restrictions.

`backup_addresses = [...]` participate only without a healthy primary of the destination family.
Pool `max_fails` and `fail_timeout` override `[breaker.egress]` for the same breaker.
`race_width` (default 2) limits simultaneous source-address dials. Prefix races have one
candidate; prefix latency selection is rejected because generated IPs have no persistent history.

The family always matches the destination: an IPv4 destination leaves from an IPv4 address of the pool, an IPv6 one from an IPv6 address, and a pool with no address of the family answers `502` with `X-ProxyX-Error: no_egress_address` (the proxy does not fall back to another source). An address whose connects fail for lack of the address itself (`EADDRNOTAVAIL`, network unreachable from that source) counts against its [circuit breaker](#circuit-breakers-and-health-checks) and the connection is retried from another address; a refusal or timeout from the destination is the destination's answer and counts against nobody. The kernel binds the address before `connect` with `IP_BIND_ADDRESS_NO_PORT`, so many connections from one address to different targets do not run out of ephemeral ports.

**Which pool a request uses**, first match wins:

1. an `[[egress]]` rule that matches (per-rule, squid `tcp_outgoing_address`): `pool = "name"` or one fixed `address = "192.0.2.11"`;
2. the pool named in the login, `alice-pool-v6` (the user must list it in `allowed_pools`);
3. the user's `pool`;
4. the listener's `pool`;
5. `server.default_pool`;
6. none: the operating system picks the source address.

## Users, logins and session options

Users come from `[[user]]` tables and an htpasswd-style file (`auth.users_file`, lines `user:hash`). Passwords are `password` (plaintext, compared in constant time) or `password_hash`: bcrypt (`$2y$`), Apache `$apr1$`, md5-crypt `$1$`, sha256/sha512-crypt (`$5$`, `$6$`), argon2 (`$argon2id$`) and legacy `{SHA}`; create them with `htpasswd -nbB user password`. A `[[user]]` table without a password adds settings (groups, pool, limits) to a user that is in the file. HTTP uses `Proxy-Authorization: Basic`, SOCKS5 RFC 1929, SOCKS4 the user id (only for a user with `socks4 = true`, because SOCKS4 has no password). Hash checks run on a blocking thread and a success is cached for a few minutes; an unknown user costs the same time as a wrong password. A source that fails `auth.fail_limit` logins in `auth.fail_window` (20 in 60 s) is answered `429` until the window ends.

With `auth.login_options = true`, the login may carry options off its right end, `user-sid-<id>-pool-<name>-ip-<n>` (values are `[a-z0-9_]`; a user name may contain dashes, but not end in an option pair, which is checked at startup):

| Option | Effect | Needs |
|---|---|---|
| `-sid-<id>` | the session id: with a `sticky` pool the same id keeps the same address | nothing |
| `-pool-<name>` | choose a pool | the pool in the user's `allowed_pools` |
| `-ip-<n>` | the n-th address of the pool (1-based; for a prefix pool the n-th address of the block) | `allow_ip_select = true` |

An option the user may not use is `403 option_denied`. This is the same style as the `px-...-sid-...` grammar of the [pool gateway](gateway.md), so a client written for one works with the other.

## Access rules and the destination check

`[[rule]]` tables are checked in order and the first match decides; no match is a deny. A `when = { ... }` table holds conditions, all of which must hold; the values of one field are alternatives.

```toml
[[rule]]
name = "no-mail"
action = "deny"
when = { port = ["25", "465", "587"] }

[[rule]]
action = "allow"
when = { group = ["staff"], time = [{ days = ["mon", "tue", "wed", "thu", "fri"], from = "08:00", to = "18:00" }] }
```

| Condition | Matches |
|---|---|
| `src` | client addresses: `192.0.2.7`, `10.0.0.0/8`, `10.0.0.1-10.0.0.9` (the PROXY protocol address when there is one) |
| `dst` | destination addresses (the name is resolved first) |
| `domain` | `example.com` exact, `.example.com` the name and its subdomains, `*.example.com` subdomains only, `re:<regex>` |
| `port` | `443`, `8000-8100` |
| `method` | `GET`, `POST`, ..., `CONNECT`; SOCKS commands count as `CONNECT`, `BIND` and `UDP` |
| `protocol` | `http`, `connect`, `socks4`, `socks5`, `udp` |
| `user`, `group`, `listener` | login name, group of the user, listener name (every name is checked to exist) |
| `time` | windows of `days` (`mon`..`sun`) and `from`/`to` (`HH:MM`, wrapping over midnight), in `server.utc_offset` |
| `authenticated` | a login was presented and accepted |
| `not` | a nested `when` that must not match |

`stage` on an access rule selects `request` (default), `pre_negotiation`, `post_auth`, `bind`
or `udp`. Early stages run before protocol negotiation or after authentication and accept only
conditions available at that point. A configured stage denies unmatched traffic; an absent
stage adds no restriction. BIND and each UDP destination must pass the normal request rules
and their configured command-stage rules. Place source-only admission rules in `pre_negotiation`
and identity rules in `post_auth`; these checks never replace destination authorization.

**Private and internal destinations are always denied**, whatever the rules say: loopback, RFC 1918, link-local and the cloud metadata addresses, IPv4-mapped and translated IPv6 forms, odd spellings (`2130706433`, `0x7f.1`), internal names (`localhost`, dotless names, `.internal`, `.local`, `.svc`), and any name that *resolves* to one of them. The answer is `403` with `X-ProxyX-Error: destination_denied`. A rule that must reach an internal network says so with `allow_internal = true` (allow rules only); the opt-out belongs to that rule, never to the proxy as a whole. The proxy connects to the addresses it checked, never to a second resolution.

## Limits

* `server.max_connections`, `server.max_connections_per_src` and a listener's `max_connections` cap client connections at accept (the connection is closed unanswered and counted `over_limit`). A `[[user]]`'s `max_connections` caps its simultaneous requests and tunnels (`429 too_many_connections`).
* `[[limit]]` tables add shaping to whatever matches their `when`; every matching table applies, each with its own budget per `scope` (`user`, `src`, or `rule` for one budget shared by everything that matches). `bandwidth_down` (target to client) and `bandwidth_up` are token buckets (a number is bytes per second; `512KiB`, `2MB`, `10Mbit/s` work), paced on both HTTP bodies and tunnels, UDP included. `max_connections` bounds simultaneous requests and `request_rate = "100/min"` new requests (HTTP requests, `CONNECT`, SOCKS commands), refused with `429 rate_limited`.
* `[timeouts]`: `handshake` (first request and login), `connect` (name resolution plus connect, over every attempt), `idle` (a tunnel with no byte either way is closed), `keepalive` (between HTTP requests).

## Parent proxies

`[[parent]]` tables define upstream HTTP, HTTPS, SOCKS4 or SOCKS5 proxies (Squid `cache_peer`, 3proxy `parent`). Lowest available priority tiers serve first; weighted random remains the default selector. HTTPS verifies the proxy certificate and hostname before forwarding or CONNECT. Plain HTTP requests use absolute-form forwarding and separate `Proxy-Authorization` toward a flat HTTP(S) parent; tunnels and chain hops use CONNECT handshakes. The first parent connection uses its own `pool`, else the request pool. Bounded parent keep-alive reuse remains available for bodyless HTTP requests. A parent `407` becomes `502 parent_error`; upstream credentials never reach the target.

`[[route]]` tables choose per request, first match wins (otherwise `server.default_route`): `route = "direct"` (squid `always_direct`), `"parent"` (squid `never_direct`: only through a parent; `503` when none is up) or `"parent_or_direct"`; `parents = [...]` restricts the choice to named parents.

### Parent selectors and multi-hop chains

`[selector]` controls parent selection: `first`/`fifo`, `round_robin`, weighted `random`,
`least_connections`, `sticky`, `hash`, `userhash`, `sourcehash`, weighted `carp`, `race` and
`latency`. Hash keys use `client_ip`, `target_host`, `user` or `session_id`. CARP-style weighted
rendezvous hashing uses stable configured names: membership changes do not rehash every key.
This does not implement Squid's cache protocol or exact cache-key algorithm.

`backup = true` nodes participate only without available primaries; `default = true` supplies
a last-resort parent. Existing priority tiers remain authoritative. Node `max_fails` and
`fail_timeout` override the existing passive breaker's threshold and open interval.
`selector.connect_retries` bounds next-path retries and `selector.forward_timeout` bounds total
connection establishment; they do not replay an already forwarded non-idempotent request body.
`selector.race_width` bounds concurrent candidate dials; losers are dropped after first success.

Chains list ordered hop groups. Each group names configured parents and may override the selector:

```toml
[selector]
strategy = "fifo"
connect_retries = 2
forward_timeout = "30s"

[[chain]]
name = "two-hop"
hops = [
  { parents = ["entry-a", "entry-b"], selector = { strategy = "race", race_width = 2 } },
  { parents = ["exit-a"], selector = { strategy = "fifo" } },
]
probe = { type = "http", url = "http://probe.example.org/health", status = 200, body_contains = "ok" }

[[route]]
when = { domain = [".example.net"] }
route = "parent"
chain = "two-hop"
```

Every hop may use HTTP(S) CONNECT, SOCKS4 or SOCKS5. The proxy connects to the first hop once
and negotiates later hops inside the established stream. Only the first hop selects a local
egress address. Race combinations are capped at 64 concurrent chain paths; larger configurations
fail validation. A keep-alive HTTP client retains its chosen chain; new requests do not silently
switch an existing client connection to another chain.

### Explicit affinity and replicas

Explicit claims are used by sticky parent selection and sticky local egress. Setting the global
parent selector to `sticky` also pins direct egress, even when that source pool uses round robin.
Stateless `hash`, `sourcehash`, `userhash` and CARP policies do not require a stored session.

`[stick]` bounds key-to-path affinity by `capacity` (65536 default) and fixed `ttl` (10 minutes).
Claims retain selected parent names and local egress, survive SIGHUP with unchanged stick
configuration, and expire rather than renewing indefinitely on access. A failed/removed path
may be remapped earlier; capacity eviction may also remap a key.
Exact source-IP claims cover explicit/discovered address lists, not addresses generated from
routed prefixes. Use a prefix pool's own `strategy = "sticky"` for deterministic prefix affinity
on identically configured replicas. A sticky parent selector does not make a round-robin prefix
pool sticky; generated prefix addresses have no replicated per-address entry.

```toml
[stick]
capacity = 65536
ttl = "10m"
[stick.redis]
url = "redis://127.0.0.1:6379/4"
key_prefix = "edge-production:affinity"
ttl = "10m"
timeout = "5s"
```

Redis is optional. When enabled, shared claims are authoritative and atomic; replicas need
identical names, capacity, namespace and key semantics. A replica replaces invalid claims atomically
and fails closed if Redis cannot answer, rather than generating an independent competing route.
This is affinity for a path, not a distributed lock on a target session or a provider exit-IP guarantee.
Redis enforces the same claim capacity with an atomic expiry index. Cleanup is bounded to
64 expired and 64 capacity victims per operation. A large configured capacity reduction can
temporarily refuse claims until subsequent bounded cleanup calls converge; plan such changes
as an availability event. Shared expiry and capacity eviction may remap a key on every replica.

## Circuit breakers and health checks

Two independent signals decide whether a parent or an egress address is used. A request goes to a parent only while **both** are good.

**Circuit breaker** (from the results of real requests), one per parent and one per explicitly listed egress address:

| State | Behavior |
|---|---|
| closed | requests pass; `failure_threshold` failures in a row open it (a success resets the count) |
| open | nothing passes (a parent is skipped, an address is not picked) until `open_duration` has passed |
| half open | up to `half_open_probes` requests pass at once as probes; `success_threshold` good results close it, one bad result opens it again for a full `open_duration`; a probe that never reports back is reclaimed after `open_duration` |

```toml
[breaker.parent]
failure_threshold = 3     # failures in a row
open_duration = "30s"
half_open_probes = 1
success_threshold = 1

[breaker.egress]
failure_threshold = 3
open_duration = "30s"
```

What counts as a failure: for a **parent**, a failed connect, handshake or login (a `407` from the parent), or an invalid or missing response to a forwarded request; a request that fails because our own egress is out of service is not the parent's. For an **egress address**, a connect that fails because of the address itself (`EADDRNOTAVAIL`, network unreachable from that source) and a failed active check; a refused or timed-out connect to the destination is not. Addresses drawn from a `prefixes` block have no breaker (each lives for one connection); the block as a whole is covered by its active check.

When every address of the destination's family is out of service the answer is `503` with `X-ProxyX-Error: egress_unavailable` (SOCKS reply 3); the proxy does not fall back to an address it has shut out. With a parent route and no usable parent, `503 no_parent`. A request that finds a breaker half open is one of its few probes, so recovery needs no extra traffic and no operator.

**Active health checks** (`[health]`, every `interval`, 10 s by default; `interval = "0"` turns them off):

* **Parents**: a probe connects to each parent from its egress pool and, with `parent_target = "host:port"`, opens a tunnel to that target through it (HTTP `CONNECT` or SOCKS5 `CONNECT`, with the parent's login), so it proves the parent *and* its path out. `unhealthy_threshold` failed probes in a row (2) take the parent out of use, `healthy_threshold` good ones (1) bring it back. Pick a target you may probe every few seconds (your own service, or a public resolver port).
* **Egress addresses**: every explicitly listed or discovered address is checked to be still assigned to a local interface and bindable, every prefix to be still routed to this host. A failed check takes the address out of the rotation at once; the next passing check puts it back. (A pool built from `interface = "eth0"` is read at start and on reload; reload after adding addresses.)

Per-parent `probe` and chain `probe` accept `type = "tcp"` with `target = "host:port"`,
`type = "http"` with an `http://` or verified `https://` URL, expected `status`, optional `body_contains` and bounded
`max_body_bytes`, or `type = "command"` with an explicit `command = ["/path/program", "arg"]`.
HTTP probes traverse the parent/chain before issuing GET. Checking only the first TCP listener
cannot prove that a later hop reaches the target. Commands run without a shell under the
proxy service account, respect `health.timeout`, and require trusted configuration ownership.

With `strategy = "latency"`, probe duration drives choice. `tolerance_ms` retains the existing
healthy node unless another improves latency enough. `health.interval` sets probe frequency;
`idle_timeout` pauses latency probes when no traffic uses the group. `interrupt_on_switch = true`
closes existing tunnels when the best node changes; leave it false to preserve active sessions.

A configuration reload builds new breakers and trackers, which start closed and healthy; the next round of checks re-establishes the verdicts.

## Ops endpoints

On `server.ops_listen`:

* `GET /healthz`: liveness. `200 ok` while the process answers. Never depends on parents or addresses, so a supervisor restarts the process only when it is stuck.
* `GET /readyz`: readiness, for a load balancer. `200` when all of the following hold, else `503`, with one line per condition in the body:

```text
ok   running
ok   config loaded
ok   listeners bound
FAIL egress path: no healthy local address or parent
```

  * *running*: the process is not shutting down;
  * *config loaded*: a configuration is compiled and in force;
  * *listeners bound*: every configured listener is bound (after a reload that moved a listener, until it is);
  * *egress path*: at least one way to reach the internet works for the default route: with `default_route = "direct"` a pool with a usable address (healthy and not shut out by its breaker) or no pool at all (the operating system picks the source), with `"parent"` a parent that is up, with `"parent_or_direct"` either.
* `GET /metrics`: [metrics/edge.md](metrics/edge.md).
* `GET /stats`: JSON with `listeners`, `pools` and `nodes`; `?format=csv` or `Accept: text/csv`
  selects CSV. Rows contain `kind`, `name`, `pool`, `state`, `active`, `total_connections`,
  `failures` and `latency_seconds`; unknown latency is null/blank. The snapshot is observational,
  not a transaction. It includes configured zero-traffic nodes, not every address drawn from a
  routed prefix. Bind ops to a trusted interface: node addresses are operational data.

## Keepalive and connection reuse

Idle parent connections are separated by client IP, target host, authenticated user and session
ID as well as the parent/path, pool and explicit address choice. They never cross configuration
generations: reload retires old idle entries from reuse by new requests. Existing active tunnels
continue normally, and a keep-alive client's selected hop names remain pinned. This preserves
hash-selected source addresses when clients share a SID or pool settings change.

```toml
[tcp.client]                 # sockets accepted from clients
keepalive = true
keepalive_time = "60s"       # idle time before the first probe
keepalive_interval = "15s"
keepalive_retries = 4        # a vanished peer is dropped after 60 + 4 x 15 s
nodelay = true

[tcp.upstream]               # sockets to targets and parents
keepalive = true
keepalive_time = "60s"
keepalive_interval = "15s"
keepalive_retries = 4
nodelay = true

[http]
client_max_requests = 1000   # requests per client connection, then Connection: close; 0 = no limit
parent_keepalive = true      # reuse connections to HTTP parents
parent_idle_timeout = "30s"
parent_max_idle = 64
```

* **TCP keepalive** finds peers that disappeared without closing (a client behind a dead NAT, a target host that lost power) so a tunnel does not hold two sockets for ever. The two tables are separate so a long-lived tunnel to your own parents can probe more often than clients. Settings apply to new connections.
* **HTTP/1.1 client keepalive**: a client connection stays open between requests for `timeouts.keepalive` (60 s) and for at most `http.client_max_requests` requests; the last answer carries `Connection: close`. HTTP/1.0 and `Connection: close` clients get one request.
* **Parent connection reuse**: a plain HTTP request without a body to an HTTP parent is sent on a persistent connection that goes back to a small idle pool after the response, if the parent kept it open and the response ended where its framing says. The pool is filed by parent, egress pool, `-ip-` choice and the client key the pool strategy hashes (session id, else user, else client address), so a reused connection leaves from an address the strategy could have chosen for that client; the strategy distributes new connections to the parent, not every request. A connection that the parent closed while idle is detected before use; if one dies in the instant between the check and the write, the request is retried once on a new connection. Requests with a body, tunnels, SOCKS parents and parents with `send_proxy_protocol` always use a connection of their own. Reuse is off with `http.parent_keepalive = false`. Connections to targets are never reused: see [Protocol behavior](#protocol-behavior-to-know).

## Timeouts

| Key | Default | Bounds |
|---|---|---|
| `timeouts.handshake` | `30s` | reading the first request head or SOCKS greeting and the login |
| `timeouts.connect` | `10s` | name resolution plus connecting (and a parent handshake), over all attempts of one request |
| `timeouts.response_header` | `60s` | waiting for the target's response head after the request was sent (`504`) |
| `timeouts.idle` | `10m` | a tunnel, an upgraded connection, a UDP association or a body transfer with no byte in either direction |
| `timeouts.keepalive` | `60s` | an HTTP client connection waiting for its next request |
| `timeouts.total` | `0` (none) | the longest one request, tunnel or UDP association may last, whatever moves on it (a forwarded HTTP request answers `504` when it is hit) |
| `health.timeout` | `5s` | one health probe |
| `server.shutdown_grace` | `30s` | SIGTERM until the remaining connections are closed |

Every timeout except `total` must be above zero (checked at start). `total` is the only way to bound a tunnel that is never idle.

## Header policy

For forwarded plain HTTP, `[http]` decides what the target sees. Hop-by-hop headers (`Connection`, `Keep-Alive`, `Proxy-*`, `TE`, `Trailer`, `Upgrade` outside a handshake) are always removed, and the client's `Proxy-Authorization` never goes on. `forwarded_for` is `delete` (default: remove `X-Forwarded-For`, `Forwarded` and `X-Real-IP`), `off` (`X-Forwarded-For: unknown`), `truncate` (only the client address), `on` (append it) or `transparent` (leave it). `via = true` adds `Via: 1.1 <proxy_name>`; by default the proxy hides itself. `request_headers_remove` and `request_headers_set` (and the `response_` pair) edit what is left.

Safe declarative hooks can scope both request and response edits to the deciding named allow rule:

```toml
[[http.header_rule]]
rule = "staff"
request_headers_remove = ["X-Debug"]
request_headers_set = { X-Client-Class = "staff" }
response_headers_remove = ["Server"]
response_headers_set = { X-Proxy-Policy = "staff" }
```

Scoped edits run after the global policy. The rule must identify exactly one named request-stage allow rule;
duplicate references, invalid header syntax, CR/LF/NUL values and attempts to rewrite `Host`,
message framing or hop-by-hop headers fail configuration validation. No dynamically loaded
code runs in the proxy. Parent credentials remain separate and are injected only toward that parent.

## DNS

The proxy resolves names itself (once per request, for the rules and the destination check, and connects to those addresses): a cache with `min_ttl`/`max_ttl`, `nameservers` (empty: `/etc/resolv.conf`), `ip_version` (`prefer_ipv4`, `prefer_ipv6`, `ipv4_only`, `ipv6_only`) and fixed answers in `dns.hosts` (3proxy `nsrecord`).

## Logs, metrics and health

* **Access log**: `[access_log] output = "file" | "stdout" | "stderr" | "off"`, `format = "squid"` (the native `access.log` format, readable by squid tools), `"combined"` (Apache) or `"json"`. One line per request, written by a separate thread: a slow disk drops lines (counted in `proxyx_edge_access_log_dropped_total`) and never slows a request. SIGHUP reopens the file. The JSON line carries the client, listener, protocol, user, method, URL, status, bytes, `egress_ip`, `pool`, `target_ip`, `parent`, matched `rule` and `result`.
* **Process log**: structured JSON to stderr (journald), `log.json = false` for text, `RUST_LOG` or `log.level` for the filter. Passwords are never logged.
* **Ops listener** (`server.ops_listen`): `/metrics` ([catalogue](metrics/edge.md)), JSON/CSV `/stats`, `/healthz`, `/readyz` (503 while stopping). Bind it to loopback or a management network.

## Operating it

* **Reload**: `systemctl reload proxyx-edge` (SIGHUP) re-reads the file and applies users, rules, limits, pools, parents, header policy and DNS settings to new requests; open tunnels and in-flight requests keep running. A listener that is new or has a new `listen` address is bound first (a bind failure rejects the whole reload); a removed one stops accepting while its open connections go on. A file that does not parse or validate is rejected as a whole, the running configuration stays and the reason is logged (`proxyx_edge_config_reloads_total{result="failed"}`). `server.ops_listen` needs a restart. Bandwidth and rate budgets and the login cache start fresh after a reload.
* **Alerts to start with**: `proxyx_edge_parent_breaker_state == 2`, `proxyx_edge_parent_healthy == 0`, `proxyx_edge_egress_addresses{state=~"open|unhealthy"} > 0`, a rising `rate(proxyx_edge_requests_total{result=~"connect_error|parent_error|timeout"}[5m])`, `proxyx_edge_config_reloads_total{result="failed"}`.
* **Stop**: SIGTERM stops accepting and waits up to `server.shutdown_grace` (30 s) for open tunnels.
* **Findings from the access log**: `result` is `ok`, `auth_required`, `denied`, `limited`, `dns_error`, `connect_error`, `timeout`, `parent_error`, `bad_request` or `internal`; the client sees `X-ProxyX-Error` with `forbidden`, `destination_denied`, `option_denied`, `auth_required`, `auth_blocked`, `rate_limited`, `too_many_connections`, `dns_error`, `connect_failed`, `connect_timeout`, `no_egress_address`, `parent_error`, `no_parent` or `bad_request`. SOCKS clients get the nearest reply code (2 not allowed, 4 host unreachable, 5 refused, 6 TTL expired for a timeout, 1 general).

## Protocol behavior to know

* The HTTP proxy speaks HTTP/1.1 and is strict about message framing: a request with both `Content-Length` and `Transfer-Encoding`, with conflicting lengths, or with a coding stack other than a lone `chunked` is refused with `400`. Request and response bodies (fixed length, chunked with trailers, until close) are passed through unchanged. A client connection stays open between requests (HTTP/1.1 only; HTTP/1.0 clients get `Connection: close`).
* Each forwarded request opens its own connection to the target and sends `Connection: close` to it, so the egress address is chosen per request and a target never sees a connection shared between two clients. There is no origin keep-alive pool.
* `Expect: 100-continue` is answered by the proxy once the request has passed the rules and the target is connected; an `Upgrade` (WebSocket) handshake is forwarded and the connection becomes a tunnel after the `101`.
* `https://` targets use `CONNECT`; listener TLS protects the client-to-proxy leg without decrypting target TLS.
* SOCKS5 `CONNECT`, `BIND` and `UDP ASSOCIATE` are served. The reply to `CONNECT` carries the local address of the outgoing connection. UDP datagrams are accepted only from the client's own address, each new destination goes through the rules and destination check, replies are accepted only from addresses the client sent to, and fragmentation is not supported.

## Using the machine's addresses from the pool gateway

The pool gateway can lease the machine's own addresses as static inventory with a `scheme = "local"` adapter: it dials straight from the chosen source address (no upstream proxy), and the gateway's stickiness, rotation, limits and exit-IP verification apply. The adapter and inventory format are in [providers.md](providers.md#local-units). Use `proxyx edge` for a self-contained host and the pool gateway with `local` units when the machine is one source among many in a fleet.

## Not included

| Not included | Why |
|---|---|
| HTTP caching (squid) | ProxyX forwards, it does not store: a cache changes what a target sees, shares responses between clients and needs eviction and revalidation logic that none of the proxy roles has. Put squid or varnish in front when you need one |
| TLS interception, `ssl_bump` | the session proxy (`proxyx-intercept`) handles authorized interception; edge listener TLS does not decrypt target tunnels |
| Origin keep-alive pools | see above: per-request egress selection |
| ICP/HTCP, ICAP/eCAP, external ACL helpers, Kerberos/NTLM/Digest | out of scope for a static-config proxy; HTTP Basic, RFC 1929 and hashed files cover the use case |
| FTP/POP3/SMTP proxies, port mappers, the 3proxy admin page | not needed by HTTP/SOCKS clients |
| Transparent (redirect/TPROXY) mode | needs firewall integration per host; clients are expected to name the proxy |
| Volume quotas per period (3proxy `countin`) | not available: bandwidth, connection and request-rate limits exist, byte quotas that persist across restarts need a store |
| Dynamic plugins and a web dashboard | declarative request/response header hooks and authenticated network boundaries avoid arbitrary in-process code; `/stats` supplies machine-readable operations data |
| HTTP/3, QUIC, VPN, SSH and WebSocket proxy transports | require distinct transport, security and lifecycle implementations; not needed for the HTTP CONNECT/SOCKS gateway contract |

## Troubleshooting

| Symptom | Check |
|---|---|
| `--check` says `not assigned to any local interface` | the address is not on the host: `ip -brief addr`, `ip addr add` |
| `cannot bind ... route the prefix to this host` | `ip route add local <prefix> dev lo` for a `prefixes` pool |
| `403 destination_denied` for a host you own | the target is private: add a rule with `allow_internal = true` for just that destination |
| `407` forever from a script | the client sends the password only after a `407` (curl does; some libraries need `-U` or preemptive auth); `proxyx_edge_auth_failures_total{reason="invalid"}` |
| `429 auth_blocked` | 20 wrong logins from the source in a minute; wait or raise `auth.fail_limit` |
| `503 egress_unavailable` | every address of that IP family is shut out by its breaker or failed its active check (`proxyx_edge_egress_addresses`, the process log says which address left the host) |
| `503 no_parent` | the route needs a parent and all are out: `proxyx_edge_parent_breaker_state`, `proxyx_edge_parent_healthy`, `health.parent_target` |
| `502 connect_failed` with shared stickiness | inspect Redis reachability, credentials, timeout and namespace capacity; `stick affinity unavailable` fails closed and never falls back to an independently chosen direct path |
| `502 no_egress_address` | the pool has no address of the destination's IP family: add one or use `ip_version = "ipv4_only"` |
| Exits do not rotate | the pool is `sticky` and no `-sid-` is sent (the user name decides), or a `[[egress]]` rule or the user's pool overrides the strategy you changed |
| Slow tunnels | a `[[limit]]` matches (every matching one applies); `proxyx_edge_limit_rejections_total` and the rule's `bandwidth_*` |
