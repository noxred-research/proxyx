# Gateway

The gateway is the data plane of ProxyX. It accepts proxy connections from clients, authenticates the
org key, narrows the request by policy, leases an upstream IP from a provider adapter, dials the
target through that upstream and relays the bytes. It never connects to a target directly: every
refusal is an answer with a stable cause code, and no path falls back to a direct dial.

`proxyx gateway` runs the gateway listeners, the control API and the ops server in one process. The
warmer is a separate role (`proxyx warmer`, see [providers.md](providers.md)). Policy documents are
described in [policies.md](policies.md); every configuration key is listed in
[configuration.md](configuration.md), and process layout is in [architecture.md](architecture.md).

- [Listeners and ports](#listeners-and-ports)
- [Protocols](#protocols)
- [Authentication](#authentication)
- [Username grammar](#username-grammar)
- [How options narrow the policy](#how-options-narrow-the-policy)
- [The open pipeline](#the-open-pipeline)
- [Sticky keys](#sticky-keys)
- [Lease walk and soft limits](#lease-walk-and-soft-limits)
- [Dial, retries and the breaker](#dial-retries-and-the-breaker)
- [Relay, idle timeout and the keeper](#relay-idle-timeout-and-the-keeper)
- [Connection caps](#connection-caps)
- [Response headers](#response-headers)
- [Cause codes](#cause-codes)
- [Denied destinations](#denied-destinations)
- [Graceful drain](#graceful-drain)
- [Control API](#control-api)

## Listeners and ports

| Listener | Default address | Setting | Protocol | Password |
| --- | --- | --- | --- | --- |
| `connect` | `0.0.0.0:8080` | `connect_listen` (`PROXYX_POOL_CONNECT_LISTEN`) | HTTP CONNECT | org key `ak_...` |
| `socks` | `0.0.0.0:1080` | `socks_listen` (`PROXYX_POOL_SOCKS_LISTEN`) | SOCKS5, username/password | org key `ak_...` |
| `probe` | `0.0.0.0:8082` | `probe_listen` (`PROXYX_POOL_PROBE_LISTEN`) | HTTP CONNECT | signed probe token |
| control API | `0.0.0.0:8081` | `api_listen` (`PROXYX_POOL_API_LISTEN`) | HTTP/1.1 JSON, see [Control API](#control-api) | admin, prober or org credential |
| ops | `0.0.0.0:8888` | `ops_listen` (`PROXYX_POOL_OPS_LISTEN`) | HTTP: `/healthz`, `/readyz`, `/metrics` | none |

The `connect` and `socks` listeners are the public data plane. The `probe` listener exists for the
prober's browsers only; it is described under [Authentication](#authentication). The ops server starts
before Postgres and Redis are connected: `/healthz` answers `200` from the first moment, `/readyz`
answers `503 starting` until the first configuration snapshot is loaded, then `200` while Redis
answers (three failed checks in a row turn it `503 redis unavailable`), and `503 draining` from the
stop request on. See [operations.md](operations.md) and [metrics/pool.md](metrics/pool.md).

## Protocols

The gateway tunnels TCP. It supports exactly two client protocols:

- **HTTP CONNECT** (`connect` and `probe` listeners). Any other method, including a plain
  `GET http://...` proxy request, is refused with `405 Method Not Allowed`.
- **SOCKS5 with username/password** (RFC 1928, RFC 1929), `CONNECT` command only. `BIND` and
  `UDP ASSOCIATE` are refused with reply `0x07`.

There is no TLS on the listeners, no HTTP proxying of plain requests, no UDP, and no SOCKS4. The
gateway does not look inside tunnel bytes.

### HTTP CONNECT

The request head is read under strict limits and refused, never repaired:

- At most 8 KiB for the whole head and 32 headers.
- The request target must be `host:port` or `[v6-literal]:port`. The port is digits only and not `0`.
  The host is 1 to 253 bytes of letters, digits, `.`, `-`, `_` and `:` and is lowercased.
- `Proxy-Authorization: Basic base64(username:password)` is read; the password is everything after the
  first `:`. The scheme name is case-insensitive.
- Bytes the client sends after the blank line (data pipelined before the `200`) are forwarded upstream
  first.

| Condition | Answer |
| --- | --- |
| Head larger than 8 KiB | `431 Request Header Fields Too Large` |
| Not HTTP/1.x, or a bad request target | `400 Bad Request` |
| Method other than `CONNECT` | `405 Method Not Allowed` |
| No usable `Proxy-Authorization: Basic` | `407 auth_required` with `Proxy-Authenticate: Basic realm="proxyx"` |

Every refusal carries `Content-Length: 0` and `Connection: close`. For a refusal that is a
[cause code](#cause-codes), the reason phrase is the code, for example `HTTP/1.1 503 cache_empty`.
Clients that print the proxy's status line therefore show the cause directly.

### SOCKS5

1. The client greeting must offer method `0x02` (username/password). Otherwise the gateway answers
   `05 ff` (no acceptable method) and closes.
2. The RFC 1929 message carries the username (the [options](#username-grammar)) and the password (the
   org key). Both must be UTF-8. A failed login of any cause is answered `01 01` (RFC 1929 failure),
   whatever the cause code; the code is counted in metrics only.
3. The request must be `CONNECT`. Address types `0x01` (IPv4), `0x03` (domain) and `0x04` (IPv6) are
   served; anything else, an invalid host, or port `0` is refused with reply `0x08`.
4. Success is reply `0x00` with a zero bound address. A refusal uses the SOCKS5 reply column of the
   [cause table](#cause-codes).

SOCKS5 has no place for response headers, so the `X-ProxyX-*` correlation headers are an HTTP CONNECT
feature.

### Pre-auth timeouts

A client must send its first byte within 3 s of the connection. The whole HTTP head, or the whole
SOCKS5 negotiation including the key check, must complete within 10 s of that. A silent or slow client
is closed and counted as `bad_request`. A reply write that makes no progress for 5 s is abandoned.
Accepted client sockets get `TCP_NODELAY` and TCP keepalive (idle 60 s, then 4 probes 15 s apart).

## Authentication

The password is the org key. The username carries the [options](#username-grammar), never the
credential, so a key is not part of any log line or metric label.

### Org keys

An org key has the form `ak_` followed by 43 URL-safe base64 characters (256 random bits). It is
created with [`POST /v1/orgs/{org}/keys`](#post-v1orgsorgkeys); only its SHA-256 is stored, so the
creation response is the only time the key can be read. Keys belong to an org and can be disabled per
org with [`DELETE /v1/orgs/{org}/keys`](#delete-v1orgsorgkeys).

| Key state | Answer |
| --- | --- |
| Unknown | `407 auth_required` |
| Disabled | `403 org_disabled` |
| Postgres down and the key not cached | `503 cache_unavailable` |
| The key of the probe org on `connect` or `socks` | `407 auth_required` |

### Key cache

A tunnel never waits on Postgres when it is down. Each gateway pod keeps a memory cache keyed by the
SHA-256 of the key, so the key itself is never held:

| Behaviour | Value |
| --- | --- |
| A verified key is trusted without a lookup | 30 s |
| After that the key is looked up again; if Postgres fails or is slow, the stale entry still answers for | up to 1 h |
| One Postgres lookup is bounded at | 1 s |
| After a failed lookup Postgres is not asked again for | 5 s |
| Lookups in flight at once per pod | 6 |
| A key Postgres says is unknown is refused from memory for | 5 s |
| Keys held | 10,000 |

Concurrent lookups of one key share one query. A disabled or unknown answer removes the key from the
cache at once.

### Brute-force limiter

Distinct wrong keys defeat the 5 s memory of unknown keys, so each source is also limited. A source
is an IPv4 address or an IPv6 /64.

- A source may cause 20 lookups that end "unknown" per 60 s window, in each of 16 buckets chosen by
  the first bits of the key's hash.
- Past the limit, until the window ends, a key of that bucket for which this pod holds no verified
  entry is refused with `407` without a lookup. A key with a verified entry is never refused by the
  limit.
- Only the caller that ran a lookup is charged, and only for an "unknown" answer. Valid keys, a
  disabled org, a repeated wrong key within 5 s and callers that joined another's lookup cost their
  source nothing.
- Lookups of unverified keys from one source take turns, one at a time (waiting at most 10 s), so a
  burst of wrong keys gets exactly the limit's worth of lookups, while a burst of valid new keys waits
  its turn instead of being refused.
- The buckets keep one tenant's wrong keys from locking the others out: using up another org's first
  verification takes failures in every bucket.

The counts are per pod and in memory; a restart or another pod starts from zero. Refusals are counted
in `auth_failures_total{reason}` (`unknown_key`, `source_limited`). The pre-auth connection slots of
[Connection caps](#connection-caps) bound how many unauthenticated sockets a source can hold.

### Probe tokens

The `probe` listener serves the prober's browsers. Its password is not an org key but a short-lived
token, so a token that leaks from a browser process is not a standing proxy credential.

- The control API issues a token with [`POST /v1/probe/token`](#post-v1probetoken): `pt1.<expiry>.<mac>`,
  where `expiry` is a Unix time and `mac` is the base64url (no padding) HMAC-SHA256 of `pt1.<expiry>`
  under the probe secret. A token lives 30 minutes (`expires_in_s: 1800`).
- The gateway verifies the MAC in constant time and the expiry without a database lookup. Rotating the
  probe secret invalidates every token at once.
- The probe secret is the file named by `probe_key_file` (default `/etc/proxyx/secrets/probe-key`). If
  the file does not exist, no token is issued (`503`) and the probe listener refuses every login.
- A valid token authenticates as the probe org (`probe_org`, default `proxyx-probe`), so that org's
  policy governs the probe's route.
- The listener opens only the hosts of `probe-targets.toml` (and their subdomains) plus its
  `extra_hosts`, on ports 80 and 443 or a page's explicit port. Any other target is
  `403 destination_denied`. See [providers.md](providers.md#probe-targets).
- The `connect` and `socks` listeners refuse tokens, and the probe listener refuses org keys.

## Username grammar

The proxy username carries the options of one request. The client builds it, or you write it by hand;
a tool that chains to the gateway (for instance a session proxy org with an egress proxy) uses the same
username as its egress login.

```text
username = "px" *( "-" key "-" value )
key      = "kind" / "cc" / "city" / "prov" / "ttl" / "sid" / "rot"
value    = 1*( %x61-7A / %x30-39 / "_" )        ; a-z 0-9 _  (never "-")
```

Because a value never contains `-`, splitting on `-` is unambiguous. Nothing is escaped or repaired:
anything that does not parse is refused with `403 option_denied` (SOCKS5 reply `0x02`).

| Key | Value | Meaning |
| --- | --- | --- |
| `kind` | `static` or `rotating` | Restrict the request to one kind of unit. |
| `cc` | two lowercase letters | Country (ISO 3166-1 alpha-2). |
| `city` | `[a-z0-9_]{1,48}` | City slug; requires `cc`. `cc-fr-city-paris` is the region `fr/paris`. |
| `prov` | provider id | Restrict to one provider adapter. |
| `ttl` | `30`, `30s`, `10m`, `2h`, `1d` | Lease idle time. Above 0 and at most the policy's `lease_ttl`. |
| `sid` | `[a-z0-9_]+` | Sticky key chosen by the caller. |
| `rot` | `sticky` (default) or `each` | `each` gives every tunnel its own unit. |

### Rules

A username is refused when:

- it does not start with `px` (the string `px` alone is valid and means "no options");
- it is longer than 128 bytes;
- the parts after `px` are not `key value` pairs (an odd count, so also a value that contains `-`);
- a key is unknown or appears twice;
- a value is empty or has a character outside `[a-z0-9_]`, including uppercase;
- `kind`, `rot`, `prov`, `ttl` or the region does not parse (`ttl-0` is refused);
- `city` is given without `cc`;
- `sid` is combined with `rot-each`.

A provider id that contains `-` (for example `vpn-pool`) cannot be named with `prov`, because its
value would contain a dash. Select such a provider through the policy's `providers` list instead.

### Examples

| Username | Result |
| --- | --- |
| `px` | The whole policy is the request. |
| `px-kind-rotating-cc-fr` | Rotating units in France. |
| `px-kind-rotating-cc-fr-city-paris-sid-scan42-ttl-30m` | Rotating unit in `fr/paris`, sticky key `scan42`, lease idle time 30 minutes. |
| `px-kind-static-prov-oxylabs_isp` | Static IPs of the `oxylabs_isp` provider only. |
| `px-rot-each` | A new unit for every tunnel. |
| `px-sid-job_17-ttl-1h` | Sticky key `job_17`, idle time 1 hour. |
| `px-kind-rotating-sid` | `option_denied`: odd number of parts. |
| `px-cc-fr-cc-de` | `option_denied`: repeated key. |
| `px-city-paris` | `option_denied`: `city` without `cc`. |
| `px-sid-a-rot-each` | `option_denied`: `sid` with `rot-each`. |
| `px-sid-my-id` | `option_denied`: the value would contain `-`. |
| `px-cc-FR` | `option_denied`: uppercase. |
| `PX-kind-static` | `option_denied`: the prefix is `px`. |

Try it with `curl`:

```sh
# HTTP CONNECT
curl -v -x http://localhost:8080 \
  -U 'px-kind-rotating-cc-fr-sid-job42:ak_YOUR_KEY' https://example.com/

# SOCKS5 (the proxy resolves the target name)
curl -v -x 'socks5h://px-kind-rotating-cc-fr:ak_YOUR_KEY@localhost:1080' https://example.com/
```

## How options narrow the policy

Each request starts from the [effective policy](policies.md#effective-policy) of its org (global, then
route class, then org). Options can only select from what that policy allows; an option that asks for
more is `option_denied`. Without options the whole policy is the request.

| Option | Allowed when | Without the option |
| --- | --- | --- |
| `kind` | the kind is in the policy's `kinds` | every kind of the policy, in order |
| `prov` | the policy's `providers` is unset or lists it | the policy's `providers` (unset: every configured provider) |
| `cc` and `city` | a policy region covers it: `fr/paris` is covered by `fr` or `fr/paris`, `fr` only by `fr` | the policy's `regions`, in order |
| `ttl` | at most `lease_ttl` | `lease_ttl` |
| `sid` | always | the policy's `sticky_scope` |
| `rot` | always (not with `sid` for `each`) | `sticky` |

Kinds and providers are narrowed against the base policy of the request. Region and `ttl` are checked
again against each provider's own policy, because a route-class policy may narrow `regions` and
`lease_ttl` for its provider. A provider whose policy refuses the request's region or `ttl` is skipped;
when every provider does, the answer is `option_denied`.

## The open pipeline

Every tunnel runs the same ordered checks. The first failure is the answer.

```mermaid
flowchart TD
    A[accept: connection and pre-auth caps] --> B[read head, authenticate]
    B --> C{probe listener?}
    C -- yes --> D[destination must be a probe target]
    C -- no --> E
    D --> E[parse username, narrow by policy]
    E --> F[denied destination check]
    F --> G[org tunnel slot: max_tunnels_per_org]
    G --> H[failed-lease memo]
    H --> I[walk partitions: port, caps, budget, breaker, lease]
    I --> J[render credential, exit-IP re-check]
    J --> K[dial upstream with retries]
    K --> L[200 and relay]
```

1. **Org key** (or probe token): `auth_required`, `org_disabled`, `cache_unavailable`.
2. **Listener rule.** On the probe listener the target must be a probe target (`destination_denied`).
3. **Options:** parse the username and narrow by policy (`option_denied`).
4. **Destination:** the [denied destination](#denied-destinations) rule (`destination_denied`).
5. **Org tunnel cap:** the org-wide `max_tunnels_per_org` counts the tunnel (`org_capacity`).
6. **Failed-lease memo:** a lease that failed with `cache_empty`, `no_healthy_ip` or `lease_timeout` is
   remembered for 5 s per org, sticky scope, kinds, providers, regions and target host, so retries do
   not multiply creates. The same cause is answered at once.
7. **Walk and lease** (see below), per partition in order: the adapter's `allowed_ports`
   (`port_not_allowed` only when every candidate refuses the port), the provider's own
   `max_tunnels_per_org`, the daily org budget `limits.org_max_gb_per_day` (`org_budget`), the route-class
   breaker, and the lease itself, which also enforces operator org blocks (`org_blocked`).
8. **Credential and exit check:** the adapter renders the upstream credential; the exit IP is
   re-checked when its last check is old.
9. **Dial** with retries, then the session record is stored, the tunnel is registered and the `200`
   is sent.

The whole open (lease, create, exit check, dial, retries, waits) answers inside an 8 s budget, so the
client sees the gateway's answer under a 10 s client dial limit. A budget that runs out is
`provider_timeout` and says nothing about the provider's health.

## Sticky keys

The sticky key decides which unit a request reuses. A lease is the pair (org, sticky key) bound to one
unit in one partition, renewed by traffic and ended after `lease_ttl` (or the request's `ttl`) without
a byte.

| Request | Lease key |
| --- | --- |
| `rot-each`, or `sticky_scope = "connection"` with no `sid` | a new key per tunnel; the lease ends with the tunnel |
| `sid-<id>` | `sid:<id>`; `sid` wins over `sticky_scope` |
| `sticky_scope = "org"` (default) | one key for the whole org |
| `sticky_scope = "target"` | one key per target host |

A lease younger than one minute stays on its partition before any priority order applies, so a sticky
key does not jump back to a higher-priority provider right after it moved. An older lease on a
degraded unit moves to a normal unit when one is free, and an org that took more static IPs than its
share (see below) gives IPs up at its next tunnel. An open tunnel is never cut by a move.

## Lease walk and soft limits

The candidate partitions of a request are walked in this order: each `kind` of the narrowed request in
order, then each provider (the policy's `providers` order; when unset, every configured adapter of that
kind in id order), then each region. A rotating partition is the wanted region itself. A static
partition is the region of an inventory entry that satisfies the wanted region, so the policy region
`fr` serves an inventory entry in `fr/paris` as the partition `fr/paris`. An org with a
[customer upstream](providers.md#customer-upstreams) sees only that unit.

The lease takes the best unit by rank. Every candidate is asked for rank 0 first, then for the best
rank any of them named, so tiers and limits apply across providers, which keep their priority inside a
rank:

| Rank | Unit |
| --- | --- |
| 0 | normal unit within its limits |
| 1 | degraded unit within its limits |
| 2 to 5 | normal unit that breaks `rest`, `orgs_hard`, `max_conns` or `fair_use` (in that order) |
| 6 to 9 | degraded unit that breaks the same limits |
| 10 | a unit that failed a tunnel at IP level a moment ago |

The four soft limits are broken only when no unit is left within them, lowest first, and
`lease_limit_broken_total{limit,provider}` names the one broken:

1. `rest` is `rest_after_release`, the rest of a free unit another org held last.
2. `orgs_hard` is the cap on distinct orgs per unit.
3. `max_conns` is `max_conns_per_ip` (unset: 80% of the adapter's `max_conns_per_ip`, at least 1). It
   has a ceiling: twice the limit, and never more than the provider allows per IP. A unit at the ceiling
   is not leased at all.
4. `fair_use` is the monthly fair-use stop of a static IP.

A static partition also gives each org a share of its IPs: an org that already holds
`max(1, ceil(IPs of the partition / orgs holding a lease in it))` static IPs takes no further one, and a
new sticky key reuses the org's least-loaded IP. An org alone may use the whole pool. The share does not
apply to rotating partitions or to a customer's own upstream.

A unit that failed a tunnel at IP level is ranked last for 10 s, doubling on each further failure up to
5 minutes, and a tunnel it serves clears the penalty. It is not withdrawn; it takes a lease when nothing
else can.

### When no unit is free: `on_empty`

When no partition holds a leasable unit, the policy's `on_empty` of that kind applies:

| `on_empty` | Behaviour |
| --- | --- |
| `create` (rotating default) | Open a new session through the provider inside `create_deadline`, two tries. The create passes the same checks as a warmed session: exit-IP quorum, reputation rule, light probe. It is refused when the provider's `cost` budget is spent. |
| `wait` (static default) | Poll for a free or shareable unit every 100 ms for up to `lease_wait`, then `lease_timeout`. |
| `fail` | Refuse at once with `cache_empty` (rotating) or `no_healthy_ip` (static). |

`create` is not valid for static IPs: static IPs are rented, never created.

## Dial, retries and the breaker

For each leased unit the adapter renders the upstream endpoint (see [providers.md](providers.md)) and
the gateway dials it, then sends `CONNECT host:port` (HTTP upstream, with `Proxy-Authorization: Basic`
when the credential has a username; only `200` is accepted, `407` is a credential failure) or a SOCKS5
`CONNECT` (SOCKS5 upstream).

**Stage timeouts** of one attempt: DNS 1 s (skipped for an IP literal), TCP connect 2 s over all
addresses, handshake 3 s. Each stage is recorded in `dial_duration_seconds{provider,stage}`.

**Retries.** A dial is tried up to 3 times, with waits of 100 ms and 200 ms, inside the 8 s budget. Only
these failures retry: a DNS or TCP stage timeout, `429` from the upstream, and a reset, abort, broken
pipe or end of stream. A handshake timeout is not retried: a provider that accepted the connection and
stayed silent will not answer the next try. Login and protocol errors never retry.

**Mapping of dial failures to causes:**

| Failure | Cause |
| --- | --- |
| Stage timeout, or TCP `TimedOut` | `provider_timeout` |
| DNS failure, TCP connect failure | `provider_unavailable` |
| Upstream `407`, SOCKS5 login failure, credential that cannot be sent | `provider_auth` |
| Any other upstream status, SOCKS5 reply, protocol error, I/O error in the handshake | `upstream_error` |
| Target that cannot be sent, or an upstream that resolves to a private address | `destination_denied` |

**`local` units** (scheme `local`, see [providers.md](providers.md#local-units)) have no upstream: the gateway
resolves the target, refuses any private or internal address it resolves to, and connects from the unit's local
address with no handshake. A connect that fails there is the target's or the machine's network's, so it
never counts for the breaker or withdraws the unit; a source address that cannot be bound cools the unit for
that target and moves the tunnel to another address.

**Exit-IP re-check.** Before the dial the gateway re-checks the unit's exit IP when its last check is
old: a static IP after 5 minutes, a rotating session after 30 s, once per unit however many tunnels
arrive together. The check is bounded at 3 s. A unit whose exit changed (a rotating session that
changed IP) is withdrawn and the tunnel leases again, up to 3 times per partition. A check that cannot
reach a verdict (services down, slow) serves the tunnel unverified.

**When a static IP fails the dial.** One IP of its class failing is withdrawn (cooldown 60 s, then the
warmer retests it) and the tunnel tries another IP. When two distinct IPs of the route class fail within
10 s the provider failed, not the IPs: nothing more is withdrawn and the tunnel tries one other IP. Any
other IP-level failure (a status, a SOCKS reply, a dropped or silent handshake) cools the unit for that
target for 10 s and moves the tunnel to another unit. A customer's own upstream fails closed: it is
never replaced by a shared IP.

**Route-class breaker.** Each partition (provider and region) has a breaker shared by every gateway
and warmer replica through Redis. Five provider failures within 60 s open it; while open, the walk
skips the partition (`breaker_skips_total`) and answers `provider_unavailable` if nothing else serves.
The first probe is allowed 5 s after opening and each failed probe doubles the wait up to 5 minutes (5,
10, 20, 40, 80, 160, 300 s); three passes close it. A failure counts for the breaker when the provider
could not be reached or rejected the login, once per tunnel that ends refused or served by another
provider. A status or SOCKS reply is an answer, and a local resource limit (no free port or descriptor)
or a customer upstream failing is not counted.

## Relay, idle timeout and the keeper

Bytes are copied both ways without being read, with an 8 KiB buffer per direction. The first byte from
the target is timed as the `first_byte` dial stage.

| Event | Behaviour |
| --- | --- |
| No byte in either direction for `tunnel_idle_timeout` (default 10 min) | The tunnel is closed. A write that makes no progress for that long counts as silence. |
| One direction ends (half-close) | The other gets 60 s to send a byte, then the tunnel is closed. |
| A peer vanishes without FIN or RST | TCP keepalive (60 s idle, 4 probes 15 s apart) finds it. |

A keeper task per tunnel runs every 5 s, separately from the relay, so a slow Redis cannot stall data:

- Pushes the tunnel's counters forward (a tunnel counts for 15 s unless touched), renews the lease when
  bytes moved, records the traffic for load spreading, and meters bytes against the provider's daily
  budget, the org's daily budget and, for a static IP, its monthly fair-use traffic (a warning at 80%,
  and at 100% the IP takes no new lease until the month ends).
- Keeps the session record resolvable for block signals (`X-ProxyX-Pool-Session`): it is stored before
  the `200`, refreshed every third of its 10-minute life while the tunnel is open, and lapses after.
- Closes the tunnel at its next tick when an [org block](#post-v1org-blocks) covers its unit, on every
  replica.
- Closes the tunnel 10 minutes after its unit was drained (a rotating session removed from the ready
  set, or a static IP that left leasing).

## Connection caps

Three limits bound a pod, all closing a new connection at once when reached (counted as `over_limit` in
`connections_total`; no cause code means "pod full", and a client that retries finds another replica):

| Setting | Default | Meaning |
| --- | --- | --- |
| `max_connections` (`PROXYX_POOL_MAX_CONNECTIONS`) | 10000 | Client connections open at once across all three listeners. |
| `max_pending_connections` | `max_connections / 2`, at least 1 | Connections that have not authenticated yet, across all listeners. |
| `max_pending_per_ip` | a quarter of the pending limit, at least 16, at most the pending limit | Unauthenticated connections of one source (an IPv4 address or an IPv6 /64). |

Permits are taken after `accept`, so an idle listener holds none and one listener cannot starve another.
A connection holds its connection permit for its whole life and its pre-auth slot only until its request
head is read and its key checked. The gateway refuses to start when the open-files limit is below
`2 x max_connections + 512`. The control API holds at most 256 connections of its own.

## Response headers

A successful HTTP CONNECT answers:

```text
HTTP/1.1 200 Connection established
X-ProxyX-Pool-Session: 5f0a7c9e2b1d4c6f8a3e0b7d9c2a1f48
X-ProxyX-Exit-IP: 203.0.113.50
```

| Header | Value |
| --- | --- |
| `X-ProxyX-Pool-Session` | An opaque id of this tunnel's lease, 32 hex characters. A client quotes it when it reports a block with [`POST /v1/block-signals`](#post-v1block-signals). |
| `X-ProxyX-Exit-IP` | The exit IP of the leased unit as recorded in the cache (for a SIM box or a customer upstream, the exit address last verified; for a `local` unit, the `ip` of its inventory entry, which is the public exit address even when the unit binds a private one behind a NAT). |

A refusal carries no correlation headers; its reason phrase is the cause code. The `407` also carries
`Proxy-Authenticate: Basic realm="proxyx"`.

## Cause codes

Every gateway refusal is one of these codes. The code is the reason phrase of the HTTP status line, the
`outcome` label of `connections_total`, and the value the failed-lease memo stores. SOCKS5 reply codes
are those of RFC 1928 section 6.

| Code | HTTP | SOCKS5 reply | Meaning |
| --- | --- | --- | --- |
| `auth_required` | 407 | `0x02` (login failure `01 01` at the login step) | Missing, unknown or rate-limited org key, a probe-org key on a public listener, or a bad probe token. |
| `org_disabled` | 403 | `0x02` | The org key exists but an operator disabled it. |
| `option_denied` | 403 | `0x02` | The username is malformed, or an option asks for more than the policy allows. |
| `org_blocked` | 403 | `0x02` | An operator block stops this org in the requested scope. |
| `port_not_allowed` | 403 | `0x02` | Every candidate provider restricts target ports (`allowed_ports`) and refuses this one. |
| `destination_denied` | 403 | `0x02` | The target is a private, loopback, link-local, metadata or cluster address or name; or, on the probe listener, not a probe target. |
| `org_capacity` | 503 | `0x01` | The org reached `max_tunnels_per_org` (org-wide, or on one provider for a route-class policy). |
| `org_budget` | 503 | `0x01` | The org used its `limits.org_max_gb_per_day` for the UTC day. Open tunnels are not cut. |
| `cache_empty` | 503 | `0x01` | No session or IP could be leased and `on_empty` is `create` or `fail`, or a create failed. |
| `no_healthy_ip` | 503 | `0x01` | A static partition has no healthy IP. |
| `cache_unavailable` | 503 | `0x01` | Redis is unreachable, or Postgres is down and the key is not cached. New leases are refused; open tunnels go on. |
| `lease_timeout` | 504 | `0x06` | `on_empty = wait` ran out of `lease_wait`, or Redis was too slow for the lease script. |
| `provider_unavailable` | 502 | `0x01` | The provider refused or could not be reached, its breaker is open, or the adapter could not render the credential. |
| `provider_auth` | 502 | `0x01` | The provider rejected the rendered credential. |
| `provider_timeout` | 504 | `0x06` | The provider did not answer in time, or the 8 s open budget ran out. |
| `upstream_error` | 502 | `0x01` | The provider answered the CONNECT with an unexpected status or SOCKS5 reply. |

Cause codes are lowercase tokens and unique. `403` means the request itself cannot be served as asked,
`407` means credentials, `503` means the pool cannot serve right now, and `502` and `504` mean the
upstream failed or was slow.

Refusals that are not cause codes: `400`, `405` and `431` for a bad HTTP head, and SOCKS5 replies `0x07`
(command not supported) and `0x08` (address type not supported, or an invalid host or port).

## Denied destinations

A target that points inside a network is refused before any lease is taken, with `403 destination_denied`.
The rule covers IP literals in every spelling a resolver accepts (dotted, bracketed IPv6, IPv4-mapped,
NAT64, 6to4, decimal, hex, octal and short IPv4 such as `127.1`) and names that are clearly internal.

IPv4 ranges: `0.0.0.0/8`, `10.0.0.0/8`, `127.0.0.0/8`, `100.64.0.0/10`, `169.254.0.0/16` (link-local,
including the `169.254.169.254` metadata address), `172.16.0.0/12`, `192.0.0.0/24`, `192.0.2.0/24`,
`192.168.0.0/16`, `198.18.0.0/15`, `198.51.100.0/24`, `203.0.113.0/24`, `224.0.0.0/4` and above
(multicast, reserved, broadcast), and the cloud wire-server address `168.63.129.16`.

IPv6: `::` and the rest of `::/96`, IPv4-mapped and IPv4-translated forms (judged by the embedded IPv4
address), NAT64 `64:ff9b::/96` (judged by the embedded IPv4 address) and its local-use `64:ff9b:1::/48`,
6to4 `2002::/16` (judged by the embedded IPv4 address), unique-local `fc00::/7`, link-local `fe80::/10`,
site-local `fec0::/10`, multicast `ff00::/8`, Teredo `2001::/32`, documentation `2001:db8::/32` and
discard `100::/64`. A zone id (`%eth0`) never changes the address.

Names: `localhost`, a name with no dot, a name whose last label is a number, and the suffixes `.svc`,
`.cluster.local`, `.local`, `.localhost`, `.localdomain`, `.internal`, `.lan` and `.home.arpa` (also the
bare zone).

The rule cannot see through a public name that resolves to a private address (for example
`127.0.0.1.nip.io`); that stays with the provider. For an upstream the customer chose
([`public_only`](providers.md#customer-upstreams)) the gateway resolves the upstream host itself, refuses
every non-public address, and connects only to the checked addresses.

## Graceful drain

On SIGTERM (or Ctrl-C) the gateway stops in this order:

1. `/readyz` answers `503 draining` at once, so the Service sends no new traffic. `/healthz` and
   `/metrics` keep answering until the process has finished, so the drain can be watched.
2. The three tunnel listeners stop accepting.
3. Open tunnels get `drain_timeout` (default 300 s) to end on their own. Background writes of the
   gateway are part of the same wait.
4. After that the remaining tunnels are closed and get 5 more seconds to finish.

`drain_timeout` must be above zero. A pod's termination grace period has to cover the pre-stop delay,
the drain and a 15 s stop margin of the role. See [operations.md](operations.md).

## Control API

The control API is served by the gateway process on `api_listen` (default port 8081). Routes live under
`/v1`. The examples use a shell variable for the base URL and the admin token:

```sh
export API=http://localhost:8081
export ADMIN_TOKEN=$(cat /etc/proxyx/secrets/admin-token)
```

See [control-api.md](control-api.md) for the integration guide; this section is the route reference.

### Credentials

| Credential | Header | Routes |
| --- | --- | --- |
| Admin bearer token | `Authorization: Bearer <token>` | inventory, policies, org keys, org blocks, customer upstreams, `POST /v1/ips/{ip}/block` |
| Prober bearer token (a separate secret) | `Authorization: Bearer <token>` | `/v1/probe/*` |
| Org key | HTTP Basic; the password is the org key. The username may carry inbound options and is ignored. | `POST /v1/block-signals` |

The admin token is read from `admin_token_file` (default `/etc/proxyx/secrets/admin-token`), the prober
token from the file `prober-token` in `secrets_dir`. Both must exist and be non-empty or the process
does not start.

Admin routes accept an optional `X-Operator` header (1 to 64 characters of `[A-Za-z0-9-_.@]`) that names
the person in the audit trail; without it the actor is `admin`. The token is shared, so the header
names the person but does not authenticate them. A malformed value is `400`.

### Conventions

- **Bodies** are JSON objects with `Content-Type: application/json` (`application/*+json` is accepted).
  A missing content type is `415`; a malformed body, a JSON array where an object is required, or an
  unknown field on a strict body is `400`. `POST /v1/block-signals` and `PUT /v1/inventory/{provider}`
  are the routes whose body shape differs, as noted below.
- **Timestamps** in responses are Unix seconds.
- A body above 4 MiB is `413`. A request, including its storage calls, must finish within 15 s or the
  answer is `504 request timed out`. A client has 10 s to send a whole request head.
- Responses never contain internal causes: those are logged and the client gets a generic message.

### Error body

Every error, also for an unknown route and a wrong method, is a JSON object with one field:

```json
{"error": "unauthorized"}
```

| Status | When |
| --- | --- |
| `400` | Invalid input: path segment, query, body, header (the message names the field). |
| `401` | Missing or wrong credential (`{"error":"unauthorized"}`). |
| `403` | A valid org key whose org is disabled (`{"error":"org_disabled"}`). |
| `404` | Unknown route (`no such route`) or unknown object. |
| `405` | Wrong method (`method not allowed`); the `Allow` header is set. |
| `409` | Conflict or a stale update (for example a policy git wrote, or an upstream changed during a check). |
| `413` | Body above 4 MiB. |
| `415` | Body route called without a JSON content type. |
| `422` | A customer upstream check failed; the body carries the reason (see the upstream routes). |
| `429` | Too many wrong credentials from this source; `Retry-After` gives the seconds left. |
| `503` | Storage unavailable, or a required secret is not configured. |
| `504` | The request exceeded 15 s. |

Wrong credentials are throttled per source (an IPv4 address or an IPv6 /64): after 20 failures in a
fixed 60 s window, a wrong org key is answered `429` without a lookup, and a wrong bearer token is `429`
instead of `401`. A correct bearer token always passes. The counts are per pod, and are visible in
`auth_failures_total{reason}`.

### Route index

| Method | Path | Credential |
| --- | --- | --- |
| `POST` | [`/v1/block-signals`](#post-v1block-signals) | org key |
| `GET` | [`/v1/inventory`](#get-v1inventory) | admin |
| `GET` | [`/v1/inventory/replacements`](#get-v1inventoryreplacements) | admin |
| `PUT` | [`/v1/inventory/{provider}`](#put-v1inventoryprovider) | admin |
| `POST` | [`/v1/ips/{ip}/block`](#post-v1ipsipblock) | admin |
| `GET` | [`/v1/policies`](#get-v1policies) | admin |
| `PUT` | [`/v1/policies`](#put-v1policies) | admin |
| `DELETE` | [`/v1/policies/{scope}/{name}`](#delete-v1policiesscopename) | admin |
| `PUT` | [`/v1/orgs/{org}/cache-policy`](#put-v1orgsorgcache-policy) | admin |
| `POST` | [`/v1/orgs/{org}/keys`](#post-v1orgsorgkeys) | admin |
| `DELETE` | [`/v1/orgs/{org}/keys`](#delete-v1orgsorgkeys) | admin |
| `GET` | [`/v1/orgs/{org}/upstream`](#get-v1orgsorgupstream) | admin |
| `PUT` | [`/v1/orgs/{org}/upstream`](#put-v1orgsorgupstream) | admin |
| `DELETE` | [`/v1/orgs/{org}/upstream`](#delete-v1orgsorgupstream) | admin |
| `POST` | [`/v1/orgs/{org}/upstream/validate`](#post-v1orgsorgupstreamvalidate) | admin |
| `POST` | [`/v1/orgs/{org}/upstream/rotate-secret`](#post-v1orgsorgupstreamrotate-secret) | admin |
| `POST` | [`/v1/org-blocks`](#post-v1org-blocks) | admin |
| `GET` | [`/v1/org-blocks`](#get-v1org-blocks) | admin |
| `DELETE` | [`/v1/org-blocks/{id}`](#delete-v1org-blocksid) | admin |
| `GET` | [`/v1/probe/targets`](#get-v1probetargets) | prober |
| `POST` | [`/v1/probe/results`](#post-v1proberesults) | prober |
| `POST` | [`/v1/probe/token`](#post-v1probetoken) | prober |

IDs: an org id is `[a-z0-9_-]{1,64}`, a provider id `[a-z0-9_-]{1,48}`, and a region `cc` or `cc/city`
(see [policies.md](policies.md#regions)). A path segment that is not valid is `400`.

### `POST /v1/block-signals`

Report that targets blocked tunnels. Clients post batches here with the org key as the Basic
password. Body: a JSON array of at most 500 events:

```json
[
  {
    "session": "5f0a7c9e2b1d4c6f8a3e0b7d9c2a1f48",
    "exit_ip": "203.0.113.50",
    "target": "example.com:443",
    "type": "rate_limited",
    "time": 1767225600
  }
]
```

| Field | Meaning |
| --- | --- |
| `session` | The `X-ProxyX-Pool-Session` of the tunnel. |
| `exit_ip` | The `X-ProxyX-Exit-IP` of the tunnel. |
| `target` | `host`, `host:port` or `[v6]:port`. |
| `type` | `rate_limited` (HTTP 429), `challenge` (403 or 503 with a challenge marker, or a `/sorry/` redirect), `forbidden` (repeated plain 403) or `reset` (reset or TLS failure after a successful tunnel). |
| `time` | Unix seconds of the event. |

Other fields (for example `org`, `status`) are ignored: the org comes from the key and the session from
the session record. An event is applied only when it is at most one hour old, its session belongs to the
calling org, and `exit_ip` equals the exit IP recorded for that session; any other event is counted as
ignored. One malformed event (an invalid `target`) refuses the whole batch with `400` before anything is
applied. A retried batch does not count its events twice.

Each applied event cools the exit IP for that target, and escalates to the whole IP by the policy's
[block rules](policies.md#block).

```sh
curl -sS -u 'px-kind-static:ak_YOUR_KEY' -H 'Content-Type: application/json' \
  -d '[{"session":"5f0a7c9e2b1d4c6f8a3e0b7d9c2a1f48","exit_ip":"203.0.113.50","target":"example.com:443","type":"rate_limited","time":1767225600}]' \
  $API/v1/block-signals
```

Response `200`: `{"accepted": 1, "ignored": 0}`. Errors: `400` (batch too large or invalid event),
`401`, `403 org_disabled`, `429`.

### `GET /v1/inventory`

List static inventory rows. Query: `provider` (provider id) and `state` (one of `candidate`, `available`,
`leased`, `degraded`, `cooldown`, `quarantined`, `rotating`, `offline`, `replace_requested`, `retired`),
both optional.

```sh
curl -sS -H "Authorization: Bearer $ADMIN_TOKEN" "$API/v1/inventory?provider=oxylabs_isp&state=available"
```

Response `200`:

```json
{
  "items": [
    {
      "ip": "203.0.113.50",
      "provider": "oxylabs_isp",
      "region": "fr/paris",
      "subtype": "isp",
      "plan": "isp-10",
      "host": "isp.oxylabs.io",
      "port": 8001,
      "asn": 12345,
      "rental_end": "2027-01-31",
      "state": "available",
      "state_since": 1767225600,
      "cooldown_until": null,
      "quarantined_at": null,
      "retest_at": null,
      "offline_since": null,
      "last_check_at": 1767226000,
      "exit_ip": "203.0.113.50",
      "owner": null
    }
  ]
}
```

`owner` is the org id for a customer upstream and `null` for a shared IP. Errors: `400`, `401`, `429`.

### `GET /v1/inventory/replacements`

The replacement report: one item per IP in `replace_requested`, with the row fields above plus `scores`
(the newest three reputation scores per service: `source`, `risk`, `flags`, `checked_at`) and
`blocks_by_target` (block counts per target over 30 days; `*` is an IP-wide block). A developer replaces
the IP in the provider panel and edits the inventory.

```sh
curl -sS -H "Authorization: Bearer $ADMIN_TOKEN" $API/v1/inventory/replacements
```

### `PUT /v1/inventory/{provider}`

Make one provider's inventory equal to the body. Known IPs keep their state, new IPs start as `candidate`,
retired IPs that return are revived as `candidate`, and every other non-retired IP of the provider that
the list leaves out is retired (customer-owned units are never retired this way). The change is atomic.

Body: `{"entries": [...]}`, at most 10,000 entries, each an entry of the
[inventory file format](providers.md#static-inventory-file) with `provider` equal to the path provider:

```sh
curl -sS -X PUT -H "Authorization: Bearer $ADMIN_TOKEN" -H 'X-Operator: alice@example.com' \
  -H 'Content-Type: application/json' $API/v1/inventory/oxylabs_isp -d '{
    "entries": [{
      "provider": "oxylabs_isp", "subtype": "isp", "plan": "isp-10",
      "ip": "203.0.113.50", "host": "isp.oxylabs.io", "port": 8001,
      "region": "fr/paris", "credentials": "oxylabs_isp_203-0-113-50",
      "rental_end": "2027-01-31"
    }]
  }'
```

An entry is refused (`400`, the message starts with its IP) when its subtype is rotating, its IP is not
a public address (unspecified, loopback, private, link-local, multicast or broadcast), its host is not a
plain DNS name or IP, its port is `0` (a `local` adapter's entries take any port, the value is not used), its `credentials` is not a plain file name, its text has a NUL
byte, or an IP appears twice. Retired and moved IPs are withdrawn from the ready set after the commit.

Response `200`:

```json
{"provider": "oxylabs_isp", "added": ["203.0.113.50"], "updated": [], "revived": [], "retired": [], "unchanged": 0}
```

### `POST /v1/ips/{ip}/block`

An operator reports that an IP is blocked. A static IP is found in the inventory; a rotating IP needs the
session id. Body (all optional):

| Field | Meaning |
| --- | --- |
| `target` | The host that blocked the IP; unset blocks the IP for every target. |
| `type` | A signal type (see `POST /v1/block-signals`); default `forbidden`. |
| `session` | The `X-ProxyX-Pool-Session` of a rotating session, when the IP is not in the inventory. |

```sh
curl -sS -X POST -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"target":"example.com"}' $API/v1/ips/203.0.113.50/block
```

Response `200`: `{"scope": "target"}`. `scope` is how far the reaction went: `target` (cooled for that
host only), `ip` (taken out of leasing for all targets) or `pool_guard` (the share of the partition that
may be cooled was reached, so escalation stopped). `404` when the IP is neither in the inventory nor a
known session of that IP. The block rules of the probe org's policy apply.

### `GET /v1/policies`

The current version of every stored policy.

```sh
curl -sS -H "Authorization: Bearer $ADMIN_TOKEN" $API/v1/policies
```

```json
{
  "items": [
    {"scope": "global", "name": "global", "match": null, "version": 3, "actor": "gitops",
     "created_at": 1767225600, "doc": {"name": "global", "scope": "global", "min_ready": 10}}
  ]
}
```

`actor` is `gitops` for a policy written from the git data directory and the operator name otherwise.
`doc` is the stored document with unset fields omitted and durations in seconds.

### `PUT /v1/policies`

Store policy documents. Body: `{"policies": [ ... ]}`, between 1 and 200 documents, each a policy document
as described in [policies.md](policies.md#policy-document), in JSON. Durations may be integers
(seconds) or strings such as `"30m"`. Each document is stored as a new version when it differs from the
current one; a document equal to the current one is `unchanged`.

```sh
curl -sS -X PUT -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  $API/v1/policies -d '{"policies":[{"name":"acme-limits","scope":"org","match":"acme",
    "max_tunnels_per_org":50,"limits":{"org_max_gb_per_day":20}}]}'
```

Every write is validated as part of the whole set first: the documents plus every current policy they do
not replace must form a valid set, fit each rotating provider's session life, and be servable (some
loaded adapter of its kinds and providers has a ready region in it). A policy the set would refuse never
reaches Postgres (`400` with the validation message). Response `200`:
`{"stored": ["org/acme-limits"], "unchanged": 0}`.

Policies of scope `global` and `route_class` belong to git. The API can still write them as an emergency
change; that version stays until git changes that same policy, and then git wins.

### `DELETE /v1/policies/{scope}/{name}`

Stop using the current version of a policy written through the API (its versions stay in the history).
`scope` is `global`, `route_class` or `org`. Deleting an API version of a policy that git defines goes back
to git's: the next reload writes git's document again. The set that remains must still be valid, so a
global policy that orgs depend on cannot be dropped from under them (`400`). `409` when git wrote the
current version: delete its file from the git policy data instead. `404` when the policy is not current.

```sh
curl -sS -X DELETE -H "Authorization: Bearer $ADMIN_TOKEN" $API/v1/policies/org/acme-limits
```

Response `200`: `{"deactivated": "org/acme-limits", "written_by": "alice@example.com"}`.

### `PUT /v1/orgs/{org}/cache-policy`

Set the policy of one org. The body is one policy document; `scope` is `org` and `match` is the org (a body
that names anything else is `400`), and `name` defaults to `org-<org>`. Validation and the response are
those of `PUT /v1/policies`.

```sh
curl -sS -X PUT -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  $API/v1/orgs/acme/cache-policy -d '{"regions":["de"],"rotating":{"headroom":1}}'
```

### `POST /v1/orgs/{org}/keys`

Create an org key and return it. Body optional: `{"label": "ci"}` (at most 128 bytes). Only the SHA-256
is stored, so this response is the only time the key can be read. The response is `201` with
`Cache-Control: no-store`:

```json
{"org": "acme", "key": "ak_EXAMPLE_ONLY_NOT_A_REAL_KEY"}
```

```sh
curl -sS -X POST -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"label":"ci"}' $API/v1/orgs/acme/keys
```

### `DELETE /v1/orgs/{org}/keys`

Disable every key of the org. Response `200`: `{"org": "acme", "disabled": 2}` (the number of keys that
were enabled). A gateway pod stops trusting a disabled key within 30 s (its cache's fresh time), and answers
`org_disabled` from then.

### `GET /v1/orgs/{org}/upstream`

The org's customer upstream, or `404`. The stored login is never returned.

```json
{
  "org": "acme", "provider": "customer", "scheme": "http",
  "host": "proxy.example.net", "port": 3128, "region": "fr",
  "unit": "fd00:1:2:3:4:5:6:7", "state": "available", "state_since": 1767225600,
  "leasable": true, "exit_ip": "198.51.100.77", "last_check_at": 1767226000,
  "has_login": true, "set_by": "alice@example.com"
}
```

`unit` is a stable key derived from the org id (never dialed, never an exit IP). `set_by` is the actor of
the latest `PUT`.

### `PUT /v1/orgs/{org}/upstream`

Set the org's own upstream proxy. The unit starts as `candidate` and nothing leases it until
[`validate`](#post-v1orgsorgupstreamvalidate) passes. Body (strict):

| Field | Meaning |
| --- | --- |
| `scheme` | `http` (CONNECT) or `socks5`; `local` is refused with `400`. |
| `host` | A plain DNS name or IP literal, without scheme, port, path or login. |
| `port` | 1 to 65535. |
| `region` | Where the upstream exits, as the org's policy regions name it. |
| `username`, `password` | Optional, both or neither, 1 to 255 bytes each, no NUL. |

The host must be public routable: it is checked as a name, then every address it resolves to must pass
the [denied destination](#denied-destinations) rule (`400` otherwise, also when it does not resolve in
3 s). The adapter's own rendering rules apply. Response `200`: the object of `GET`, plus a `warning` when
the org's effective policy lists `providers` without the upstream's provider (every tunnel would answer
`no_healthy_ip`).

```sh
curl -sS -X PUT -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  $API/v1/orgs/acme/upstream -d '{"scheme":"http","host":"proxy.example.net","port":3128,
    "region":"fr","username":"u","password":"p"}'
```

The gateway reads its snapshot every `reload_every` (default 30 s), so a `PUT` or `DELETE` is in force on
each pod after its next reload. Until then an org that had no upstream keeps leaving through a shared IP,
and a `DELETE` answers `504 lease_timeout`. Set the upstream before the org's first tunnel.

### `DELETE /v1/orgs/{org}/upstream`

Retire the unit and delete the login. No new tunnel starts on it; open tunnels end on their own.
Response `200`: `{"org": "acme", "unit": "fd00:...", "state": "retired"}`; `404` when there is none.

### `POST /v1/orgs/{org}/upstream/validate`

Dial through the upstream with the stored login and run the exit-IP quorum (12 s limit). The exit country
must be the declared region's. A pass makes the unit `available` and leasable by its org:

```json
{"org": "acme", "provider": "customer", "state": "available", "leasable": true,
 "exit_ip": "198.51.100.77", "valid": true, "country": "fr"}
```

A failure changes nothing and answers `422`:
`{"org": "acme", "reason": "unverified", "error": "...", "valid": false}`, where `reason` is one of
`refused`, `unverified`, `exit_disagree`, `country_mismatch`, `timeout`, `private_exit`. Every outcome is
audited. `409` when a `PUT`, `rotate-secret` or `DELETE` landed during the check (nothing changes).

### `POST /v1/orgs/{org}/upstream/rotate-secret`

Replace the stored login after a check through the upstream with the new one passed. Body (strict):
`{"password": "...", "username": "..."}`; `username` unset keeps the stored one. Response `200`:
`{"org": "acme", "rotated": true}`. A failed check answers `422` with `"rotated": false` and the same
`reason` values as `validate`. `409` when the unit changed during the check.

### `POST /v1/org-blocks`

Stop an org from using a scope. Open tunnels of the org inside the scope are asked to close, on the replica
that served the call at once and on every other replica at its keeper's next tick. Body (strict):

| Field | Meaning |
| --- | --- |
| `org` | Org id. |
| `scope` | `ip`, `provider`, `route_class` or `pool`. |
| `value` | An address for `ip`; a provider id for `provider`; `provider:region` for `route_class`; `shared` or `private` for `pool`. |
| `reason` | Free text, at most 1,000 bytes. |
| `ttl` | Optional, `2h`, `30m`, at most 366 days; unset: until revoked. |

```sh
curl -sS -X POST -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  $API/v1/org-blocks -d '{"org":"acme","scope":"provider","value":"oxylabs_res",
    "reason":"abuse report 1234","ttl":"2h"}'
```

Response `201`:

```json
{"id": "6f1f6d5e-3c7a-4d4b-9c52-2f1a5a5d8f10", "org": "acme", "scope": "provider",
 "value": "oxylabs_res", "reason": "abuse report 1234", "operator": "admin",
 "created_at": 1767225600, "expires_at": 1767232800, "revoked_at": null, "drained": 3}
```

`drained` is how many open tunnels this replica asked to close. New tunnels in the scope are refused with
`org_blocked` (a block is checked inside the lease, so an org with other usable units is not refused).

### `GET /v1/org-blocks`

Blocks that are neither revoked nor expired; optional query `org`. Response `200`: `{"items": [ ... ]}` with
the block object above (without `drained`).

### `DELETE /v1/org-blocks/{id}`

Lift a block by its uuid. Response `200` with the block object (`revoked_at` set). The cache entry stays
while another active block of the same org and scope still needs it. `404` when the block is unknown or
already lifted; a cache failure is `503` and lifts nothing.

### `GET /v1/probe/targets`

For the prober (bearer `prober-token`). What to test: every route class once per interval (the hourly
canary), and the browser samples the warmer queued.

```json
{
  "route_classes": [
    {"route_class": "oxylabs_res", "provider": "oxylabs_res",
     "regions": [{"region": "fr", "country": "fr", "targets": ["https://www.google.com/", "https://www.google.fr/"]}]}
  ],
  "samples": [
    {"job_id": "a1b2", "route_class": "oxylabs_res", "provider": "oxylabs_res", "region": "fr",
     "country": "fr", "sid": "s9", "targets": ["https://www.google.com/"]}
  ]
}
```

Every provider is a route class (a provider with a `route_class` policy takes that policy's name). A
provider id that contains `-` is skipped, because the prober builds usernames from it. Regions come from
the probe org's effective policy; targets come from [`probe-targets.toml`](providers.md#probe-targets).

### `POST /v1/probe/results`

The prober's raw measurements. The API applies the policy criteria (`max_ttfb_ms`, `max_load_ms`,
`min_success`) and returns the verdict. Body:

```json
{
  "kind": "canary", "provider": "oxylabs_res", "region": "fr",
  "results": [
    {"outcome": "ok", "status": 200, "ttfb_ms": 410.0, "load_ms": 1800.0},
    {"outcome": "blocked", "status": 429, "block_reason": "rate limited"}
  ]
}
```

| Field | Meaning |
| --- | --- |
| `kind` | `canary` or `sample`. A `sample` needs `job_id` (1 to 64 of `[A-Za-z0-9_-]`). |
| `provider`, `region` | The route class tested. The region must be one of the provider's policy regions. |
| `results` | 1 to 1,000 page loads: `outcome` is `ok`, `blocked`, `timeout` or `error`; optional `status`, `ttfb_ms`, `load_ms`, `block_reason`. |

A run is good when it loaded and stayed within the time limits; the verdict passes when the share of good
runs reaches `min_success`. A **sample** verdict is stored under its job id and the job is no longer listed.
A **canary** verdict is stored under `canary:<provider>:<region>`: a canary that failed on blocks or errors
drains the route class (every ready unit leaves the ready set, static IPs go to cooldown) and pauses
warming for 2 hours; one that only found slow pages moves the route class's units to the degraded tier and
keeps leasing; a passing one lifts the pause and returns degraded units to normal. Response `200`:
`{"verdict": {...}, "drained": 0, "degraded": 0, "promoted": 0}`. `404` for an unknown provider.

### `POST /v1/probe/token`

Issue a probe-listener password (see [Probe tokens](#probe-tokens)). No body.

```sh
curl -sS -X POST -H "Authorization: Bearer $PROBER_TOKEN" $API/v1/probe/token
```

Response `200`: `{"token": "pt1.1767227400.AbC...", "expires_in_s": 1800}`. `503` when no probe secret is
configured.
