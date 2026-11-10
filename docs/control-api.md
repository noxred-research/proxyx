# Control plane API

`proxyx control` is the session control plane. It has two long-running roles and two admin tools:

| Command | Role |
|---|---|
| `proxyx control api` | REST (`/rpc/*`) and GraphQL (`/graphql`) server: sessions, orgs, traffic queries, traffic view exports; also runs the background reapers |
| `proxyx control ingester` | consumes the captures log and writes ClickHouse (see [capture-pipeline.md](capture-pipeline.md)); serves health and metrics on its own port |
| `proxyx control keys create\|list\|disable` | manage API keys (needs Postgres only) |
| `proxyx control schema export\|validate\|manifest` | GraphQL federation schema tooling (needs no infrastructure) |

`proxyx migrate control [--target all|postgres|clickhouse|opensearch|broker] [--check]` applies (or verifies) the Postgres schema, the schema of the capture store and the captures log of the broker: `all` takes the store from `capture_store.backend` and the broker from `broker_kind` (a Kafka topic, or the RabbitMQ exchanges and queues; Redis Streams needs none); `clickhouse`, `opensearch` and `broker` name one part. `--target clickhouse` no longer creates the broker topic, use `all` or `broker`. Each command takes `--config <file>`, which overrides the environment.

Configuration comes from `./control.toml` (or `/etc/proxyx/control.toml`), environment variables `PROXYX_CONTROL_<KEY>` (`__` nests, for example `PROXYX_CONTROL_CLICKHOUSE__URL`) and `--config`; see [configuration.md](configuration.md). The session data plane that consumes what this API creates is described in [session-proxy.md](session-proxy.md); the overall layout is in [architecture.md](architecture.md).

```mermaid
flowchart LR
    S[Service client] -->|"/rpc, Bearer pxk_ service key"| API[control api :9000]
    U[Operator or UI] -->|"/graphql, user or admin key"| API
    API --> PG[(Postgres<br/>orgs, keys, session_lifecycle, view jobs)]
    API --> R[(Redis<br/>session JSON, rate limits)]
    API --> CH[(ClickHouse<br/>reads)]
    API -->|SessionEnd| B[(Broker)]
    API -->|"INSERT INTO FUNCTION"| CH
    CH -->|Parquet| O[(S3 or Azure Blob)]
    PX[proxyx-intercept] --> R
    PX --> B
    B --> ING[control ingester :9001]
    ING --> CH
    ING -->|"close sessions"| PG
```

## Listeners

| Address | Default | Served by |
|---|---|---|
| `api_addr` | `0.0.0.0:9000` | `control api`: `/rpc/*`, `/graphql`, health, metrics |
| `ingester_health_addr` | `0.0.0.0:9001` | `control ingester`: `GET /health`, `GET /metrics` |

Unauthenticated routes of the API: `GET /health`, `GET /health/live`, `GET /health/ready`, `GET /health/store`, `GET /health/broker`, `GET /rpc/health` (`/health/live` always returns `200` with an empty body; `/health/ready`, `/health` and `/rpc/health` return `200` only when Postgres (`SELECT 1`) and Redis (`PING`) both answer within 2 s, else `503`; the capture store is not part of readiness; `/health/store` probes it and `/health/broker` reports the captures-log producer, see below) and `GET /metrics`. The ingester's `/health` returns `200` while its consumer task runs, the capture store's circuit breaker is closed and the broker connection is up (Kafka, RabbitMQ), and `503` otherwise; `/metrics` is the Prometheus endpoint (catalogue: [metrics/session-proxy.md](metrics/session-proxy.md)). Requests carry W3C `traceparent` through to the server span.

## Authentication

`auth_mode` (`PROXYX_CONTROL_AUTH_MODE`) selects how callers are identified. Two principal types exist, and each part of the API accepts one:

| Surface | Accepts | Everything else |
|---|---|---|
| `/rpc/*` | service principal | `401` |
| `/graphql` | user principal (including superadmin) | `401` |

An error response from authentication has an empty body. `401` means missing or wrong credentials (or the wrong principal type for the surface), `503` means the key store could not be reached.

### `keys` (default): Bearer API keys

Send `Authorization: Bearer pxk_...` (scheme is case-insensitive). A key is `pxk_` followed by 43 base64url characters (32 random bytes). Only its SHA-256 is stored in the Postgres table `api_keys`; the key is printed once, when created.

| Kind | Bound to | Principal | Can call |
|---|---|---|---|
| `service` | one org | service (`service_name` = key name) | `/rpc/*` of its own org |
| `user` | one org | user with that org | `/graphql`, scoped to its org |
| `admin` | no org | user with the `superadmin` role | `/graphql`, every org, and the superadmin mutations |

Manage keys from any host that can reach Postgres (`database_url`):

```sh
proxyx control keys create --kind service --org acme --name crawler
# pxk_...   (printed once on stdout)
proxyx control keys create --kind admin --name ops@example.com
proxyx control keys list --org acme        # JSON lines: id, kind, org_id, name, disabled, created_at
proxyx control keys disable 3f9a0c51d2b7e684     # id as shown by `list`
```

`--name` is 1-64 characters of `[A-Za-z0-9._@-]`. Service and user keys require `--org`; an admin key must not have one. The key id is the hex of the first 8 bytes of the hash. A verified key is cached for 30 s and an unknown key is remembered for 5 s, so a disabled key stops working everywhere within 30 s. The user id of a `user` or `admin` principal is a UUIDv5 of the key name, so two keys with the same name act as the same user.

### `trusted_headers`: principal headers from a gateway

Choose this when an authenticating gateway sits in front of the API and sets the principal headers itself. The API then trusts the headers as given, so it must not be reachable by anyone else.

| Header | Meaning |
|---|---|
| `x-proxyx-principal-type` | `service`, `user` or `superadmin` (anything else is `401`) |
| `x-proxyx-service-name` | service name (service) |
| `x-proxyx-org-id` | org (required for service; optional for user) |
| `x-proxyx-user-id` | user UUID (user, superadmin) |
| `x-proxyx-system-roles` | comma-separated roles; `superadmin` grants cross-org access |

Outside `env = "dev"` the `/rpc/*` routes additionally require the first address of `X-Forwarded-For` to be inside `internal_allowed_cidrs` (comma-separated CIDRs or single addresses); otherwise the response is `403`. The check runs before authentication. It does not apply to `/graphql`.

### Authorization

A service principal may only act inside its own org. Any `{org_id}` in a path, `org_id` in a body or query, or org of a session that differs from the principal's org gives `403 {"error":"service principal cannot access requested org"}`. When a request body omits `org_id`, the principal's org is used.

User principals on `/graphql`: a regular user is limited to its own org (asking for another gives an error); a superadmin may name any org, and when `orgId` is omitted on a search it may query across all orgs.

## Conventions

- All REST bodies are JSON. Errors are `{"error": "<message>"}` with the status codes shown below. Internal errors return `500` and include the error text.
- Timestamps in responses are RFC 3339 strings, except `expires_at_ms`, which is epoch milliseconds.
- `org_id` must match for every call; examples below use `acme` and a service key in `$KEY`.

```sh
export API=http://localhost:9000
export KEY=pxk_...
alias px='curl -sS -H "Authorization: Bearer $KEY" -H "Content-Type: application/json"'
```

## REST routes

| Method | Path | Purpose | Success |
|---|---|---|---|
| POST | `/rpc/sessions` | create or attach to a session | `201` |
| GET | `/rpc/sessions/{session_id}` | read a session's configuration | `200` |
| PATCH | `/rpc/sessions/{session_id}` | extend a session | `200` |
| DELETE | `/rpc/sessions/{session_id}` | release a session | `200` |
| GET | `/rpc/sessions/{session_id}/status` | lifecycle state | `200` |
| GET | `/rpc/processed` | whether a source's capture was stored | `200` |
| POST | `/rpc/requests/search` | search HTTP captures | `200` |
| POST | `/rpc/requests/count` | count HTTP captures | `200` |
| GET | `/rpc/orgs/{org_id}/requests/{id}` | one HTTP capture with bodies | `200` |
| POST | `/rpc/ws/search` | search WebSocket messages | `200` |
| POST | `/rpc/ws/count` | count WebSocket messages | `200` |
| GET | `/rpc/orgs/{org_id}/ws-messages/{id}` | one WebSocket message | `200` |
| GET | `/rpc/orgs/{org_id}/captures/{parent_event_id}/ws-messages` | one conversation | `200` |
| GET | `/rpc/sequence` | watermark cursor and count of a source | `200` |
| GET | `/rpc/orgs/{org_id}/rate-limit-state` | live rate-limit bucket | `200` |
| GET, POST | `/rpc/orgs` | list (own org only), create | `200`, `201` |
| GET, DELETE | `/rpc/orgs/{org_id}` | read, delete | `200`, `204` |
| GET, PUT | `/rpc/orgs/{org_id}/rate-limit` | read, set limits | `200` |
| GET, PUT, DELETE | `/rpc/orgs/{org_id}/proxy` | egress proxy of the org | `200`, `200`, `204` |
| GET | `/rpc/certificate` | MITM CA certificate (PEM, `text/plain`) | `200` |
| POST | `/rpc/views` | start or reuse a Parquet export | `200` or `202` |
| GET | `/rpc/views/{view_id}` | poll an export | `200` |

Unparsable UUIDs in a path give `400`.

### Sessions

#### `POST /rpc/sessions`

Request:

```json
{
  "org_id": "acme",
  "source": "crawler",
  "source_id": "run-2026-11-10-001",
  "captured_hosts": ["*.example.com", "api.partner.io"],
  "excluded_hosts": ["static.example.com"],
  "upstream_overrides": { "app.example.test:443": "http://app.internal.svc:8000" },
  "inject_headers": [["Accept-Language", "en-US"], ["X-Tenant", "acme"]],
  "serialize": false,
  "agent": "Mozilla/5.0 (X11; Linux x86_64) Firefox/135.0",
  "ttl_secs": 900
}
```

| Field | Required | Notes |
|---|---|---|
| `org_id`, `source`, `source_id` | yes | `org_id` and `source_id` must be non-empty. `source` labels the caller kind; `source_id` identifies the run and is what traffic queries filter on. |
| `captured_hosts` | yes | host patterns to intercept; `[]` captures nothing (see [session-proxy.md](session-proxy.md#capture-patterns)) |
| `inject_headers` | yes | list of `[name, value]` pairs; `[]` for none |
| `serialize` | yes | run one exchange at a time per session |
| `ttl_secs` | yes | `0` uses `session_default_ttl_secs` (default 600) |
| `excluded_hosts`, `upstream_overrides` | no | default empty |
| `agent` | no | user-agent string that picks the TLS profile ([session-proxy.md](session-proxy.md#tls-profiles)) |

`upstream_overrides` entries are validated here: invalid entries give `400` naming the entry.

Response `201`:

```json
{
  "session_id": "0f6d3a4e-5b1c-4d52-9a0e-7c1b2e8d4f10",
  "ca_cert_pem": "-----BEGIN CERTIFICATE-----\n...",
  "expires_at_ms": 1783689600000,
  "proxy_url": "http://0f6d3a4e-...:password@localhost:8443",
  "proxy_url_socks5": "socks5://0f6d3a4e-...:password@localhost:1080",
  "upstream_overrides": { "app.example.test:443": "http://app.internal.svc:8000" }
}
```

`proxy_url` and `proxy_url_socks5` are built from `proxy_public_host` (default `localhost:8443`) and `proxy_public_host_socks5` (default `localhost:1080`); set them to the externally reachable addresses. The literal password `password` is arbitrary, because the proxy ignores it. When the call attached to an existing session, the response also has `"attached": true` and, if the capture configuration differs, `"warning"`. `success` is `true`, and `error` is absent.

| Status | Cause |
|---|---|
| `400` | empty `org_id` or `source_id`; invalid override entry; malformed body |
| `403` | org is not the principal's org |
| `409` | an active session exists for the same `(org_id, source, source_id)` with different `upstream_overrides` |
| `500` | Redis or Postgres failure |

```sh
px -X POST $API/rpc/sessions -d '{
  "org_id":"acme","source":"crawler","source_id":"run-001",
  "captured_hosts":["*"],"excluded_hosts":[],"inject_headers":[],
  "serialize":false,"ttl_secs":900}'
```

##### What creating a session does

1. Looks for an active `session_lifecycle` row for `(org_id, source, source_id)`; if found, attaches (below).
2. Otherwise reads the org row from Postgres. The org's rate limits (falling back to `default_rate_limit_rpm`/`default_rate_limit_burst` when the columns are `NULL`, or when the org does not exist) and egress proxy are copied into the session. If either limit is above 0, they are also written to Redis `{prefix}:ratelimit:{org}:config`.
3. Writes the session JSON to `{prefix}:session:{session_id}:data` with an expiry of `ttl_secs`, and inserts the `session_lifecycle` row (`state = 'active'`, `ref_count = 1`). If the insert fails, the Redis key is deleted again; a unique violation (a concurrent create won) turns into an attach to the winner.

A session's `org_id`, `source` and `source_id` become `org_id`, `source` and `source_id` of every capture made through it.

#### Session lifecycle

```mermaid
stateDiagram-v2
    [*] --> active: POST /sessions (ref_count 1)
    active --> active: POST (attach) +1 / DELETE -1
    active --> consuming: last DELETE, or expired + 5 min grace
    consuming --> closed: ingester stored every earlier capture
    consuming --> consuming: reaper re-sends SessionEnd after 5 min
    closed --> [*]
```

- **Attach.** A second `POST /rpc/sessions` with the same `(org_id, source, source_id)` while the session is `active` returns the same `session_id` with `"attached": true`, and increments `ref_count`. The expiry becomes the later of the two deadlines (Redis TTL and `expires_at` both move). The existing configuration is kept: if `captured_hosts`, `excluded_hosts`, `inject_headers`, `serialize` or `agent` differ from the request, the response carries `"warning": "attached to existing session but config differs on: <fields>; existing config is used"`. If `upstream_overrides` differ, the request fails with `409` instead, because routing to private targets must not change under another caller. A unique index allows at most one active row per triple.
- **Release.** `DELETE /rpc/sessions/{id}` decrements `ref_count` (never below 0) and answers `200`. Only when it reaches 0 does teardown run: the row moves to `consuming`, `{prefix}:session_invalidations` is published so proxies drop their cached copy, and a `SessionEnd` event is published to the captures log keyed by `source_id`. A `DELETE` is `404` when the session's Redis key no longer exists (expired or never created); while the key exists, a session that is already past `active` answers `200` and does nothing. The Redis key is not removed; it expires at its TTL.
- **Close.** The ingester marks the row `closed` once the `SessionEnd` and every message its consumer read before it have been stored in ClickHouse (see [capture-pipeline.md](capture-pipeline.md#session-close)).
- **Reapers.** The API process runs a pass every 60 s. Sessions still `active` more than 300 s after `expires_at` (callers that never `DELETE`) move to `consuming` and get a `SessionEnd`. Sessions stuck in `consuming` for more than 300 s get their `SessionEnd` re-published (each claim renews the row's `closing_at`, so replicas do not publish it twice in one window). The same pass expires old [traffic views](#traffic-views).

A session's traffic is only guaranteed queryable once the session is `closed`; `GET /rpc/processed` reports this per source.

#### `GET /rpc/sessions/{session_id}`

Returns the stored configuration:

```json
{
  "session_id": "0f6d3a4e-...", "org_id": "acme", "source": "crawler", "source_id": "run-001",
  "agent": null, "captured_hosts": ["*"], "excluded_hosts": [], "upstream_overrides": {},
  "inject_headers": [], "serialize": false, "expires_at_ms": 1783689600000,
  "egress_proxy": null, "rate_limit": { "requests_per_minute": 6000, "burst": 1000 }
}
```

`egress_proxy`, when the org has one, includes its `username` and a `password` of `"<redacted>"` when a password is set: stored egress passwords are write-only. `404` when the Redis key does not exist (expired or never created), `403` for another org.

#### `PATCH /rpc/sessions/{session_id}`

Body: `{"additional_secs": 300}` adds to the current deadline, or `{"new_ttl_secs": 600}` sets the deadline to that long from now (`new_ttl_secs` wins when both are present). One of them is required (`400`). Response `200`: `{"expires_at_ms": 1783690200000}`. Only `active` sessions can be extended: a session that is unknown, expired, `consuming` or `closed` gives `409` (not `404`). The proxies pick up the new deadline when their cached copy expires.

#### `GET /rpc/sessions/{session_id}/status`

```json
{ "state": "closed", "opened_at": "2026-11-10T10:00:00Z", "closing_at": "2026-11-10T10:12:00Z", "closed_at": "2026-11-10T10:12:03Z" }
```

`state` is `active`, `consuming` or `closed`; `closing_at` and `closed_at` are `null` until reached. `404` when no lifecycle row exists.

#### `GET /rpc/processed?source_id=<id>[&org_id=<org>]`

`{"all_processed": true}` when at least one session of that `(org_id, source_id)` is `closed`, otherwise `false` (also when the source is unknown). Because it is true as soon as any one session is closed, it does not wait for other sessions that share the `source_id`.

### Traffic queries

Search and count run against ClickHouse with a 30 s execution limit and, for search, a 2 GiB memory limit; a query that hits a limit returns `500`.

#### `POST /rpc/requests/search`

```json
{
  "org_id": "acme",
  "branches": [
    { "source_id": ["run-001"], "host": { "op": "contains", "value": "example.com" },
      "status_code": { "op": "gte", "value": 500 } },
    { "source_id": "run-001", "response_body": { "op": "regex_match", "value": "(?i)rate.?limit" } }
  ],
  "order": "desc",
  "limit": 100,
  "cursor": null,
  "end_cursor": null,
  "request_body_max_fetch_size": 0,
  "response_body_max_fetch_size": 65536
}
```

| Field | Notes |
|---|---|
| `org_id` | optional; defaults to the principal's org |
| `branches` | required, non-empty; see [query language](#query-language). Branches are OR'd. |
| `order` | `asc` (default) or `desc`, by `(timestamp, session_offset, id)`. The REST API always orders by timestamp (`order_by` is not read). |
| `limit` | default 100, maximum 5000 |
| `cursor` | the `next_cursor` of the previous page; exclusive |
| `end_cursor` | optional stop boundary (inclusive) in the same ordering; `400` if it lies before `cursor` |
| `request_body_max_fetch_size`, `response_body_max_fetch_size` | include that side's body when its size is at most this many bytes; omit to skip bodies entirely |

Response:

```json
{
  "items": [{
    "id": "0190...", "org_id": "acme", "timestamp": "2026-11-10T10:01:02.345Z", "session_offset": 1731232862345216,
    "method": "GET", "path": "/v1/items", "host": "api.example.com", "scheme": "https",
    "session_id": "0f6d3a4e-...", "proxy_id": "proxy-1",
    "request_size": 0, "status_code": 200, "response_size": 1280, "duration_ms": 42, "ratelimit_wait_ms": 0,
    "source": "crawler", "source_id": "run-001",
    "correlation_id": "agent-7", "parent_correlation_id": null, "account_id": null, "tool_call_id": null,
    "request_headers": [["accept", "*/*"]], "response_headers": [["content-type", "application/json"]],
    "request_body": null,
    "response_body": { "status": "body", "value": "{\"ok\":true}" }
  }],
  "next_cursor": "AAAAAAAA...",
  "total_count": null
}
```

- `request_body`/`response_body` are `null` when not requested, `{"status":"body","value":"..."}` when within the size cap, and `{"status":"too_large","size":N}` otherwise (fetch the full row from `GET /rpc/orgs/{org}/requests/{id}`).
- Header lists in summaries are arrays of `[name, value]` pairs. They are only filled when the query is served from the base `http_captures` table (any branch that filters on `source_id`, bodies, correlation fields, headers or MIME type forces it); on the `http_captures_timeline` view they come back empty.
- `next_cursor` is present only when more rows exist. `total_count` is always `null` here; use `/rpc/requests/count`.
- A `400` is returned for an invalid regular expression (`regex compilation failed at branches[0].response_body: ...`) or an undecodable cursor.
- Results are de-duplicated by `id` at query time (see [capture-pipeline.md](capture-pipeline.md#duplicates-and-deduplication)).

#### `POST /rpc/requests/count`

Same body as search (`limit`, bodies and order are ignored). Response `{"count": 1234}`. The count is `uniqCombined(id)`: approximate (about 0.07% error), with bounded memory.

When every `source_id` of a branch belongs to known sessions, the query is also bounded to the time range in which those sessions were open (widened by one hour each side), so ClickHouse can prune parts. A branch with a `source_id` that has no session row is unbounded.

#### `GET /rpc/orgs/{org_id}/requests/{id}`

Full capture, with bodies. Header sets are JSON objects here:

```json
{ "id": "0190...", "org_id": "acme", "timestamp": "2026-11-10T10:01:02.345Z", "method": "POST", "path": "/login",
  "host": "example.com", "scheme": "https", "session_id": "...", "proxy_id": "...",
  "request_headers": {"content-type": "application/json"}, "request_body": "{...}", "request_size": 512,
  "status_code": 200, "response_headers": {}, "response_body": "...", "response_size": 90,
  "duration_ms": 31, "ratelimit_wait_ms": 0, "source": "crawler", "source_id": "run-001",
  "correlation_id": null, "parent_correlation_id": null, "account_id": null, "tool_call_id": null }
```

`404` when the id is not in that org.

#### WebSocket routes

`POST /rpc/ws/search` and `/rpc/ws/count` take the same envelope with WebSocket branches and `payload_max_fetch_size` instead of the two body caps; there is no `end_cursor`. `GET /rpc/orgs/{org}/ws-messages/{id}` returns one message with its payload; `GET /rpc/orgs/{org}/captures/{parent_event_id}/ws-messages?cursor=&limit=&order=&payload_max_fetch_size=` returns one conversation (all messages of a `101` handshake row, whose `id` is the `parent_event_id`), served from the `ws_messages_by_parent` view.

Message summaries:

```json
{ "id": "...", "parent_event_id": "...", "org_id": "acme", "timestamp": "...", "session_offset": 123,
  "direction": "c2s", "opcode": "text", "session_id": "...", "proxy_id": "...", "source": "crawler",
  "source_id": "run-001", "host": "api.example.com", "payload_size": 42, "payload_truncated": false,
  "payload_is_text": true, "was_compressed": false, "close_code": 0, "close_reason": "",
  "payload": { "status": "body", "value": "{\"type\":\"ping\"}" } }
```

`direction` is `c2s` or `s2c`; `opcode` is `text`, `binary`, `close`, `ping` or `pong` (the last two only exist if control frames are captured). Binary payloads are stored byte for byte, so use `payload_is_text` to decide whether to decode.

#### `GET /rpc/sequence?source_id=<id>[&org_id=<org>]`

```json
{ "org_id": "acme", "source_id": "run-001", "cursor": "AAAAAAAA...", "count": 4821 }
```

`cursor` is the position of the newest stored capture of the source (or `null` when none exists); pass it as `cursor` to `/rpc/requests/search` with `order: "asc"` to read only captures stored afterwards. `count` is `uniqCombined(id)`, a progress metric.

#### Cursors

A cursor is URL-safe base64 (no padding) of a 40-byte key: 16 bytes of big-endian Unix nanoseconds, 8 bytes of `session_offset`, 16 bytes of the capture UUID, which sorts the same way as the ClickHouse sort key `(timestamp, session_offset, id)`. Treat it as opaque. Searches ordered by another column (GraphQL `orderBy`) append a tag byte and the sort value, and such a cursor is rejected under a different field or direction.

### Query language

A search is an OR of **branches**. Within a branch, every present field must match (AND). A branch with no fields matches every capture of the org. Each field is a filter tree; all string comparisons run in ClickHouse.

#### HTTP branch fields

| Field | Type | Notes |
|---|---|---|
| `source_id` | string or list of strings | exact; several values become `IN (...)`. An empty list is treated as absent. |
| `source` | string | exact |
| `host`, `method`, `path` | string filter | |
| `request_body`, `response_body` | string filter | decoded text; reads the wide body columns, so these queries are the slowest |
| `correlation_id`, `parent_correlation_id`, `account_id`, `tool_call_id` | string filter | extracted columns, `NULL` when the header was absent |
| `mime_type` | string filter | media type of the response `Content-Type`, lower-cased, parameters removed; `''` when absent |
| `status_code`, `response_size`, `duration_ms` | int filter | |
| `request_sends_cookies`, `response_sets_cookies` | boolean | a `Cookie` / `Set-Cookie` header is present |
| `request_header`, `response_header` | `{ "key": "...", "value": "..." }` | exact match on one header; the key is lower-cased by the query |

#### String filters

Selected by `op`:

| `op` | Extra fields | Meaning |
|---|---|---|
| `contains` | `value` | case-insensitive substring |
| `exact` | `value` | equality, case-sensitive |
| `regex_match` | `value` | RE2, unanchored, case-sensitive (use `(?i)`); validated before the query, `400` if invalid |
| `length` | `value` (an int filter) | octet length of the column |
| `is_null`, `is_present` | none | `IS NULL` / `IS NOT NULL` |
| `all`, `any` | `filters` (non-empty list) | AND / OR of nested filters |
| `not` | `filter` | negation |

For single alphanumeric tokens of at least three characters, a `contains` on a body column also uses a bloom-filter token probe, so such searches prune data without changing the result.

#### Int filters

`exact`, `lt`, `lte`, `gt`, `gte` (each with an integer `value`), `all`/`any` (`filters`, non-empty) and `not` (`filter`):

```json
{ "status_code": { "op": "any", "filters": [ { "op": "exact", "value": 401 }, { "op": "exact", "value": 403 } ] } }
```

Empty `branches`, empty `filters` lists and unknown `op` values are rejected when the body is parsed (`400`/`422`).

#### WebSocket branch fields

`source_id` (a single string), `source`, `session_id`, `parent_event_id` (a UUID string), string filters `host`, `payload`, `direction`, `opcode`, `close_reason`, int filters `close_code`, `payload_size`, and booleans `was_compressed`, `payload_is_text`, `payload_truncated`. A query whose every branch has only `parent_event_id` is served from the by-parent view.

#### Which table serves a query

This is ClickHouse routing; the OpenSearch store has no views and searches one index pattern (see [capture-stores.md](capture-stores.md), which also lists the few DSL constructs that store rejects with `400`).

The API picks the cheapest table that contains every requested column: `http_captures_timeline` for org-wide pagination (no body, correlation, `source_id` or header filters), `http_captures_by_agent_hierarchy` when the branches pin `parent_correlation_id` (optionally with `correlation_id` and `tool_call_id` exact matches), otherwise the base `http_captures`. See [capture-pipeline.md](capture-pipeline.md#clickhouse-schema).

### Orgs and rate limits

An org row holds default rate limits and one optional egress proxy. Sessions copy these at creation, so changing an org does not alter existing sessions' copy of the egress proxy or `rate_limit`.

| Call | Body or result |
|---|---|
| `POST /rpc/orgs` | `{"org_id":"acme","rate_limit_rpm":6000,"rate_limit_burst":1000}` (limits optional). `201`; a duplicate id gives `500` (unique violation). |
| `GET /rpc/orgs` | `[Org]` (egress proxy passwords redacted) containing only the principal's own org (the `limit`/`offset` query parameters are accepted and ignored) |
| `GET /rpc/orgs/{org}` | `{"org_id":"acme","rate_limit_settings":{"requests_per_minute":6000,"burst":1000},"egress_proxy":null}`; `404` if absent |
| `DELETE /rpc/orgs/{org}` | `204`, `404` |
| `GET /rpc/orgs/{org}/rate-limit` | `{"requests_per_minute":6000,"burst":1000}`; an org without a row (or with `NULL` limits) returns the configured defaults |
| `PUT /rpc/orgs/{org}/rate-limit` | `{"requests_per_minute":3000,"burst":500}`; upserts the org. An omitted field is stored as `NULL` (inherit the default), not left unchanged. `200`. Values above 2147483647 are `400`. |
| `GET /rpc/orgs/{org}/proxy` | `{"proxy_type":"socks5","address":"host:1080","username":"u","password":"<redacted>"}` (`password` is `null` when none is set); `404` when none set |
| `PUT /rpc/orgs/{org}/proxy` | `{"proxy_type":"socks5"\|"http","address":"host:port","username":"u","password":"p"}`; upserts. `400` for another `proxy_type`. `200`. |
| `DELETE /rpc/orgs/{org}/proxy` | clears the proxy; `204`, `404` if the org is absent |
| `GET /rpc/orgs/{org}/rate-limit-state` | live bucket, see below |

Creating an org and setting its limits also write the effective values (`burst`, `rpm`, after applying the control plane defaults) to Redis `{prefix}:ratelimit:{org}:config`, which the Redis rate-limit backend reads on each refill, so new limits reach running proxies without a new session. The write is best effort: a Redis failure is logged and the call still succeeds. The `limiter` backend instead uses the limits stored in the session. Defaults are `default_rate_limit_rpm` and `default_rate_limit_burst`, both 0 unless configured.

`GET .../rate-limit-state` returns `{"org_id","exists","tokens","burst","rpm","last_refill_ms"}`: `burst` and `rpm` come from the Redis hash `{prefix}:ratelimit:{org}:config`, and `tokens` and `last_refill_ms` (the hash field `last_ms`) from `{prefix}:ratelimit:{org}`. `exists` is true once the proxy has touched the bucket. The GraphQL `rateLimitState` field returns the same values.

### Certificate

`GET /rpc/certificate` returns the CA certificate as PEM text. It is behind the same authentication as every other `/rpc` route. The same PEM is in every session response. Configure the CA with `ca.type` (`generate` for development, `file` with `cert_path`, or `env` reading the PEM from `PROXYX_CONTROL_CA_CERT`). It must be the certificate of the CA the proxy signs with; see [session-proxy.md](session-proxy.md#ca-and-client-trust).

### Traffic views

A view is an asynchronous Parquet export of the captures matching a set of branches, written by ClickHouse directly to object storage. Views exist only with the ClickHouse capture store: with `capture_store.backend = "opensearch"`, `POST /rpc/views`, `GET /rpc/views/{view_id}` and the GraphQL view operations answer `501 Not Implemented` ([capture-stores.md](capture-stores.md#traffic-view-exports)).

```sh
px -X POST $API/rpc/views -d '{"branches":[{"source_id":"run-001"}]}'
# 202 {"view_id":"2c9f...","status":"running","s3_key":null}
px $API/rpc/views/2c9f...
# 200 {"view_id":"2c9f...","status":"completed","s3_key":"traffic-views/acme/2c9f....parquet"}
```

`POST /rpc/views` takes `{"org_id"?, "branches": [...]}` with the same HTTP branches as search (cursor, order and body options do not apply). The `view_id` is a UUIDv5 of the org and the canonical branches, so submitting an identical query returns the same view instead of exporting again. Response status: `200` if already `completed`, otherwise `202`. `status` is `pending`, `running`, `completed` or `failed`; a `failed` job is retried by the next `POST`.

`GET /rpc/views/{view_id}` returns `view_id`, `status` and, when present, `s3_key`, `error`, `read_rows`, `written_rows`, `total_rows` (approximate while running). Polling is debounced to one ClickHouse check per 3 s per view. It reconciles the Postgres job row with `system.processes` and `system.query_log` (on every replica) and the object store; a job whose export cannot be found is reset to `pending` so the next `POST` re-exports. `404` for an unknown view or another org's view.

The REST response carries no download link; the signed URL is returned by the GraphQL `trafficView` query and `createTrafficView` mutation.

| Setting | Default | Meaning |
|---|---|---|
| `traffic_views_backend` | `s3` | `s3` or `azure` |
| `traffic_views_bucket` | empty | S3 bucket, or Azure container |
| `traffic_views_azure_account` | empty | Azure storage account (required for `azure`) |
| `traffic_views_s3_region` | `us-east-1` | region of the S3 bucket |
| `traffic_views_ttl_secs` | 86400 | completed exports are deleted this long after completion |
| `cloudfront_domain`, `cloudfront_key_pair_id`, `cloudfront_private_key` | empty | S3 download URLs are CloudFront-signed; without all three there is no URL |
| `export_preferred_block_size_bytes` | 33554432 | ClickHouse read block size for wide rows |
| `export_max_block_size` | 5000 | rows per block |
| `export_row_group_size_bytes` | 134217728 | Parquet row group size in bytes |
| `export_row_group_size` | 10000 | Parquet row group size in rows |

Backends:

- **S3.** ClickHouse writes with `s3()` using the API's own AWS credentials, which are sent in the `INSERT` statement and therefore appear in ClickHouse's query log. Download URLs are CloudFront canned-policy signed URLs valid for one hour.
- **Azure Blob Storage.** ClickHouse writes with `azureBlobStorage()` and no credentials (its own workload identity); the API uses its workload identity for existence checks, deletes and user-delegation SAS read URLs valid for one hour.

Objects are named `traffic-views/{org_id}/{view_id}.parquet`. The export selects every column of the base table with bodies, without a cursor, and does not de-duplicate rows still present on disk twice. The reaper (every 60 s) deletes the object first and the job row second for completed views older than `traffic_views_ttl_secs`, measured from completion, in batches of 500.

## GraphQL

`POST /graphql` executes operations; `GET /graphql` serves the GraphQL Playground. Authentication is a user principal ([above](#authentication)); a service key gets `401`. The GraphQL layer is built from `crates/control-graphql`, shares its resolvers with the services behind REST, and is an Apollo Federation subgraph named `proxyx`.

```sh
curl -sS $API/graphql -H "Authorization: Bearer $USER_KEY" -H 'Content-Type: application/json' -d '{
  "query": "query($i: HttpTrafficQueryInput!){ httpTraffic(input:$i){ totalCount nextCursor items{ id method host path statusCode mimeType } } }",
  "variables": {"i": {"filter": {"sourceId": "run-001", "response": {"statusClasses": [5]}}, "limit": 50, "descending": true}}
}'
```

### Queries

| Field | Purpose |
|---|---|
| `organizationSettings(orgId)` | rate limits and egress proxy type and address (no credentials) |
| `organizationRateLimit(orgId)` | requests per minute and burst |
| `rateLimitState(orgId)` | live bucket (same fields as the REST route) |
| `requestRateSeries(input)` | requests per minute, from the `http_request_counts_per_minute` view; RFC 3339 `start` (inclusive) and `end` (exclusive) |
| `httpTrafficTimeSeries(input)` | requests per time bucket and source over `[start, end)`; `bucketSeconds` default 60 |
| `scanTrafficSummary(input)` | bucketed totals plus per-source totals for a list of `sourceIds` |
| `httpTraffic(input)` | search HTTP captures with `totalCount` |
| `httpRequest(id, orgId)` | one capture with bodies |
| `wsTraffic(input)` | search WebSocket messages |
| `wsMessage(id, orgId)` | one WebSocket message |
| `traffic(input)` | unified, time-ordered feed of HTTP and WS (`kind`: `ALL`, `HTTP`, `WS`), merged under one cursor |
| `wsConversations(input)` | one row per conversation with message counts and first and last time (no cursor; at most 5000) |
| `trafficView(viewId, orgId)` | poll an export; includes `signedUrl` once completed |

Mutations: `upsertOrganizationSettings` and `upsertOrganizationRateLimit` (superadmin only; they upsert the org and write the rate-limit config to Redis like the REST calls; setting a proxy requires both `proxyType` and `proxyAddress`) and `createTrafficView` (any user for their org).

`orgId` arguments are optional; a regular user always acts in its own org. Cross-org queries (`orgId` omitted by a superadmin) are accepted by the search and time-series fields; the single-record, rate-limit, settings and conversation fields need an org.

The GraphQL search filters are a simplified projection of the [query language](#query-language): `host` and `method` are exact, `path` is a case-insensitive substring, `search` matches the host or the path (or host or payload for WebSockets) as a substring, `statusCode` is exact, correlation fields are exact, and `request { methods, urlContains, sendsCookies }` and `response { statusClasses, statusCodes, mimeType, setsCookies, minLength, maxLength, minDurationMs, maxDurationMs }` add the Burp-style filters. `sourceId` and `sourceIds` are merged. `orderBy` accepts `TIMESTAMP`, `METHOD`, `URL`, `STATUS_CODE`, `RESPONSE_SIZE`, `MIME_TYPE`, `COOKIES`, `DURATION_MS` with `descending`. Bodies are not searchable through GraphQL; use the REST search for `request_body` and `response_body` filters. Limits and ordering are the same as REST (default 100, maximum 5000).

### Federation SDL

```sh
proxyx control schema export                    # SDL on stdout
proxyx control schema export -o schema.graphql  # or to a file
proxyx control schema validate
proxyx control schema manifest --out dist --version "$GIT_SHA"
```

`manifest` writes `proxyx.json` (`subgraph`, `routing_url`, `schema`, `version`) to the output directory for supergraph composition. `--version` (or `PROVENANCE_ID`) is required; `routing_url` comes from `PROXYX_SCHEMA_ROUTING_URL` (default `http://localhost:9000/graphql`). The workspace binary `proxyx-control-schema manifest --out <dir> --version <v>` produces the same file. None of these commands connect to any service. The running API also answers the federation introspection field `_service { sdl }`.

## Capture store health

`GET /health/store` on the API port probes the configured capture store (`SELECT 1` on ClickHouse, `GET /` on OpenSearch / Elasticsearch, which checks reachability and credentials) and answers within 3 s: `200 {"store":"opensearch","status":"ok"}`, or `503` with `"status":"unreachable"` or `"timeout"` and an `error` string. It is deliberately separate from `/health/ready`, so a slow analytics store never takes the session API out of rotation; point a store-specific alert or a dependency check at it. See [capture-stores.md](capture-stores.md#resilience-and-health).

## Broker health

`GET /health/broker` on the API port reports whether the API's captures-log producer has a working broker connection: `200 {"broker":"rabbitmq","status":"ok"}`, or `503` with `"status":"disconnected"` after a failed connect or publish and until the next success. Redis Streams cannot tell and always answers `200` (the session API needs Redis anyway, which `/health/ready` covers). Like `/health/store` it is not part of readiness, so a broker outage never takes the session API out of rotation; a failed `SessionEnd` publish is re-sent by the reaper.

## Ingester health

`proxyx control ingester` listens on `ingester_health_addr` (default `0.0.0.0:9001`): `GET /health` is `200` while the consumer loop runs, the broker connection is up (Kafka and RabbitMQ track it) and the capture store's circuit breaker is closed, and `503` (body `consumer stopped`, `broker connection down` or `capture store circuit breaker open`) otherwise; `GET /metrics` exposes `proxyx_ingester_*` and `proxyx_capture_commit_lag_seconds`. It has no other routes.

## Background work and configuration

The API process runs the session reapers and view expiry every 60 s; the ingester runs the consumer and the ClickHouse flushers. Keys that matter for the API (all `PROXYX_CONTROL_*`):

| Key | Default | Notes |
|---|---|---|
| `env` | `dev` | `dev` skips the CIDR allowlist in `trusted_headers` mode |
| `auth_mode` | `keys` | `keys` or `trusted_headers` |
| `internal_allowed_cidrs` | empty | for `trusted_headers` outside dev |
| `database_url` | empty | Postgres; required |
| `api_addr` | `0.0.0.0:9000` | |
| `ingester_health_addr` | `0.0.0.0:9001` | |
| `redis_url`, `redis_key_prefix` | `redis://127.0.0.1:6379`, `proxyx` | must match the proxy |
| `clickhouse.url`, `.database`, `.user`, `.password` | url required | `.table` (default `http_captures`) and the flush settings are listed in [capture-pipeline.md](capture-pipeline.md#batch-flushing-and-backpressure) |
| `session_default_ttl_secs` | 600 | used when `ttl_secs` is 0 |
| `default_rate_limit_rpm`, `default_rate_limit_burst` | 0, 0 | applied when the org has no value or does not exist; 0 for both means no per-org settings are written into the session |
| `proxy_public_host`, `proxy_public_host_socks5` | `localhost:8443`, `localhost:1080` | used to build `proxy_url` and `proxy_url_socks5` |
| `ca.type` | `generate` | see [Certificate](#certificate) |
| `broker_kind`, `kafka.*`, `rabbitmq.*`, `request_log_stream`, `request_log_max_stream_len`, `consumer_group` | `redis_stream`, none, none, `proxyx:request_log`, 1000000, `proxyx_control` | see [capture-pipeline.md](capture-pipeline.md#broker) |
| `session_lifecycle_writes` | `true` | whether this ingester marks sessions `closed` |
| `correlation_id_header`, `parent_correlation_id_header`, `account_id_header`, `tool_call_id_header` | `X-ProxyX-Agent`, `X-ProxyX-Parent-Agent`, `X-ProxyX-Account`, `X-ProxyX-Tool` | request headers copied into columns |
| `traffic_views_*`, `cloudfront_*`, `export_*` | see [Traffic views](#traffic-views) | |
| `sentry.*` | disabled | |

Logging uses `RUST_LOG`, `PROXYX_LOG_JSON=1` and `OTEL_ENABLED=true` as in [session-proxy.md](session-proxy.md#configuration-reference). Operating procedures are in [operations.md](operations.md).
