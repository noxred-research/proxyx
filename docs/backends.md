# Backends

ProxyX stores and moves data in six families of systems. Each family is supported **where ProxyX has data of that kind**, with the engines below, and each can share one instance with other products (a crawler, a browser fleet) without collisions. This page is the support matrix, the reason for each family, the namespacing rules and a shared-instance setup.

- [Support matrix](#support-matrix)
- [Why each family](#why-each-family)
- [Shared instances](#shared-instances)
- [Relational databases](#relational-databases)
- [Object storage](#object-storage)
- [Redis and Valkey](#redis-and-valkey)
- [ClickHouse](#clickhouse)
- [OpenSearch and Elasticsearch](#opensearch-and-elasticsearch)
- [Kafka and RabbitMQ](#kafka-and-rabbitmq)
- [How each is tested](#how-each-is-tested)

## Support matrix

| Family | Engines | What ProxyX keeps there | Selected by | Namespace |
|---|---|---|---|---|
| Relational | PostgreSQL, MariaDB, SQLite | pool state of record (org keys, policies, inventory, blocks, audit) and control plane (orgs, session lifecycle, export jobs, API keys) | scheme of `database_url` | PostgreSQL: `database_schema`; MariaDB: the database in the URL; SQLite: the file |
| Object store | S3 API (profiles `standard`, `edge`, `self-hosted`, `compatible`), Azure Blob Storage | Parquet traffic view exports | `traffic_views_backend`, `traffic_views_s3_profile` | bucket + `traffic_views_prefix` (default `proxyx/`) |
| Cache / coordination | Valkey, Redis (Sentinel, TLS, ACL users) | leases and hot pool state, session state, rate-limit buckets, the capture stream | `redis_url` | session proxy and control plane: `redis_key_prefix` (default `proxyx`); pool: the database index in the URL |
| Analytics | ClickHouse | captured HTTP exchanges and WebSocket messages (default capture store), Parquet export source | `capture_store.backend = "clickhouse"`, `[clickhouse]` | `clickhouse.database`, created by `migrate` |
| Search | OpenSearch, Elasticsearch 8 | the alternative capture store | `capture_store.backend = "opensearch"` | `index_prefix` (default `proxyx`: `proxyx-http-*`, `proxyx-ws-*`) |
| Event stream | Kafka (and compatible brokers), RabbitMQ, Redis streams | the capture log between the session proxy and the ingester | `broker_kind` | topic, exchange and queue names, vhost, `consumer_group` |

Versions the `backends` CI job runs against: Valkey 8.1 and Redis 8, ClickHouse 25.8, OpenSearch 2.19.7, Elasticsearch 8.17, Kafka 3.9 and RabbitMQ 4, and PostgreSQL 18 in the unit job. The relational and search pages list the other versions their suites were run against ([databases.md](databases.md), [capture-stores.md](capture-stores.md)).

## Why each family

| Family | Why ProxyX has it |
|---|---|
| Relational | Org keys, policies, inventory, blocks and the audit trail must survive restarts and be consistent across gateways and control API replicas. Three engines because deployments differ: PostgreSQL is the default, MariaDB for sites that already run it, SQLite for one host. ([databases.md](databases.md)) |
| Object store | A traffic view is a Parquet file that ClickHouse writes straight to object storage and that a caller downloads later. That is a blob workload, and S3 is its de facto API, so one S3 client covers the original service, an edge store, a self-hosted store and anything compatible. Azure Blob Storage was already there. |
| Cache / coordination | Leases, ready sets, cooldowns, breakers, sessions and token buckets are short-lived, shared across replicas and touched on every connection. They live in Redis protocol stores; Valkey and Redis are the same protocol, so both work. |
| Analytics | Captures are append-only, very large and queried by filters. ClickHouse is the default capture store. |
| Search | Some deployments already run OpenSearch or Elasticsearch and want retention and access control with the tools they have. It is a second implementation of the capture store, not a separate feature. ([capture-stores.md](capture-stores.md)) |
| Event stream | The session proxy must not wait for the capture store. A broker decouples them with backpressure and replay. Redis streams are the default; Kafka and RabbitMQ are for sites that want a durable log of their own. ([capture-pipeline.md](capture-pipeline.md)) |

What ProxyX does **not** have, on purpose: an outbound event or audit export (the audit trail lives in the relational database and the MCP server's own log; nothing needs a second copy), and an idempotent Kafka producer (the client library does not offer one; producing is at-least-once with acks from every in-sync replica, and the ingester tolerates duplicates because every capture has an id). There are no settings for either.

## Shared instances

All six families can be shared with other products on the same servers. The rule is one namespace per product, chosen by the operator, never by a tool:

| Family | One namespace per product |
|---|---|
| PostgreSQL | a schema per plane: `database_schema = "proxyx_pool"` and `"proxyx_control"` (and the other products' own). One database, separate tables and separate `_sqlx_migrations`. |
| MariaDB | a database per plane in the URL path |
| SQLite | a file per plane |
| Redis / Valkey | control plane and session proxy: `redis_key_prefix`. Pool: **a database index of its own** (`redis://host:6379/3`) or its own instance. The pool's keys (`ready:`, `lease:`, `lock:` and so on) carry no prefix, so a pool must not share a database index with anything. Add ACL users in the URL (`redis://user:pw@host/3`) and `rediss://` for TLS. |
| Object store | one bucket, a `traffic_views_prefix` per product |
| ClickHouse | a database per product: `clickhouse.database` |
| OpenSearch / Elasticsearch | an `index_prefix` per product; ProxyX never deletes an index and only reads and writes names under its prefix |
| Kafka / RabbitMQ | distinct topic or exchange names (`proxyx.captures`), a vhost for RabbitMQ, and a distinct `consumer_group` |

A shared PostgreSQL, step by step:

```toml
# pool.toml
database_url = "postgres://proxyx@db.internal/platform"
database_schema = "proxyx_pool"
redis_url = "redis://pool:secret@cache.internal:6379/3"

# control.toml
database_url = "postgres://proxyx@db.internal/platform"
database_schema = "proxyx_control"
redis_url = "redis://control:secret@cache.internal:6379/0"
redis_key_prefix = "proxyx"
traffic_views_bucket = "platform-exports"
traffic_views_prefix = "proxyx/"

[clickhouse]
url = "http://clickhouse.internal:8123"
database = "proxyx"
```

Run `proxyx migrate pool` and `proxyx migrate control --target all` once: they create the schema and the ClickHouse database. Another product on the same servers picks its own names; neither sees the other's rows, keys, objects or indices. Secrets (database passwords, the Redis password, S3 keys) come from files or the environment, never from examples.

## Relational databases

See [databases.md](databases.md) for URLs, versions and per-engine differences. For sharing, `database_schema` pins every connection of a PostgreSQL pool to one schema with `search_path`, creates the schema on migration and keeps the migration history in it. The `pg_trgm` extension that a control migration needs exists once per database and is installed in `public`, which stays on the search path behind the product's schema only so that the extension resolves; no ProxyX table is created there. `database_schema` must be a lowercase identifier, not `public`, not `pg_*`, and is refused for MariaDB and SQLite with a message that says where their namespace is.

## Object storage

Traffic view exports are written by ClickHouse with the `s3()` table function, and ProxyX itself checks, deletes and signs download links. Settings (control plane):

| Key | Meaning |
|---|---|
| `traffic_views_backend` | `s3` (default) or `azure` |
| `traffic_views_bucket` | bucket (or Azure container) |
| `traffic_views_s3_profile` | `standard`, `edge`, `self-hosted` or `compatible`. Default: `standard`, or `compatible` when an endpoint is set |
| `traffic_views_s3_endpoint` | required by every profile but `standard`; refused by `standard` |
| `traffic_views_s3_region` | region (`us-east-1` is accepted by edge stores that ask for `auto`) |
| `traffic_views_s3_path_style` | bucket in the path (default with an endpoint) or in the host name |
| `traffic_views_s3_credentials_file` | `access_key_id`, `secret_access_key`, optional `session_token` lines; unset uses the AWS environment chain |
| `traffic_views_prefix` | key prefix, default `proxyx/` |

Server-side encryption is not a ProxyX setting: ProxyX never uploads an object itself (ClickHouse does), so an encryption setting here would be parsed and ignored. Use the bucket's default encryption. The S3 keys are sent to ClickHouse in the `INSERT` statement, as before; treat its query log as sensitive.

## Redis and Valkey

Valkey and Redis speak the same protocol and both are tested. The control plane and the session proxy build every key as `<redis_key_prefix>:...` (they must use the same prefix) and never run a server-wide delete. The pool does not prefix its keys; a shared instance gives it a database index of its own. The benchmark harness, which used to flush its Redis database, now refuses a database that is not empty. An ACL user restricted to `~<prefix>:*` works for the control plane and session proxy and is exercised by a test.

## ClickHouse

`clickhouse.database` names the product's database. `proxyx migrate control --target clickhouse` creates it (`CREATE DATABASE IF NOT EXISTS`, name validated as a plain identifier) and applies the versioned migrations inside it; each database has its own `_ch_migrations`. Without `database` the server's default database is used, as before.

## OpenSearch and Elasticsearch

One configuration serves both engines: the REST subset they share (`_bulk`, composable index templates, `_search` with `search_after`, `_count`, aggregations, `ids` and `wildcard`). At migration and ingester start ProxyX reads `GET /`, logs the engine and version, and refuses OpenSearch before 2 and Elasticsearch before 8. `kind = "opensearch"` or `"elasticsearch"` makes it refuse the other engine too. Templates are versioned (`schema_version`); the ingester refuses to start when they are missing or old. See [capture-stores.md](capture-stores.md).

## Kafka and RabbitMQ

Names are explicit, which is what makes sharing work: the Kafka `topic`, the RabbitMQ `exchange` (default `proxyx.captures`, queues `<exchange>.pNN`), the RabbitMQ vhost in the URL and the `consumer_group` (default `proxyx_control`). Producers wait for every in-sync replica (Kafka) or publisher confirms (RabbitMQ) and buffers are bounded. TLS and SASL are supported for Kafka and TLS for RabbitMQ.

## How each is tested

Every test below runs against a real service in a throwaway container and skips with a message when its `PROXYX_TEST_*` variable is unset. `ci/backends-up.sh` starts all of them with data in tmpfs (the `backends` CI job) and `ci/backends-down.sh` removes them.

| Test | Real services | What it shows |
|---|---|---|
| `control/tests/shared_database.rs`, `store/tests/shared_database.rs` | PostgreSQL | two schemas and a neighbour's schema in one database: separate tables, separate migration history, nothing in `public`, the neighbour untouched |
| `control/tests/object_store.rs` | an S3-API server and ClickHouse | ClickHouse writes Parquet to the store with a credentials file; two prefixes in one bucket see only their own objects; delete is idempotent; wrong credentials are refused; profile and prefix combinations are validated |
| `control/src/session.rs` (`key_prefixes_...`) | Valkey and Redis | two prefixes on one server are separate; an ACL user fenced to one prefix is refused outside it |
| `store/tests/shared_redis.rs` | Valkey or Redis | two database indexes hold separate pool state |
| `control/tests/shared_clickhouse.rs` | ClickHouse | `migrate` creates two databases with separate migration history and data |
| `control/tests/search_engines.rs`, `capture_store_opensearch.rs` | OpenSearch and Elasticsearch | engine detection, the `kind` check, two prefixes with separate templates, the full capture-store suite |
| `control/tests/broker_kafka.rs`, `broker_rabbitmq.rs` | Kafka and RabbitMQ | publish, consume, redelivery and reconnect with per-run topic and exchange names |

The self-hosted object store in CI is RustFS (an S3-API server): the `self-hosted` profile is verified against it, and the same API is what MinIO speaks; MinIO's own image was not available to the maintainers' registry when this was written, so it is not itself run. The `standard` and `edge` profiles are covered by configuration, URL and SDK tests, not by a call to the commercial services.
