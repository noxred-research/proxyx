# Relational databases

ProxyX keeps its durable relational state in one of three databases. The scheme of the database URL selects the backend; PostgreSQL is the default and the one the project's own deployments are sized for.

| Backend | URL | Versions | Multi-node |
|---|---|---|---|
| PostgreSQL | `postgres://user:password@host:5432/database` | 13 or newer (18 tested) | yes |
| MariaDB | `mariadb://user:password@host:3306/database` or `mysql://...` | 10.6 or newer (11.8 and 13.0 tested) | yes |
| SQLite | `sqlite:///var/lib/proxyx/pool.db?mode=rwc` | 3.40 or newer (3.46 bundled) | no: one host |

MySQL itself is not supported: the schema uses `IF NOT EXISTS` on columns and indexes and the sequence and `SKIP LOCKED` behavior of MariaDB, and `proxyx doctor` fails a `mysql://` URL that does not answer as MariaDB.

## What uses a database

| Plane | URL | Holds |
|---|---|---|
| Pool (`gateway`, `warmer`, `migrate pool`) | `PROXYX_POOL_DATABASE_URL` | org keys (hashes), policies and their versions, static inventory with state and deadlines, reputation scores, block history, org blocks, customer upstream logins, git sync hashes, the append-only audit trail |
| Control (`control api`, `control ingester`, `control keys`, `migrate control`) | `PROXYX_CONTROL_DATABASE_URL` | orgs and their rate limits and egress proxies, the session lifecycle, traffic view export jobs, API keys |

The two planes keep separate schemas and separate migration histories. They may use different backends, but give each its own database (PostgreSQL, MariaDB) or file (SQLite). Redis, ClickHouse or OpenSearch and the broker are unrelated to this choice.

## Choosing

- **PostgreSQL.** The default. Choose it unless you have a reason not to.
- **MariaDB.** When your operations already run MariaDB or a Galera cluster and you want one fewer database engine. It carries the same multi-replica guarantees as PostgreSQL, with the differences listed [below](#mariadb).
- **SQLite.** One host, one disk: a laptop, a trial, a single-box deployment. Every ProxyX process that uses the file (gateway, warmer, control API, ingester, the migrate jobs) must run on that host, on a local filesystem. Gateways, warmers or control APIs on several hosts need PostgreSQL or MariaDB. See [SQLite](#sqlite).

Switching backends later means starting from an empty database. ProxyX has no data copy between backends: the pool re-reads policies and inventory from the git files under `data_dir` at start, and org keys, customer upstreams, orgs and API keys are created again through the control APIs and `proxyx control keys`. Redis hot state is rebuilt from the database as after any loss.

## Migrations

The three backends have one migration directory each (`crates/store/migrations/{postgres,mariadb,sqlite}` and `crates/control/migrations/{postgres,mariadb,sqlite}`) with the same versions, so a `--check` on any backend reports the same names:

```
proxyx migrate pool --check            # pending migrations, exit 1 if any
proxyx migrate pool
proxyx migrate control --target database --check   # alias: --target postgres
proxyx migrate control --target database
```

The migration tables are `_sqlx_migrations` on every backend. Migrations are safe to run from several processes at once: PostgreSQL takes an advisory lock, MariaDB takes `GET_LOCK` (waiting up to an hour), SQLite takes an exclusive lock on `<database file>.migrate-lock`, so the later process finds nothing to apply. The connection that migrates has its statement and lock limits lifted and restored afterwards.
Migration commands make one bounded connection attempt. An invalid URL, an in-memory SQLite URL or a
rejected database login fails with its cause instead of entering the serving roles' dependency retry loop.

A SQLite database file is created by the first connection (`mode=rwc` in the URL); the directory must exist and be writable. The control plane's SQLite and MariaDB schemas are created in the shape the PostgreSQL migrations reach, so a few migration versions (the vestigial `http_captures` table, `pg_partman`) are no-ops there; the versions stay equal everywhere.

## Limits per connection

Every pooled connection is limited the same way on all backends, with the values the PostgreSQL role has always used (pool store: 5 s statement, 2 s lock wait, 10 connections; control: 30 s statement, 10 s lock wait):

| | PostgreSQL | MariaDB | SQLite |
|---|---|---|---|
| Statement limit | `statement_timeout` (startup parameter) | `max_statement_time` (session) | busy timeout (the wait for the file lock) |
| Lock wait | `lock_timeout` | `innodb_lock_wait_timeout` (whole seconds, rounded up) | the same busy timeout |
| Isolation | read committed | read committed (set per session) | serialized writers, snapshot readers (WAL) |

## Backend differences

What differs is dialect, not meaning: the same logical schema and the same repository behavior on each, pinned by the cross-backend contract test (`crates/store/tests/contract.rs`). The things an operator can notice:

### MariaDB

- **Text comparison.** Tables use `utf8mb4_general_ci`: text compares **without regard to case or accents**. The client driver reads a column with a binary collation (`utf8mb4_bin`) as bytes, so a case-sensitive text column is not an option. Ids that ProxyX validates (org ids, provider and region names) are lowercase anyway, and format checks switch case sensitivity back on. What can collide are free-form names that differ only by case: a policy name `Fast` and `fast`, a data source file name, an org id or source id in the control plane (`Acme` and `acme` are one org). On PostgreSQL and SQLite they are different.
- **Identifier length.** Free-form ids of the control plane (`org_id`, `source`, `source_id`) are `VARCHAR(255)`; a longer value is refused by the database.
- **Locks.** PostgreSQL's advisory locks (which serialize the read-modify-write transactions of inventory, policies and the org block cache) become row locks: one row per lock name in `advisory_locks`, taken `FOR UPDATE` and held to the end of the transaction. Org block changes of different orgs hash to one of 64 rows, so two orgs can share a lock; they still serialize correctly, only a little less parallel.
- **Deadlocks.** InnoDB may abort one of two transactions that take locks in opposite order (error 1213). The repository does not retry: the caller gets an error and tries again. The write paths take the table-level lock row first to keep this rare.
- **Partial unique indexes** (one current policy per name, one live upstream per org, one active session per `(org, source, source_id)`) are unique indexes over a generated column that is `NULL` outside the condition. Such an index treats `NULL` as distinct, which is what makes it partial.
- **Audit trail.** The `UPDATE` and `DELETE` triggers keep it append-only (`audit rows are append-only`), with the same retention exception as PostgreSQL. MariaDB runs no trigger for `TRUNCATE` and `DROP`: the application user must not hold the `DROP` privilege on `audit`.
- **Timestamps** are `DATETIME(6)` in UTC.
- **`SKIP LOCKED`** (10.6+) lets several control API replicas claim different expired sessions in the reapers, as on PostgreSQL.

### SQLite

- **One node.** SQLite is a file. Processes on one host share it correctly (WAL journal, `synchronous=NORMAL`, busy timeout); processes on several hosts cannot, and a file on NFS, SMB or another network filesystem is not safe at all. ProxyX cannot see which filesystem a path is on: ProxyX logs a `WARN` at the first connection of every process that it runs on SQLite and where that is sound, and nothing stops you from starting a gateway on a second host. **That is your deployment's responsibility**; a deployment with replicas on several hosts needs PostgreSQL or MariaDB.
- **No in-memory database.** `sqlite::memory:` is private to one connection and is lost at exit: every role refuses it.
- **One writer.** Writes queue behind the single write lock (a write transaction starts with `BEGIN IMMEDIATE`). Because writers are serialized, the advisory locks of the other backends are not needed there and the reapers' `SKIP LOCKED` is a plain `SELECT`. The gateway's hot path reads Redis, not the database, so this is rarely the bottleneck; a warmer sweep, a policy sync or an inventory sync is.
- **Types.** Timestamps are integer microseconds since the Unix epoch (UTC; column defaults are to the millisecond), JSON is `TEXT` checked by `json_valid`, UUIDs are 16-byte blobs, and the org id format is checked with `GLOB`. There are no sequences: the customer upstream version is a counter row advanced inside the writing transaction.
- **Audit trail.** `UPDATE` and `DELETE` triggers keep it append-only; SQLite has no `TRUNCATE`.
- **Replacing a check constraint** is a table rebuild in SQLite; the migrations that change one do it.

### All backends

- The audit trail never holds a secret, and an operator-written or git-written row is never deleted; the warmer deletes the machine-written rows after 90 days.
- A query result is ordered by the text of an address (`ORDER BY ip`), byte by byte, on every backend.
- Metric and check names keep their historical `postgres` spelling (`proxyx_pool_postgres_down`, `postgres.reachable`) on every backend so existing dashboards and alerts keep working; the messages name the real backend.

## Docker Compose

`docker/docker-compose.yml` runs PostgreSQL by default. Two profiles, each with an env file that sets the two database URLs, swap it out:

```
# MariaDB 13 for both planes
docker compose --env-file docker/db-mariadb.env -f docker/docker-compose.yml --profile mariadb up -d --build --wait
# SQLite: one file per plane on the shared `sqlite-data` volume (single host)
docker compose --env-file docker/db-sqlite.env -f docker/docker-compose.yml --profile sqlite up -d --build --wait
```

The PostgreSQL container still starts under both (it is idle); `docker compose stop postgres` frees it. The files are development defaults with default passwords, like the rest of that stack.

## Testing against a backend

The test suites run on PostgreSQL by default (`PROXYX_TEST_DATABASE_URL`). To run a suite on another backend, set the variable of that backend and select it:

```
export PROXYX_TEST_MARIADB_URL=mysql://root:secret@127.0.0.1:3306/mysql   # a server where the user may CREATE DATABASE
export PROXYX_TEST_SQLITE_DIR=/tmp/proxyx-sqlite                          # a directory for <name>.db files
PROXYX_TEST_BACKEND=mariadb cargo test -p proxyx-store -p proxyx-pool-api -p proxyx-warmer -p proxyx-gateway
```

`PROXYX_TEST_BACKEND` is `postgres` (default), `mariadb` or `sqlite`. A suite whose variable is unset skips with a message. `crates/store/tests/contract.rs` and `crates/control/tests/db_backends.rs` run on every backend whose variable is set, in one run.

Gateway, pool API and warmer integration tests also need `PROXYX_TEST_REDIS_URL`. These suites honor an
explicit database number in that URL. Use a dedicated test database: the warmer suite clears its selected
Redis database between tests.
