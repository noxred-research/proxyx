//! Test support shared by the integration tests of every crate: a scratch
//! database on each backend a developer has running.
//!
//! * PostgreSQL: `PROXYX_TEST_DATABASE_URL`, a URL that ends in any database
//!   of a server where the user may `CREATE DATABASE`.
//! * MariaDB: `PROXYX_TEST_MARIADB_URL`, the same for a MariaDB server
//!   (`mysql://root:pw@127.0.0.1:3306/mysql`).
//! * SQLite: `PROXYX_TEST_SQLITE_DIR`, a directory the tests may fill with
//!   `<name>.db` files.
//!
//! A backend whose variable is unset is skipped with a message.

use std::path::Path;

use sqlx::Connection as _;
use sqlx::types::Json;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{Backend, Pool, PoolSettings, Ts};

/// Serialises the database creation of all test binaries on one server.
const CREATE_LOCK: i64 = 70001;
const MARIADB_CREATE_LOCK: &str = "proxyx-test-create";

/// The environment variable that configures `backend` for tests.
pub const fn env_var(backend: Backend) -> &'static str {
    match backend {
        Backend::Postgres => "PROXYX_TEST_DATABASE_URL",
        Backend::MariaDb => "PROXYX_TEST_MARIADB_URL",
        Backend::Sqlite => "PROXYX_TEST_SQLITE_DIR",
    }
}

/// The backends whose environment variable is set.
pub fn configured() -> Vec<Backend> {
    Backend::ALL
        .into_iter()
        .filter(|b| std::env::var(env_var(*b)).is_ok())
        .collect()
}

/// The backend the suite under test runs on: `PROXYX_TEST_BACKEND`
/// (`postgres`, `mariadb`, `sqlite`), PostgreSQL when unset.
pub fn selected() -> Backend {
    match std::env::var("PROXYX_TEST_BACKEND") {
        Ok(name) => name
            .parse()
            .unwrap_or_else(|_| panic!("PROXYX_TEST_BACKEND={name:?} names no backend")),
        Err(_) => Backend::Postgres,
    }
}

/// Create the database `name` on `backend` if it is missing, and return its
/// URL; `fresh` drops it first. `None` (with a message on stderr) when the
/// backend is not configured. `name` is an identifier: letters, digits and
/// underscores.
pub async fn database(
    backend: Backend,
    name: &str,
    fresh: bool,
) -> Result<Option<String>, sqlx::Error> {
    let var = env_var(backend);
    let Ok(base) = std::env::var(var) else {
        eprintln!("SKIP: {var} is not set ({backend})");
        return Ok(None);
    };
    if !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return Err(sqlx::Error::Configuration(
            format!("database name {name:?} is not an identifier").into(),
        ));
    }
    let url = match backend {
        Backend::Postgres => postgres(&base, name, fresh).await?,
        Backend::MariaDb => mariadb(&base, name, fresh).await?,
        Backend::Sqlite => sqlite(&base, name, fresh)?,
    };
    Ok(Some(url))
}

/// `base` (a URL ending in a database) with its database replaced by `name`.
fn with_database(base: &str, name: &str) -> Result<String, sqlx::Error> {
    let without_query = base.split('?').next().unwrap_or(base);
    let (prefix, _) = without_query
        .rsplit_once('/')
        .ok_or_else(|| sqlx::Error::Configuration("database url has no path".into()))?;
    Ok(format!("{prefix}/{name}"))
}

async fn postgres(base: &str, name: &str, fresh: bool) -> Result<String, sqlx::Error> {
    let mut admin = sqlx::PgConnection::connect(base).await?;
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(CREATE_LOCK)
        .execute(&mut admin)
        .await?;
    if fresh {
        sqlx::query(&format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)"))
            .execute(&mut admin)
            .await?;
    }
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)")
            .bind(name)
            .fetch_one(&mut admin)
            .await?;
    if !exists {
        sqlx::query(&format!("CREATE DATABASE {name}"))
            .execute(&mut admin)
            .await?;
    }
    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(CREATE_LOCK)
        .execute(&mut admin)
        .await?;
    with_database(base, name)
}

async fn mariadb(base: &str, name: &str, fresh: bool) -> Result<String, sqlx::Error> {
    let mut admin = sqlx::MySqlConnection::connect(base).await?;
    sqlx::query("SELECT GET_LOCK(?, 60)")
        .bind(MARIADB_CREATE_LOCK)
        .execute(&mut admin)
        .await?;
    if fresh {
        // MariaDB sometimes finds a file it has not finished writing in the
        // directory it removes (error 1010): try again.
        let mut attempt = 0;
        loop {
            match sqlx::query(&format!("DROP DATABASE IF EXISTS `{name}`"))
                .execute(&mut admin)
                .await
            {
                Ok(_) => break,
                Err(sqlx::Error::Database(e))
                    if attempt < 5 && e.code().as_deref() == Some("HY000") =>
                {
                    attempt += 1;
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                }
                Err(e) => return Err(e),
            }
        }
    }
    sqlx::query(&format!(
        "CREATE DATABASE IF NOT EXISTS `{name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci"
    ))
    .execute(&mut admin)
    .await?;
    sqlx::query("SELECT RELEASE_LOCK(?)")
        .bind(MARIADB_CREATE_LOCK)
        .execute(&mut admin)
        .await?;
    with_database(base, name)
}

fn sqlite(dir: &str, name: &str, fresh: bool) -> Result<String, sqlx::Error> {
    let dir = Path::new(dir);
    std::fs::create_dir_all(dir).map_err(sqlx::Error::Io)?;
    let file = dir.join(format!("{name}.db"));
    if fresh {
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let mut path = file.clone().into_os_string();
            path.push(suffix);
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(sqlx::Error::Io(e)),
            }
        }
    }
    Ok(format!("sqlite://{}?mode=rwc", file.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_database_of_a_url_is_replaced() {
        assert_eq!(
            with_database("postgres://u:p@h:5432/postgres", "x").expect("url"),
            "postgres://u:p@h:5432/x"
        );
        assert_eq!(
            with_database("mysql://root:pw@h/mysql?ssl-mode=disabled", "x").expect("url"),
            "mysql://root:pw@h/x"
        );
    }
}

/// A value bound to a statement of [`Raw`].
#[derive(Debug, Clone)]
pub enum Arg {
    Text(String),
    Int(i64),
    Bool(bool),
    Bytes(Vec<u8>),
    Time(OffsetDateTime),
    Uuid(Uuid),
    Json(serde_json::Value),
    Null,
}

impl From<&str> for Arg {
    fn from(v: &str) -> Self {
        Self::Text(v.to_owned())
    }
}
impl From<String> for Arg {
    fn from(v: String) -> Self {
        Self::Text(v)
    }
}
impl From<&String> for Arg {
    fn from(v: &String) -> Self {
        Self::Text(v.clone())
    }
}
impl From<i64> for Arg {
    fn from(v: i64) -> Self {
        Self::Int(v)
    }
}
impl From<bool> for Arg {
    fn from(v: bool) -> Self {
        Self::Bool(v)
    }
}
impl From<OffsetDateTime> for Arg {
    fn from(v: OffsetDateTime) -> Self {
        Self::Time(v)
    }
}
impl From<Uuid> for Arg {
    fn from(v: Uuid) -> Self {
        Self::Uuid(v)
    }
}
impl From<&[u8]> for Arg {
    fn from(v: &[u8]) -> Self {
        Self::Bytes(v.to_vec())
    }
}

/// Raw SQL against the database of a test, for what the repository does not
/// expose: seeding old rows, changing a row behind its back, counting.
/// Statements use `?` placeholders on every backend.
#[derive(Clone)]
pub struct Raw {
    pool: Pool,
}

macro_rules! bind_all {
    ($query:expr, $args:expr) => {{
        let mut query = $query;
        for arg in $args {
            query = match arg {
                Arg::Text(v) => query.bind(v.clone()),
                Arg::Int(v) => query.bind(*v),
                Arg::Bool(v) => query.bind(*v),
                Arg::Bytes(v) => query.bind(v.clone()),
                Arg::Time(v) => query.bind(Ts(*v)),
                Arg::Uuid(v) => query.bind(*v),
                Arg::Json(v) => query.bind(Json(v.clone())),
                Arg::Null => query.bind(None::<String>),
            };
        }
        query
    }};
}

impl Raw {
    /// Connect to the database `url` names.
    pub async fn connect(url: &str) -> Result<Self, sqlx::Error> {
        Ok(Self {
            pool: Pool::connect(url, &PoolSettings::default()).await?,
        })
    }

    /// The backend of this database.
    pub fn backend(&self) -> Backend {
        self.pool.backend()
    }

    /// The underlying pool.
    pub fn pool(&self) -> &Pool {
        &self.pool
    }

    /// Run a statement; the rows it changed.
    pub async fn execute(&self, sql: &str, args: &[Arg]) -> Result<u64, sqlx::Error> {
        match &self.pool {
            Pool::Postgres(p) => {
                let sql = number_placeholders(sql);
                Ok(bind_all!(sqlx::query(&sql), args)
                    .execute(p)
                    .await?
                    .rows_affected())
            }
            Pool::MariaDb(p) => Ok(bind_all!(sqlx::query(sql), args)
                .execute(p)
                .await?
                .rows_affected()),
            Pool::Sqlite(p) => Ok(bind_all!(sqlx::query(sql), args)
                .execute(p)
                .await?
                .rows_affected()),
        }
    }

    /// The first column of the first row as an integer (`count(*)`, `max(x)`).
    pub async fn int(&self, sql: &str, args: &[Arg]) -> Result<i64, sqlx::Error> {
        match &self.pool {
            Pool::Postgres(p) => {
                let sql = number_placeholders(sql);
                bind_all!(sqlx::query_scalar(&sql), args).fetch_one(p).await
            }
            Pool::MariaDb(p) => bind_all!(sqlx::query_scalar(sql), args).fetch_one(p).await,
            Pool::Sqlite(p) => bind_all!(sqlx::query_scalar(sql), args).fetch_one(p).await,
        }
    }

    /// The first column of the first row as bytes.
    pub async fn bytes(&self, sql: &str, args: &[Arg]) -> Result<Vec<u8>, sqlx::Error> {
        match &self.pool {
            Pool::Postgres(p) => {
                let sql = number_placeholders(sql);
                bind_all!(sqlx::query_scalar(&sql), args).fetch_one(p).await
            }
            Pool::MariaDb(p) => bind_all!(sqlx::query_scalar(sql), args).fetch_one(p).await,
            Pool::Sqlite(p) => bind_all!(sqlx::query_scalar(sql), args).fetch_one(p).await,
        }
    }

    /// The first column of the first row as text.
    pub async fn text(&self, sql: &str, args: &[Arg]) -> Result<String, sqlx::Error> {
        match &self.pool {
            Pool::Postgres(p) => {
                let sql = number_placeholders(sql);
                bind_all!(sqlx::query_scalar(&sql), args).fetch_one(p).await
            }
            Pool::MariaDb(p) => bind_all!(sqlx::query_scalar(sql), args).fetch_one(p).await,
            Pool::Sqlite(p) => bind_all!(sqlx::query_scalar(sql), args).fetch_one(p).await,
        }
    }

    /// The first column of the first row as a time (a [`Ts`] column).
    pub async fn time(&self, sql: &str, args: &[Arg]) -> Result<OffsetDateTime, sqlx::Error> {
        let ts: Ts = match &self.pool {
            Pool::Postgres(p) => {
                let sql = number_placeholders(sql);
                bind_all!(sqlx::query_scalar(&sql), args)
                    .fetch_one(p)
                    .await?
            }
            Pool::MariaDb(p) => {
                bind_all!(sqlx::query_scalar(sql), args)
                    .fetch_one(p)
                    .await?
            }
            Pool::Sqlite(p) => {
                bind_all!(sqlx::query_scalar(sql), args)
                    .fetch_one(p)
                    .await?
            }
        };
        Ok(ts.0)
    }
}

/// `?` to `$1`, `$2`, ... outside string literals, at run time (tests only).
fn number_placeholders(sql: &str) -> String {
    let (mut out, mut n, mut quoted) = (String::with_capacity(sql.len() + 8), 0, false);
    for c in sql.chars() {
        match c {
            '\'' => {
                quoted = !quoted;
                out.push(c);
            }
            '?' if !quoted => {
                n += 1;
                out.push_str(&format!("${n}"));
            }
            _ => out.push(c),
        }
    }
    out
}
