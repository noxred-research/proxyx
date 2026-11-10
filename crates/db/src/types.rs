//! Column types that one Rust value maps to on every backend.
//!
//! Most values need nothing special: strings, integers, booleans, bytes,
//! `uuid::Uuid` and `sqlx::types::Json<serde_json::Value>` encode natively on
//! PostgreSQL, MariaDB and SQLite. A timestamp does not: SQLite has no
//! timestamp type, and sqlx writes `OffsetDateTime` there as RFC 3339 text
//! without a fixed width, which does not sort or compare like time. [`Ts`]
//! stores an instant as `TIMESTAMPTZ` (PostgreSQL), `DATETIME(6)` in UTC
//! (MariaDB) and integer microseconds since the Unix epoch (SQLite).

use sqlx::decode::Decode;
use sqlx::encode::{Encode, IsNull};
use sqlx::error::BoxDynError;
use sqlx::sqlite::{SqliteArgumentValue, SqliteTypeInfo, SqliteValueRef};
use sqlx::types::Type;
use sqlx::{MySql, Postgres, Sqlite};
use time::OffsetDateTime;

/// An instant with microsecond resolution, bound and read as one column type
/// on every backend. Anything finer than a microsecond is dropped on write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ts(pub OffsetDateTime);

impl From<OffsetDateTime> for Ts {
    fn from(t: OffsetDateTime) -> Self {
        Self(t)
    }
}

impl From<Ts> for OffsetDateTime {
    fn from(t: Ts) -> Self {
        t.0
    }
}

impl Ts {
    /// Microseconds since the Unix epoch.
    pub fn unix_micros(self) -> i64 {
        // `OffsetDateTime` spans years -9999..=9999: always inside `i64` micros.
        i64::try_from(self.0.unix_timestamp_nanos() / 1_000).unwrap_or(i64::MAX)
    }

    /// The instant `micros` microseconds after the Unix epoch.
    pub fn from_unix_micros(micros: i64) -> Result<Self, time::error::ComponentRange> {
        OffsetDateTime::from_unix_timestamp_nanos(i128::from(micros) * 1_000).map(Self)
    }
}

impl Type<Postgres> for Ts {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <OffsetDateTime as Type<Postgres>>::type_info()
    }

    fn compatible(ty: &sqlx::postgres::PgTypeInfo) -> bool {
        <OffsetDateTime as Type<Postgres>>::compatible(ty)
    }
}

impl Encode<'_, Postgres> for Ts {
    fn encode_by_ref(
        &self,
        buf: &mut sqlx::postgres::PgArgumentBuffer,
    ) -> Result<IsNull, BoxDynError> {
        Encode::<Postgres>::encode_by_ref(&self.0, buf)
    }
}

impl<'r> Decode<'r, Postgres> for Ts {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, BoxDynError> {
        Ok(Self(<OffsetDateTime as Decode<Postgres>>::decode(value)?))
    }
}

impl Type<MySql> for Ts {
    fn type_info() -> sqlx::mysql::MySqlTypeInfo {
        <OffsetDateTime as Type<MySql>>::type_info()
    }

    fn compatible(ty: &sqlx::mysql::MySqlTypeInfo) -> bool {
        <OffsetDateTime as Type<MySql>>::compatible(ty)
    }
}

impl Encode<'_, MySql> for Ts {
    fn encode_by_ref(&self, buf: &mut Vec<u8>) -> Result<IsNull, BoxDynError> {
        Encode::<MySql>::encode_by_ref(&self.0, buf)
    }
}

impl<'r> Decode<'r, MySql> for Ts {
    fn decode(value: sqlx::mysql::MySqlValueRef<'r>) -> Result<Self, BoxDynError> {
        Ok(Self(<OffsetDateTime as Decode<MySql>>::decode(value)?))
    }
}

impl Type<Sqlite> for Ts {
    fn type_info() -> SqliteTypeInfo {
        <i64 as Type<Sqlite>>::type_info()
    }

    fn compatible(ty: &SqliteTypeInfo) -> bool {
        <i64 as Type<Sqlite>>::compatible(ty)
    }
}

impl<'q> Encode<'q, Sqlite> for Ts {
    fn encode_by_ref(
        &self,
        args: &mut Vec<SqliteArgumentValue<'q>>,
    ) -> Result<IsNull, BoxDynError> {
        Encode::<Sqlite>::encode(self.unix_micros(), args)
    }
}

impl<'r> Decode<'r, Sqlite> for Ts {
    fn decode(value: SqliteValueRef<'r>) -> Result<Self, BoxDynError> {
        Ok(Self::from_unix_micros(<i64 as Decode<Sqlite>>::decode(
            value,
        )?)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn micros_round_trip_and_drop_the_nanoseconds() {
        let t = OffsetDateTime::from_unix_timestamp_nanos(1_790_000_000_123_456_789).expect("time");
        let ts = Ts(t);
        assert_eq!(ts.unix_micros(), 1_790_000_000_123_456);
        let back = Ts::from_unix_micros(ts.unix_micros()).expect("back");
        assert_eq!(back.0.unix_timestamp_nanos(), 1_790_000_000_123_456_000);
        assert!(back <= ts);
    }

    #[test]
    fn instants_before_the_epoch_keep_their_order() {
        let a = Ts::from_unix_micros(-5).expect("a");
        let b = Ts::from_unix_micros(-4).expect("b");
        assert!(a < b);
        assert_eq!(a.unix_micros(), -5);
    }
}
