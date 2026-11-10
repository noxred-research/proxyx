//! What differs between the backends, one module each.
//!
//! The repository code in `db/impls` is written once and compiled three
//! times, each time with one of these modules as `d`. A dialect gives it
//! * the sqlx types of its backend (`Conn`, `Tx`, `Pool`),
//! * macros that expand to the SQL text that differs (`now!`, `json_text!`,
//!   `next_version!`, `upsert_*!`, ...), usable inside `concat!`,
//! * `sql!`, which numbers the `?` placeholders for PostgreSQL at compile
//!   time and leaves them as they are for the other two,
//! * the few operations that are not a statement: how a write transaction
//!   begins, how rows are locked by name, how the upstream version advances.
//!
//! Statements are written with `?` placeholders in bind order. Nothing is
//! chosen at run time except which of the three compiled copies runs.

pub(super) mod mariadb;
pub(super) mod postgres;
pub(super) mod sqlite;

/// A name hashed to one of [`ORG_LOCK_BUCKETS`] lock rows (FNV-1a): the
/// backends with row locks keep a fixed set of rows for locks that PostgreSQL
/// takes by hashing a string.
pub(super) fn org_lock_bucket(org: &str) -> u32 {
    let mut hash: u32 = 0x811c_9dc5;
    for byte in org.bytes() {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash % ORG_LOCK_BUCKETS
}

/// The name of the lock row an org maps to on MariaDB (`org_block:N`).
pub(crate) fn org_lock_name(org: &str) -> String {
    format!("org_block:{}", org_lock_bucket(org))
}

/// Seeded by the MariaDB migration `init`: `org_block:0` .. `org_block:63`.
pub(super) const ORG_LOCK_BUCKETS: u32 = 64;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_org_always_maps_to_the_same_bucket_inside_the_range() {
        for org in ["a", "ovw", "org-1", "x_y"] {
            let bucket = org_lock_bucket(org);
            assert!(bucket < ORG_LOCK_BUCKETS);
            assert_eq!(bucket, org_lock_bucket(org));
        }
    }
}
