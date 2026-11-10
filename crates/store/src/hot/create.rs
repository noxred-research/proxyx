//! Create reservations: a cap on concurrent provider creates per partition, so a
//! burst of misses cannot buy more sessions than `max_ready` allows (free and
//! leased ready units, creates in flight and reservations all count).

use std::time::Duration;

use common::types::Partition;
use serde_json::json;
use uuid::Uuid;

use super::{Hot, ms};
use crate::error::Result;

/// A reservation lives this long unless it becomes an in-flight create
///.
pub const RESERVATION_TTL: Duration = Duration::from_secs(120);

/// Permission to start one create.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reservation {
    pub id: Uuid,
}

impl Hot {
    /// Reserve one create when `ready (free + leased) + in flight + reserved < max_ready`.
    /// `None`: the partition is full (or filling); share instead.
    pub async fn reserve_create(
        &self,
        p: &Partition,
        max_ready: u32,
    ) -> Result<Option<Reservation>> {
        let id = Uuid::new_v4();
        let granted: i64 = self
            .run_ready(
                &self.scripts.reserve,
                p,
                json!({ "id": id.to_string(), "max_ready": max_ready, "ttl": ms(RESERVATION_TTL) }),
            )
            .await?;
        Ok((granted > 0).then_some(Reservation { id }))
    }

    /// The create started: swap the reservation for an in-flight entry that
    /// lives `ttl` (twice `create_deadline`). It ends in [`Hot::ready_put`]
    /// of the same session id, or [`Hot::create_abort`]. Returns false when
    /// the reservation had already expired.
    pub async fn create_start(
        &self,
        p: &Partition,
        reservation: &Reservation,
        session: &str,
        ttl: Duration,
    ) -> Result<bool> {
        self.run_ready(
            &self.scripts.create_start,
            p,
            json!({ "reservation": reservation.id.to_string(), "session": session, "ttl": ms(ttl) }),
        )
        .await
    }

    /// Give up a reservation (pass its id) or an in-flight create (pass the
    /// session id).
    pub async fn create_abort(&self, p: &Partition, id: &str) -> Result<bool> {
        self.run_ready(&self.scripts.create_abort, p, json!({ "id": id }))
            .await
    }
}
