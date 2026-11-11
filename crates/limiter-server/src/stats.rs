//! Service counters. All relaxed atomics: they feed `/metrics` and carry no
//! ordering with the bucket state.

use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct Stats {
    /// Open client connections (gauge).
    pub connections: AtomicU64,
    /// Connections accepted and then dropped at the connection cap.
    pub connections_refused: AtomicU64,
    /// Records handled per op.
    pub create: AtomicU64,
    pub consume: AtomicU64,
    pub drain: AtomicU64,
    pub snapshot: AtomicU64,
    pub ping: AtomicU64,
    /// CONSUME records answered `allowed = false` (status OK).
    pub consume_denied: AtomicU64,
    /// CREATE records refused because the slab was full.
    pub create_full: AtomicU64,
    /// Connections ended by an I/O or protocol error.
    pub connection_errors: AtomicU64,
}

impl Stats {
    #[inline]
    pub fn add(counter: &AtomicU64, n: u64) {
        counter.fetch_add(n, Ordering::Relaxed);
    }

    #[inline]
    pub fn get(counter: &AtomicU64) -> u64 {
        counter.load(Ordering::Relaxed)
    }
}

/// Decrements the connection gauge when a connection thread ends, however it ends.
pub struct ConnGuard(pub std::sync::Arc<Stats>);

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.0.connections.fetch_sub(1, Ordering::Relaxed);
    }
}
