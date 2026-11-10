//! The bucket registry: a lock-free generational slab addressed by u64 handle,
//! plus a sharded name->handle map for first-lookup `create`. Hot-path ops
//! (`consume`/`snapshot`) take no shard lock; each bucket carries its own
//! spinlock (in `limiter_core::TokenBucket`).

use limiter_core::TokenBucket;
use limiter_proto::{ConsumeResult, DrainResult, SnapshotResult, ST_FULL, ST_OK, ST_STALE};
use parking_lot::Mutex;
use std::cell::UnsafeCell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

/// Low 32 bits of a handle hold the slot index; high 32 hold the generation.
const SLOT_INDEX_MASK: u64 = 0xFFFF_FFFF;

/// Name -> handle map, sharded to spread first-lookup contention.
type ShardMap = Mutex<HashMap<Box<[u8]>, u64>>;

/// One slab entry. A handle is `(generation << 32) | slot_index`; a stale handle
/// (slot evicted and the generation bumped) fails the generation check.
struct Slot {
    generation: AtomicU64,
    occupied: AtomicBool,
    last_access_ns: AtomicU64,
    ttl_ns: AtomicU64,
    /// Written only under the owning key's shard lock while the slot is free, and
    /// cleared by the reaper under that same lock. Read lock-free by the reaper
    /// only after an Acquire-load of `occupied == true`, which has no concurrent
    /// writer (create never touches an occupied slot's key).
    key: UnsafeCell<Option<Box<[u8]>>>,
    bucket: TokenBucket,
}

// SAFETY: see the field doc on `key`; `bucket` carries its own spinlock and the
// atomics are independently synchronized.
unsafe impl Sync for Slot {}

impl Slot {
    fn new() -> Self {
        Slot {
            generation: AtomicU64::new(0),
            occupied: AtomicBool::new(false),
            last_access_ns: AtomicU64::new(0),
            ttl_ns: AtomicU64::new(0),
            key: UnsafeCell::new(None),
            bucket: TokenBucket::new(0, 0, 0, 0),
        }
    }
}

pub struct Registry {
    slots: Box<[Slot]>,
    free: Mutex<Vec<u32>>,
    shards: Box<[ShardMap]>,
    shard_mask: usize,
    start: Instant,
}

impl Registry {
    pub fn new(max_buckets: usize, shard_count: usize) -> Self {
        let n = max_buckets.max(1).next_power_of_two();
        let slots: Box<[Slot]> = (0..n).map(|_| Slot::new()).collect();
        // Pop from the tail; reversed so allocation hands out ascending indices.
        let free: Vec<u32> = (0..n as u32).rev().collect();
        let shard_count = shard_count.max(1).next_power_of_two();
        let shards: Box<[ShardMap]> = (0..shard_count)
            .map(|_| Mutex::new(HashMap::new()))
            .collect();
        Registry {
            slots,
            free: Mutex::new(free),
            shard_mask: shard_count - 1,
            shards,
            start: Instant::now(),
        }
    }

    pub fn capacity(&self) -> usize {
        self.slots.len()
    }

    /// Buckets currently allocated. Takes the free-list lock, so call it from
    /// scrapes, not from the hot path.
    pub fn used(&self) -> usize {
        self.slots.len() - self.free.lock().len()
    }

    /// Server-authoritative monotonic clock, nanoseconds since start.
    #[inline]
    pub fn now_ns(&self) -> u64 {
        self.start.elapsed().as_nanos() as u64
    }

    #[inline]
    fn shard_of(&self, key: &[u8]) -> usize {
        // FNV-1a, dependency-free and good enough for shard spread.
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for &b in key {
            h ^= b as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        (h as usize) & self.shard_mask
    }

    /// Decode a handle to its slot, rejecting out-of-range indices. The full
    /// low 32 bits are used so a high-bit-set forgery cannot alias a real slot.
    #[inline]
    fn slot_for(&self, handle: u64) -> Option<&Slot> {
        self.slots.get((handle & SLOT_INDEX_MASK) as usize)
    }

    /// Create-or-update. Returns the bucket handle, or `Err(ST_FULL)` when the
    /// slab is exhausted.
    pub fn create(
        &self,
        now_ns: u64,
        key: &[u8],
        capacity: u64,
        refill_rate: u64,
        ttl_ns: u64,
    ) -> Result<u64, u8> {
        let mut map = self.shards[self.shard_of(key)].lock();
        if let Some(&handle) = map.get(key) {
            // Existing bucket for this key: update config in place. The slot is
            // still valid (the reaper removes the map entry under this lock
            // before recycling), so no generation check is needed here.
            let slot = &self.slots[(handle & SLOT_INDEX_MASK) as usize];
            slot.bucket
                .update(now_ns, Some(capacity), Some(refill_rate));
            slot.ttl_ns.store(ttl_ns, Ordering::Relaxed);
            slot.last_access_ns.store(now_ns, Ordering::Relaxed);
            return Ok(handle);
        }

        let idx = match self.free.lock().pop() {
            Some(i) => i,
            None => return Err(ST_FULL),
        };
        let slot = &self.slots[idx as usize];
        let generation = slot.generation.fetch_add(1, Ordering::Release) + 1;
        slot.last_access_ns.store(now_ns, Ordering::Relaxed);
        slot.ttl_ns.store(ttl_ns, Ordering::Relaxed);
        // SAFETY: the slot was free (no consumer matches its generation) and we
        // hold the shard lock, so there is no concurrent access to `key`.
        unsafe {
            *slot.key.get() = Some(key.into());
        }
        // Fresh buckets start full.
        slot.bucket.reset(capacity, refill_rate, capacity, now_ns);
        slot.occupied.store(true, Ordering::Release);
        let handle = (generation << 32) | idx as u64;
        map.insert(key.into(), handle);
        Ok(handle)
    }

    pub fn consume(&self, now_ns: u64, handle: u64, amount: u64) -> ConsumeResult {
        let stale = || ConsumeResult {
            status: ST_STALE,
            allowed: false,
            remaining: 0,
            retry_after_ns: 0,
        };
        let slot = match self.slot_for(handle) {
            Some(s) => s,
            None => return stale(),
        };
        if slot.generation.load(Ordering::Acquire) != handle >> 32
            || !slot.occupied.load(Ordering::Acquire)
        {
            return stale();
        }
        slot.last_access_ns.store(now_ns, Ordering::Relaxed);
        let r = slot.bucket.consume(amount, now_ns);
        ConsumeResult {
            status: ST_OK,
            allowed: r.allowed,
            remaining: r.remaining,
            retry_after_ns: r.retry_after_ns,
        }
    }

    pub fn drain(&self, now_ns: u64, handle: u64, amount: u64) -> DrainResult {
        let slot = match self.slot_for(handle) {
            Some(s) => s,
            None => {
                return DrainResult {
                    status: ST_STALE,
                    drained: 0,
                };
            }
        };
        if slot.generation.load(Ordering::Acquire) != handle >> 32
            || !slot.occupied.load(Ordering::Acquire)
        {
            return DrainResult {
                status: ST_STALE,
                drained: 0,
            };
        }
        slot.last_access_ns.store(now_ns, Ordering::Relaxed);
        DrainResult {
            status: ST_OK,
            drained: slot.bucket.drain(amount, now_ns),
        }
    }

    pub fn snapshot(&self, now_ns: u64, handle: u64) -> SnapshotResult {
        let stale = || SnapshotResult {
            status: ST_STALE,
            capacity: 0,
            refill_rate: 0,
            tokens: 0,
            last_refill_ns: 0,
        };
        let slot = match self.slot_for(handle) {
            Some(s) => s,
            None => return stale(),
        };
        if slot.generation.load(Ordering::Acquire) != handle >> 32
            || !slot.occupied.load(Ordering::Acquire)
        {
            return stale();
        }
        slot.last_access_ns.store(now_ns, Ordering::Relaxed);
        let s = slot.bucket.snapshot();
        SnapshotResult {
            status: ST_OK,
            capacity: s.capacity,
            refill_rate: s.refill_rate,
            tokens: s.tokens,
            last_refill_ns: s.last_refill_ns,
        }
    }

    /// Evict every idle-expired bucket. One pass; called by the reaper thread.
    pub fn reap(&self, now_ns: u64) {
        for idx in 0..self.slots.len() {
            let slot = &self.slots[idx];
            // Phase 1: lock-free filter. Acquire on `occupied` orders the
            // following key read after the create that set it.
            if !slot.occupied.load(Ordering::Acquire) {
                continue;
            }
            let ttl = slot.ttl_ns.load(Ordering::Relaxed);
            if ttl == 0 || now_ns.saturating_sub(slot.last_access_ns.load(Ordering::Relaxed)) <= ttl
            {
                continue;
            }
            self.try_evict(idx, now_ns);
        }
    }

    fn try_evict(&self, idx: usize, now_ns: u64) {
        let slot = &self.slots[idx];
        // SAFETY: `occupied` was Acquire-loaded true by the caller; an occupied
        // slot's key has no concurrent writer (create only writes free slots,
        // the reaper is single-threaded). Clone so we can mutate `key` below
        // without aliasing the borrow.
        let key: Box<[u8]> = match unsafe { (*slot.key.get()).as_ref() } {
            Some(k) => k.clone(),
            None => return,
        };
        let mut map = self.shards[self.shard_of(&key)].lock();
        // Re-check expiry under the shard lock; last_access may have advanced.
        if !slot.occupied.load(Ordering::Acquire) {
            return;
        }
        let ttl = slot.ttl_ns.load(Ordering::Relaxed);
        if ttl == 0 || now_ns.saturating_sub(slot.last_access_ns.load(Ordering::Relaxed)) <= ttl {
            return;
        }
        map.remove(key.as_ref());
        slot.generation.fetch_add(1, Ordering::Release);
        slot.occupied.store(false, Ordering::Release);
        // SAFETY: still under the shard lock; the slot is now unoccupied.
        unsafe {
            *slot.key.get() = None;
        }
        drop(map);
        self.free.lock().push(idx as u32);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_then_consume_to_empty() {
        let reg = Registry::new(16, 4);
        let h = reg.create(0, b"k", 3, 0, 0).unwrap();
        assert!(reg.consume(0, h, 1).allowed);
        assert!(reg.consume(0, h, 1).allowed);
        assert!(reg.consume(0, h, 1).allowed);
        let denied = reg.consume(0, h, 1);
        assert!(!denied.allowed);
        assert_eq!(denied.status, ST_OK);
        assert_eq!(denied.retry_after_ns, u64::MAX); // zero refill
    }

    #[test]
    fn recreate_same_key_returns_same_handle_and_updates() {
        let reg = Registry::new(16, 4);
        let h1 = reg.create(0, b"k", 3, 0, 0).unwrap();
        reg.consume(0, h1, 3);
        let h2 = reg.create(0, b"k", 10, 0, 0).unwrap();
        assert_eq!(h1, h2);
        // capacity raised; tokens were 0, update doesn't refill them.
        assert_eq!(reg.snapshot(0, h2).capacity, 10);
    }

    #[test]
    fn full_when_slab_exhausted() {
        let reg = Registry::new(2, 1);
        reg.create(0, b"a", 1, 0, 0).unwrap();
        reg.create(0, b"b", 1, 0, 0).unwrap();
        assert_eq!(reg.create(0, b"c", 1, 0, 0), Err(ST_FULL));
    }

    #[test]
    fn eviction_makes_handle_stale_and_frees_slot() {
        let reg = Registry::new(2, 1);
        let h = reg.create(0, b"a", 1, 0, 5).unwrap();
        // now well past ttl
        reg.reap(100);
        assert_eq!(reg.consume(200, h, 1).status, ST_STALE);
        // slot freed -> can create two more
        reg.create(200, b"b", 1, 0, 0).unwrap();
        reg.create(200, b"c", 1, 0, 0).unwrap();
    }

    #[test]
    fn zero_ttl_never_evicted() {
        let reg = Registry::new(2, 1);
        let h = reg.create(0, b"a", 1, 0, 0).unwrap();
        reg.reap(u64::MAX / 2);
        assert_eq!(reg.consume(0, h, 1).status, ST_OK);
    }

    #[test]
    fn forged_handle_is_stale() {
        let reg = Registry::new(16, 4);
        assert_eq!(reg.consume(0, 0, 1).status, ST_STALE);
        assert_eq!(reg.consume(0, 12345, 1).status, ST_STALE);
    }
}
