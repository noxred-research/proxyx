//! Background TTL reaper: one thread, fixed interval, full slab sweep.

use crate::state::Registry;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

pub fn spawn(registry: Arc<Registry>, interval: Duration) -> thread::JoinHandle<()> {
    thread::spawn(move || loop {
        thread::sleep(interval);
        registry.reap(registry.now_ns());
    })
}
