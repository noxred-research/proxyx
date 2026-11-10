//! Opt-in diagnostics for whole-process pauses (`PROXYX_INTERCEPT_PROFILING=1`).
//!
//! Adds two routes to the API server:
//! - `GET /debug/pprof/profile?seconds=N`: CPU profile (pprof protobuf).
//! - `GET /debug/stalls`: recent runtime stalls with thread states.
//!
//! A stall is detected by a Tokio task ticking every 10 ms; when a tick fires
//! more than 50 ms late, an event is recorded. That task runs on the runtime,
//! so it only observes the stall after it ended: its `threads` snapshot shows
//! threads *after* the pause. A plain OS thread samples `/proc/self/task`
//! every 10 ms into a 200 ms window, and the first sample taken at or after
//! the late tick's due time is attached as `before` — threads *during* the
//! pause (unless the sampler thread itself was descheduled too).

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::{
    Json, Router,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use parking_lot::Mutex;
use pprof::protos::Message as _;
use serde::{Deserialize, Serialize};
use tokio::time::MissedTickBehavior;
use tokio_util::sync::CancellationToken;

const INTERVAL: Duration = Duration::from_millis(10);
const THRESHOLD: Duration = Duration::from_millis(50);
const MAX_EVENTS: usize = 2_000;
const SAMPLE_WINDOW: Duration = Duration::from_millis(200);

pub fn enabled() -> bool {
    std::env::var("PROXYX_INTERCEPT_PROFILING")
        .is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}

#[derive(Clone, Debug, Serialize)]
pub struct ThreadState {
    tid: u32,
    name: String,
    state: String,
    wchan: String,
    syscall: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct StallEvent {
    at_unix_ms: u64,
    lag_ms: f64,
    threads: Vec<ThreadState>,
    before: Vec<ThreadState>,
}

#[derive(Default)]
pub struct Profiler {
    events: Mutex<VecDeque<StallEvent>>,
    samples: Mutex<VecDeque<(Instant, Vec<ThreadState>)>>,
    cpu_busy: AtomicBool,
}

impl Profiler {
    /// Start the stall probe task and the sampler thread.
    pub fn start(cancel: CancellationToken) -> Arc<Self> {
        let profiler = Arc::new(Self::default());

        let sampler = profiler.clone();
        std::thread::Builder::new()
            .name("stall-sampler".into())
            .spawn(move || {
                loop {
                    sampler.push_sample(Instant::now(), snapshot_threads());
                    std::thread::sleep(INTERVAL);
                }
            })
            .expect("spawn stall sampler thread");

        let probe = profiler.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(INTERVAL);
            interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    due = interval.tick() => probe.on_tick(due.into_std(), due.elapsed()),
                    _ = cancel.cancelled() => break,
                }
            }
        });

        profiler
    }

    fn push_sample(&self, at: Instant, threads: Vec<ThreadState>) {
        let mut samples = self.samples.lock();
        while samples
            .front()
            .is_some_and(|(t, _)| at.duration_since(*t) > SAMPLE_WINDOW)
        {
            samples.pop_front();
        }
        samples.push_back((at, threads));
    }

    fn on_tick(&self, due: Instant, lag: Duration) {
        common::metrics::PROXY_SCHEDULER_LAG_SECONDS.observe(lag.as_secs_f64());
        if lag <= THRESHOLD {
            return;
        }
        let before = {
            let samples = self.samples.lock();
            samples
                .iter()
                .find(|(t, _)| *t >= due)
                .or(samples.back())
                .map(|(_, threads)| threads.clone())
                .unwrap_or_default()
        };
        let event = StallEvent {
            at_unix_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            lag_ms: lag.as_secs_f64() * 1000.0,
            threads: snapshot_threads(),
            before,
        };
        let mut events = self.events.lock();
        if events.len() == MAX_EVENTS {
            events.pop_front();
        }
        events.push_back(event);
    }
}

fn snapshot_threads() -> Vec<ThreadState> {
    let Ok(dir) = std::fs::read_dir("/proc/self/task") else {
        return Vec::new();
    };
    dir.filter_map(|entry| {
        let entry = entry.ok()?;
        let tid: u32 = entry.file_name().to_str()?.parse().ok()?;
        let path = entry.path();
        // `stat` is "tid (comm) S ...": comm may contain spaces or parens.
        let stat = std::fs::read_to_string(path.join("stat")).ok()?;
        let open = stat.find('(')?;
        let close = stat.rfind(')')?;
        Some(ThreadState {
            tid,
            name: stat[open + 1..close].to_string(),
            state: stat[close + 1..].split_whitespace().next()?.to_string(),
            wchan: std::fs::read_to_string(path.join("wchan")).unwrap_or_default(),
            syscall: std::fs::read_to_string(path.join("syscall"))
                .ok()
                .and_then(|s| s.split_whitespace().next().map(str::to_string)),
        })
    })
    .collect()
}

pub fn router(profiler: Arc<Profiler>) -> Router {
    Router::new()
        .route("/debug/stalls", get(stalls))
        .route("/debug/pprof/profile", get(cpu_profile))
        .with_state(profiler)
}

#[derive(Serialize)]
struct StallsBody {
    threshold_ms: u64,
    interval_ms: u64,
    events: Vec<StallEvent>,
}

async fn stalls(State(profiler): State<Arc<Profiler>>) -> Json<StallsBody> {
    Json(StallsBody {
        threshold_ms: THRESHOLD.as_millis() as u64,
        interval_ms: INTERVAL.as_millis() as u64,
        events: profiler.events.lock().iter().cloned().collect(),
    })
}

#[derive(Deserialize)]
struct ProfileParams {
    seconds: Option<u64>,
}

struct BusyGuard<'a>(&'a AtomicBool);

impl Drop for BusyGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

async fn cpu_profile(
    State(profiler): State<Arc<Profiler>>,
    Query(params): Query<ProfileParams>,
) -> Response {
    let seconds = params.seconds.unwrap_or(30);
    if !(1..=3600).contains(&seconds) {
        return (StatusCode::BAD_REQUEST, "seconds must be in 1..=3600").into_response();
    }
    if profiler
        .cpu_busy
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return (StatusCode::CONFLICT, "a profile is already running").into_response();
    }
    let _busy = BusyGuard(&profiler.cpu_busy);

    let guard = match pprof::ProfilerGuardBuilder::default()
        .frequency(99)
        .blocklist(&["libc", "libgcc", "pthread", "vdso"])
        .build()
    {
        Ok(guard) => guard,
        Err(e) => return internal_error(e),
    };
    tokio::time::sleep(Duration::from_secs(seconds)).await;
    let profile = match guard.report().build().and_then(|r| r.pprof()) {
        Ok(profile) => profile,
        Err(e) => return internal_error(e),
    };
    (
        [("content-type", "application/octet-stream")],
        profile.encode_to_vec(),
    )
        .into_response()
}

fn internal_error(e: pprof::Error) -> Response {
    tracing::warn!(error = %e, "CPU profile failed");
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_only_lag_above_threshold() {
        let profiler = Profiler::default();
        let t0 = Instant::now();
        profiler.push_sample(t0, Vec::new());
        let during = vec![ThreadState {
            tid: 1,
            name: "worker".into(),
            state: "D".into(),
            wchan: "io".into(),
            syscall: None,
        }];
        profiler.push_sample(t0 + Duration::from_millis(20), during);

        profiler.on_tick(t0, Duration::from_millis(10));
        profiler.on_tick(t0 + Duration::from_millis(15), Duration::from_millis(60));

        let events = profiler.events.lock();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].lag_ms, 60.0);
        assert_eq!(events[0].before[0].state, "D");
        assert!(!events[0].threads.is_empty(), "own threads are listed");
    }

    #[test]
    fn sample_window_and_event_ring_are_bounded() {
        let profiler = Profiler::default();
        let t0 = Instant::now();
        for i in 0..100 {
            profiler.push_sample(t0 + INTERVAL * i, Vec::new());
        }
        assert!(profiler.samples.lock().len() <= 21);

        for _ in 0..MAX_EVENTS + 5 {
            profiler.on_tick(t0, Duration::from_millis(51));
        }
        assert_eq!(profiler.events.lock().len(), MAX_EVENTS);
    }
}
