//! CPU time and memory of the process under test, read from `/proc`.
//!
//! Everything here is plain text parsing; no libc call is needed.

use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use serde::Serialize;
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;

/// Clock ticks per second in `/proc/<pid>/stat`. `USER_HZ` is 100 on every
/// Linux architecture ProxyX supports; reading it with `sysconf` would need
/// an `unsafe` libc call.
pub const CLOCK_TICKS_PER_SEC: u64 = 100;

/// How often the sampler reads the process.
const SAMPLE_EVERY: Duration = Duration::from_millis(100);

/// User and system CPU time of a process (all its threads), in clock ticks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuTicks {
    pub user: u64,
    pub system: u64,
}

impl CpuTicks {
    pub fn total(self) -> u64 {
        self.user + self.system
    }
}

/// Memory of a process from `/proc/<pid>/status`, in KiB.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Memory {
    /// Resident set size now (`VmRSS`).
    pub rss_kb: u64,
    /// Peak resident set size since the process started (`VmHWM`).
    pub peak_rss_kb: u64,
}

/// Parse the contents of `/proc/<pid>/stat`.
///
/// The second field is the command name in parentheses and may itself contain
/// spaces and parentheses, so the fields after it are located from the last
/// `)`. `utime` and `stime` are fields 14 and 15 of the line.
pub fn parse_stat(text: &str) -> Result<CpuTicks> {
    let close = text.rfind(')').context("stat: no closing parenthesis")?;
    // After ")" come: state (3), ppid (4), ... so utime (14) is the 12th field.
    let mut fields = text[close + 1..].split_ascii_whitespace();
    let utime = fields.nth(11).context("stat: no utime field")?;
    let stime = fields.next().context("stat: no stime field")?;
    Ok(CpuTicks {
        user: utime.parse().context("stat: utime is not a number")?,
        system: stime.parse().context("stat: stime is not a number")?,
    })
}

/// Parse the contents of `/proc/<pid>/status`.
pub fn parse_status(text: &str) -> Result<Memory> {
    let (mut rss, mut hwm) = (None, None);
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            rss = Some(parse_kb(rest)?);
        } else if let Some(rest) = line.strip_prefix("VmHWM:") {
            hwm = Some(parse_kb(rest)?);
        }
    }
    let rss_kb = rss.context("status: no VmRSS line")?;
    // A kernel without VmHWM still gives a usable peak: the current value.
    Ok(Memory {
        rss_kb,
        peak_rss_kb: hwm.unwrap_or(rss_kb).max(rss_kb),
    })
}

fn parse_kb(rest: &str) -> Result<u64> {
    let mut parts = rest.split_ascii_whitespace();
    let value = parts.next().context("status: empty value")?;
    match parts.next() {
        Some("kB") | None => {}
        Some(unit) => bail!("status: unexpected unit {unit:?}"),
    }
    value.parse().context("status: value is not a number")
}

/// One reading of a process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sample {
    pub cpu: CpuTicks,
    pub memory: Memory,
}

/// Read `/proc/<pid>/stat` and `/proc/<pid>/status`.
pub fn sample(pid: u32) -> Result<Sample> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .with_context(|| format!("read /proc/{pid}/stat"))?;
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))
        .with_context(|| format!("read /proc/{pid}/status"))?;
    Ok(Sample {
        cpu: parse_stat(&stat)?,
        memory: parse_status(&status)?,
    })
}

/// What a process used between [`Monitor::start`] and [`Monitor::finish`].
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct Usage {
    pub pid: u32,
    /// CPU seconds (user + system) used inside the window.
    pub cpu_seconds: f64,
    pub cpu_user_seconds: f64,
    pub cpu_system_seconds: f64,
    /// CPU seconds over wall seconds, in percent of one core.
    pub cpu_percent_of_one_core: f64,
    /// Resident set at the end of the window.
    pub rss_kb: u64,
    /// Peak resident set of the process (`VmHWM`, or the largest sample).
    pub peak_rss_kb: u64,
}

impl Usage {
    /// The usage between two readings, `wall` apart, with `peak_rss_kb` the
    /// largest resident set seen.
    pub fn between(pid: u32, start: Sample, end: Sample, peak_rss_kb: u64, wall: Duration) -> Self {
        let ticks = |a: u64, b: u64| b.saturating_sub(a) as f64 / CLOCK_TICKS_PER_SEC as f64;
        let user = ticks(start.cpu.user, end.cpu.user);
        let system = ticks(start.cpu.system, end.cpu.system);
        let cpu = user + system;
        let wall = wall.as_secs_f64();
        Usage {
            pid,
            cpu_seconds: cpu,
            cpu_user_seconds: user,
            cpu_system_seconds: system,
            cpu_percent_of_one_core: if wall > 0.0 { cpu / wall * 100.0 } else { 0.0 },
            rss_kb: end.memory.rss_kb,
            peak_rss_kb: peak_rss_kb.max(end.memory.peak_rss_kb),
        }
    }
}

/// Samples one process in the background while a load runs.
pub struct Monitor {
    pid: u32,
    start: Sample,
    started: std::time::Instant,
    task: JoinHandle<u64>,
    stop: tokio::sync::watch::Sender<bool>,
}

impl Monitor {
    /// Take the first reading and start sampling. Fails when the process is
    /// not readable.
    pub fn start(pid: u32) -> Result<Self> {
        let start = sample(pid)?;
        let (stop, mut stopped) = tokio::sync::watch::channel(false);
        let first_peak = start.memory.peak_rss_kb;
        let task = tokio::spawn(async move {
            let mut peak = first_peak;
            let mut tick = tokio::time::interval(SAMPLE_EVERY);
            tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = tick.tick() => {
                        if let Ok(s) = sample(pid) {
                            peak = peak.max(s.memory.rss_kb).max(s.memory.peak_rss_kb);
                        }
                    }
                    _ = stopped.changed() => break,
                }
            }
            peak
        });
        Ok(Self {
            pid,
            start,
            started: std::time::Instant::now(),
            task,
            stop,
        })
    }

    /// Take the last reading and stop sampling.
    pub async fn finish(self) -> Result<Usage> {
        let wall = self.started.elapsed();
        let end = sample(self.pid)?;
        let _ = self.stop.send(true);
        let peak = self.task.await.unwrap_or(0);
        Ok(Usage::between(self.pid, self.start, end, peak, wall))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A real line: comm "(proxyx gateway)" contains a space, and the numbers
    // after it are the usual 52 fields.
    const STAT: &str = "4242 (proxyx gateway) S 1 4242 4242 0 -1 4194560 1830 0 0 0 \
        812 190 0 0 20 0 9 0 1234567 123456789 4321 18446744073709551615 1 1 0 0 0 0 0 \
        4096 0 0 0 0 17 3 0 0 0 0 0 0 0 0 0 0 0 0 0";

    const STATUS: &str = "Name:\tproxyx\nUmask:\t0022\nState:\tS (sleeping)\n\
        VmPeak:\t  900000 kB\nVmSize:\t  800000 kB\nVmHWM:\t   45678 kB\nVmRSS:\t   34567 kB\n\
        RssAnon:\t   20000 kB\nThreads:\t12\n";

    #[test]
    fn stat_gives_user_and_system_ticks() {
        let t = parse_stat(STAT).expect("parse");
        assert_eq!(
            t,
            CpuTicks {
                user: 812,
                system: 190
            }
        );
        assert_eq!(t.total(), 1002);
    }

    #[test]
    fn a_command_name_with_parentheses_and_spaces_does_not_shift_the_fields() {
        let line = STAT.replace("(proxyx gateway)", "(a) b (c d)");
        assert_eq!(parse_stat(&line).expect("parse").user, 812);
    }

    #[test]
    fn a_short_or_garbled_stat_line_is_an_error() {
        assert!(parse_stat("").is_err());
        assert!(parse_stat("1 (x) S 1 2 3").is_err());
        assert!(parse_stat("1 (x) S 1 4 4 0 -1 0 0 0 0 0 abc 5 0").is_err());
    }

    #[test]
    fn status_gives_rss_and_peak() {
        let m = parse_status(STATUS).expect("parse");
        assert_eq!(
            m,
            Memory {
                rss_kb: 34567,
                peak_rss_kb: 45678
            }
        );
    }

    #[test]
    fn status_without_a_peak_line_falls_back_to_rss() {
        let m = parse_status("VmRSS:\t 100 kB\n").expect("parse");
        assert_eq!(
            m,
            Memory {
                rss_kb: 100,
                peak_rss_kb: 100
            }
        );
    }

    #[test]
    fn status_without_rss_is_an_error() {
        assert!(parse_status("Name:\tx\nVmHWM:\t 5 kB\n").is_err());
        assert!(parse_status("VmRSS:\t 5 MB\n").is_err());
    }

    #[test]
    fn usage_is_the_difference_of_two_samples() {
        let at = |user, system, rss, hwm| Sample {
            cpu: CpuTicks { user, system },
            memory: Memory {
                rss_kb: rss,
                peak_rss_kb: hwm,
            },
        };
        let u = Usage::between(
            7,
            at(100, 50, 1000, 1200),
            at(300, 150, 2000, 2500),
            2400,
            Duration::from_secs(4),
        );
        assert_eq!(u.pid, 7);
        assert!((u.cpu_user_seconds - 2.0).abs() < 1e-9);
        assert!((u.cpu_system_seconds - 1.0).abs() < 1e-9);
        assert!((u.cpu_seconds - 3.0).abs() < 1e-9);
        assert!((u.cpu_percent_of_one_core - 75.0).abs() < 1e-9);
        assert_eq!(u.rss_kb, 2000);
        assert_eq!(u.peak_rss_kb, 2500);
    }

    #[test]
    fn the_running_process_can_be_sampled() {
        let s = sample(std::process::id()).expect("sample self");
        assert!(s.memory.rss_kb > 0);
        assert!(s.memory.peak_rss_kb >= s.memory.rss_kb);
    }

    #[tokio::test]
    async fn the_monitor_reports_cpu_burned_inside_its_window() {
        let monitor = Monitor::start(std::process::id()).expect("start");
        let end = std::time::Instant::now() + Duration::from_millis(300);
        let burn = tokio::task::spawn_blocking(move || {
            let mut x = 1u64;
            while std::time::Instant::now() < end {
                x = std::hint::black_box(x.wrapping_mul(6364136223846793005).wrapping_add(1));
            }
            x
        });
        burn.await.expect("burn");
        let usage = monitor.finish().await.expect("finish");
        assert!(usage.cpu_seconds > 0.0, "cpu {}", usage.cpu_seconds);
        assert!(usage.peak_rss_kb >= usage.rss_kb);
    }
}
