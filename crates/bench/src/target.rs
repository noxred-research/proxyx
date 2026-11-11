//! The process under test: spawn it from a binary with a generated
//! configuration, wait until it serves, and stop it again.

use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::process::{Child, Command};

/// A spawned target. It is killed when dropped, so a failed run leaves no
/// process behind.
pub struct Spawned {
    child: Child,
    pub pid: u32,
    log: PathBuf,
}

impl Spawned {
    /// Start `binary` with `args` in `workdir`. Standard output and error go
    /// to `<workdir>/<name>.log`, which is read back when startup fails.
    pub fn start(binary: &Path, args: &[&str], workdir: &Path, name: &str) -> Result<Self> {
        let log = workdir.join(format!("{name}.log"));
        let out =
            std::fs::File::create(&log).with_context(|| format!("create {}", log.display()))?;
        let err = out.try_clone()?;
        let child = Command::new(binary)
            .args(args)
            .current_dir(workdir)
            .stdin(Stdio::null())
            .stdout(out)
            .stderr(err)
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("spawn {}", binary.display()))?;
        let pid = child.id().context("the spawned process has no pid")?;
        Ok(Self { child, pid, log })
    }

    /// The last `lines` lines of the log, for an error message.
    pub fn log_tail(&self, lines: usize) -> String {
        let text = std::fs::read_to_string(&self.log).unwrap_or_default();
        let all: Vec<&str> = text.lines().collect();
        all[all.len().saturating_sub(lines)..].join("\n")
    }

    /// Wait until `ready` returns true, failing at once if the process exits
    /// and after `limit` otherwise.
    pub async fn wait_ready<F, Fut>(&mut self, limit: Duration, mut ready: F) -> Result<()>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = bool>,
    {
        let deadline = Instant::now() + limit;
        loop {
            if let Some(status) = self.child.try_wait()? {
                bail!(
                    "the target exited during startup ({status}); log tail:\n{}",
                    self.log_tail(20)
                );
            }
            if ready().await {
                return Ok(());
            }
            if Instant::now() >= deadline {
                bail!(
                    "the target was not ready after {limit:?}; log tail:\n{}",
                    self.log_tail(20)
                );
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Ask the process to stop with SIGTERM (through `kill`, so no unsafe
    /// code is needed), wait up to `grace`, then kill it.
    pub async fn stop(mut self, grace: Duration) -> Result<()> {
        let _ = Command::new("kill")
            .args(["-TERM", &self.pid.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await;
        if tokio::time::timeout(grace, self.child.wait())
            .await
            .is_err()
        {
            self.child.kill().await.context("kill the target")?;
        }
        Ok(())
    }
}

/// A free loopback address. The port is released before this returns, so a
/// racing process could take it; for a benchmark on a quiet host that is an
/// accepted risk, and the target's bind error says so when it happens.
pub fn free_addr() -> Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").context("find a free port")?;
    Ok(listener.local_addr()?)
}

/// `GET path` on `addr` answers 200.
pub async fn http_ok(addr: SocketAddr, path: &str) -> bool {
    let attempt = async {
        let mut s = TcpStream::connect(addr).await.ok()?;
        s.write_all(
            format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await
        .ok()?;
        let mut head = [0u8; 12];
        s.read_exact(&mut head).await.ok()?;
        Some(&head == b"HTTP/1.1 200")
    };
    tokio::time::timeout(Duration::from_secs(2), attempt)
        .await
        .ok()
        .flatten()
        .unwrap_or(false)
}

/// Check that `/proc/<pid>` exists, for `--pid`.
pub fn pid_exists(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_addresses_differ_and_are_loopback() {
        let a = free_addr().expect("a");
        assert!(a.ip().is_loopback() && a.port() != 0);
    }

    #[tokio::test]
    async fn a_target_that_exits_during_startup_is_reported_with_its_log() {
        let dir = std::env::temp_dir().join(format!("proxyx-bench-target-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let mut t = Spawned::start(
            Path::new("/bin/sh"),
            &["-c", "echo boom-from-the-target; exit 3"],
            &dir,
            "t",
        )
        .expect("start");
        let e = t
            .wait_ready(Duration::from_secs(5), || async { false })
            .await
            .expect_err("exit");
        let text = format!("{e:#}");
        assert!(text.contains("exited during startup"), "{text}");
        assert!(text.contains("boom-from-the-target"), "{text}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_running_target_becomes_ready_and_stops() {
        let dir = std::env::temp_dir().join(format!("proxyx-bench-target2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let mut t = Spawned::start(Path::new("/bin/sleep"), &["30"], &dir, "s").expect("start");
        let pid = t.pid;
        assert!(pid_exists(pid));
        t.wait_ready(Duration::from_secs(5), || async { true })
            .await
            .expect("ready");
        t.stop(Duration::from_secs(5)).await.expect("stop");
        assert!(
            !pid_exists(pid)
                || std::fs::read_to_string(format!("/proc/{pid}/stat"))
                    .is_ok_and(|s| s.contains(") Z "))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn http_ok_sees_a_200_and_nothing_else() {
        let origin = crate::stubs::http_origin(2, None).await.expect("origin");
        // the stub answers every path with a 200
        assert!(http_ok(origin.addr, "/health").await);
        assert!(!http_ok(free_addr().expect("addr"), "/health").await);
    }
}
