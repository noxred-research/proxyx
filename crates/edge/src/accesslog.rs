//! Access log: line formatting and a non-blocking writer.
//!
//! [`format_line`] renders one [`AccessRecord`] as a squid native, Apache combined or JSON
//! line. Client-controlled fields are neutralised so a request can never forge or split a log
//! line. [`AccessLog`] owns one dedicated writer thread fed through a bounded channel:
//! [`AccessLog::log`] never blocks the request path and counts what it had to drop.

use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Capacity of the channel between request tasks and the writer thread.
const CHANNEL_CAPACITY: usize = 8192;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    /// Squid native `access.log`.
    #[default]
    Squid,
    /// Apache combined.
    Combined,
    /// One JSON object per line.
    Json,
}

#[derive(Debug, Clone)]
pub struct AccessRecord {
    /// Request start.
    pub time: SystemTime,
    pub elapsed: Duration,
    /// Effective client address (after PROXY protocol).
    pub client: SocketAddr,
    pub listener: String,
    /// `http`, `connect`, `socks4`, `socks5` or `udp`.
    pub protocol: &'static str,
    pub user: Option<String>,
    /// `GET`, `CONNECT`, ...; `UDP` for a SOCKS5 UDP associate.
    pub method: String,
    /// Absolute URL for http, `host:port` for tunnels.
    pub url: String,
    pub host: String,
    pub port: u16,
    /// HTTP status sent or received; SOCKS replies are mapped by the caller.
    pub status: u16,
    /// Client to target payload bytes.
    pub bytes_up: u64,
    /// Target to client payload bytes.
    pub bytes_down: u64,
    /// Local source address used.
    pub egress: Option<IpAddr>,
    pub pool: Option<String>,
    /// Address connected to (the parent's, when via a parent).
    pub target_ip: Option<IpAddr>,
    pub parent: Option<String>,
    /// Closed label: ok, auth_required, denied, bad_request, dns_error, connect_error,
    /// parent_error, timeout, limited, internal.
    pub result: &'static str,
    /// Name of the matched ACL rule.
    pub rule: Option<String>,
    pub referer: Option<String>,
    pub user_agent: Option<String>,
    pub mime: Option<String>,
    pub session: Option<String>,
}

// --- formatting ------------------------------------------------------------------------

/// Format one record as a single line, without a trailing newline.
pub fn format_line(f: Format, r: &AccessRecord) -> String {
    match f {
        Format::Squid => squid_line(r),
        Format::Combined => combined_line(r),
        Format::Json => json_line(r),
    }
}

/// Seconds since the epoch and the millisecond part; times before the epoch clamp to zero.
fn epoch_parts(t: SystemTime) -> (u64, u32) {
    t.duration_since(UNIX_EPOCH)
        .map_or((0, 0), |d| (d.as_secs(), d.subsec_millis()))
}

struct Civil {
    year: i64,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
}

/// UTC calendar fields for `secs` since the epoch (civil-from-days).
fn civil(secs: u64) -> Civil {
    let days = i64::try_from(secs / 86_400).unwrap_or(i64::MAX / 2);
    let rem = (secs % 86_400) as u32;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    Civil {
        year,
        month,
        day,
        hour: rem / 3_600,
        minute: rem % 3_600 / 60,
        second: rem % 60,
    }
}

/// Append `s` with control characters, quotes and backslashes percent-encoded (spaces too when
/// `encode_space`). Already percent-encoded input is left alone, so a URL stays a URL.
fn push_clean(out: &mut String, s: &str, encode_space: bool) {
    for c in s.chars() {
        let encode = c.is_control()
            || matches!(c, '"' | '\\' | '\u{2028}' | '\u{2029}')
            || (encode_space && c == ' ');
        if encode {
            let mut utf8 = [0u8; 4];
            for byte in c.encode_utf8(&mut utf8).bytes() {
                let _ = write!(out, "%{byte:02X}");
            }
        } else {
            out.push(c);
        }
    }
}

/// Append a cleaned optional field, `-` when absent or empty.
fn push_field(out: &mut String, s: Option<&str>, encode_space: bool) {
    match s {
        Some(s) if !s.is_empty() => push_clean(out, s, encode_space),
        _ => out.push('-'),
    }
}

fn is_denial(result: &str) -> bool {
    matches!(result, "denied" | "auth_required" | "limited")
}

fn squid_result_code(r: &AccessRecord) -> &'static str {
    let tunnel = matches!(r.protocol, "connect" | "socks4" | "socks5" | "udp");
    if tunnel && (200..300).contains(&r.status) {
        "TCP_TUNNEL"
    } else if is_denial(r.result) {
        "TCP_DENIED"
    } else {
        "TCP_MISS"
    }
}

fn squid_line(r: &AccessRecord) -> String {
    let (secs, millis) = epoch_parts(r.time);
    let mut out = String::with_capacity(160 + r.url.len());
    let _ = write!(
        out,
        "{secs}.{millis:03} {:>6} {} {}/{:03} {} ",
        r.elapsed.as_millis(),
        r.client.ip(),
        squid_result_code(r),
        r.status,
        r.bytes_down,
    );
    push_field(&mut out, Some(&r.method), true);
    out.push(' ');
    push_field(&mut out, Some(&r.url), true);
    out.push(' ');
    push_field(&mut out, r.user.as_deref(), true);
    out.push(' ');
    let hierarchy = if r.parent.is_some() {
        "FIRSTUP_PARENT"
    } else if r.target_ip.is_some() {
        "HIER_DIRECT"
    } else {
        "HIER_NONE"
    };
    out.push_str(hierarchy);
    out.push('/');
    match r.target_ip {
        Some(ip) => {
            let _ = write!(out, "{ip}");
        }
        None => out.push('-'),
    }
    out.push(' ');
    push_field(&mut out, r.mime.as_deref(), true);
    out
}

fn combined_line(r: &AccessRecord) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let (secs, _) = epoch_parts(r.time);
    let c = civil(secs);
    let mut out = String::with_capacity(200 + r.url.len());
    let _ = write!(out, "{} - ", r.client.ip());
    push_field(&mut out, r.user.as_deref(), true);
    let _ = write!(
        out,
        " [{:02}/{}/{:04}:{:02}:{:02}:{:02} +0000] \"",
        c.day,
        MONTHS[(c.month - 1) as usize],
        c.year,
        c.hour,
        c.minute,
        c.second,
    );
    push_clean(&mut out, &r.method, true);
    out.push(' ');
    push_clean(&mut out, &r.url, true);
    let _ = write!(out, " HTTP/1.1\" {} {} \"", r.status, r.bytes_down);
    push_field(&mut out, r.referer.as_deref(), true);
    out.push_str("\" \"");
    push_field(&mut out, r.user_agent.as_deref(), false);
    out.push('"');
    out
}

fn json_line(r: &AccessRecord) -> String {
    let (secs, millis) = epoch_parts(r.time);
    let c = civil(secs);
    let ts = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        c.year, c.month, c.day, c.hour, c.minute, c.second,
    );
    let duration_ms = u64::try_from(r.elapsed.as_millis()).unwrap_or(u64::MAX);
    let value = serde_json::json!({
        "ts": ts,
        "duration_ms": duration_ms,
        "client": r.client.ip().to_string(),
        "client_port": r.client.port(),
        "listener": r.listener,
        "protocol": r.protocol,
        "user": r.user,
        "method": r.method,
        "url": r.url,
        "host": r.host,
        "port": r.port,
        "status": r.status,
        "bytes_up": r.bytes_up,
        "bytes_down": r.bytes_down,
        "egress_ip": r.egress.map(|ip| ip.to_string()),
        "pool": r.pool,
        "target_ip": r.target_ip.map(|ip| ip.to_string()),
        "parent": r.parent,
        "result": r.result,
        "rule": r.rule,
        "session": r.session,
        "referer": r.referer,
        "user_agent": r.user_agent,
        "mime": r.mime,
    });
    // serde_json escapes C0 controls but leaves DEL, the C1 range and the Unicode line
    // separators raw. Line splitters in other tools break on some of them, so escape them
    // too; they can only occur inside string literals.
    let compact = value.to_string();
    let mut out = String::with_capacity(compact.len());
    for ch in compact.chars() {
        if matches!(ch, '\u{7f}'..='\u{9f}' | '\u{2028}' | '\u{2029}') {
            let _ = write!(out, "\\u{:04x}", u32::from(ch));
        } else {
            out.push(ch);
        }
    }
    out
}

// --- writer ----------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessLogConfig {
    /// `off`, `stdout`, `stderr` or a file path.
    #[serde(default = "default_output")]
    pub output: String,
    #[serde(default)]
    pub format: Format,
}

fn default_output() -> String {
    "off".to_owned()
}

impl Default for AccessLogConfig {
    fn default() -> Self {
        AccessLogConfig {
            output: default_output(),
            format: Format::Squid,
        }
    }
}

/// Records dominate by far; the rare reopen request is not worth boxing every record.
#[allow(clippy::large_enum_variant)]
enum Msg {
    Record(AccessRecord),
    /// Close and reopen the log file, then report the outcome.
    Reopen(mpsc::Sender<io::Result<()>>),
}

/// What the writer thread owns: the buffered sink and, for files, how to reopen it.
struct Sink {
    writer: BufWriter<Box<dyn Write + Send>>,
    path: Option<PathBuf>,
}

impl Sink {
    fn reopen(&mut self) -> io::Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        self.writer.flush()?;
        let file = open_file(path)?;
        self.writer = BufWriter::new(Box::new(file));
        Ok(())
    }
}

fn open_file(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o640)
        .open(path)
}

/// Non-blocking access log. Cheap to share behind an `Arc`.
pub struct AccessLog {
    format: Format,
    /// `None` when the log is off.
    tx: Option<SyncSender<Msg>>,
    worker: Option<JoinHandle<()>>,
    dropped: Arc<AtomicU64>,
    reopenable: bool,
}

impl AccessLog {
    /// Open the configured sink and start the writer thread. `off` starts nothing.
    pub fn open(cfg: &AccessLogConfig) -> io::Result<AccessLog> {
        let (writer, path): (Box<dyn Write + Send>, Option<PathBuf>) = match cfg.output.as_str() {
            "off" => {
                return Ok(AccessLog {
                    format: cfg.format,
                    tx: None,
                    worker: None,
                    dropped: Arc::new(AtomicU64::new(0)),
                    reopenable: false,
                });
            }
            "" => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "access log output is empty",
                ));
            }
            "stdout" => (Box::new(io::stdout()), None),
            "stderr" => (Box::new(io::stderr()), None),
            file => {
                let path = PathBuf::from(file);
                (Box::new(open_file(&path)?), Some(path))
            }
        };
        Self::start(writer, path, cfg.format, CHANNEL_CAPACITY)
    }

    fn start(
        writer: Box<dyn Write + Send>,
        path: Option<PathBuf>,
        format: Format,
        capacity: usize,
    ) -> io::Result<AccessLog> {
        let (tx, rx) = mpsc::sync_channel(capacity);
        let dropped = Arc::new(AtomicU64::new(0));
        let reopenable = path.is_some();
        let sink = Sink {
            writer: BufWriter::new(writer),
            path,
        };
        let worker = {
            let dropped = Arc::clone(&dropped);
            std::thread::Builder::new()
                .name("edge-accesslog".to_owned())
                .spawn(move || run_writer(&rx, sink, format, &dropped))?
        };
        Ok(AccessLog {
            format,
            tx: Some(tx),
            worker: Some(worker),
            dropped,
            reopenable,
        })
    }

    /// Queue a record. Never blocks: when the channel is full the record is dropped and
    /// counted.
    pub fn log(&self, r: AccessRecord) {
        let Some(tx) = &self.tx else {
            return;
        };
        match tx.try_send(Msg::Record(r)) {
            Ok(()) => {}
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Records not written: the channel was full, or the sink failed.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Close and reopen the log file (logrotate support). Returns once the writer thread has
    /// done so; lines queued before the call land in the old file. No-op for stdout, stderr
    /// and `off`.
    pub fn reopen(&self) -> io::Result<()> {
        let Some(tx) = &self.tx else {
            return Ok(());
        };
        if !self.reopenable {
            return Ok(());
        }
        let (ack_tx, ack_rx) = mpsc::channel();
        let gone = || io::Error::new(io::ErrorKind::BrokenPipe, "access log writer has stopped");
        tx.send(Msg::Reopen(ack_tx)).map_err(|_| gone())?;
        ack_rx.recv().map_err(|_| gone())?
    }

    pub fn format(&self) -> Format {
        self.format
    }
}

impl Drop for AccessLog {
    /// Close the channel and wait for the writer to drain and flush what is queued.
    fn drop(&mut self) {
        self.tx.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

impl std::fmt::Debug for AccessLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessLog")
            .field("format", &self.format)
            .field("enabled", &self.tx.is_some())
            .field("dropped", &self.dropped())
            .finish()
    }
}

/// Writer thread body: flush every record so sink failures count against that record,
/// and exit after draining once every sender is gone.
fn run_writer(rx: &Receiver<Msg>, mut sink: Sink, format: Format, dropped: &AtomicU64) {
    let mut failing = false;
    let mut note = |result: io::Result<()>, lost: u64| match result {
        Ok(()) => failing = false,
        Err(e) => {
            dropped.fetch_add(lost, Ordering::Relaxed);
            if !failing {
                failing = true;
                tracing::warn!(error = %e, "access log write failed");
            }
        }
    };
    while let Ok(msg) = rx.recv() {
        match msg {
            Msg::Record(record) => {
                let mut line = format_line(format, &record);
                line.push('\n');
                // Surface buffered sink failures while this record can still be counted.
                note(
                    sink.writer
                        .write_all(line.as_bytes())
                        .and_then(|()| sink.writer.flush()),
                    1,
                );
            }
            Msg::Reopen(ack) => {
                let result = sink.reopen();
                let _ = ack.send(result);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::AtomicUsize;
    use std::sync::{Condvar, Mutex};

    fn ts() -> SystemTime {
        UNIX_EPOCH + Duration::new(1_700_000_000, 123_000_000)
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("test ip")
    }

    fn http_record() -> AccessRecord {
        AccessRecord {
            time: ts(),
            elapsed: Duration::from_millis(245),
            client: "192.0.2.10:51234".parse().expect("addr"),
            listener: "main".to_owned(),
            protocol: "http",
            user: Some("alice".to_owned()),
            method: "GET".to_owned(),
            url: "http://example.com/a?b=1".to_owned(),
            host: "example.com".to_owned(),
            port: 80,
            status: 200,
            bytes_up: 120,
            bytes_down: 5120,
            egress: Some(ip("203.0.113.5")),
            pool: Some("residential".to_owned()),
            target_ip: Some(ip("93.184.216.34")),
            parent: None,
            result: "ok",
            rule: Some("allow-all".to_owned()),
            referer: None,
            user_agent: Some("curl/8.0".to_owned()),
            mime: Some("text/html".to_owned()),
            session: None,
        }
    }

    fn connect_record() -> AccessRecord {
        AccessRecord {
            protocol: "connect",
            user: None,
            method: "CONNECT".to_owned(),
            url: "example.com:443".to_owned(),
            host: "example.com".to_owned(),
            port: 443,
            bytes_down: 9000,
            target_ip: Some(ip("198.51.100.7")),
            parent: Some("up1".to_owned()),
            user_agent: None,
            mime: None,
            ..http_record()
        }
    }

    fn denied_record() -> AccessRecord {
        AccessRecord {
            user: None,
            url: "http://blocked.test/".to_owned(),
            host: "blocked.test".to_owned(),
            status: 403,
            bytes_up: 0,
            bytes_down: 0,
            egress: None,
            pool: None,
            target_ip: None,
            result: "denied",
            rule: Some("block-list".to_owned()),
            user_agent: None,
            mime: None,
            ..http_record()
        }
    }

    #[test]
    fn squid_formats() {
        assert_eq!(
            format_line(Format::Squid, &http_record()),
            "1700000000.123    245 192.0.2.10 TCP_MISS/200 5120 GET http://example.com/a?b=1 alice HIER_DIRECT/93.184.216.34 text/html"
        );
        assert_eq!(
            format_line(Format::Squid, &connect_record()),
            "1700000000.123    245 192.0.2.10 TCP_TUNNEL/200 9000 CONNECT example.com:443 - FIRSTUP_PARENT/198.51.100.7 -"
        );
        assert_eq!(
            format_line(Format::Squid, &denied_record()),
            "1700000000.123    245 192.0.2.10 TCP_DENIED/403 0 GET http://blocked.test/ - HIER_NONE/- -"
        );
    }

    #[test]
    fn squid_result_and_hierarchy_codes() {
        let code = |r: &AccessRecord| {
            let line = format_line(Format::Squid, r);
            let mut it = line.split(' ').filter(|s| !s.is_empty());
            let result = it.nth(3).expect("result").to_owned();
            let hier = it.nth(4).expect("hier").to_owned();
            (result, hier)
        };
        let mut r = connect_record();
        r.status = 403;
        r.result = "denied";
        r.parent = None;
        r.target_ip = None;
        assert_eq!(code(&r), ("TCP_DENIED/403".into(), "HIER_NONE/-".into()));
        r.status = 502;
        r.result = "connect_error";
        assert_eq!(code(&r).0, "TCP_MISS/502");
        r.status = 407;
        r.result = "auth_required";
        assert_eq!(code(&r).0, "TCP_DENIED/407");
        r.status = 429;
        r.result = "limited";
        assert_eq!(code(&r).0, "TCP_DENIED/429");
        r.protocol = "socks5";
        r.status = 200;
        r.result = "ok";
        r.target_ip = Some(ip("2001:db8::1"));
        assert_eq!(
            code(&r),
            ("TCP_TUNNEL/200".into(), "HIER_DIRECT/2001:db8::1".into())
        );
        r.protocol = "udp";
        assert_eq!(code(&r).0, "TCP_TUNNEL/200");
        // HTTP requests are never tunnels, even with a 2xx status.
        let mut h = http_record();
        h.status = 204;
        assert_eq!(code(&h).0, "TCP_MISS/204");
        h.status = 7;
        assert_eq!(code(&h).0, "TCP_MISS/007");
    }

    #[test]
    fn combined_formats() {
        assert_eq!(
            format_line(Format::Combined, &http_record()),
            "192.0.2.10 - alice [14/Nov/2023:22:13:20 +0000] \"GET http://example.com/a?b=1 HTTP/1.1\" 200 5120 \"-\" \"curl/8.0\""
        );
        let mut r = connect_record();
        r.referer = Some("https://ref.example/".to_owned());
        r.user_agent = Some("Mozilla/5.0 (X11; Linux x86_64)".to_owned());
        assert_eq!(
            format_line(Format::Combined, &r),
            "192.0.2.10 - - [14/Nov/2023:22:13:20 +0000] \"CONNECT example.com:443 HTTP/1.1\" 200 9000 \"https://ref.example/\" \"Mozilla/5.0 (X11; Linux x86_64)\""
        );
        assert_eq!(
            format_line(Format::Combined, &denied_record()),
            "192.0.2.10 - - [14/Nov/2023:22:13:20 +0000] \"GET http://blocked.test/ HTTP/1.1\" 403 0 \"-\" \"-\""
        );
    }

    #[test]
    fn json_formats() {
        let line = format_line(Format::Json, &http_record());
        assert!(!line.contains('\n'));
        let v: serde_json::Value = serde_json::from_str(&line).expect("json");
        assert_eq!(
            v,
            json!({
                "ts": "2023-11-14T22:13:20.123Z",
                "duration_ms": 245,
                "client": "192.0.2.10",
                "client_port": 51234,
                "listener": "main",
                "protocol": "http",
                "user": "alice",
                "method": "GET",
                "url": "http://example.com/a?b=1",
                "host": "example.com",
                "port": 80,
                "status": 200,
                "bytes_up": 120,
                "bytes_down": 5120,
                "egress_ip": "203.0.113.5",
                "pool": "residential",
                "target_ip": "93.184.216.34",
                "parent": null,
                "result": "ok",
                "rule": "allow-all",
                "session": null,
                "referer": null,
                "user_agent": "curl/8.0",
                "mime": "text/html",
            })
        );

        let v: serde_json::Value =
            serde_json::from_str(&format_line(Format::Json, &denied_record())).expect("json");
        assert_eq!(v["user"], serde_json::Value::Null);
        assert_eq!(v["egress_ip"], serde_json::Value::Null);
        assert_eq!(v["target_ip"], serde_json::Value::Null);
        assert_eq!(v["result"], "denied");
        assert_eq!(v["rule"], "block-list");
        assert_eq!(v["status"], 403);

        let mut v6 = connect_record();
        v6.client = "[2001:db8::9]:4000".parse().expect("addr");
        let v: serde_json::Value =
            serde_json::from_str(&format_line(Format::Json, &v6)).expect("json");
        assert_eq!(v["client"], "2001:db8::9");
        assert_eq!(v["client_port"], 4000);
        assert_eq!(v["parent"], "up1");
    }

    #[test]
    fn civil_dates() {
        let fmt = |secs| {
            let c = civil(secs);
            format!(
                "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
                c.year, c.month, c.day, c.hour, c.minute, c.second
            )
        };
        assert_eq!(fmt(0), "1970-01-01T00:00:00");
        assert_eq!(fmt(86_399), "1970-01-01T23:59:59");
        assert_eq!(fmt(951_782_400), "2000-02-29T00:00:00"); // leap day, divisible by 400
        assert_eq!(fmt(951_868_800), "2000-03-01T00:00:00");
        assert_eq!(fmt(1_709_164_799), "2024-02-28T23:59:59");
        assert_eq!(fmt(1_709_164_800), "2024-02-29T00:00:00");
        assert_eq!(fmt(1_709_251_200), "2024-03-01T00:00:00");
        assert_eq!(fmt(4_102_444_799), "2099-12-31T23:59:59");
        assert_eq!(fmt(4_107_542_400), "2100-03-01T00:00:00"); // 2100 is not a leap year
        assert_eq!(fmt(1_700_000_000), "2023-11-14T22:13:20");

        let mut r = http_record();
        r.time = UNIX_EPOCH;
        assert!(format_line(Format::Combined, &r).contains("[01/Jan/1970:00:00:00 +0000]"));
        r.time = UNIX_EPOCH - Duration::from_secs(5); // before the epoch clamps
        assert!(format_line(Format::Squid, &r).starts_with("0.000 "));
    }

    #[test]
    fn long_elapsed_widens_the_column() {
        let mut r = http_record();
        r.elapsed = Duration::from_millis(1_234_567_890);
        assert!(format_line(Format::Squid, &r).starts_with("1700000000.123 1234567890 192"));
    }

    fn hostile_record() -> AccessRecord {
        AccessRecord {
            user: Some("bob smith\r\nINJECTED".to_owned()),
            method: "GE T\n".to_owned(),
            url: "http://x.test/a b\r\n1.1.1.1 - - [forged] \"GET /\" 200 1 \"-\" \"-\"\u{0}\u{7f}\u{85}\u{2028}c\\\"q\"".to_owned(),
            referer: Some("http://r/ \"x\"\nbad".to_owned()),
            user_agent: Some("Mozilla/5.0 \"evil\"\r\nX-Forged: 1 \\ ünï🙂".to_owned()),
            mime: Some("text/html\r\nx".to_owned()),
            session: Some("s\nid".to_owned()),
            rule: Some("r\nule".to_owned()),
            ..http_record()
        }
    }

    #[test]
    fn injection_is_neutralised_in_every_format() {
        let r = hostile_record();
        for format in [Format::Squid, Format::Combined, Format::Json] {
            let line = format_line(format, &r);
            assert!(
                !line
                    .chars()
                    .any(|c| c.is_control() || c == '\u{2028}' || c == '\u{2029}'),
                "{format:?}: {line:?}"
            );
        }
    }

    #[test]
    fn squid_fields_stay_single_tokens() {
        let line = format_line(Format::Squid, &hostile_record());
        let tokens: Vec<&str> = line.split(' ').collect();
        // ts, elapsed (padded to 6 => "   245" splits into 3 empties + value), client,
        // code, bytes, method, url, user, hierarchy, mime.
        let fields: Vec<&str> = tokens.iter().copied().filter(|t| !t.is_empty()).collect();
        assert_eq!(fields.len(), 10, "{line}");
        assert_eq!(fields[5], "GE%20T%0A");
        assert_eq!(fields[7], "bob%20smith%0D%0AINJECTED");
        assert!(
            fields[6]
                .starts_with("http://x.test/a%20b%0D%0A1.1.1.1%20-%20-%20[forged]%20%22GET%20/%22")
        );
        assert!(fields[6].ends_with("%00%7F%C2%85%E2%80%A8c%5C%22q%22"));
        assert_eq!(fields[9], "text/html%0D%0Ax");
    }

    #[test]
    fn combined_quotes_cannot_be_broken_out_of() {
        let line = format_line(Format::Combined, &hostile_record());
        // Exactly the 6 framing quotes plus the quotes around request, referer and agent:
        // request (2) + referer (2) + agent (2).
        assert_eq!(line.matches('"').count(), 6, "{line}");
        assert!(line.contains("\"Mozilla/5.0 %22evil%22%0D%0AX-Forged: 1 %5C ünï🙂\""));
        assert!(line.contains("\"http://r/%20%22x%22%0Abad\""));
        assert!(line.starts_with("192.0.2.10 - bob%20smith%0D%0AINJECTED [14/Nov/2023"));
    }

    #[test]
    fn json_stays_one_line_and_round_trips() {
        let r = hostile_record();
        let line = format_line(Format::Json, &r);
        assert!(!line.contains('\n') && !line.contains('\r'));
        assert!(!line.contains('\u{7f}') && !line.contains('\u{85}') && !line.contains('\u{2028}'));
        let v: serde_json::Value = serde_json::from_str(&line).expect("json");
        assert_eq!(v["url"], r.url.as_str());
        assert_eq!(v["user_agent"], r.user_agent.as_deref().expect("ua"));
        assert_eq!(v["user"], r.user.as_deref().expect("user"));
    }

    #[test]
    fn empty_optionals_render_as_dash() {
        let mut r = http_record();
        r.user = Some(String::new());
        r.mime = Some(String::new());
        r.user_agent = Some(String::new());
        let squid = format_line(Format::Squid, &r);
        assert!(squid.ends_with(" - HIER_DIRECT/93.184.216.34 -"), "{squid}");
        assert!(format_line(Format::Combined, &r).ends_with("\"-\" \"-\""));
    }

    #[test]
    fn config_deserialises() {
        let cfg: AccessLogConfig = serde_json::from_str("{}").expect("empty");
        assert_eq!(cfg.output, "off");
        assert_eq!(cfg.format, Format::Squid);
        let cfg = AccessLogConfig::default();
        assert_eq!((cfg.output.as_str(), cfg.format), ("off", Format::Squid));
        let cfg: AccessLogConfig =
            serde_json::from_str(r#"{"output":"/var/log/x.log","format":"json"}"#).expect("cfg");
        assert_eq!(cfg.output, "/var/log/x.log");
        assert_eq!(cfg.format, Format::Json);
        let cfg: AccessLogConfig = serde_json::from_str(r#"{"format":"combined"}"#).expect("cfg");
        assert_eq!(cfg.format, Format::Combined);
        assert!(serde_json::from_str::<AccessLogConfig>(r#"{"format":"clf"}"#).is_err());
        assert!(serde_json::from_str::<AccessLogConfig>(r#"{"path":"x"}"#).is_err());
    }

    // --- writer tests ---

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> TempDir {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let dir = std::env::temp_dir().join(format!(
                "edge-accesslog-{name}-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&dir).expect("create temp dir");
            TempDir(dir)
        }

        fn file(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn file_cfg(path: &Path, format: Format) -> AccessLogConfig {
        AccessLogConfig {
            output: path.to_str().expect("utf-8 path").to_owned(),
            format,
        }
    }

    fn read(path: &Path) -> String {
        std::fs::read_to_string(path).expect("read log")
    }

    #[test]
    fn off_is_a_noop() {
        let log = AccessLog::open(&AccessLogConfig::default()).expect("open");
        assert!(log.worker.is_none() && log.tx.is_none());
        log.log(http_record());
        assert_eq!(log.dropped(), 0);
        log.reopen().expect("reopen");
        assert_eq!(log.format(), Format::Squid);
        assert!(
            AccessLog::open(&AccessLogConfig {
                output: String::new(),
                format: Format::Json
            })
            .is_err()
        );
    }

    #[test]
    fn writes_lines_and_drains_on_drop() {
        let dir = TempDir::new("drain");
        let path = dir.file("access.log");
        let log = AccessLog::open(&file_cfg(&path, Format::Combined)).expect("open");
        assert_eq!(log.format(), Format::Combined);
        for _ in 0..3 {
            log.log(http_record());
        }
        drop(log);
        let want = format_line(Format::Combined, &http_record());
        assert_eq!(read(&path), format!("{want}\n{want}\n{want}\n"));
    }

    #[test]
    fn flushes_without_drop_so_tail_works() {
        let dir = TempDir::new("flush");
        let path = dir.file("access.log");
        let log = AccessLog::open(&file_cfg(&path, Format::Json)).expect("open");
        log.log(connect_record());
        let want = format!("{}\n", format_line(Format::Json, &connect_record()));
        let started = std::time::Instant::now();
        while read(&path) != want {
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "line never flushed"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(log.dropped(), 0);
    }

    #[test]
    fn appends_to_an_existing_file_and_sets_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new("append");
        let path = dir.file("access.log");
        std::fs::write(&path, "old line\n").expect("seed");
        let log = AccessLog::open(&file_cfg(&path, Format::Squid)).expect("open");
        log.log(denied_record());
        drop(log);
        let text = read(&path);
        assert!(text.starts_with("old line\n1700000000.123"), "{text}");
        assert_eq!(text.lines().count(), 2);

        let fresh = dir.file("fresh.log");
        drop(AccessLog::open(&file_cfg(&fresh, Format::Squid)).expect("open"));
        let mode = std::fs::metadata(&fresh)
            .expect("meta")
            .permissions()
            .mode();
        assert_eq!(mode & !0o640 & 0o777, 0, "mode {mode:o}");
        assert_ne!(mode & 0o400, 0, "mode {mode:o}");
    }

    #[test]
    fn open_reports_bad_paths() {
        let dir = TempDir::new("badpath");
        let path = dir.file("missing-dir/access.log");
        assert!(AccessLog::open(&file_cfg(&path, Format::Squid)).is_err());
    }

    #[test]
    fn reopen_follows_a_rotation() {
        let dir = TempDir::new("rotate");
        let path = dir.file("access.log");
        let rotated = dir.file("access.log.1");
        let log = AccessLog::open(&file_cfg(&path, Format::Squid)).expect("open");

        log.log(http_record());
        // Simulated logrotate: move the file, then ask for a reopen.
        std::fs::rename(&path, &rotated).expect("rename");
        log.reopen().expect("reopen");
        assert_eq!(
            read(&rotated),
            format!("{}\n", format_line(Format::Squid, &http_record())),
            "line queued before reopen must land in the rotated file"
        );
        assert!(path.exists(), "reopen creates the new file");

        log.log(denied_record());
        drop(log);
        assert_eq!(
            read(&path),
            format!("{}\n", format_line(Format::Squid, &denied_record()))
        );
        assert_eq!(read(&rotated).lines().count(), 1);
    }

    #[test]
    fn reopen_failure_keeps_the_old_file() {
        let dir = TempDir::new("reopen-fail");
        let sub = dir.file("sub");
        std::fs::create_dir(&sub).expect("mkdir");
        let path = sub.join("access.log");
        let log = AccessLog::open(&file_cfg(&path, Format::Squid)).expect("open");
        let moved = dir.file("moved-sub");
        std::fs::rename(&sub, &moved).expect("rename dir");
        // The path no longer resolves to a directory: reopen must fail but logging go on.
        assert!(log.reopen().is_err());
        log.log(http_record());
        drop(log);
        assert_eq!(read(&moved.join("access.log")).lines().count(), 1);
    }

    #[test]
    fn reopen_is_a_noop_for_stdio() {
        let log = AccessLog::open(&AccessLogConfig {
            output: "stderr".to_owned(),
            format: Format::Squid,
        })
        .expect("open");
        log.reopen().expect("noop");
    }

    /// Writer whose `write` blocks until the gate opens.
    struct GateWriter {
        entered: mpsc::Sender<()>,
        gate: Arc<(Mutex<bool>, Condvar)>,
        out: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for GateWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let _ = self.entered.send(());
            let (lock, cv) = &*self.gate;
            let mut open = lock.lock().expect("gate lock");
            while !*open {
                open = cv.wait(open).expect("gate wait");
            }
            self.out.lock().expect("out lock").extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn full_channel_drops_and_counts_without_blocking() {
        let (entered_tx, entered_rx) = mpsc::channel();
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let out = Arc::new(Mutex::new(Vec::new()));
        let writer = GateWriter {
            entered: entered_tx,
            gate: Arc::clone(&gate),
            out: Arc::clone(&out),
        };
        let log = AccessLog::start(Box::new(writer), None, Format::Squid, 4).expect("start");

        // A record bigger than the BufWriter capacity is written straight through, so the
        // writer thread parks inside `write` on the first one.
        let big = |n: usize| AccessRecord {
            url: format!("http://big.test/{}", "a".repeat(9000 + n)),
            ..http_record()
        };
        log.log(big(0));
        entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("writer reached the sink");
        for n in 1..=10 {
            log.log(big(n));
        }
        assert_eq!(log.dropped(), 6, "4 queued, 6 dropped");

        {
            let (lock, cv) = &*gate;
            *lock.lock().expect("gate lock") = true;
            cv.notify_all();
        }
        drop(log);
        let written = out.lock().expect("out lock").clone();
        let text = String::from_utf8(written).expect("utf-8");
        assert_eq!(text.lines().count(), 5);
    }

    #[test]
    fn write_failures_are_counted_as_dropped() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::other("disk gone"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Err(io::Error::other("disk gone"))
            }
        }
        let big = AccessRecord {
            url: format!("http://big.test/{}", "a".repeat(9000)),
            ..http_record()
        };
        let log = AccessLog::start(Box::new(Broken), None, Format::Squid, 16).expect("start");
        log.log(big.clone());
        log.log(big);
        // Small records fail on BufWriter flush, not write_all.
        log.log(http_record());
        let dropped = Arc::clone(&log.dropped);
        drop(log);
        assert_eq!(dropped.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn shared_across_threads() {
        let dir = TempDir::new("threads");
        let path = dir.file("access.log");
        let log = Arc::new(AccessLog::open(&file_cfg(&path, Format::Squid)).expect("open"));
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let log = Arc::clone(&log);
                std::thread::spawn(move || {
                    for _ in 0..100 {
                        log.log(http_record());
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().expect("thread");
        }
        assert_eq!(log.dropped(), 0);
        drop(log);
        assert_eq!(read(&path).lines().count(), 400);
    }
}
