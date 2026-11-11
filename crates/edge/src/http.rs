//! The HTTP side of a listener: absolute-form forward proxying with
//! keep-alive on the client side, and `CONNECT` tunnels.
//!
//! Every forwarded request opens its own connection to the target (or parent)
//! and sends `Connection: close` to it: the egress address is chosen per
//! request, so reusing a target connection would pin a client to an address the
//! strategy did not pick. The client connection stays open between requests.

use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Instant, SystemTime};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use dial::ProxyStream;
use tokio::io::AsyncWriteExt as _;

use crate::accesslog::AccessRecord;
use crate::acl::Proto;
use crate::conn::{self, Held, LoginFailure, Opened, ReqCtx, Shared};
use crate::connect::Mode;
use crate::headers::Header;
use crate::limits::Dir;
use crate::relay::relay;
use crate::state::{ListenerRt, State};
use crate::transport::Transport;
use crate::wire::{
    Framing, HeadError, Pipe, RequestHead, ResponseHead, copy_body, has_token, header_str,
    read_request_head, read_response_head, render_head, request_framing, response_framing,
};

const MAX_HOST_BYTES: usize = 253;

/// Parse `host`, `host:port`, `[v6]` or `[v6]:port`. The host comes back
/// lowercase without brackets or trailing dot. `default_port: None` makes the
/// port mandatory (CONNECT).
pub fn parse_authority(s: &str, default_port: Option<u16>) -> Option<(String, u16)> {
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let (host, rest) = rest.split_once(']')?;
        host.parse::<Ipv6Addr>().ok()?;
        match rest.strip_prefix(':') {
            Some(p) => (host, Some(p)),
            None if rest.is_empty() => (host, None),
            None => return None,
        }
    } else {
        match s.rsplit_once(':') {
            Some((h, p)) => {
                if h.contains(':') {
                    return None;
                }
                (h, Some(p))
            }
            None => (s, None),
        }
    };
    let port = match port {
        Some(p) => {
            // `u16::from_str` accepts a leading `+`
            if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            p.parse::<u16>().ok()?
        }
        None => default_port?,
    };
    let host = host.trim_end_matches('.');
    if port == 0
        || host.is_empty()
        || host.len() > MAX_HOST_BYTES
        || !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':'))
    {
        return None;
    }
    Some((host.to_ascii_lowercase(), port))
}

/// An absolute-form `http://` target split into its parts.
#[derive(Debug, PartialEq, Eq)]
pub struct Absolute {
    pub host: String,
    pub port: u16,
    /// Path and query, always starting with `/`.
    pub path: String,
}

impl Absolute {
    fn authority(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port == 80 {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }

    fn url(&self) -> String {
        format!("http://{}{}", self.authority(), self.path)
    }
}

/// `http://host[:port]/path?query`; `None` for anything else (userinfo included).
pub fn parse_absolute(target: &str) -> Option<Absolute> {
    let rest = target
        .get(..7)
        .filter(|p| p.eq_ignore_ascii_case("http://"))?;
    let rest = &target[rest.len()..];
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    if authority.contains('@') {
        return None;
    }
    let (host, port) = parse_authority(authority, Some(80))?;
    let tail = tail.split('#').next().unwrap_or_default();
    let path = if tail.is_empty() {
        "/".to_owned()
    } else if tail.starts_with('?') {
        format!("/{tail}")
    } else {
        tail.to_owned()
    };
    Some(Absolute { host, port, path })
}

/// `Basic base64(user:password)` of a `Proxy-Authorization` header.
fn parse_basic(h: &[Header]) -> Option<(String, String)> {
    parse_basic_value(header_str(h, "proxy-authorization")?)
}

pub(crate) fn parse_basic_value(value: &str) -> Option<(String, String)> {
    let v = value.trim();
    let (scheme, enc) = v.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let dec = String::from_utf8(STANDARD.decode(enc.trim()).ok()?).ok()?;
    let (u, p) = dec.split_once(':')?;
    Some((u.to_owned(), p.to_owned()))
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        407 => "Proxy Authentication Required",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Error",
    }
}

fn error_reply(status: u16, code: &str, msg: &str, keep: bool, realm: Option<&str>) -> Vec<u8> {
    let body = format!("{msg}\n");
    let mut out = format!("HTTP/1.1 {status} {}\r\n", reason(status));
    if status == 407
        && let Some(realm) = realm
    {
        let realm = realm.replace(['"', '\\', '\r', '\n'], "");
        out.push_str(&format!("Proxy-Authenticate: Basic realm=\"{realm}\"\r\n"));
    }
    out.push_str(&format!(
        "X-ProxyX-Error: {code}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\n{}\r\n",
        body.len(),
        if keep { "" } else { "Connection: close\r\n" }
    ));
    out.push_str(&body);
    out.into_bytes()
}

/// A tunnel to run once the request is answered: the connection is handed to
/// the relay, which owns it from there.
struct TunnelJob {
    stream: ProxyStream,
    /// Bytes the upstream sent before the relay started.
    early: Vec<u8>,
    held: Held,
    rec: AccessRecord,
    t0: Instant,
}

/// What to do with the client connection after a request.
enum Next {
    KeepAlive,
    Close,
    Tunnel(Box<TunnelJob>),
}

struct Session {
    shared: Arc<Shared>,
    rt: ListenerRt,
    peer: SocketAddr,
}

/// Serve an HTTP proxy connection. `stream` has had nothing read except what
/// the caller peeked; `early` holds bytes already taken from it.
pub async fn serve<S: Transport>(
    shared: Arc<Shared>,
    rt: ListenerRt,
    stream: S,
    peer: SocketAddr,
    early: Vec<u8>,
) {
    let mut client = Pipe::new(stream);
    client.buf = early;
    let s = Session { shared, rt, peer };
    let mut first = true;
    let mut served: u32 = 0;
    let mut parent_chain: Option<Vec<String>> = None;
    loop {
        let state = s.shared.state();
        let rt = state.listeners.get(&s.rt.cfg.name).unwrap_or(&s.rt);
        let t = &state.cfg.timeouts;
        let wait = if first { t.handshake } else { t.keepalive };
        let head = match read_request_head(&mut client, state.cfg.http.max_header_bytes, wait).await
        {
            Ok(h) => h,
            Err(HeadError::Closed | HeadError::Io(_)) => return,
            Err(HeadError::Timeout) => {
                if first {
                    let _ = client
                        .stream
                        .write_all(&error_reply(
                            408,
                            "timeout",
                            "request head timed out",
                            false,
                            None,
                        ))
                        .await;
                }
                return;
            }
            Err(HeadError::TooLarge) => {
                let _ = client
                    .stream
                    .write_all(&error_reply(
                        431,
                        "bad_request",
                        "request head too large",
                        false,
                        None,
                    ))
                    .await;
                return;
            }
            Err(HeadError::Malformed(m)) => {
                let _ = client
                    .stream
                    .write_all(&error_reply(400, "bad_request", m, false, None))
                    .await;
                return;
            }
        };
        first = false;
        served += 1;
        let max_requests = state.cfg.http.client_max_requests;
        let last = max_requests != 0 && served >= max_requests;
        match s
            .handle(&state, rt, &mut client, head, last, &mut parent_chain)
            .await
        {
            Next::KeepAlive => {}
            Next::Close => return,
            Next::Tunnel(job) => {
                let TunnelJob {
                    stream,
                    early,
                    held,
                    mut rec,
                    t0,
                } = *job;
                let (c, client_early) = client.into_parts();
                let totals = relay(
                    c,
                    stream,
                    client_early,
                    early,
                    held.admission.shaper(Dir::Up),
                    held.admission.shaper(Dir::Down),
                    state.cfg.timeouts.idle,
                    state.cfg.timeouts.total,
                )
                .await;
                rec.bytes_up += totals.up;
                rec.bytes_down += totals.down;
                rec.elapsed = t0.elapsed();
                s.shared.log(rec);
                return;
            }
        }
    }
}

impl Session {
    #[allow(clippy::too_many_lines)]
    async fn handle<S: Transport>(
        &self,
        state: &Arc<State>,
        rt: &ListenerRt,
        client: &mut Pipe<S>,
        head: RequestHead,
        last: bool,
        parent_chain: &mut Option<Vec<String>>,
    ) -> Next {
        let started = SystemTime::now();
        let t0 = Instant::now();
        let shared = &self.shared;
        let is_connect = head.method.eq_ignore_ascii_case("CONNECT");
        let framing = match request_framing(&head.headers) {
            Ok(f) => f,
            Err(m) => return self.reply_close(client, 400, "bad_request", m).await,
        };
        // `last`: this is the connection's final request (`http.client_max_requests`).
        let keep_wanted = (head.minor == 1 && !has_token(&head.headers, "connection", "close"))
            && !is_connect
            && !last;

        let target: Result<(String, u16, Option<Absolute>), &'static str> = if is_connect {
            parse_authority(&head.target, None)
                .map(|(h, p)| (h, p, None))
                .ok_or("CONNECT needs host:port")
        } else if head
            .target
            .get(..8)
            .is_some_and(|p| p.eq_ignore_ascii_case("https://"))
        {
            Err("https targets need CONNECT")
        } else {
            parse_absolute(&head.target)
                .map(|a| (a.host.clone(), a.port, Some(a)))
                .ok_or("this is a proxy: send an absolute http:// URL or CONNECT host:port")
        };
        let (host, port, abs) = match target {
            Ok(t) => t,
            Err(m) => return self.reply_close(client, 400, "bad_request", m).await,
        };

        // Login.
        let creds = parse_basic(&head.headers);
        let login = match conn::authenticate(
            shared,
            state,
            rt,
            self.peer.ip(),
            creds.as_ref().map(|(u, p)| (u.as_str(), p.as_str())),
        )
        .await
        {
            Ok(l) => l,
            Err(f) => {
                let (status, code, msg, keep) = match f {
                    LoginFailure::Missing | LoginFailure::Invalid => (
                        407,
                        "auth_required",
                        "proxy authentication required",
                        keep_wanted && framing == Framing::None,
                    ),
                    LoginFailure::Blocked => (429, "auth_blocked", "too many failed logins", false),
                    LoginFailure::OptionDenied => (
                        403,
                        "option_denied",
                        "login option not allowed for this user",
                        false,
                    ),
                    LoginFailure::ListenerDenied => (
                        403,
                        "forbidden",
                        "this user may not use this listener",
                        false,
                    ),
                };
                let ctx_proto = if is_connect {
                    Proto::Connect
                } else {
                    Proto::Http
                };
                let ctx = ReqCtx {
                    shared,
                    state,
                    listener: rt,
                    client: self.peer,
                    proto: ctx_proto,
                    method: &head.method,
                    host: &host,
                    port,
                    login: None,
                    mode: Mode::Http,
                    reuse: false,
                };
                let mut rec = ctx.record(
                    started,
                    t0.elapsed(),
                    status,
                    if status == 407 {
                        "auth_required"
                    } else {
                        "denied"
                    },
                );
                if let Some(a) = &abs {
                    rec.url = a.url();
                }
                shared.log(rec);
                let reply = error_reply(status, code, msg, keep, Some(&state.cfg.auth.realm));
                if client.stream.write_all(&reply).await.is_err() || !keep {
                    return Next::Close;
                }
                return Next::KeepAlive;
            }
        };
        if let Err(r) = conn::check_stage(
            shared,
            state,
            rt,
            self.peer,
            login.as_ref(),
            crate::config::RuleStage::PostAuth,
            if is_connect {
                Proto::Connect
            } else {
                Proto::Http
            },
        ) {
            return self
                .reply_close(client, r.status(), r.code(), &r.message())
                .await;
        }

        let proto = if is_connect {
            Proto::Connect
        } else {
            Proto::Http
        };
        let mut ctx = ReqCtx {
            shared,
            state,
            listener: rt,
            client: self.peer,
            proto,
            method: &head.method,
            host: &host,
            port,
            login: login.as_ref(),
            mode: if is_connect { Mode::Tunnel } else { Mode::Http },
            reuse: !is_connect && framing == Framing::None,
        };
        let mut rec = ctx.record(started, t0.elapsed(), 0, "ok");
        if let Some(a) = &abs {
            rec.url = a.url();
        }
        rec.referer = header_str(&head.headers, "referer").map(str::to_owned);
        rec.user_agent = header_str(&head.headers, "user-agent").map(str::to_owned);

        let opened = match conn::open_pinned(&ctx, parent_chain.as_deref()).await {
            Ok(o) => o,
            Err(r) => {
                let keep = keep_wanted && framing == Framing::None;
                rec.status = r.status();
                rec.result = r.result();
                rec.rule = r.rule.clone();
                rec.elapsed = t0.elapsed();
                shared.log(rec);
                let reply = error_reply(r.status(), r.code(), &r.message(), keep, None);
                if client.stream.write_all(&reply).await.is_err() || !keep {
                    return Next::Close;
                }
                return Next::KeepAlive;
            }
        };
        if parent_chain.is_none() && !opened.chain.is_empty() {
            *parent_chain = Some(opened.chain.clone());
        }
        rec.rule = opened.rule.clone();
        rec.pool = opened.pool.clone();
        rec.egress = opened.egress;
        rec.target_ip = Some(opened.peer);
        rec.parent = opened.parent.as_ref().map(|p| p.name.clone());

        if is_connect {
            if client
                .stream
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .is_err()
            {
                return Next::Close;
            }
            rec.status = 200;
            return Next::Tunnel(Box::new(TunnelJob {
                stream: opened.stream,
                early: Vec::new(),
                held: opened.held,
                rec,
                t0,
            }));
        }

        let Some(abs) = abs else {
            return Next::Close;
        };
        let mut out = self
            .forward_timed(state, client, &head, framing, keep_wanted, &abs, opened)
            .await;
        if out.retry {
            // The idle parent connection had gone stale before it answered: once more on a new one.
            ctx.reuse = false;
            match conn::open_pinned(&ctx, parent_chain.as_deref()).await {
                Ok(o) => {
                    rec.egress = o.egress;
                    rec.target_ip = Some(o.peer);
                    out = self
                        .forward_timed(state, client, &head, framing, keep_wanted, &abs, o)
                        .await;
                }
                Err(r) => {
                    self.send_error(client, r.status(), r.code(), &r.message(), false)
                        .await;
                    out = Outcome::new(r.status(), r.result());
                }
            }
        }
        rec.status = out.status;
        rec.result = out.result;
        rec.bytes_up = out.up;
        rec.bytes_down = out.down;
        rec.mime = out.mime.take();
        rec.elapsed = t0.elapsed();
        if let Some((stream, early, held)) = out.tunnel.take() {
            return Next::Tunnel(Box::new(TunnelJob {
                stream,
                early,
                held,
                rec,
                t0,
            }));
        }
        shared.log(rec);
        if out.keep {
            Next::KeepAlive
        } else {
            Next::Close
        }
    }

    async fn reply_close<S: Transport>(
        &self,
        client: &mut Pipe<S>,
        status: u16,
        code: &str,
        msg: &str,
    ) -> Next {
        let _ = client
            .stream
            .write_all(&error_reply(status, code, msg, false, None))
            .await;
        Next::Close
    }

    /// [`Self::forward`] under `timeouts.total`.
    #[allow(clippy::too_many_arguments)]
    async fn forward_timed<S: Transport>(
        &self,
        state: &Arc<State>,
        client: &mut Pipe<S>,
        head: &RequestHead,
        framing: Framing,
        keep_wanted: bool,
        abs: &Absolute,
        opened: Opened,
    ) -> Outcome {
        let work = self.forward(state, client, head, framing, keep_wanted, abs, opened);
        let total = state.cfg.timeouts.total;
        if total.is_zero() {
            return work.await;
        }
        tokio::time::timeout(total, work)
            .await
            .unwrap_or_else(|_| Outcome::new(504, "timeout"))
    }

    /// Forward one plain HTTP request and its response.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    async fn forward<S: Transport>(
        &self,
        state: &Arc<State>,
        client: &mut Pipe<S>,
        head: &RequestHead,
        framing: Framing,
        keep_wanted: bool,
        abs: &Absolute,
        opened: Opened,
    ) -> Outcome {
        let t = &state.cfg.timeouts;
        let max = state.cfg.http.max_header_bytes;
        let rule = opened.rule.clone();
        let local_ip = opened.egress;
        let Opened {
            stream,
            mut held,
            parent,
            http_proxy,
            reuse_key,
            reused,
            peer: upstream_peer,
            ..
        } = opened;
        let mut up = Pipe::new(stream);
        let up_shaper = held.admission.shaper(Dir::Up);
        let down_shaper = held.admission.shaper(Dir::Down);
        let mut out = Outcome::new(502, "connect_error");

        let upgrade = has_token(&head.headers, "connection", "upgrade")
            && head
                .headers
                .iter()
                .any(|(n, _)| n.eq_ignore_ascii_case("upgrade"));
        let head_request = head.method.eq_ignore_ascii_case("HEAD");
        let expect_continue = header_str(&head.headers, "expect")
            .is_some_and(|v| v.trim().eq_ignore_ascii_case("100-continue"));

        let mut headers = head.headers.clone();
        state
            .headers
            .apply_request(&mut headers, self.peer.ip(), upgrade);
        state
            .headers
            .apply_rule_request(&mut headers, rule.as_deref());
        headers.retain(|(n, _)| !n.eq_ignore_ascii_case("host"));
        // The request passed every check and the target is connected, so the body is
        // accepted: say 100 here and keep `Expect` away from a target that may never
        // answer it (the client would wait for a 100 that does not come).
        let answer_expect = expect_continue && framing != Framing::None;
        if answer_expect {
            headers.retain(|(n, _)| !n.eq_ignore_ascii_case("expect"));
        }
        headers.insert(0, ("Host".to_owned(), abs.authority().into_bytes()));
        if upgrade {
            headers.push(("Connection".to_owned(), b"Upgrade".to_vec()));
        } else if reuse_key.is_none() {
            headers.push(("Connection".to_owned(), b"close".to_vec()));
        }
        // With a reuse key the request stays persistent (HTTP/1.1 default): the
        // parent keeps the connection and it goes back to the idle pool.
        let line = if http_proxy {
            if let Some(auth) = parent.as_ref().and_then(|p| p.proxy_authorization()) {
                headers.push(("Proxy-Authorization".to_owned(), auth.into_bytes()));
            }
            format!("{} {} HTTP/1.1", head.method, abs.url())
        } else {
            format!("{} {} HTTP/1.1", head.method, abs.path)
        };
        if up
            .stream
            .write_all(&render_head(&line, &headers))
            .await
            .is_err()
        {
            if reused {
                if let Some(parent) = &parent {
                    parent.breaker.cancel();
                }
                return Outcome { retry: true, ..out };
            }
            self.parent_report(&parent, false);
            self.send_error(
                client,
                502,
                "bad_gateway",
                "could not send the request upstream",
                false,
            )
            .await;
            return out;
        }

        let mut body_consumed = framing == Framing::None;
        let mut sent_up = 0u64;
        if answer_expect
            && client
                .stream
                .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
                .await
                .is_err()
        {
            return Outcome::closed(499, "ok");
        }
        if framing != Framing::None {
            match copy_body(client, &mut up.stream, framing, &up_shaper, t.idle, max).await {
                Ok(n) => {
                    sent_up = n;
                    body_consumed = true;
                }
                Err(_) => {
                    return Outcome::closed(400, "bad_request");
                }
            }
        }

        // Interim responses and the final one.
        let resp: ResponseHead = loop {
            let r = match read_response_head(&mut up, max, t.response_header).await {
                Ok(r) => r,
                Err(e) => {
                    if reused && matches!(e, HeadError::Closed | HeadError::Io(_)) {
                        if let Some(parent) = &parent {
                            parent.breaker.cancel();
                        }
                        return Outcome { retry: true, ..out };
                    }
                    self.parent_report(&parent, false);
                    let (status, code) = match e {
                        HeadError::Timeout => (504, "connect_timeout"),
                        _ => (502, "bad_gateway"),
                    };
                    self.send_error(
                        client,
                        status,
                        code,
                        "no valid response from the upstream",
                        false,
                    )
                    .await;
                    out.status = status;
                    out.result = if status == 504 {
                        "timeout"
                    } else {
                        "connect_error"
                    };
                    return out;
                }
            };
            if (100..200).contains(&r.status) && r.status != 101 {
                let line = format!("HTTP/1.1 {} {}", r.status, r.reason);
                if client
                    .stream
                    .write_all(&render_head(&line, &[]))
                    .await
                    .is_err()
                {
                    return Outcome::closed(499, "ok");
                }
                continue;
            }
            break r;
        };

        if parent.is_some() && http_proxy && resp.status == 407 {
            self.parent_report(&parent, false);
            self.send_error(
                client,
                502,
                "parent_error",
                "the parent proxy refused our login",
                false,
            )
            .await;
            out.status = 502;
            out.result = "parent_error";
            return out;
        }
        self.parent_report(&parent, true);

        out.mime = header_str(&resp.headers, "content-type").map(str::to_owned);
        out.up = sent_up;
        out.status = resp.status;
        out.result = "ok";

        if resp.status == 101 && upgrade {
            let mut hdrs = resp.headers.clone();
            state.headers.apply_response(&mut hdrs, true);
            state
                .headers
                .apply_rule_response(&mut hdrs, rule.as_deref());
            hdrs.push(("Connection".to_owned(), b"Upgrade".to_vec()));
            let line = format!("HTTP/1.1 101 {}", resp.reason);
            if client
                .stream
                .write_all(&render_head(&line, &hdrs))
                .await
                .is_err()
            {
                return Outcome::closed(101, "ok");
            }
            let (us, ubuf) = up.into_parts();
            return Outcome {
                keep: false,
                tunnel: Some((us, ubuf, held)),
                ..out
            };
        }

        let resp_framing = match response_framing(resp.status, head_request, &resp.headers) {
            Ok(f) => f,
            Err(m) => {
                self.send_error(client, 502, "bad_gateway", m, false).await;
                out.status = 502;
                out.result = "connect_error";
                return out;
            }
        };
        let parent_keeps = resp.minor == 1 && !has_token(&resp.headers, "connection", "close");
        let mut hdrs = resp.headers.clone();
        state.headers.apply_response(&mut hdrs, false);
        state
            .headers
            .apply_rule_response(&mut hdrs, rule.as_deref());
        let keep = keep_wanted && body_consumed && resp_framing != Framing::UntilClose;
        if !keep {
            hdrs.push(("Connection".to_owned(), b"close".to_vec()));
        }
        let line = format!("HTTP/1.1 {} {}", resp.status, resp.reason);
        if client
            .stream
            .write_all(&render_head(&line, &hdrs))
            .await
            .is_err()
        {
            return Outcome { keep: false, ..out };
        }
        match copy_body(
            &mut up,
            &mut client.stream,
            resp_framing,
            &down_shaper,
            t.idle,
            max,
        )
        .await
        {
            Ok(n) => {
                out.down = n;
                // The parent kept the connection open and the response ended where its
                // framing says: file the connection for the next bodyless request.
                if let Some(key) = reuse_key
                    && parent_keeps
                    && resp_framing != Framing::UntilClose
                    && up.buf.is_empty()
                {
                    self.shared.parent_conns.put(
                        key,
                        up.stream,
                        held.take_lease(),
                        upstream_peer,
                        local_ip,
                    );
                }
                Outcome { keep, ..out }
            }
            Err(_) => Outcome { keep: false, ..out },
        }
    }

    fn parent_report(&self, parent: &Option<Arc<crate::parent::Parent>>, ok: bool) {
        if let Some(p) = parent {
            p.report(ok);
        }
    }

    async fn send_error<S: Transport>(
        &self,
        client: &mut Pipe<S>,
        status: u16,
        code: &str,
        msg: &str,
        keep: bool,
    ) {
        let _ = client
            .stream
            .write_all(&error_reply(status, code, msg, keep, None))
            .await;
    }
}

struct Outcome {
    status: u16,
    result: &'static str,
    up: u64,
    down: u64,
    mime: Option<String>,
    keep: bool,
    /// The idle parent connection used was stale: run the request again on a new one.
    retry: bool,
    /// Set for an upgraded connection: relay it instead of reading more requests.
    tunnel: Option<(ProxyStream, Vec<u8>, Held)>,
}

impl Outcome {
    fn new(status: u16, result: &'static str) -> Self {
        Self {
            status,
            result,
            up: 0,
            down: 0,
            mime: None,
            keep: false,
            retry: false,
            tunnel: None,
        }
    }

    fn closed(status: u16, result: &'static str) -> Self {
        Self::new(status, result)
    }
}
