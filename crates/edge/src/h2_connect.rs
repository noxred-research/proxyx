//! RFC 9113 CONNECT tunnels over TLS ALPN `h2` (not extended CONNECT or HTTP/3).

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use std::time::{Instant, SystemTime};

use bytes::{Buf as _, Bytes};
use h2::{RecvStream, SendStream, server::SendResponse};
use http::{Method, Request, Response, StatusCode};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::task::JoinSet;
use tokio::time::timeout;

use crate::accesslog::AccessRecord;
use crate::acl::Proto;
use crate::config::RuleStage;
use crate::conn::{self, LoginFailure, ReqCtx, Shared};
use crate::connect::Mode;
use crate::limits::Dir;
use crate::state::ListenerRt;
use crate::transport::Transport;

const MAX_STREAMS: usize = 128;
const WINDOW: u32 = 64 * 1024;
const CHUNK: usize = 16 * 1024;

pub(crate) async fn serve<S: Transport>(
    shared: Arc<Shared>,
    rt: ListenerRt,
    stream: S,
    peer: std::net::SocketAddr,
) {
    let state = shared.state();
    let mut builder = h2::server::Builder::new();
    builder
        .max_concurrent_streams(MAX_STREAMS as u32)
        .initial_window_size(WINDOW)
        .initial_connection_window_size(WINDOW)
        .max_send_buffer_size(WINDOW as usize)
        .max_concurrent_reset_streams(MAX_STREAMS)
        .max_pending_accept_reset_streams(MAX_STREAMS)
        .max_local_error_reset_streams(Some(MAX_STREAMS))
        .max_header_list_size(u32::try_from(state.cfg.http.max_header_bytes).unwrap_or(u32::MAX));
    let Ok(Ok(mut connection)) = timeout(
        state.cfg.timeouts.handshake,
        builder.handshake::<_, Bytes>(stream),
    )
    .await
    else {
        return;
    };
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            _ = shared.shutdown.cancelled() => return,
            _ = tasks.join_next(), if !tasks.is_empty() => {},
            next = timeout(state.cfg.timeouts.keepalive, connection.accept()) => {
                match next {
                    Ok(Some(Ok((request, mut response)))) => {
                        if tasks.len() >= MAX_STREAMS {
                            response.send_reset(h2::Reason::REFUSED_STREAM);
                            let (mut record, _) = request_record(&rt.cfg.name, peer, &request);
                            record.status = 429;
                            record.result = "limited";
                            shared.log(record);
                            continue;
                        }
                        let shared = Arc::clone(&shared);
                        let rt = rt.clone();
                        tasks.spawn(async move { connect(shared, rt, peer, request, response).await; });
                    }
                    Ok(None | Some(Err(_))) => return,
                    Err(_) if tasks.is_empty() => return,
                    Err(_) => {},
                }
            }
        }
    }
}

fn answer(response: &mut SendResponse<Bytes>, status: u16, challenge: Option<&str>) {
    let Ok(status) = StatusCode::from_u16(status) else {
        return;
    };
    let mut reply = Response::new(());
    *reply.status_mut() = status;
    if let Some(realm) = challenge
        && let Ok(value) = http::HeaderValue::from_str(&format!("Basic realm=\"{realm}\""))
    {
        reply
            .headers_mut()
            .insert(http::header::PROXY_AUTHENTICATE, value);
    }
    let _ = response.send_response(reply, true);
}

/// Invalid authorities are deliberately absent: logging their raw URI could
/// disclose userinfo credentials that the authority parser rejected.
fn request_record<B>(
    listener: &str,
    peer: std::net::SocketAddr,
    request: &Request<B>,
) -> (AccessRecord, Option<(String, u16)>) {
    let target = request
        .uri()
        .authority()
        .and_then(|a| crate::http::parse_authority(a.as_str(), None));
    let record = AccessRecord {
        time: SystemTime::now(),
        elapsed: std::time::Duration::ZERO,
        client: peer,
        listener: listener.to_owned(),
        protocol: if request.method() == Method::CONNECT {
            "connect"
        } else {
            "http"
        },
        user: None,
        method: request.method().as_str().to_owned(),
        url: if target.is_some() {
            request
                .uri()
                .authority()
                .map_or_else(String::new, |a| a.as_str().to_owned())
        } else {
            String::new()
        },
        host: target
            .as_ref()
            .map_or_else(String::new, |(host, _)| host.clone()),
        port: target.as_ref().map_or(0, |(_, port)| *port),
        status: 400,
        bytes_up: 0,
        bytes_down: 0,
        egress: None,
        pool: None,
        target_ip: None,
        parent: None,
        result: "bad_request",
        rule: None,
        referer: None,
        user_agent: None,
        mime: None,
        session: None,
    };
    (record, target)
}

/// Cancellation drops active stream tasks too; account for them exactly once.
struct RequestLog<'a> {
    shared: &'a Shared,
    record: Option<AccessRecord>,
    began: Instant,
    completed: bool,
}

impl Drop for RequestLog<'_> {
    fn drop(&mut self) {
        if let Some(mut record) = self.record.take() {
            record.elapsed = self.began.elapsed();
            if !self.completed {
                record.status = 499;
                record.result = "connect_error";
            }
            self.shared.log(record);
        }
    }
}

async fn connect(
    shared: Arc<Shared>,
    rt: ListenerRt,
    peer: std::net::SocketAddr,
    request: Request<RecvStream>,
    response: SendResponse<Bytes>,
) {
    let (record, target) = request_record(&rt.cfg.name, peer, &request);
    let mut log = RequestLog {
        shared: &shared,
        record: Some(record),
        began: Instant::now(),
        completed: false,
    };
    if let Some(record) = log.record.as_mut() {
        handle_connect(
            &shared,
            rt,
            peer,
            request,
            response,
            target.as_ref(),
            record,
        )
        .await;
    }
    log.completed = true;
}

async fn handle_connect(
    shared: &Arc<Shared>,
    rt: ListenerRt,
    peer: std::net::SocketAddr,
    request: Request<RecvStream>,
    mut response: SendResponse<Bytes>,
    target: Option<&(String, u16)>,
    rec: &mut AccessRecord,
) {
    let state = shared.state();
    let rt = state.listeners.get(&rt.cfg.name).unwrap_or(&rt);
    if request.method() != Method::CONNECT {
        answer(&mut response, 405, None);
        rec.status = 405;
        return;
    }
    // Classic CONNECT has authority only. No scheme, path or extended protocol.
    if request.uri().scheme().is_some()
        || request.uri().path_and_query().is_some()
        || request.extensions().get::<h2::ext::Protocol>().is_some()
    {
        answer(&mut response, 400, None);
        return;
    }
    let Some((host, port)) = target else {
        answer(&mut response, 400, None);
        return;
    };
    let started = rec.time;
    let mut ctx = ReqCtx {
        shared,
        state: &state,
        listener: rt,
        client: peer,
        proto: Proto::Connect,
        method: "CONNECT",
        host,
        port: *port,
        login: None,
        mode: Mode::Tunnel,
        reuse: false,
    };
    *rec = ctx.record(started, std::time::Duration::ZERO, 200, "ok");
    let creds = request
        .headers()
        .get(http::header::PROXY_AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(crate::http::parse_basic_value);
    let login = match conn::authenticate(
        shared,
        &state,
        rt,
        peer.ip(),
        creds.as_ref().map(|(u, p)| (u.as_str(), p.as_str())),
    )
    .await
    {
        Ok(login) => login,
        Err(LoginFailure::Missing | LoginFailure::Invalid) => {
            answer(&mut response, 407, Some(&state.cfg.auth.realm));
            rec.status = 407;
            rec.result = "auth_required";
            return;
        }
        Err(LoginFailure::Blocked) => {
            answer(&mut response, 429, None);
            rec.status = 429;
            rec.result = "denied";
            return;
        }
        Err(_) => {
            answer(&mut response, 403, None);
            rec.status = 403;
            rec.result = "denied";
            return;
        }
    };
    ctx.login = login.as_ref();
    *rec = ctx.record(started, std::time::Duration::ZERO, 200, "ok");
    if let Err(r) = conn::check_stage(
        shared,
        &state,
        rt,
        peer,
        login.as_ref(),
        RuleStage::PostAuth,
        Proto::Connect,
    ) {
        answer(&mut response, r.status(), None);
        rec.status = r.status();
        rec.result = r.result();
        rec.rule = r.rule;
        return;
    }
    let opened = match conn::open(&ctx).await {
        Ok(opened) => opened,
        Err(r) => {
            answer(&mut response, r.status(), None);
            rec.status = r.status();
            rec.result = r.result();
            rec.rule = r.rule;
            return;
        }
    };
    let Ok(send) = response.send_response(Response::new(()), false) else {
        rec.status = 499;
        return;
    };
    rec.rule = opened.rule.clone();
    rec.pool = opened.pool.clone();
    rec.egress = opened.egress;
    rec.target_ip = Some(opened.peer);
    rec.parent = opened.parent.as_ref().map(|p| p.name.clone());
    let tunnel = H2Stream {
        recv: request.into_body(),
        send,
        pending: Bytes::new(),
        ended: false,
    };
    let totals = crate::relay::relay(
        tunnel,
        opened.stream,
        Vec::new(),
        Vec::new(),
        opened.held.admission.shaper(Dir::Up),
        opened.held.admission.shaper(Dir::Down),
        state.cfg.timeouts.idle,
        state.cfg.timeouts.total,
    )
    .await;
    rec.bytes_up = totals.up;
    rec.bytes_down = totals.down;
}

/// Own at most one received DATA frame. Release receive capacity only after
/// copying bytes to the consumer; reserve send capacity before queueing DATA.
struct H2Stream {
    recv: RecvStream,
    send: SendStream<Bytes>,
    pending: Bytes,
    ended: bool,
}

fn stream_error(error: h2::Error) -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionReset, error)
}

impl AsyncRead for H2Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        for _ in 0..16 {
            if !self.pending.is_empty() {
                let n = out.remaining().min(self.pending.len());
                out.put_slice(&self.pending[..n]);
                self.pending.advance(n);
                self.recv
                    .flow_control()
                    .release_capacity(n)
                    .map_err(stream_error)?;
                return Poll::Ready(Ok(()));
            }
            match ready!(self.recv.poll_data(cx)) {
                Some(Ok(data)) => self.pending = data,
                Some(Err(error)) => return Poll::Ready(Err(stream_error(error))),
                None => {
                    if ready!(self.recv.poll_trailers(cx))
                        .map_err(stream_error)?
                        .is_some()
                    {
                        self.send.send_reset(h2::Reason::PROTOCOL_ERROR);
                        self.ended = true;
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "trailers are not allowed on a CONNECT tunnel",
                        )));
                    }
                    return Poll::Ready(Ok(()));
                }
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl AsyncWrite for H2Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.ended {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let wanted = data.len().min(CHUNK);
        self.send.reserve_capacity(wanted);
        if self.send.capacity() == 0 {
            match ready!(self.send.poll_capacity(cx)) {
                Some(Ok(_)) => {}
                Some(Err(error)) => return Poll::Ready(Err(stream_error(error))),
                None => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            }
        }
        let n = wanted.min(self.send.capacity());
        if n == 0 {
            return Poll::Pending;
        }
        self.send
            .send_data(Bytes::copy_from_slice(&data[..n]), false)
            .map_err(stream_error)?;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.ended {
            self.send
                .send_data(Bytes::new(), true)
                .map_err(stream_error)?;
            self.ended = true;
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for H2Stream {
    fn drop(&mut self) {
        if !self.ended {
            self.send.send_reset(h2::Reason::CONNECT_ERROR);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejected_authority_logging_omits_userinfo_and_fake_targets() {
        let uri = http::Uri::builder()
            .authority("alice:secret@example.test:443")
            .build()
            .expect("authority URI");
        let request = Request::builder()
            .method("CONNECT")
            .uri(uri)
            .body(())
            .expect("request");
        let (record, target) =
            request_record("main", "192.0.2.1:1000".parse().expect("client"), &request);
        assert!(target.is_none());
        assert!(record.url.is_empty());
        assert!(record.host.is_empty());
        assert_eq!(record.port, 0);
        assert_eq!(
            (record.method.as_str(), record.protocol, record.status),
            ("CONNECT", "connect", 400)
        );
    }
}
