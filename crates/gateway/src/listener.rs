//! Accept loops and the per-connection protocol handlers: HTTP CONNECT
//! (`connect` and `probe` listeners) and SOCKS5 (RFC 1928, RFC 1929).
//!
//! A handler reads the request under a timeout, authenticates the key, opens
//! the tunnel ([`Gateway::open`]), answers, and relays. A refusal answers with
//! the status line or SOCKS5 reply code of its [`Cause`]; the gateway never
//! connects to the target itself.

use std::sync::Arc;
use std::time::Duration;

use common::Cause;
use common::types::{OrgId, Target};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout};
use tokio_util::sync::CancellationToken;

use crate::gateway::{Gateway, Listener, Pending};
use crate::relay::relay;
use crate::wire::{
    self, HeadError, SOCKS_AUTH_FAILED, SOCKS_AUTH_OK, SOCKS_SELECT_NONE, SOCKS_SELECT_USER_PASS,
    SOCKS_SUCCESS, SocksError,
};

// The client must complete its request head (or SOCKS5 handshake) inside
// `settings.handshake_timeout`, and its first byte must arrive inside
// `settings.first_byte_timeout`: a socket that sends nothing holds a pre-auth
// slot only that long.
/// One write of a reply.
const REPLY_TIMEOUT: Duration = Duration::from_secs(5);
/// Pause after a failed `accept` (descriptor exhaustion), so the loop does not spin.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// Outcome label of a request that is not a valid CONNECT or SOCKS5 request.
const BAD_REQUEST: &str = "bad_request";
/// Outcome label of a connection closed because the pod is at `max_connections`,
/// `max_pending_connections`, or the source of the connection at
/// `max_pending_per_ip`.
const OVER_LIMIT: &str = "over_limit";

/// Accept connections of `listener` until `cancel` fires.
///
/// Every connection takes one permit of [`Gateway::connections`] for its whole
/// life and one pre-auth slot ([`Gateway::try_pending`]: a permit of
/// [`Gateway::pending`] and one of its source's share) until its request head
/// is read and its key checked. The permits are taken after `accept`, so an
/// idle listener holds none and one listener cannot starve another. At any
/// cap the connection is closed at once: none of the [`Cause`]s means "pod
/// full", and a client that retries finds another replica.
pub(crate) async fn accept_loop(
    gw: Arc<Gateway>,
    listener: TcpListener,
    kind: Listener,
    cancel: CancellationToken,
) {
    loop {
        tokio::select! {
            () = cancel.cancelled() => return,
            accepted = listener.accept() => match accepted {
                Ok((stream, peer)) => {
                    // `try_pending` reserves a slot, so it must run only after a
                    // connection permit was granted; `zip` would evaluate it eagerly.
                    #[allow(clippy::manual_option_zip)]
                    let permits = Arc::clone(&gw.connections)
                        .try_acquire_owned()
                        .ok()
                        .and_then(|permit| {
                            gw.try_pending(peer.ip()).map(|pending| (permit, pending))
                        });
                    let Some((permit, pending)) = permits else {
                        gw.count(kind, OVER_LIMIT);
                        tracing::debug!(
                            listener = kind.label(),
                            max_connections = gw.settings.max_connections,
                            max_pending_connections = gw.settings.pending_limit(),
                            max_pending_per_ip = gw.settings.pending_per_ip_limit(),
                            "connection limit reached, closing a new connection"
                        );
                        continue;
                    };
                    prepare_client(&stream, gw.settings.keepalive());
                    let gw_conn = Arc::clone(&gw);
                    gw.tracker.spawn(async move {
                        // held until the connection ends
                        let _permit = permit;
                        match kind {
                            Listener::Socks => serve_socks(gw_conn, stream, pending).await,
                            Listener::Connect | Listener::Probe => {
                                serve_connect(gw_conn, stream, kind, pending).await;
                            }
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(listener = kind.label(), error = %e, "accept failed");
                    sleep(ACCEPT_BACKOFF).await;
                }
            }
        }
    }
}

/// Nodelay and TCP keepalive on an accepted client socket, so a client that
/// vanished without FIN or RST is found by the kernel. A
/// failure is logged: the tunnel works without them.
fn prepare_client(stream: &TcpStream, keepalive: Option<common::config::TcpKeepalive>) {
    if let Err(e) = stream.set_nodelay(true) {
        tracing::debug!(error = %e, "failed to set nodelay on a client socket");
    }
    if let Err(e) = dial::set_keepalive(stream, keepalive) {
        tracing::debug!(error = %e, "failed to set keepalive on a client socket");
    }
}

async fn write_reply<W: AsyncWrite + Unpin>(w: &mut W, bytes: &[u8]) -> bool {
    match timeout(REPLY_TIMEOUT, async {
        w.write_all(bytes).await?;
        w.flush().await
    })
    .await
    {
        Ok(Ok(())) => true,
        Ok(Err(e)) => {
            tracing::debug!(error = %e, "failed to write a reply");
            false
        }
        Err(_) => {
            tracing::debug!("reply write timed out");
            false
        }
    }
}

/// True when the client sent a first byte (or closed) in time; the byte stays
/// in the socket for the reader. A silent client ends here, counted as a
/// request that timed out.
async fn spoke_up(gw: &Gateway, client: &TcpStream, listener: Listener) -> bool {
    let spoke = timeout(gw.settings.first_byte_timeout, client.peek(&mut [0u8; 1]))
        .await
        .is_ok();
    if !spoke {
        gw.count(listener, BAD_REQUEST);
    }
    spoke
}

/// HTTP CONNECT on the `connect` or `probe` listener. `pending` is the
/// connection's pre-auth slot: it is given back once the key checked out.
async fn serve_connect(
    gw: Arc<Gateway>,
    mut client: TcpStream,
    listener: Listener,
    pending: Pending,
) {
    if !spoke_up(&gw, &client, listener).await {
        return;
    }
    let head = match timeout(
        gw.settings.handshake_timeout,
        wire::read_connect(&mut client),
    )
    .await
    {
        Ok(Ok(head)) => head,
        Ok(Err(e)) => {
            // a peer that left (clean close or reset) sent no bad request
            if !matches!(e, HeadError::Closed | HeadError::Io) {
                gw.count(listener, BAD_REQUEST);
            }
            if let Some(reply) = e.reply() {
                write_reply(&mut client, &reply).await;
            }
            return;
        }
        Err(_) => {
            gw.count(listener, BAD_REQUEST);
            return;
        }
    };

    let Some(login) = head.login else {
        gw.count(listener, Cause::AuthRequired.code());
        write_reply(&mut client, &wire::refusal(Cause::AuthRequired)).await;
        return;
    };
    let org = match gw
        .authenticate(listener, pending.source(), &login.key)
        .await
    {
        Ok(org) => org,
        Err(cause) => {
            gw.count(listener, cause.code());
            write_reply(&mut client, &wire::refusal(cause)).await;
            return;
        }
    };
    drop(pending);
    let opened = match gw.open(listener, org, &login.username, head.target).await {
        Ok(opened) => opened,
        Err(cause) => {
            write_reply(&mut client, &wire::refusal(cause)).await;
            return;
        }
    };
    let reply = wire::established(&opened.session, opened.tunnel.lease.grant.ip);
    if !write_reply(&mut client, &reply).await {
        opened.tunnel.finish(&gw).await;
        return;
    }
    relay(&gw, opened.tunnel, client, opened.stream, head.leftover).await;
}

/// What the SOCKS5 negotiation produced.
struct SocksRequest {
    org: OrgId,
    username: String,
    target: Target,
}

/// Greeting, login and CONNECT request. `None` when the exchange ended with a
/// reply (or none, for a peer that left). `pending` is given back once the
/// login checked out.
async fn socks_negotiate(
    gw: &Gateway,
    client: &mut TcpStream,
    pending: Pending,
) -> Option<SocksRequest> {
    let listener = Listener::Socks;
    if let Err(e) = wire::socks_greeting(client).await {
        if e != SocksError::Io {
            gw.count(listener, BAD_REQUEST);
        }
        if e == SocksError::NoMethod {
            write_reply(client, &SOCKS_SELECT_NONE).await;
        }
        return None;
    }
    if !write_reply(client, &SOCKS_SELECT_USER_PASS).await {
        return None;
    }
    let login = match wire::socks_login(client).await {
        Ok(login) => login,
        Err(e) => {
            if e != SocksError::Io {
                gw.count(listener, BAD_REQUEST);
            }
            return None;
        }
    };
    let org = match gw
        .authenticate(listener, pending.source(), &login.key)
        .await
    {
        Ok(org) => org,
        Err(cause) => {
            gw.count(listener, cause.code());
            write_reply(client, &SOCKS_AUTH_FAILED).await;
            return None;
        }
    };
    drop(pending);
    if !write_reply(client, &SOCKS_AUTH_OK).await {
        return None;
    }
    let target = match wire::socks_request(client).await {
        Ok(target) => target,
        Err(e) => {
            if e != SocksError::Io {
                gw.count(listener, BAD_REQUEST);
            }
            if let SocksError::Refused(code) = e {
                write_reply(client, &wire::socks_reply(code)).await;
            }
            return None;
        }
    };
    Some(SocksRequest {
        org,
        username: login.username,
        target,
    })
}

async fn serve_socks(gw: Arc<Gateway>, mut client: TcpStream, pending: Pending) {
    if !spoke_up(&gw, &client, Listener::Socks).await {
        return;
    }
    let negotiated = timeout(
        gw.settings.handshake_timeout,
        socks_negotiate(&gw, &mut client, pending),
    )
    .await;
    let Ok(Some(request)) = negotiated else {
        if negotiated.is_err() {
            gw.count(Listener::Socks, BAD_REQUEST);
        }
        return;
    };
    let opened = match gw
        .open(
            Listener::Socks,
            request.org,
            &request.username,
            request.target,
        )
        .await
    {
        Ok(opened) => opened,
        Err(cause) => {
            write_reply(&mut client, &wire::socks_reply(cause.socks5_reply())).await;
            return;
        }
    };
    if !write_reply(&mut client, &wire::socks_reply(SOCKS_SUCCESS)).await {
        opened.tunnel.finish(&gw).await;
        return;
    }
    relay(&gw, opened.tunnel, client, opened.stream, Vec::new()).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn an_accepted_client_socket_has_nodelay_and_keepalive_on() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let _client = TcpStream::connect(addr).await.expect("connect");
        let (stream, _) = listener.accept().await.expect("accept");

        prepare_client(&stream, dial::DEFAULT_KEEPALIVE);

        assert!(stream.nodelay().expect("nodelay"));
        let sock = socket2::SockRef::from(&stream);
        assert!(sock.keepalive().expect("keepalive"));
        assert_eq!(
            sock.tcp_keepalive_time().expect("time"),
            Duration::from_secs(60)
        );
        assert_eq!(
            sock.tcp_keepalive_interval().expect("interval"),
            Duration::from_secs(15)
        );
        assert_eq!(sock.tcp_keepalive_retries().expect("retries"), 4);
    }
}
