//! SOCKS4, SOCKS4a and SOCKS5 (CONNECT, and UDP ASSOCIATE through
//! [`crate::udp`]) on a listener.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Instant, SystemTime};

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::acl::Proto;
use crate::auth::Login;
use crate::config::ListenerAuth;
use crate::conn::{self, LoginFailure, ReqCtx, Shared};
use crate::connect::Mode;
use crate::limits::Dir;
use crate::relay::relay;
use crate::state::{ListenerRt, State};

const V5: u8 = 5;
const V4: u8 = 4;
const CMD_CONNECT: u8 = 1;
const CMD_UDP: u8 = 3;

const REPLY_OK: u8 = 0x00;
const REPLY_NOT_SUPPORTED: u8 = 0x07;
const REPLY_ADDR_NOT_SUPPORTED: u8 = 0x08;

/// Encode a bound address the way a SOCKS5 reply carries it.
pub fn encode_addr(a: SocketAddr, out: &mut Vec<u8>) {
    match a.ip() {
        IpAddr::V4(ip) => {
            out.push(1);
            out.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            out.push(4);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(&a.port().to_be_bytes());
}

pub fn reply5(code: u8, bound: Option<SocketAddr>) -> Vec<u8> {
    let mut out = vec![V5, code, 0];
    encode_addr(
        bound.unwrap_or_else(|| SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))),
        &mut out,
    );
    out
}

/// A DNS name from the wire: lowercase, no trailing dot, plausible bytes.
fn clean_host(raw: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(raw).ok()?.trim_end_matches('.');
    if s.is_empty()
        || s.len() > 253
        || !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
    {
        return None;
    }
    Some(s.to_ascii_lowercase())
}

/// Read an ATYP-tagged address and port. `Err(code)` is the reply to send.
async fn read_addr(s: &mut TcpStream) -> Result<(String, u16), u8> {
    let io = |_| 0x01u8;
    let atyp = s.read_u8().await.map_err(io)?;
    let host = match atyp {
        1 => {
            let mut b = [0u8; 4];
            s.read_exact(&mut b).await.map_err(io)?;
            Ipv4Addr::from(b).to_string()
        }
        4 => {
            let mut b = [0u8; 16];
            s.read_exact(&mut b).await.map_err(io)?;
            Ipv6Addr::from(b).to_string()
        }
        3 => {
            let n = usize::from(s.read_u8().await.map_err(io)?);
            let mut b = vec![0u8; n];
            s.read_exact(&mut b).await.map_err(io)?;
            clean_host(&b).ok_or(REPLY_ADDR_NOT_SUPPORTED)?
        }
        _ => return Err(REPLY_ADDR_NOT_SUPPORTED),
    };
    let port = s.read_u16().await.map_err(io)?;
    Ok((host, port))
}

/// A SOCKS client connection. The first byte tells the version.
pub async fn serve(shared: Arc<Shared>, rt: ListenerRt, mut stream: TcpStream, peer: SocketAddr) {
    let state = shared.state();
    let handshake = state.cfg.timeouts.handshake;
    let ver = match timeout(handshake, stream.read_u8()).await {
        Ok(Ok(v)) => v,
        _ => return,
    };
    match ver {
        V5 => serve5(shared, state, rt, stream, peer).await,
        V4 => serve4(shared, state, rt, stream, peer).await,
        _ => {}
    }
}

struct Greeted {
    login: Option<Login>,
}

/// Method selection and the RFC 1929 login. `None`: close.
async fn negotiate5(
    shared: &Shared,
    state: &State,
    rt: &ListenerRt,
    s: &mut TcpStream,
    peer: SocketAddr,
) -> Option<Greeted> {
    let n = usize::from(s.read_u8().await.ok()?);
    let mut methods = vec![0u8; n];
    s.read_exact(&mut methods).await.ok()?;
    let want_login = rt.cfg.auth == ListenerAuth::Users;
    let chosen = if want_login {
        methods.contains(&2).then_some(2u8)
    } else if methods.contains(&0) {
        Some(0)
    } else {
        methods.contains(&2).then_some(2)
    };
    let Some(method) = chosen else {
        let _ = s.write_all(&[V5, 0xff]).await;
        return None;
    };
    s.write_all(&[V5, method]).await.ok()?;
    if method == 0 {
        return Some(Greeted { login: None });
    }
    // RFC 1929
    if s.read_u8().await.ok()? != 1 {
        return None;
    }
    let ulen = usize::from(s.read_u8().await.ok()?);
    let mut user = vec![0u8; ulen];
    s.read_exact(&mut user).await.ok()?;
    let plen = usize::from(s.read_u8().await.ok()?);
    let mut pass = vec![0u8; plen];
    s.read_exact(&mut pass).await.ok()?;
    let (Ok(user), Ok(pass)) = (String::from_utf8(user), String::from_utf8(pass)) else {
        let _ = s.write_all(&[1, 1]).await;
        return None;
    };
    match conn::authenticate(shared, state, rt, peer.ip(), Some((&user, &pass))).await {
        Ok(login) => {
            s.write_all(&[1, 0]).await.ok()?;
            Some(Greeted { login })
        }
        Err(LoginFailure::Missing | LoginFailure::Invalid | LoginFailure::Blocked) => {
            let _ = s.write_all(&[1, 1]).await;
            None
        }
        Err(LoginFailure::OptionDenied | LoginFailure::ListenerDenied) => {
            let _ = s.write_all(&[1, 1]).await;
            None
        }
    }
}

async fn serve5(
    shared: Arc<Shared>,
    state: Arc<State>,
    rt: ListenerRt,
    mut s: TcpStream,
    peer: SocketAddr,
) {
    let rt = state.listeners.get(&rt.cfg.name).unwrap_or(&rt);
    let handshake = state.cfg.timeouts.handshake;
    let first = timeout(handshake, async {
        let g = negotiate5(&shared, &state, rt, &mut s, peer).await?;
        let mut head = [0u8; 3];
        s.read_exact(&mut head).await.ok()?;
        if head[0] != V5 {
            return None;
        }
        let cmd = head[1];
        let addr = read_addr(&mut s).await;
        Some((g, cmd, addr))
    })
    .await;
    let Ok(Some((greeted, cmd, addr))) = first else {
        return;
    };
    let (host, port) = match addr {
        Ok(a) => a,
        Err(code) => {
            let _ = s.write_all(&reply5(code, None)).await;
            return;
        }
    };
    let started = SystemTime::now();
    let t0 = Instant::now();
    match cmd {
        CMD_CONNECT => {
            let ctx = ReqCtx {
                shared: &shared,
                state: &state,
                listener: rt,
                client: peer,
                proto: Proto::Socks5,
                method: "CONNECT",
                host: &host,
                port,
                login: greeted.login.as_ref(),
                mode: Mode::Tunnel,
                reuse: false,
            };
            let mut rec = ctx.record(started, t0.elapsed(), 200, "ok");
            match conn::open(&ctx).await {
                Ok(o) => {
                    rec.rule = o.rule.clone();
                    rec.pool = o.pool.clone();
                    rec.egress = o.egress;
                    rec.target_ip = Some(o.peer);
                    rec.parent = o.parent.as_ref().map(|p| p.name.clone());
                    // The reply carries the local address of the outgoing connection: the egress IP.
                    let bound = o.stream.local_addr().ok();
                    if s.write_all(&reply5(REPLY_OK, bound)).await.is_err() {
                        return;
                    }
                    let totals = relay(
                        s,
                        o.stream,
                        Vec::new(),
                        Vec::new(),
                        o.held.admission.shaper(Dir::Up),
                        o.held.admission.shaper(Dir::Down),
                        state.cfg.timeouts.idle,
                        state.cfg.timeouts.total,
                    )
                    .await;
                    rec.bytes_up = totals.up;
                    rec.bytes_down = totals.down;
                    rec.elapsed = t0.elapsed();
                    shared.log(rec);
                }
                Err(r) => {
                    rec.status = r.status();
                    rec.result = r.result();
                    rec.rule = r.rule.clone();
                    rec.elapsed = t0.elapsed();
                    shared.log(rec);
                    let _ = s.write_all(&reply5(r.socks5_reply(), None)).await;
                }
            }
        }
        CMD_UDP if rt.cfg.udp => {
            crate::udp::associate(
                shared,
                state.clone(),
                rt,
                s,
                peer,
                greeted.login,
                (host, port),
            )
            .await;
        }
        CMD_UDP => {
            let _ = s.write_all(&reply5(REPLY_NOT_SUPPORTED, None)).await;
        }
        _ => {
            let _ = s.write_all(&reply5(REPLY_NOT_SUPPORTED, None)).await;
        }
    }
}

// --- SOCKS4 / 4a ---

const GRANTED: u8 = 90;
const REJECTED: u8 = 91;
const NO_IDENTD: u8 = 92;
const BAD_USERID: u8 = 93;

fn reply4(code: u8, bound: Option<SocketAddr>) -> [u8; 8] {
    let mut out = [0u8; 8];
    out[1] = code;
    if let Some(SocketAddr::V4(a)) = bound {
        out[2..4].copy_from_slice(&a.port().to_be_bytes());
        out[4..8].copy_from_slice(&a.ip().octets());
    }
    out
}

/// A NUL-terminated string of at most 255 bytes.
async fn read_cstr(s: &mut TcpStream) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let b = s.read_u8().await.ok()?;
        if b == 0 {
            return Some(out);
        }
        if out.len() >= 255 {
            return None;
        }
        out.push(b);
    }
}

async fn serve4(
    shared: Arc<Shared>,
    state: Arc<State>,
    rt: ListenerRt,
    mut s: TcpStream,
    peer: SocketAddr,
) {
    let rt = state.listeners.get(&rt.cfg.name).unwrap_or(&rt);
    let handshake = state.cfg.timeouts.handshake;
    let req = timeout(handshake, async {
        let cmd = s.read_u8().await.ok()?;
        let port = s.read_u16().await.ok()?;
        let mut ip = [0u8; 4];
        s.read_exact(&mut ip).await.ok()?;
        let userid = read_cstr(&mut s).await?;
        // SOCKS4a: 0.0.0.x (x != 0) means a host name follows the user id.
        let host = if ip[..3] == [0, 0, 0] && ip[3] != 0 {
            clean_host(&read_cstr(&mut s).await?)?
        } else {
            Ipv4Addr::from(ip).to_string()
        };
        Some((cmd, port, String::from_utf8(userid).ok()?, host))
    })
    .await;
    let Ok(Some((cmd, port, userid, host))) = req else {
        return;
    };
    if cmd != CMD_CONNECT || port == 0 {
        let _ = s.write_all(&reply4(REJECTED, None)).await;
        return;
    }
    let started = SystemTime::now();
    let t0 = Instant::now();
    let login = match conn::authenticate_userid(&shared, &state, rt, peer.ip(), &userid) {
        Ok(l) => l,
        Err(f) => {
            let code = match f {
                LoginFailure::Invalid | LoginFailure::Missing => BAD_USERID,
                LoginFailure::Blocked => NO_IDENTD,
                _ => REJECTED,
            };
            let _ = s.write_all(&reply4(code, None)).await;
            return;
        }
    };
    let ctx = ReqCtx {
        shared: &shared,
        state: &state,
        listener: rt,
        client: peer,
        proto: Proto::Socks4,
        method: "CONNECT",
        host: &host,
        port,
        login: login.as_ref(),
        mode: Mode::Tunnel,
        reuse: false,
    };
    let mut rec = ctx.record(started, t0.elapsed(), 200, "ok");
    match conn::open(&ctx).await {
        Ok(o) => {
            rec.rule = o.rule.clone();
            rec.pool = o.pool.clone();
            rec.egress = o.egress;
            rec.target_ip = Some(o.peer);
            rec.parent = o.parent.as_ref().map(|p| p.name.clone());
            let bound = o.stream.local_addr().ok();
            if s.write_all(&reply4(GRANTED, bound)).await.is_err() {
                return;
            }
            let totals = relay(
                s,
                o.stream,
                Vec::new(),
                Vec::new(),
                o.held.admission.shaper(Dir::Up),
                o.held.admission.shaper(Dir::Down),
                state.cfg.timeouts.idle,
                state.cfg.timeouts.total,
            )
            .await;
            rec.bytes_up = totals.up;
            rec.bytes_down = totals.down;
            rec.elapsed = t0.elapsed();
            shared.log(rec);
        }
        Err(r) => {
            rec.status = r.status();
            rec.result = r.result();
            rec.rule = r.rule.clone();
            rec.elapsed = t0.elapsed();
            shared.log(rec);
            let _ = s.write_all(&reply4(REJECTED, None)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replies_encode_the_bound_address() {
        let v4 = reply5(0, Some("10.0.0.7:4242".parse().expect("addr")));
        assert_eq!(v4, vec![5, 0, 0, 1, 10, 0, 0, 7, 0x10, 0x92]);
        let v6 = reply5(5, Some("[::1]:80".parse().expect("addr")));
        assert_eq!(v6.len(), 4 + 16 + 2);
        assert_eq!(&v6[..4], &[5, 5, 0, 4]);
        assert_eq!(reply5(1, None), vec![5, 1, 0, 1, 0, 0, 0, 0, 0, 0]);
        let r4 = reply4(GRANTED, Some("10.0.0.7:4242".parse().expect("addr")));
        assert_eq!(r4, [0, 90, 0x10, 0x92, 10, 0, 0, 7]);
        assert_eq!(reply4(REJECTED, None), [0, 91, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn host_names_are_cleaned_and_junk_is_refused() {
        assert_eq!(clean_host(b"Example.COM.").as_deref(), Some("example.com"));
        for bad in [&b""[..], b"a b.test", b"a\0b", b"a/b", &[0xff, 0xfe]] {
            assert!(clean_host(bad).is_none());
        }
    }
}
