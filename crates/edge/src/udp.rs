//! SOCKS5 UDP ASSOCIATE (RFC 1928 7).
//!
//! The association lives as long as the client's TCP control connection. The
//! client sends datagrams to the relay socket, each with a SOCKS5 UDP header;
//! the relay checks every new destination against the access rules and the
//! destination denial, sends from an egress address of the destination's IP
//! family, and wraps replies from destinations it sent to. Fragmentation is
//! not supported (datagrams with `FRAG != 0` are dropped).

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Instant, SystemTime};

use tokio::io::AsyncReadExt as _;
use tokio::io::AsyncWriteExt as _;
use tokio::net::{TcpStream, UdpSocket};

use crate::acl::Proto;
use crate::auth::Login;
use crate::conn::{self, ReqCtx, Shared};
use crate::connect::Mode;
use crate::egress::{Family, Lease, PickKey};
use crate::limits::{Dir, Shaper};
use crate::socks::reply5;
use crate::state::{ListenerRt, State};

/// Distinct destinations remembered per association.
const MAX_DESTINATIONS: usize = 1024;

struct Out {
    sock: UdpSocket,
    _lease: Option<Lease>,
}

/// Parse the SOCKS5 UDP header; returns the destination (host text, port) and the payload offset.
fn parse_header(d: &[u8]) -> Option<(String, u16, usize)> {
    if d.len() < 4 || d[0] != 0 || d[1] != 0 || d[2] != 0 {
        return None;
    }
    let (host, end) = match d[3] {
        1 => {
            let b: [u8; 4] = d.get(4..8)?.try_into().ok()?;
            (IpAddr::from(b).to_string(), 8)
        }
        4 => {
            let b: [u8; 16] = d.get(4..20)?.try_into().ok()?;
            (IpAddr::from(b).to_string(), 20)
        }
        3 => {
            let n = usize::from(*d.get(4)?);
            let raw = d.get(5..5 + n)?;
            let name = std::str::from_utf8(raw)
                .ok()?
                .trim_end_matches('.')
                .to_ascii_lowercase();
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
            {
                return None;
            }
            (name, 5 + n)
        }
        _ => return None,
    };
    let port = u16::from_be_bytes(d.get(end..end + 2)?.try_into().ok()?);
    Some((host, port, end + 2))
}

fn wrap(src: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0, 0, 0];
    crate::socks::encode_addr(src, &mut out);
    out.extend_from_slice(payload);
    out
}

async fn recv_opt(o: &Option<Out>, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
    match o {
        Some(o) => o.sock.recv_from(buf).await,
        None => std::future::pending().await,
    }
}

pub async fn associate(
    shared: Arc<Shared>,
    state: Arc<State>,
    rt: &ListenerRt,
    mut control: TcpStream,
    peer: SocketAddr,
    login: Option<Login>,
    _requested: (String, u16),
) {
    let started = SystemTime::now();
    let t0 = Instant::now();
    let metrics = &shared.metrics;
    let local_ip = match control.local_addr() {
        Ok(a) => a.ip(),
        Err(_) => return,
    };
    let relay_sock = match UdpSocket::bind(SocketAddr::new(local_ip, 0)).await {
        Ok(s) => s,
        Err(_) => {
            let _ = control.write_all(&reply5(0x01, None)).await;
            return;
        }
    };
    let Ok(bound) = relay_sock.local_addr() else {
        return;
    };
    if control.write_all(&reply5(0x00, Some(bound))).await.is_err() {
        return;
    }
    metrics
        .udp_associations_open
        .with_label_values(&[&rt.cfg.name])
        .inc();

    // Limits of the association: admitted once, as a UDP request without a destination.
    let unspec: IpAddr = [0, 0, 0, 0].into();
    let ctx0 = ReqCtx {
        shared: &shared,
        state: &state,
        listener: rt,
        client: peer,
        proto: Proto::Udp,
        method: "UDP",
        host: "0.0.0.0",
        port: 0,
        login: login.as_ref(),
        mode: Mode::Tunnel,
        reuse: false,
    };
    let admission = state.limits.admit(&ctx0.req(&[unspec]));
    let (up, down) = match &admission {
        Ok(a) => (a.shaper(Dir::Up), a.shaper(Dir::Down)),
        Err(_) => (Shaper::none(), Shaper::none()),
    };
    let pool = state
        .egress_for(&ctx0.req(&[unspec]), login.as_ref(), rt)
        .ok()
        .and_then(|p| p.pool);
    let index = login.as_ref().and_then(|l| l.options.ip);

    let mut out4: Option<Out> = None;
    let mut out6: Option<Out> = None;
    let mut client_addr: Option<SocketAddr> = None;
    let mut sent_to: HashSet<SocketAddr> = HashSet::new();
    let mut decided: HashMap<(String, u16), Option<Vec<IpAddr>>> = HashMap::new();
    let (mut bytes_up, mut bytes_down) = (0u64, 0u64);
    let mut last_egress: Option<IpAddr> = None;
    let idle = state.cfg.timeouts.idle;
    let total = state.cfg.timeouts.total;
    let began = tokio::time::Instant::now();
    let mut last = tokio::time::Instant::now();

    let mut ctl = [0u8; 64];
    let mut buf_c = vec![0u8; 65_535];
    let mut buf_4 = vec![0u8; 65_535];
    let mut buf_6 = vec![0u8; 65_535];
    let refused = admission.is_err();

    loop {
        let deadline = last + idle;
        tokio::select! {
            // The control connection closing ends the association.
            r = control.read(&mut ctl) => {
                match r { Ok(0) | Err(_) => break, Ok(_) => {} }
            }
            _ = tokio::time::sleep_until(deadline) => break,
            () = async {
                if total.is_zero() {
                    std::future::pending::<()>().await;
                } else {
                    tokio::time::sleep_until(began + total).await;
                }
            } => break,
            r = relay_sock.recv_from(&mut buf_c) => {
                let Ok((n, src)) = r else { continue };
                if refused || src.ip() != peer.ip() {
                    continue;
                }
                if client_addr.is_some_and(|c| c != src) {
                    continue;
                }
                client_addr = Some(src);
                let Some((host, port, off)) = parse_header(&buf_c[..n]) else { continue };
                let payload = &buf_c[off..n];
                let key = (host.clone(), port);
                if !decided.contains_key(&key) {
                    if decided.len() >= MAX_DESTINATIONS {
                        continue;
                    }
                    let ctx = ReqCtx {
                        shared: &shared,
                        state: &state,
                        listener: rt,
                        client: peer,
                        proto: Proto::Udp,
                        method: "UDP",
                        host: &host,
                        port,
                        login: login.as_ref(),
                        mode: Mode::Tunnel,
                        reuse: false,
                    };
                    let ips = conn::check(&ctx).await.ok().map(|c| c.ips);
                    decided.insert(key.clone(), ips);
                }
                let Some(Some(ips)) = decided.get(&key) else { continue };
                // First address that has an egress address of its family.
                for ip in ips {
                    let ip = match ip {
                        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(*ip, IpAddr::V4),
                        v4 => *v4,
                    };
                    let slot = if ip.is_ipv4() { &mut out4 } else { &mut out6 };
                    if slot.is_none() {
                        let (src_ip, lease) = match &pool {
                            Some(p) => {
                                let k = PickKey {
                                    session: login.as_ref().and_then(|l| l.options.sid.as_deref()),
                                    user: login.as_ref().map(|l| l.user.name.as_str()),
                                    client: peer.ip(),
                                };
                                match p.pick(Family::of(ip), &k, index, &[]) {
                                    Ok(l) => (Some(l.ip()), Some(l)),
                                    Err(_) => continue,
                                }
                            }
                            None => (None, None),
                        };
                        let bind: SocketAddr = match src_ip {
                            Some(s) => SocketAddr::new(s, 0),
                            None if ip.is_ipv4() => ([0, 0, 0, 0], 0).into(),
                            None => ([0u16; 8], 0).into(),
                        };
                        let Ok(sock) = UdpSocket::bind(bind).await else { continue };
                        *slot = Some(Out { sock, _lease: lease });
                    }
                    let Some(o) = slot.as_ref() else { continue };
                    up.pace(payload.len()).await;
                    let dst = SocketAddr::new(ip, port);
                    if o.sock.send_to(payload, dst).await.is_ok() {
                        sent_to.insert(dst);
                        bytes_up += payload.len() as u64;
                        last = tokio::time::Instant::now();
                        last_egress = o.sock.local_addr().ok().map(|a| a.ip());
                        break;
                    }
                }
            }
            r = recv_opt(&out4, &mut buf_4) => {
                let Ok((n, src)) = r else { continue };
                if let Some(c) = client_addr
                    && sent_to.contains(&src)
                {
                    down.pace(n).await;
                    let _ = relay_sock.send_to(&wrap(src, &buf_4[..n]), c).await;
                    bytes_down += n as u64;
                    last = tokio::time::Instant::now();
                }
            }
            r = recv_opt(&out6, &mut buf_6) => {
                let Ok((n, src)) = r else { continue };
                if let Some(c) = client_addr
                    && sent_to.contains(&src)
                {
                    down.pace(n).await;
                    let _ = relay_sock.send_to(&wrap(src, &buf_6[..n]), c).await;
                    bytes_down += n as u64;
                    last = tokio::time::Instant::now();
                }
            }
        }
    }
    metrics
        .udp_associations_open
        .with_label_values(&[&rt.cfg.name])
        .dec();
    let mut rec = ctx0.record(
        started,
        t0.elapsed(),
        if refused { 429 } else { 200 },
        if refused { "limited" } else { "ok" },
    );
    rec.url = format!("udp://{bound}");
    rec.egress = last_egress;
    rec.pool = pool.as_ref().map(|p| p.name().to_owned());
    rec.bytes_up = bytes_up;
    rec.bytes_down = bytes_down;
    shared.log(rec);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers_parse_for_every_address_type() {
        let mut d = vec![0, 0, 0, 1, 203, 0, 113, 5, 0x00, 0x35];
        d.extend_from_slice(b"payload");
        let (h, p, off) = parse_header(&d).expect("v4");
        assert_eq!(
            (h.as_str(), p, &d[off..]),
            ("203.0.113.5", 53, &b"payload"[..])
        );
        let mut d = vec![0, 0, 0, 3, 11];
        d.extend_from_slice(b"Example.COM");
        d.extend_from_slice(&[0x01, 0xbb, b'x']);
        let (h, p, off) = parse_header(&d).expect("name");
        assert_eq!((h.as_str(), p, &d[off..]), ("example.com", 443, &b"x"[..]));
        let mut d = vec![0, 0, 0, 4];
        d.extend_from_slice(&[0; 15]);
        d.extend_from_slice(&[1, 0, 80]);
        let (h, p, _) = parse_header(&d).expect("v6");
        assert_eq!((h.as_str(), p), ("::1", 80));
    }

    #[test]
    fn fragments_and_garbage_are_refused() {
        assert!(
            parse_header(&[0, 0, 1, 1, 1, 2, 3, 4, 0, 1]).is_none(),
            "FRAG != 0"
        );
        assert!(
            parse_header(&[1, 0, 0, 1, 1, 2, 3, 4, 0, 1]).is_none(),
            "RSV != 0"
        );
        assert!(parse_header(&[0, 0, 0, 9]).is_none());
        assert!(parse_header(&[0, 0, 0, 1, 1, 2]).is_none());
        assert!(parse_header(&[0, 0, 0, 3, 200, b'a']).is_none());
        assert!(parse_header(&[0, 0, 0, 3, 3, b'a', b' ', b'b', 0, 1]).is_none());
    }

    #[test]
    fn replies_are_wrapped_with_the_source() {
        let w = wrap("10.0.0.1:53".parse().expect("addr"), b"hi");
        assert_eq!(w, vec![0, 0, 0, 1, 10, 0, 0, 1, 0, 53, b'h', b'i']);
    }
}
