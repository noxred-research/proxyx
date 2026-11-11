//! HAProxy PROXY protocol, versions 1 and 2.
//!
//! [`parse`] is a pure, allocation-free parser over a byte slice. [`read_header`] drives it
//! against a live [`TcpStream`] using `peek`, so it consumes exactly the header and never a byte
//! of the payload behind it; when the first bytes are not a PROXY signature it leaves the
//! stream untouched and returns [`ProxyProtocolError::NotProxyProtocol`], which lets a listener
//! in "optional" mode treat the connection as a plain one. [`encode_v1`] and [`encode_v2`]
//! build headers for connections to a parent proxy.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::io::Interest;
use tokio::net::TcpStream;

/// v1 header: `PROXY ` prefix.
const V1_PREFIX: &[u8] = b"PROXY ";
/// Longest legal v1 header including the trailing CRLF.
const V1_MAX: usize = 107;
/// v2 header: 12-byte signature.
const V2_SIG: [u8; 12] = *b"\r\n\r\n\0\r\nQUIT\n";
/// Fixed part of a v2 header: signature, version/command, family/protocol, length.
const V2_FIXED: usize = 16;
/// Largest accepted v2 payload (addresses plus TLVs).
const V2_MAX_LEN: usize = 536;
/// Largest header either version can produce.
const MAX_HEADER: usize = V2_FIXED + V2_MAX_LEN;
/// v2 address block sizes.
const V2_INET_LEN: usize = 12;
const V2_INET6_LEN: usize = 36;
const V2_UNIX_LEN: usize = 216;

/// Addresses announced by a PROXY header. Both are `None` for `PROXY UNKNOWN`, the v2 `LOCAL`
/// command and address families that carry no usable TCP addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyHeader {
    pub src: Option<SocketAddr>,
    pub dst: Option<SocketAddr>,
}

impl ProxyHeader {
    const NONE: ProxyHeader = ProxyHeader {
        src: None,
        dst: None,
    };
}

#[derive(Debug, thiserror::Error)]
pub enum ProxyProtocolError {
    #[error("stream does not start with a PROXY protocol header")]
    NotProxyProtocol,
    #[error("malformed PROXY protocol header: {0}")]
    Malformed(&'static str),
    #[error("I/O error while reading PROXY protocol header: {0}")]
    Io(#[from] io::Error),
    #[error("timed out reading PROXY protocol header")]
    Timeout,
    #[error("PROXY protocol header too large")]
    TooLarge,
}

/// True when the bytes in `buf` are consistent with the first `buf.len()` bytes of `sig`.
fn prefix_agrees(buf: &[u8], sig: &[u8]) -> bool {
    let n = buf.len().min(sig.len());
    buf[..n] == sig[..n]
}

/// Parse a header at the start of `buf`.
///
/// `Ok(Some((header, consumed)))` when complete, `Ok(None)` when more bytes are needed,
/// `Err(NotProxyProtocol)` when the bytes cannot be a PROXY header, `Err(Malformed)` for a
/// recognised but broken header and `Err(TooLarge)` for a header over the protocol limits.
pub fn parse(buf: &[u8]) -> Result<Option<(ProxyHeader, usize)>, ProxyProtocolError> {
    if buf.is_empty() {
        return Ok(None);
    }
    let v1 = prefix_agrees(buf, V1_PREFIX);
    let v2 = prefix_agrees(buf, &V2_SIG);
    if v1 && buf.len() >= V1_PREFIX.len() {
        parse_v1(buf)
    } else if v2 && buf.len() >= V2_SIG.len() {
        parse_v2(buf)
    } else if v1 || v2 {
        Ok(None)
    } else {
        Err(ProxyProtocolError::NotProxyProtocol)
    }
}

fn parse_v1(buf: &[u8]) -> Result<Option<(ProxyHeader, usize)>, ProxyProtocolError> {
    let window = &buf[..buf.len().min(V1_MAX)];
    let Some(lf) = window.iter().position(|&b| b == b'\n') else {
        return if buf.len() >= V1_MAX {
            Err(ProxyProtocolError::TooLarge)
        } else {
            Ok(None)
        };
    };
    if lf == 0 || window[lf - 1] != b'\r' {
        return Err(ProxyProtocolError::Malformed(
            "v1 line not terminated by CRLF",
        ));
    }
    let line = std::str::from_utf8(&window[V1_PREFIX.len()..lf - 1])
        .map_err(|_| ProxyProtocolError::Malformed("v1 header is not ASCII"))?;
    let consumed = lf + 1;

    let mut fields = line.split(' ');
    match fields.next() {
        Some("UNKNOWN") => Ok(Some((ProxyHeader::NONE, consumed))),
        Some(proto @ ("TCP4" | "TCP6")) => {
            let (Some(src), Some(dst), Some(sport), Some(dport), None) = (
                fields.next(),
                fields.next(),
                fields.next(),
                fields.next(),
                fields.next(),
            ) else {
                return Err(ProxyProtocolError::Malformed("v1 field count"));
            };
            let (src_ip, dst_ip) = if proto == "TCP4" {
                (
                    src.parse::<Ipv4Addr>().map(IpAddr::V4),
                    dst.parse::<Ipv4Addr>().map(IpAddr::V4),
                )
            } else {
                (
                    src.parse::<Ipv6Addr>().map(IpAddr::V6),
                    dst.parse::<Ipv6Addr>().map(IpAddr::V6),
                )
            };
            let (Ok(src_ip), Ok(dst_ip)) = (src_ip, dst_ip) else {
                return Err(ProxyProtocolError::Malformed("v1 address"));
            };
            let header = ProxyHeader {
                src: Some(SocketAddr::new(src_ip, parse_port(sport)?)),
                dst: Some(SocketAddr::new(dst_ip, parse_port(dport)?)),
            };
            Ok(Some((header, consumed)))
        }
        _ => Err(ProxyProtocolError::Malformed("v1 protocol")),
    }
}

/// Decimal port, 1 to 5 digits, no sign and no leading zeros.
fn parse_port(s: &str) -> Result<u16, ProxyProtocolError> {
    const BAD: ProxyProtocolError = ProxyProtocolError::Malformed("v1 port");
    if s.is_empty() || s.len() > 5 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(BAD);
    }
    if s.len() > 1 && s.starts_with('0') {
        return Err(BAD);
    }
    s.parse::<u16>().map_err(|_| BAD)
}

fn parse_v2(buf: &[u8]) -> Result<Option<(ProxyHeader, usize)>, ProxyProtocolError> {
    if buf.len() < V2_FIXED {
        return Ok(None);
    }
    let ver_cmd = buf[12];
    let fam = buf[13];
    let len = usize::from(u16::from_be_bytes([buf[14], buf[15]]));
    if ver_cmd >> 4 != 2 {
        return Err(ProxyProtocolError::Malformed("v2 version"));
    }
    let local = match ver_cmd & 0x0f {
        0 => true,
        1 => false,
        _ => return Err(ProxyProtocolError::Malformed("v2 command")),
    };
    if len > V2_MAX_LEN {
        return Err(ProxyProtocolError::TooLarge);
    }
    let total = V2_FIXED + len;
    if buf.len() < total {
        return Ok(None);
    }
    if local {
        return Ok(Some((ProxyHeader::NONE, total)));
    }

    let af = fam >> 4;
    let transport = fam & 0x0f;
    if af > 3 {
        return Err(ProxyProtocolError::Malformed("v2 address family"));
    }
    if transport > 2 {
        return Err(ProxyProtocolError::Malformed("v2 transport protocol"));
    }
    let need = match af {
        1 => V2_INET_LEN,
        2 => V2_INET6_LEN,
        3 => V2_UNIX_LEN,
        _ => 0,
    };
    if len < need {
        return Err(ProxyProtocolError::Malformed("v2 address block too short"));
    }
    let addrs = &buf[V2_FIXED..total];
    // Only TCP over IPv4/IPv6 yields addresses; UNSPEC, datagram and UNIX carry none.
    let header = match (af, transport) {
        (1, 1) => {
            let src = Ipv4Addr::new(addrs[0], addrs[1], addrs[2], addrs[3]);
            let dst = Ipv4Addr::new(addrs[4], addrs[5], addrs[6], addrs[7]);
            ProxyHeader {
                src: Some(SocketAddr::new(
                    IpAddr::V4(src),
                    u16::from_be_bytes([addrs[8], addrs[9]]),
                )),
                dst: Some(SocketAddr::new(
                    IpAddr::V4(dst),
                    u16::from_be_bytes([addrs[10], addrs[11]]),
                )),
            }
        }
        (2, 1) => {
            let mut s = [0u8; 16];
            let mut d = [0u8; 16];
            s.copy_from_slice(&addrs[..16]);
            d.copy_from_slice(&addrs[16..32]);
            ProxyHeader {
                src: Some(SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::from(s)),
                    u16::from_be_bytes([addrs[32], addrs[33]]),
                )),
                dst: Some(SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::from(d)),
                    u16::from_be_bytes([addrs[34], addrs[35]]),
                )),
            }
        }
        _ => ProxyHeader::NONE,
    };
    Ok(Some((header, total)))
}

/// Read exactly one header from the front of `stream` without consuming any byte beyond it.
///
/// `deadline` bounds the whole read. When the first bytes cannot be a PROXY header the stream
/// is left untouched and `Err(NotProxyProtocol)` is returned.
pub async fn read_header(
    stream: &TcpStream,
    deadline: Duration,
) -> Result<ProxyHeader, ProxyProtocolError> {
    match tokio::time::timeout(deadline, read_inner(stream)).await {
        Ok(result) => result,
        Err(_) => Err(ProxyProtocolError::Timeout),
    }
}

async fn read_inner(stream: &TcpStream) -> Result<ProxyHeader, ProxyProtocolError> {
    const MIN_BACKOFF: Duration = Duration::from_millis(1);
    const MAX_BACKOFF: Duration = Duration::from_millis(20);

    let mut buf = [0u8; MAX_HEADER];
    let mut seen = 0usize;
    let mut backoff = MIN_BACKOFF;
    loop {
        // `peek` returns as soon as any byte is queued, so waiting for the rest of a split
        // header means polling until the queue grows.
        let n = stream.peek(&mut buf).await?;
        if n == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
        }
        if let Some((header, consumed)) = parse(&buf[..n])? {
            consume(stream, &mut buf[..consumed]).await?;
            return Ok(header);
        }
        if n > seen {
            seen = n;
            backoff = MIN_BACKOFF;
        } else if stream.ready(Interest::READABLE).await?.is_read_closed() {
            // The peer closed with a header still incomplete. Peek once more in case the
            // last bytes landed after the previous peek.
            if stream.peek(&mut buf).await? == n {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
            }
        } else {
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(MAX_BACKOFF);
        }
    }
}

/// Fill `out` with bytes read from the front of the stream.
async fn consume(stream: &TcpStream, out: &mut [u8]) -> Result<(), ProxyProtocolError> {
    let mut filled = 0;
    while filled < out.len() {
        stream.readable().await?;
        match stream.try_read(&mut out[filled..]) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into()),
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// Both addresses in the same family; mixed families are mapped into IPv6.
enum Pair {
    V4(SocketAddrV4Parts),
    V6(SocketAddrV6Parts),
}

type SocketAddrV4Parts = (Ipv4Addr, u16, Ipv4Addr, u16);
type SocketAddrV6Parts = (Ipv6Addr, u16, Ipv6Addr, u16);

fn unify(src: SocketAddr, dst: SocketAddr) -> Pair {
    match (src.ip(), dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => Pair::V4((s, src.port(), d, dst.port())),
        (s, d) => Pair::V6((to_v6(s), src.port(), to_v6(d), dst.port())),
    }
}

fn to_v6(ip: IpAddr) -> Ipv6Addr {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    }
}

/// Encode a v1 header: `PROXY TCP4|TCP6 src dst sport dport\r\n`.
pub fn encode_v1(src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
    match unify(src, dst) {
        Pair::V4((s, sp, d, dp)) => format!("PROXY TCP4 {s} {d} {sp} {dp}\r\n"),
        Pair::V6((s, sp, d, dp)) => format!("PROXY TCP6 {s} {d} {sp} {dp}\r\n"),
    }
    .into_bytes()
}

/// Encode a v2 header with the PROXY command over a stream transport.
pub fn encode_v2(src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
    let mut out = Vec::with_capacity(V2_FIXED + V2_INET6_LEN);
    out.extend_from_slice(&V2_SIG);
    out.push(0x21);
    match unify(src, dst) {
        Pair::V4((s, sp, d, dp)) => {
            out.push(0x11);
            out.extend_from_slice(&(V2_INET_LEN as u16).to_be_bytes());
            out.extend_from_slice(&s.octets());
            out.extend_from_slice(&d.octets());
            out.extend_from_slice(&sp.to_be_bytes());
            out.extend_from_slice(&dp.to_be_bytes());
        }
        Pair::V6((s, sp, d, dp)) => {
            out.push(0x21);
            out.extend_from_slice(&(V2_INET6_LEN as u16).to_be_bytes());
            out.extend_from_slice(&s.octets());
            out.extend_from_slice(&d.octets());
            out.extend_from_slice(&sp.to_be_bytes());
            out.extend_from_slice(&dp.to_be_bytes());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn sa(s: &str) -> SocketAddr {
        s.parse().expect("test address")
    }

    fn v2_header(ver_cmd: u8, fam: u8, body: &[u8]) -> Vec<u8> {
        let mut h = V2_SIG.to_vec();
        h.push(ver_cmd);
        h.push(fam);
        h.extend_from_slice(&(body.len() as u16).to_be_bytes());
        h.extend_from_slice(body);
        h
    }

    fn parsed(buf: &[u8]) -> (ProxyHeader, usize) {
        parse(buf).expect("parse ok").expect("complete header")
    }

    #[test]
    fn v1_tcp4() {
        let line = b"PROXY TCP4 192.0.2.1 198.51.100.2 56324 443\r\nGET / HTTP/1.1\r\n";
        let (h, n) = parsed(line);
        assert_eq!(h.src, Some(sa("192.0.2.1:56324")));
        assert_eq!(h.dst, Some(sa("198.51.100.2:443")));
        assert_eq!(&line[n..], b"GET / HTTP/1.1\r\n");
    }

    #[test]
    fn v1_tcp6() {
        let (h, n) = parsed(b"PROXY TCP6 2001:db8::1 ::1 0 65535\r\n");
        assert_eq!(h.src, Some(sa("[2001:db8::1]:0")));
        assert_eq!(h.dst, Some(sa("[::1]:65535")));
        assert_eq!(n, 36);
    }

    #[test]
    fn v1_unknown() {
        let (h, n) = parsed(b"PROXY UNKNOWN\r\nrest");
        assert_eq!(h, ProxyHeader::NONE);
        assert_eq!(n, 15);
        let (h, n) = parsed(b"PROXY UNKNOWN ff:::garbage 1 2 3 4 5 6\r\n");
        assert_eq!(h, ProxyHeader::NONE);
        assert_eq!(n, 40);
    }

    #[test]
    fn v1_rejects_broken_lines() {
        let bad: &[&[u8]] = &[
            b"PROXY TCP4 192.0.2.1 198.51.100.2 56324\r\n",
            b"PROXY TCP4 192.0.2.1 198.51.100.2 56324 443 1\r\n",
            b"PROXY TCP4 192.0.2.1  198.51.100.2 56324 443\r\n",
            b"PROXY TCP4 192.0.2.256 198.51.100.2 56324 443\r\n",
            b"PROXY TCP4 192.0.2.01 198.51.100.2 56324 443\r\n",
            b"PROXY TCP4 ::1 198.51.100.2 56324 443\r\n",
            b"PROXY TCP6 192.0.2.1 ::1 56324 443\r\n",
            b"PROXY TCP4 192.0.2.1 198.51.100.2 65536 443\r\n",
            b"PROXY TCP4 192.0.2.1 198.51.100.2 +80 443\r\n",
            b"PROXY TCP4 192.0.2.1 198.51.100.2 080 443\r\n",
            b"PROXY TCP4 192.0.2.1 198.51.100.2 -1 443\r\n",
            b"PROXY TCP4 192.0.2.1 198.51.100.2 80 443 \r\n",
            b"PROXY tcp4 192.0.2.1 198.51.100.2 80 443\r\n",
            b"PROXY UDP4 192.0.2.1 198.51.100.2 80 443\r\n",
            b"PROXY UNKNOWNX\r\n",
            b"PROXY TCP4 192.0.2.1 198.51.100.2 80 443\n",
            b"PROXY \r\n",
            b"PROXY TCP4 192.0.2.1 198.51.100.2 80 \xff\r\n",
        ];
        for line in bad {
            assert!(
                matches!(parse(line), Err(ProxyProtocolError::Malformed(_))),
                "accepted {:?}",
                String::from_utf8_lossy(line)
            );
        }
    }

    #[test]
    fn v1_oversized_line() {
        let mut line = b"PROXY UNKNOWN ".to_vec();
        line.resize(V1_MAX, b'a');
        assert!(matches!(parse(&line), Err(ProxyProtocolError::TooLarge)));
        // Exactly 107 bytes including CRLF is fine.
        let mut ok = b"PROXY UNKNOWN ".to_vec();
        ok.resize(V1_MAX - 2, b'a');
        ok.extend_from_slice(b"\r\n");
        assert_eq!(parsed(&ok).1, V1_MAX);
        // 108 bytes is not, even with a CRLF.
        let mut long = b"PROXY UNKNOWN ".to_vec();
        long.resize(V1_MAX - 1, b'a');
        long.extend_from_slice(b"\r\n");
        assert!(matches!(parse(&long), Err(ProxyProtocolError::TooLarge)));
    }

    #[test]
    fn v2_ipv4_and_ipv6() {
        let h = encode_v2(sa("192.0.2.1:1234"), sa("198.51.100.2:80"));
        assert_eq!(h.len(), 28);
        let (p, n) = parsed(&h);
        assert_eq!(p.src, Some(sa("192.0.2.1:1234")));
        assert_eq!(p.dst, Some(sa("198.51.100.2:80")));
        assert_eq!(n, 28);

        let h = encode_v2(sa("[2001:db8::7]:5555"), sa("[2001:db8::8]:443"));
        assert_eq!(h.len(), 52);
        let (p, n) = parsed(&h);
        assert_eq!(p.src, Some(sa("[2001:db8::7]:5555")));
        assert_eq!(p.dst, Some(sa("[2001:db8::8]:443")));
        assert_eq!(n, 52);
    }

    #[test]
    fn v2_known_bytes() {
        let mut expected = V2_SIG.to_vec();
        expected.extend_from_slice(&[0x21, 0x11, 0x00, 0x0c, 192, 0, 2, 1, 198, 51, 100, 2]);
        expected.extend_from_slice(&[0x04, 0xd2, 0x00, 0x50]);
        assert_eq!(
            encode_v2(sa("192.0.2.1:1234"), sa("198.51.100.2:80")),
            expected
        );
    }

    #[test]
    fn v2_local_and_unspec_and_dgram() {
        // LOCAL ignores the address block.
        let h = v2_header(0x20, 0x11, &[0; 12]);
        assert_eq!(parsed(&h), (ProxyHeader::NONE, h.len()));
        let h = v2_header(0x20, 0x00, &[]);
        assert_eq!(parsed(&h), (ProxyHeader::NONE, 16));
        // UNSPEC consumes its (possibly non-empty) body.
        let h = v2_header(0x21, 0x00, &[1, 2, 3]);
        assert_eq!(parsed(&h), (ProxyHeader::NONE, 19));
        // DGRAM has addresses we do not report.
        let h = v2_header(0x21, 0x12, &[0; 12]);
        assert_eq!(parsed(&h), (ProxyHeader::NONE, 28));
        let h = v2_header(0x21, 0x22, &[0; 36]);
        assert_eq!(parsed(&h), (ProxyHeader::NONE, 52));
        // UNIX stream: consumed, no addresses.
        let h = v2_header(0x21, 0x31, &[0; 216]);
        assert_eq!(parsed(&h), (ProxyHeader::NONE, 232));
    }

    #[test]
    fn v2_skips_tlvs() {
        let mut body = vec![192, 0, 2, 1, 198, 51, 100, 2, 0x04, 0xd2, 0x00, 0x50];
        body.extend_from_slice(&[0x04, 0x00, 0x03, b'a', b'b', b'c']); // a TLV
        let mut h = v2_header(0x21, 0x11, &body);
        h.extend_from_slice(b"payload");
        let (p, n) = parsed(&h);
        assert_eq!(p.src, Some(sa("192.0.2.1:1234")));
        assert_eq!(&h[n..], b"payload");
    }

    #[test]
    fn v2_rejects_broken_headers() {
        let bad = [
            v2_header(0x11, 0x11, &[0; 12]),  // version 1
            v2_header(0x31, 0x11, &[0; 12]),  // version 3
            v2_header(0x22, 0x11, &[0; 12]),  // command 2
            v2_header(0x21, 0x11, &[0; 11]),  // short INET block
            v2_header(0x21, 0x21, &[0; 35]),  // short INET6 block
            v2_header(0x21, 0x31, &[0; 215]), // short UNIX block
            v2_header(0x21, 0x41, &[0; 12]),  // unknown family
            v2_header(0x21, 0x13, &[0; 12]),  // unknown transport
            v2_header(0x21, 0x11, &[]),       // empty body
        ];
        for h in &bad {
            assert!(
                matches!(parse(h), Err(ProxyProtocolError::Malformed(_))),
                "accepted {h:02x?}"
            );
        }
    }

    #[test]
    fn v2_oversized() {
        let mut h = V2_SIG.to_vec();
        h.extend_from_slice(&[0x21, 0x11]);
        h.extend_from_slice(&((V2_MAX_LEN + 1) as u16).to_be_bytes());
        assert!(matches!(parse(&h), Err(ProxyProtocolError::TooLarge)));
        // Exactly the limit is accepted once complete.
        let h = v2_header(0x21, 0x00, &[0; V2_MAX_LEN]);
        assert_eq!(parsed(&h).1, MAX_HEADER);
    }

    #[test]
    fn every_prefix_is_incomplete_or_final() {
        let mut samples: Vec<Vec<u8>> = vec![
            b"PROXY TCP4 192.0.2.1 198.51.100.2 56324 443\r\n".to_vec(),
            b"PROXY TCP6 2001:db8::1 ::1 1 2\r\n".to_vec(),
            b"PROXY UNKNOWN\r\n".to_vec(),
            encode_v2(sa("192.0.2.1:1"), sa("198.51.100.2:2")),
            encode_v2(sa("[::1]:1"), sa("[::2]:2")),
            v2_header(0x20, 0x00, &[]),
        ];
        let tlv = vec![192, 0, 2, 1, 198, 51, 100, 2, 0, 1, 0, 2, 0x20, 0, 1, 9];
        samples.push(v2_header(0x21, 0x11, &tlv));
        for full in &samples {
            let (want, want_n) = parsed(full);
            assert_eq!(want_n, full.len());
            for k in 0..full.len() {
                assert!(
                    matches!(parse(&full[..k]), Ok(None)),
                    "prefix {k} of {:?}",
                    String::from_utf8_lossy(full)
                );
            }
            let mut with_tail = full.clone();
            with_tail.extend_from_slice(b"tail");
            assert_eq!(parsed(&with_tail), (want, want_n));
        }
    }

    #[test]
    fn non_proxy_data_is_detected_early() {
        let plain: &[&[u8]] = &[
            b"G",
            b"GET / HTTP/1.1\r\n",
            b"CONNECT a:1 HTTP/1.1\r\n",
            b"\x05\x01\x00",
            b"\x04\x01\x00\x50",
            b"PROXX ",
            b"PROXYX",
            b"\r\n\r\n\0\r\nQUIX",
            b"\r\n\r\nGET",
            b"\x16\x03\x01",
        ];
        for data in plain {
            assert!(
                matches!(parse(data), Err(ProxyProtocolError::NotProxyProtocol)),
                "{:?}",
                String::from_utf8_lossy(data)
            );
        }
        // A prefix of a signature is not yet decidable.
        assert!(matches!(parse(b""), Ok(None)));
        assert!(matches!(parse(b"P"), Ok(None)));
        assert!(matches!(parse(b"PROXY"), Ok(None)));
        assert!(matches!(parse(b"\r\n\r\n\0"), Ok(None)));
    }

    #[test]
    fn garbage_after_signature_is_malformed() {
        assert!(matches!(
            parse(b"PROXY garbage here\r\n"),
            Err(ProxyProtocolError::Malformed(_))
        ));
    }

    #[test]
    fn v1_round_trip() {
        for (s, d) in [
            ("192.0.2.1:1", "198.51.100.2:65535"),
            (
                "[2001:db8::1]:40000",
                "[2001:db8:ffff:ffff:ffff:ffff:ffff:ffff]:443",
            ),
        ] {
            let h = encode_v1(sa(s), sa(d));
            let (p, n) = parsed(&h);
            assert_eq!((p.src, p.dst, n), (Some(sa(s)), Some(sa(d)), h.len()));
            assert!(h.len() <= V1_MAX);
        }
        assert_eq!(
            encode_v1(sa("192.0.2.1:1234"), sa("198.51.100.2:80")),
            b"PROXY TCP4 192.0.2.1 198.51.100.2 1234 80\r\n"
        );
        assert!(encode_v1(sa("[2001:db8::1]:1"), sa("[::1]:2")).starts_with(b"PROXY TCP6 "));
    }

    #[test]
    fn mixed_families_map_to_v6() {
        let src = sa("192.0.2.1:1000");
        let dst = sa("[2001:db8::2]:2000");
        let want_src = sa("[::ffff:192.0.2.1]:1000");
        for h in [encode_v1(src, dst), encode_v2(src, dst)] {
            let (p, n) = parsed(&h);
            assert_eq!((p.src, p.dst, n), (Some(want_src), Some(dst), h.len()));
        }
        assert!(encode_v1(src, dst).starts_with(b"PROXY TCP6 ::ffff:192.0.2.1 "));
        let (p, _) = parsed(&encode_v2(dst, src));
        assert_eq!(p.dst, Some(want_src));
    }

    async fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (client, server) = tokio::join!(TcpStream::connect(addr), listener.accept());
        (client.expect("connect"), server.expect("accept").0)
    }

    async fn drain(mut server: TcpStream, mut client: TcpStream) -> Vec<u8> {
        client.shutdown().await.expect("shutdown");
        let mut rest = Vec::new();
        server.read_to_end(&mut rest).await.expect("read rest");
        rest
    }

    #[tokio::test]
    async fn stream_leaves_payload_unread_v1() {
        let (mut client, server) = pair().await;
        client
            .write_all(b"PROXY TCP4 192.0.2.1 198.51.100.2 1234 80\r\nGET / HTTP/1.1\r\n\r\n")
            .await
            .expect("write");
        let h = read_header(&server, Duration::from_secs(5))
            .await
            .expect("header");
        assert_eq!(h.src, Some(sa("192.0.2.1:1234")));
        assert_eq!(h.dst, Some(sa("198.51.100.2:80")));
        assert_eq!(drain(server, client).await, b"GET / HTTP/1.1\r\n\r\n");
    }

    #[tokio::test]
    async fn stream_leaves_payload_unread_v2() {
        let (mut client, server) = pair().await;
        let mut data = encode_v2(sa("[2001:db8::1]:9"), sa("[2001:db8::2]:10"));
        data.extend_from_slice(b"\x05\x01\x00");
        client.write_all(&data).await.expect("write");
        let h = read_header(&server, Duration::from_secs(5))
            .await
            .expect("header");
        assert_eq!(h.src, Some(sa("[2001:db8::1]:9")));
        assert_eq!(drain(server, client).await, b"\x05\x01\x00");
    }

    #[tokio::test]
    async fn stream_header_split_across_writes() {
        let (mut client, server) = pair().await;
        let full = encode_v2(sa("192.0.2.1:1"), sa("198.51.100.2:2"));
        let writer = tokio::spawn(async move {
            for chunk in full.chunks(5) {
                client.write_all(chunk).await.expect("write chunk");
                client.flush().await.expect("flush");
                tokio::time::sleep(Duration::from_millis(15)).await;
            }
            client.write_all(b"after").await.expect("write tail");
            client
        });
        let h = read_header(&server, Duration::from_secs(5))
            .await
            .expect("header");
        assert_eq!(h.dst, Some(sa("198.51.100.2:2")));
        let client = writer.await.expect("writer task");
        assert_eq!(drain(server, client).await, b"after");
    }

    #[tokio::test]
    async fn optional_mode_leaves_plain_http_untouched() {
        let (mut client, server) = pair().await;
        let req = b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n";
        client.write_all(req).await.expect("write");
        let err = read_header(&server, Duration::from_secs(5))
            .await
            .expect_err("not a PROXY header");
        assert!(matches!(err, ProxyProtocolError::NotProxyProtocol));
        assert_eq!(drain(server, client).await, req);
    }

    #[tokio::test]
    async fn stream_errors() {
        // Broken header.
        let (mut client, server) = pair().await;
        client
            .write_all(b"PROXY TCP4 nope\r\n")
            .await
            .expect("write");
        assert!(matches!(
            read_header(&server, Duration::from_secs(5)).await,
            Err(ProxyProtocolError::Malformed(_))
        ));

        // Silent peer.
        let (client, server) = pair().await;
        assert!(matches!(
            read_header(&server, Duration::from_millis(50)).await,
            Err(ProxyProtocolError::Timeout)
        ));
        drop(client);

        // Header cut off mid-way, then EOF.
        let (mut client, server) = pair().await;
        client.write_all(b"PROXY TCP4 192.0").await.expect("write");
        drop(client);
        assert!(matches!(
            read_header(&server, Duration::from_secs(5)).await,
            Err(ProxyProtocolError::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof
        ));

        // Oversized v2 length.
        let (mut client, server) = pair().await;
        let mut h = V2_SIG.to_vec();
        h.extend_from_slice(&[0x21, 0x11, 0xff, 0xff]);
        client.write_all(&h).await.expect("write");
        assert!(matches!(
            read_header(&server, Duration::from_secs(5)).await,
            Err(ProxyProtocolError::TooLarge)
        ));
    }
}
