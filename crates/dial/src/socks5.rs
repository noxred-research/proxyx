//! SOCKS5 client (RFC 1928 CONNECT, RFC 1929 username/password).

use std::net::IpAddr;

use common::types::UpstreamEndpoint;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::DialError;

const VERSION: u8 = 0x05;
const METHOD_NONE: u8 = 0x00;
const METHOD_PASSWORD: u8 = 0x02;
const METHOD_REFUSED: u8 = 0xff;
const AUTH_VERSION: u8 = 0x01;
const ATYP_V4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_V6: u8 = 0x04;

pub(crate) async fn connect<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    up: &UpstreamEndpoint,
    host: &str,
    port: u16,
) -> Result<(), DialError> {
    let wants_auth = !up.username.is_empty();
    let greeting: &[u8] = if wants_auth {
        &[VERSION, 2, METHOD_NONE, METHOD_PASSWORD]
    } else {
        &[VERSION, 1, METHOD_NONE]
    };
    stream.write_all(greeting).await.map_err(DialError::Io)?;

    let mut choice = [0u8; 2];
    stream
        .read_exact(&mut choice)
        .await
        .map_err(DialError::Io)?;
    if choice[0] != VERSION {
        return Err(DialError::Protocol("not a SOCKS5 server"));
    }
    match choice[1] {
        METHOD_NONE => {}
        // A server that asks for a login we do not have is a credential failure.
        METHOD_PASSWORD if wants_auth => password_auth(stream, up).await?,
        METHOD_PASSWORD | METHOD_REFUSED => return Err(DialError::Auth),
        _ => return Err(DialError::Protocol("unsupported SOCKS5 method")),
    }

    stream
        .write_all(&request(host, port)?)
        .await
        .map_err(DialError::Io)?;
    read_reply(stream).await
}

async fn password_auth<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    up: &UpstreamEndpoint,
) -> Result<(), DialError> {
    let user = up.username.expose().as_bytes();
    let pass = up.password.expose().as_bytes();
    let (Ok(user_len), Ok(pass_len)) = (u8::try_from(user.len()), u8::try_from(pass.len())) else {
        return Err(DialError::BadCredential(
            "SOCKS5 limits fields to 255 bytes",
        ));
    };
    let mut msg = Vec::with_capacity(3 + user.len() + pass.len());
    msg.extend_from_slice(&[AUTH_VERSION, user_len]);
    msg.extend_from_slice(user);
    msg.push(pass_len);
    msg.extend_from_slice(pass);
    stream.write_all(&msg).await.map_err(DialError::Io)?;

    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await.map_err(DialError::Io)?;
    if reply[0] != AUTH_VERSION {
        return Err(DialError::Protocol("bad SOCKS5 auth reply version"));
    }
    if reply[1] != 0 {
        return Err(DialError::Auth);
    }
    Ok(())
}

/// CONNECT request. An IP literal goes as an address, not as a name, so the
/// upstream does not resolve a string that is already an address.
fn request(host: &str, port: u16) -> Result<Vec<u8>, DialError> {
    let mut req = Vec::with_capacity(7 + host.len());
    req.extend_from_slice(&[VERSION, 0x01, 0x00]);
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            req.push(ATYP_V4);
            req.extend_from_slice(&ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            req.push(ATYP_V6);
            req.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            let len = u8::try_from(host.len())
                .map_err(|_| DialError::BadTarget("host longer than 255 bytes"))?;
            req.extend_from_slice(&[ATYP_DOMAIN, len]);
            req.extend_from_slice(host.as_bytes());
        }
    }
    req.extend_from_slice(&port.to_be_bytes());
    Ok(req)
}

/// Read the reply and the bound address that follows it, so the stream is
/// left at the first tunnel byte.
async fn read_reply<S: AsyncRead + Unpin>(stream: &mut S) -> Result<(), DialError> {
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await.map_err(DialError::Io)?;
    if head[0] != VERSION {
        return Err(DialError::Protocol("bad SOCKS5 reply version"));
    }
    if head[1] != 0 {
        return Err(DialError::SocksReply(head[1]));
    }
    let rest = match head[3] {
        ATYP_V4 => 4 + 2,
        ATYP_V6 => 16 + 2,
        ATYP_DOMAIN => usize::from(stream.read_u8().await.map_err(DialError::Io)?) + 2,
        _ => return Err(DialError::Protocol("unknown SOCKS5 address type")),
    };
    let mut bound = [0u8; 258];
    stream
        .read_exact(&mut bound[..rest])
        .await
        .map_err(DialError::Io)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::request;

    #[test]
    fn request_encodes_name_v4_and_v6() {
        assert_eq!(
            request("example.com", 443).ok(),
            Some([&[5, 1, 0, 3, 11][..], b"example.com", &[0x01, 0xbb]].concat())
        );
        assert_eq!(
            request("1.2.3.4", 80).ok(),
            Some(vec![5, 1, 0, 1, 1, 2, 3, 4, 0, 80])
        );
        let v6 = request("::1", 80).ok();
        let mut expect = vec![5, 1, 0, 4];
        expect.extend_from_slice(&[0; 15]);
        expect.extend_from_slice(&[1, 0, 80]);
        assert_eq!(v6, Some(expect));
    }

    #[test]
    fn request_refuses_a_name_over_255_bytes() {
        let long = "a".repeat(256);
        assert!(request(&long, 80).is_err());
        assert!(request(&"a".repeat(255), 80).is_ok());
    }
}
