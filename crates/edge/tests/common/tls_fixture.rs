#![allow(dead_code, clippy::unwrap_used)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::{TlsConnector, client::TlsStream};

static SEQ: AtomicUsize = AtomicUsize::new(0);

pub struct TlsFixture {
    dir: PathBuf,
    cert: CertificateDer<'static>,
}

impl TlsFixture {
    pub fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "edge-tls-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        std::fs::write(dir.join("cert.pem"), cert.pem()).unwrap();
        std::fs::write(dir.join("key.pem"), key_pair.serialize_pem()).unwrap();
        Self {
            dir,
            cert: cert.der().clone(),
        }
    }

    pub fn listener(&self, protocol: &str, auth: &str) -> String {
        format!(
            "[[listener]]\nname = \"main\"\nlisten = \"127.0.0.1:0\"\nprotocol = {protocol:?}\nauth = {auth:?}\ntls = {{ cert = {:?}, key = {:?} }}\n",
            self.dir.join("cert.pem").to_str().unwrap(),
            self.dir.join("key.pem").to_str().unwrap()
        )
    }

    pub fn connector(&self, alpn: &[&[u8]], trust: bool) -> TlsConnector {
        let mut roots = rustls::RootCertStore::empty();
        if trust {
            roots.add(self.cert.clone()).unwrap();
        }
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        TlsConnector::from(Arc::new(config))
    }

    pub async fn connect(&self, addr: SocketAddr, alpn: &[&[u8]]) -> TlsStream<TcpStream> {
        self.wrap(TcpStream::connect(addr).await.unwrap(), alpn)
            .await
    }

    pub async fn wrap(&self, tcp: TcpStream, alpn: &[&[u8]]) -> TlsStream<TcpStream> {
        tokio::time::timeout(
            Duration::from_secs(3),
            self.connector(alpn, true)
                .connect(ServerName::try_from("localhost").unwrap(), tcp),
        )
        .await
        .unwrap()
        .unwrap()
    }
}

impl Drop for TlsFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

pub async fn head<S: AsyncRead + Unpin>(stream: &mut S) -> String {
    tokio::time::timeout(Duration::from_secs(3), async {
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            bytes.push(stream.read_u8().await.unwrap());
            assert!(bytes.len() < 64 * 1024);
        }
        String::from_utf8(bytes).unwrap()
    })
    .await
    .unwrap()
}

pub async fn response<S: AsyncRead + Unpin>(stream: &mut S) -> (String, Vec<u8>) {
    let head = head(stream).await;
    let len = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().unwrap())
        })
        .unwrap_or(0);
    let mut body = vec![0; len];
    tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut body))
        .await
        .unwrap()
        .unwrap();
    (head, body)
}

pub async fn greeting<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) {
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut reply = [0; 2];
    tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply, [5, 0]);
}

pub async fn request5<S: AsyncWrite + Unpin>(stream: &mut S, cmd: u8, target: SocketAddr) {
    let mut bytes = vec![5, cmd, 0];
    match target.ip() {
        IpAddr::V4(ip) => {
            bytes.push(1);
            bytes.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            bytes.push(4);
            bytes.extend_from_slice(&ip.octets());
        }
    }
    bytes.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&bytes).await.unwrap();
}

pub async fn reply5<S: AsyncRead + Unpin>(stream: &mut S) -> (u8, SocketAddr) {
    tokio::time::timeout(Duration::from_secs(3), async {
        let mut header = [0; 4];
        stream.read_exact(&mut header).await.unwrap();
        assert_eq!((header[0], header[2]), (5, 0));
        let ip = match header[3] {
            1 => {
                let mut ip = [0; 4];
                stream.read_exact(&mut ip).await.unwrap();
                IpAddr::V4(Ipv4Addr::from(ip))
            }
            4 => {
                let mut ip = [0; 16];
                stream.read_exact(&mut ip).await.unwrap();
                IpAddr::V6(Ipv6Addr::from(ip))
            }
            other => panic!("unexpected address type {other}"),
        };
        let port = stream.read_u16().await.unwrap();
        (header[1], SocketAddr::new(ip, port))
    })
    .await
    .unwrap()
}
