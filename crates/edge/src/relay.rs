//! Two-way copy between the client and the upstream, with bandwidth shaping
//! and an idle timeout.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::time::Instant;

use crate::limits::Shaper;

const BUF: usize = 16 * 1024;

/// Bytes moved in each direction.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Totals {
    pub up: u64,
    pub down: u64,
}

struct Activity {
    started: Instant,
    last_ms: AtomicU64,
}

impl Activity {
    fn touch(&self) {
        let ms = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last_ms.store(ms, Ordering::Relaxed);
    }

    fn idle_for(&self) -> Duration {
        let now = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        Duration::from_millis(now.saturating_sub(self.last_ms.load(Ordering::Relaxed)))
    }
}

async fn pump<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut r: R,
    mut w: W,
    first: Vec<u8>,
    shaper: Shaper,
    moved: Arc<AtomicU64>,
    act: Arc<Activity>,
) -> io::Result<()> {
    if !first.is_empty() {
        shaper.pace(first.len()).await;
        w.write_all(&first).await?;
        moved.fetch_add(first.len() as u64, Ordering::Relaxed);
        act.touch();
    }
    let mut buf = vec![0u8; BUF];
    loop {
        let lim = shaper.chunk(buf.len());
        let n = r.read(&mut buf[..lim]).await?;
        if n == 0 {
            // Pass the end of this direction on and let the other one finish.
            let _ = w.shutdown().await;
            return Ok(());
        }
        act.touch();
        shaper.pace(n).await;
        w.write_all(&buf[..n]).await?;
        moved.fetch_add(n as u64, Ordering::Relaxed);
        act.touch();
    }
}

/// Copy until both directions end, one fails, nothing moves for `idle`, or
/// `total` (when not zero) has passed since the start.
/// `client_first` holds bytes the client sent before the tunnel opened (they
/// go to the upstream first); `upstream_first` the same the other way.
#[allow(clippy::too_many_arguments)]
pub async fn relay<C: AsyncRead + AsyncWrite + Unpin, U: AsyncRead + AsyncWrite + Unpin>(
    client: C,
    upstream: U,
    client_first: Vec<u8>,
    upstream_first: Vec<u8>,
    up: Shaper,
    down: Shaper,
    idle: Duration,
    total: Duration,
) -> Totals {
    let (cr, cw) = tokio::io::split(client);
    let (ur, uw) = tokio::io::split(upstream);
    let act = Arc::new(Activity {
        started: Instant::now(),
        last_ms: AtomicU64::new(0),
    });
    let (up_n, down_n) = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
    let a = pump(
        cr,
        uw,
        client_first,
        up,
        Arc::clone(&up_n),
        Arc::clone(&act),
    );
    let b = pump(
        ur,
        cw,
        upstream_first,
        down,
        Arc::clone(&down_n),
        Arc::clone(&act),
    );
    tokio::pin!(a, b);
    let (mut a_done, mut b_done) = (false, false);
    let mut check = (idle / 4).max(Duration::from_millis(20));
    if !total.is_zero() {
        check = check.min((total / 4).max(Duration::from_millis(20)));
    }
    let began = Instant::now();
    let mut tick = tokio::time::interval(check);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    while !(a_done && b_done) {
        tokio::select! {
            r = &mut a, if !a_done => {
                a_done = true;
                if r.is_err() { break; }
            }
            r = &mut b, if !b_done => {
                b_done = true;
                if r.is_err() { break; }
            }
            _ = tick.tick() => {
                if act.idle_for() >= idle { break; }
                if !total.is_zero() && began.elapsed() >= total { break; }
            }
        }
    }
    Totals {
        up: up_n.load(Ordering::Relaxed),
        down: down_n.load(Ordering::Relaxed),
    }
}

#[cfg(test)]
mod tests {
    use tokio::net::{TcpListener, TcpStream};

    use super::*;

    async fn pair() -> (TcpStream, TcpStream) {
        let l = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = l.local_addr().expect("addr");
        let (a, b) = tokio::join!(TcpStream::connect(addr), l.accept());
        (a.expect("connect"), b.expect("accept").0)
    }

    #[tokio::test]
    async fn generic_duplex_transport_preserves_half_close() {
        let (mut client, incoming) = tokio::io::duplex(128);
        let (mut target, outgoing) = tokio::io::duplex(128);
        let task = tokio::spawn(relay(
            incoming,
            outgoing,
            Vec::new(),
            Vec::new(),
            Shaper::none(),
            Shaper::none(),
            Duration::from_secs(1),
            Duration::ZERO,
        ));
        client.write_all(b"request").await.expect("request");
        client.shutdown().await.expect("half close");
        let mut received = Vec::new();
        target
            .read_to_end(&mut received)
            .await
            .expect("request EOF");
        assert_eq!(received, b"request");
        target.write_all(b"response").await.expect("response");
        target.shutdown().await.expect("half close");
        let mut received = Vec::new();
        client
            .read_to_end(&mut received)
            .await
            .expect("response EOF");
        assert_eq!(received, b"response");
        assert_eq!(task.await.expect("relay"), Totals { up: 7, down: 8 });
    }

    #[tokio::test]
    async fn bytes_flow_both_ways_with_early_data_and_half_close() {
        let (mut c_peer, c_srv) = pair().await;
        let (mut u_peer, u_srv) = pair().await;
        let h = tokio::spawn(relay(
            c_srv,
            u_srv,
            b"early-up".to_vec(),
            b"early-down".to_vec(),
            Shaper::none(),
            Shaper::none(),
            Duration::from_secs(5),
            Duration::ZERO,
        ));
        c_peer.write_all(b"-more").await.expect("write");
        let mut got = vec![0u8; 13];
        u_peer.read_exact(&mut got).await.expect("read");
        assert_eq!(got, b"early-up-more");
        u_peer.write_all(b"pong").await.expect("write");
        let mut got = vec![0u8; 14];
        c_peer.read_exact(&mut got).await.expect("read");
        assert_eq!(got, b"early-downpong");
        // client half-closes; the upstream still answers
        c_peer.shutdown().await.expect("shutdown");
        let mut rest = Vec::new();
        u_peer.read_to_end(&mut rest).await.expect("eof");
        u_peer.write_all(b"tail").await.expect("write");
        u_peer.shutdown().await.expect("shutdown");
        let mut tail = Vec::new();
        c_peer.read_to_end(&mut tail).await.expect("read");
        assert_eq!(tail, b"tail");
        let t = h.await.expect("join");
        assert_eq!(t, Totals { up: 13, down: 18 });
    }

    #[tokio::test]
    async fn a_silent_tunnel_is_closed_after_the_idle_time() {
        let (_c_peer, c_srv) = pair().await;
        let (_u_peer, u_srv) = pair().await;
        let started = Instant::now();
        let t = relay(
            c_srv,
            u_srv,
            Vec::new(),
            Vec::new(),
            Shaper::none(),
            Shaper::none(),
            Duration::from_millis(300),
            Duration::ZERO,
        )
        .await;
        assert_eq!(t, Totals::default());
        let took = started.elapsed();
        assert!(
            took >= Duration::from_millis(250) && took < Duration::from_secs(3),
            "{took:?}"
        );
    }

    #[tokio::test]
    async fn a_reset_ends_the_relay() {
        let (c_peer, c_srv) = pair().await;
        let (_u_peer, u_srv) = pair().await;
        let h = tokio::spawn(relay(
            c_srv,
            u_srv,
            Vec::new(),
            Vec::new(),
            Shaper::none(),
            Shaper::none(),
            Duration::from_secs(30),
            Duration::ZERO,
        ));
        socket2::SockRef::from(&c_peer)
            .set_linger(Some(Duration::ZERO))
            .expect("linger");
        drop(c_peer);
        tokio::time::timeout(Duration::from_secs(3), h)
            .await
            .expect("relay ends")
            .expect("join");
    }

    #[tokio::test]
    async fn a_busy_tunnel_still_ends_at_the_total_limit() {
        let (mut c_peer, c_srv) = pair().await;
        let (_u_peer, u_srv) = pair().await;
        let h = tokio::spawn(relay(
            c_srv,
            u_srv,
            Vec::new(),
            Vec::new(),
            Shaper::none(),
            Shaper::none(),
            Duration::from_secs(30),
            Duration::from_millis(400),
        ));
        let start = Instant::now();
        // keep the tunnel active so only the total limit can end it
        let keep = tokio::spawn(async move {
            loop {
                if c_peer.write_all(b"x").await.is_err() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        });
        tokio::time::timeout(Duration::from_secs(5), h)
            .await
            .expect("ends")
            .expect("join");
        let took = start.elapsed();
        assert!(
            took >= Duration::from_millis(350) && took < Duration::from_secs(3),
            "{took:?}"
        );
        keep.abort();
    }
}
