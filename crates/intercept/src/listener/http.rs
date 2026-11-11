use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use anyhow::{Context, Result};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::common::{UpGuard, refuse_over_limit};
use crate::context::{ProxyContext, Refusal};

pub async fn serve(
    addr: SocketAddr,
    ctx: Arc<ProxyContext>,
    up: Arc<AtomicBool>,
    shutdown: CancellationToken,
) -> Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind {}", addr))?;

    info!(%addr, "HTTP proxy listening");

    let _up = UpGuard::new(&up);
    loop {
        let (stream, peer) = tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok(pair) => pair,
                    Err(e) => {
                        warn!(error = %e, "accept error on HTTP listener; backing off");
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        continue;
                    }
                }
            }
            _ = shutdown.cancelled() => {
                info!("HTTP listener shutting down");
                return Ok(());
            }
        };

        let ctx = ctx.clone();
        let slot = match ctx.admit(&stream) {
            Ok(slot) => slot,
            Err(Refusal::LimitReached) => {
                refuse_over_limit(stream, "http", true);
                continue;
            }
            Err(Refusal::Closed) => break, // semaphore closed — shutting down
        };

        tokio::spawn(async move {
            let outcome = match super::connect::handle_client(stream, peer, ctx).await {
                Ok(outcome) => outcome.label(),
                Err(e) => {
                    debug!(%peer, error=?e, "connection ended with error");
                    "error"
                }
            };
            common::metrics::PROXY_CONNECTIONS_TOTAL
                .with_label_values(&[outcome, "http"])
                .inc();
            drop(slot);
        });
    }
    Ok(())
}
