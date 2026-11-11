//! The stdio transport: newline-delimited JSON-RPC 2.0 on stdin and stdout.
//!
//! stdout carries protocol frames and nothing else; logs go to stderr. The server exits when
//! stdin reaches end of file, after answering every request already received. Requests run
//! concurrently (up to `limits.max_in_flight`), each under a cancellation token that
//! `notifications/cancelled` fires; replies are written by one task, so frames never interleave.
//! Mutating tools are not interrupted by a cancellation: they run to completion and are audited.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use serde_json::{Value, json};
use tokio::io::{AsyncBufRead, AsyncWrite};
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::protocol::{
    Frame, INTERNAL_ERROR, INVALID_REQUEST, Incoming, MAX_FRAME_BYTES, PARSE_ERROR, RpcError,
    error_frame, parse_incoming, read_frame, result_frame, write_frame,
};
use crate::server::{Server, Transport};

/// Frames waiting for the stdout writer.
const OUTBOX_DEPTH: usize = 64;

struct Engine {
    server: Arc<Server>,
    in_flight: Mutex<BTreeMap<String, CancellationToken>>,
    permits: Arc<Semaphore>,
    limit: usize,
}

impl Engine {
    fn tokens(&self) -> MutexGuard<'_, BTreeMap<String, CancellationToken>> {
        self.in_flight
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn notify(&self, method: &str, params: Option<&Value>) {
        if method != "notifications/cancelled" {
            return;
        }
        let Some(request_id) = params.and_then(|params| params.get("requestId")) else {
            return;
        };
        if let Some(token) = self.tokens().get(&request_id.to_string()) {
            token.cancel();
        }
    }

    async fn run_request(
        &self,
        id: Value,
        method: String,
        params: Option<Value>,
        token: CancellationToken,
    ) -> Option<Value> {
        let transport = Transport {
            name: "stdio",
            remote: None,
        };
        let outcome = tokio::select! {
            () = token.cancelled() => None,
            result = self.server.handle(&method, params, &transport) => Some(result),
        };
        self.tokens().remove(&id.to_string());
        outcome.map(|result| match result {
            Ok(value) => result_frame(&id, value),
            Err(error) => error_frame(&id, &error),
        })
    }
}

/// Serve MCP over `input` and `output` until `input` ends, then answer the requests still in
/// flight and return.
///
/// # Errors
/// When reading or writing the streams fails.
pub async fn serve<R, W>(mut input: R, output: W, server: Arc<Server>) -> std::io::Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let limit = server.ctx.cfg.limits.max_in_flight;
    let engine = Arc::new(Engine {
        server,
        in_flight: Mutex::new(BTreeMap::new()),
        permits: Arc::new(Semaphore::new(limit)),
        limit,
    });
    let (outbox, mut inbox) = mpsc::channel::<Value>(OUTBOX_DEPTH);
    let writer = tokio::spawn(async move {
        let mut output = output;
        while let Some(frame) = inbox.recv().await {
            write_frame(&mut output, &frame).await?;
        }
        Ok::<(), std::io::Error>(())
    });
    let mut tasks: JoinSet<()> = JoinSet::new();
    let read = loop {
        let frame = match read_frame(&mut input, MAX_FRAME_BYTES).await {
            Ok(frame) => frame,
            Err(error) => break Err(error),
        };
        while tasks.try_join_next().is_some() {}
        let early = match frame {
            Frame::Eof => break Ok(()),
            Frame::Oversized => Some(error_frame(
                &Value::Null,
                &RpcError::new(
                    INVALID_REQUEST,
                    format!("a frame must not exceed {MAX_FRAME_BYTES} bytes"),
                ),
            )),
            Frame::Message(bytes) => match serde_json::from_slice::<Value>(&bytes) {
                Ok(value) => admit(&engine, &outbox, &mut tasks, value),
                Err(error) => Some(error_frame(
                    &Value::Null,
                    &RpcError::new(PARSE_ERROR, format!("parse error: {error}")),
                )),
            },
        };
        if let Some(frame) = early
            && outbox.send(frame).await.is_err()
        {
            break Ok(());
        }
    };
    while let Some(joined) = tasks.join_next().await {
        if let Err(error) = joined {
            tracing::error!(%error, "a request task failed");
        }
    }
    drop(outbox);
    let written = writer.await.map_err(std::io::Error::other)?;
    read.and(written)
}

/// Route one decoded frame: answer what needs no work at once, run requests on `tasks`.
fn admit(
    engine: &Arc<Engine>,
    outbox: &mpsc::Sender<Value>,
    tasks: &mut JoinSet<()>,
    value: Value,
) -> Option<Value> {
    if value.is_array() {
        return Some(error_frame(
            &Value::Null,
            &RpcError::new(INVALID_REQUEST, "JSON-RPC batches are not supported"),
        ));
    }
    let (id, method, params) = match parse_incoming(value) {
        Err((id, error)) => return Some(error_frame(&id, &error)),
        Ok(Incoming::Notification { method, params }) => {
            engine.notify(&method, params.as_ref());
            return None;
        }
        Ok(Incoming::Response) => return None,
        Ok(Incoming::Request { id, method, params }) => (id, method, params),
    };
    let Ok(permit) = Arc::clone(&engine.permits).try_acquire_owned() else {
        return Some(error_frame(
            &id,
            &RpcError::new(
                INTERNAL_ERROR,
                format!("too many requests in flight (limit {})", engine.limit),
            )
            .with_data(json!({"reason": "busy"})),
        ));
    };
    // registered before the task starts, so an immediate cancellation finds it
    let token = CancellationToken::new();
    engine.tokens().insert(id.to_string(), token.clone());
    let engine = Arc::clone(engine);
    let outbox = outbox.clone();
    tasks.spawn(async move {
        let _permit = permit;
        let reply = engine.run_request(id, method, params, token).await;
        if let Some(frame) = reply {
            // a closed outbox means the writer failed: nothing more to do
            let _ = outbox.send(frame).await;
        }
    });
    None
}
