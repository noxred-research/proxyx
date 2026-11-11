//! WebSocket frame parsing, message reassembly, and `permessage-deflate`
//! inflation for capture.
//!
//! The MITM proxy passes WS frames through byte-for-byte. This module is the
//! capture-side parallel: we parse a copy of each frame, reassemble logical
//! messages, and inflate when permessage-deflate (RFC 7692) was negotiated.
//!
//! All types here are pure — no I/O, no logging. The proxy loop in
//! `proxy_websocket` is responsible for emitting structured `tracing` events
//! based on the `Result`s returned here.

use anyhow::{Context, Result, bail};

pub const OPCODE_CONTINUATION: u8 = 0x0;
pub const OPCODE_TEXT: u8 = 0x1;
pub const OPCODE_BINARY: u8 = 0x2;
pub const OPCODE_CLOSE: u8 = 0x8;
pub const OPCODE_PING: u8 = 0x9;
pub const OPCODE_PONG: u8 = 0xA;

#[inline]
pub fn is_control(opcode: u8) -> bool {
    opcode >= 0x8
}

/// RFC 7692 §7.2.2: empty non-final DEFLATE block appended before inflation.
const DEFLATE_TRAILER: [u8; 4] = [0x00, 0x00, 0xff, 0xff];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameHeader {
    pub fin: bool,
    pub rsv1: bool,
    pub opcode: u8,
    pub mask_key: Option<[u8; 4]>,
    pub payload_len: u64,
    /// Number of header bytes consumed from the input. The frame's payload
    /// begins at this offset.
    pub header_len: usize,
}

/// Parse a WebSocket frame header from `buf`.
///
/// - `Ok(Some(h))`: header parsed; `buf[h.header_len..]` is the payload start.
/// - `Ok(None)`: `buf` is shorter than the header it describes; caller reads
///   more and retries.
/// - `Err`: protocol violation (reserved bits, reserved opcode, malformed
///   control frame). The proxy loop logs and tears down the connection.
pub fn parse_frame_header(buf: &[u8]) -> Result<Option<FrameHeader>> {
    if buf.len() < 2 {
        return Ok(None);
    }

    let b0 = buf[0];
    let b1 = buf[1];

    let fin = b0 & 0x80 != 0;
    let rsv1 = b0 & 0x40 != 0;
    let rsv2 = b0 & 0x20 != 0;
    let rsv3 = b0 & 0x10 != 0;
    let opcode = b0 & 0x0F;
    let masked = b1 & 0x80 != 0;
    let len7 = b1 & 0x7F;

    // RSV2/RSV3 require a negotiated extension; we don't implement any that
    // would set them. RSV1 is permessage-deflate (validated against the
    // negotiated extension list at a higher level).
    if rsv2 || rsv3 {
        bail!("reserved bits rsv2/rsv3 set without negotiated extension");
    }

    // RFC 6455 §5.2: opcodes 3-7 and 11-15 are reserved.
    if !matches!(opcode, 0x0 | 0x1 | 0x2 | 0x8 | 0x9 | 0xA) {
        bail!("reserved opcode {:#x}", opcode);
    }

    // RFC 6455 §5.5: control frames cannot be fragmented and must be ≤125 bytes.
    if is_control(opcode) {
        if !fin {
            bail!("fragmented control frame (opcode {:#x})", opcode);
        }
        if len7 > 125 {
            bail!("control frame payload length > 125 (got {})", len7);
        }
    }

    let mut cursor = 2usize;

    let payload_len: u64 = match len7 {
        126 => {
            if buf.len() < cursor + 2 {
                return Ok(None);
            }
            let v = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]) as u64;
            cursor += 2;
            v
        }
        127 => {
            if buf.len() < cursor + 8 {
                return Ok(None);
            }
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&buf[cursor..cursor + 8]);
            let v = u64::from_be_bytes(bytes);
            // RFC 6455 §5.2: the most significant bit MUST be 0.
            if v & (1 << 63) != 0 {
                bail!("64-bit payload length high bit set");
            }
            cursor += 8;
            v
        }
        n => n as u64,
    };

    let mask_key = if masked {
        if buf.len() < cursor + 4 {
            return Ok(None);
        }
        let mut k = [0u8; 4];
        k.copy_from_slice(&buf[cursor..cursor + 4]);
        cursor += 4;
        Some(k)
    } else {
        None
    };

    Ok(Some(FrameHeader {
        fin,
        rsv1,
        opcode,
        mask_key,
        payload_len,
        header_len: cursor,
    }))
}

/// Apply the RFC 6455 §5.3 masking transform in-place. The same operation is
/// its own inverse (XOR), so this both masks and unmasks.
#[inline]
pub fn unmask(payload: &mut [u8], key: [u8; 4]) {
    for (i, b) in payload.iter_mut().enumerate() {
        *b ^= key[i & 3];
    }
}

#[derive(Debug, Clone)]
pub struct Reassembled {
    pub opcode: u8,
    pub rsv1: bool,
    /// Reassembled payload, capped at the configured capture limit.
    pub payload: Vec<u8>,
    /// Pre-truncation size in bytes. `payload.len() == min(payload_size, cap)`.
    pub payload_size: u64,
    pub truncated: bool,
}

/// Per-direction reassembly state. Holds the in-flight fragmented data
/// message; control frames bypass this state entirely.
#[derive(Debug)]
pub struct Reassembler {
    capture_buf: Vec<u8>,
    captured_size: u64,
    truncated: bool,
    leading_opcode: Option<u8>,
    rsv1: bool,
    max_capture: usize,
    max_compressed_message_bytes: usize,
}

impl Reassembler {
    pub fn new(max_capture: usize, max_compressed_message_bytes: usize) -> Self {
        Self {
            capture_buf: Vec::new(),
            captured_size: 0,
            truncated: false,
            leading_opcode: None,
            rsv1: false,
            max_capture,
            max_compressed_message_bytes,
        }
    }

    /// Reject compressed frames before buffering their payload, including
    /// continuations that would exceed the logical message's wire-byte limit.
    fn check_compressed_size(&self, payload_len: u64, opcode: u8, rsv1: bool) -> Result<()> {
        if is_control(opcode) {
            return Ok(());
        }
        let (compressed, buffered) = if opcode == OPCODE_CONTINUATION {
            (self.rsv1, self.capture_buf.len())
        } else {
            (rsv1, 0)
        };
        if compressed
            && payload_len > self.max_compressed_message_bytes.saturating_sub(buffered) as u64
        {
            bail!(
                "compressed websocket message exceeds {} bytes",
                self.max_compressed_message_bytes
            );
        }
        Ok(())
    }

    /// Feed a frame's payload bytes (post-unmask for c2s).
    ///
    /// Returns:
    /// - `Ok(Some(reassembled))` when the message completes (FIN=1) — for
    ///   data frames this is the reassembled message; for control frames
    ///   it's the single-frame payload (control frames cannot fragment).
    /// - `Ok(None)` when this is a non-final fragment of a data message.
    /// - `Err` on a protocol violation (orphan continuation, nested data
    ///   message, RSV1 on continuation).
    pub fn feed(
        &mut self,
        payload: &[u8],
        opcode: u8,
        fin: bool,
        rsv1: bool,
    ) -> Result<Option<Reassembled>> {
        self.feed_frame(payload, payload.len() as u64, opcode, fin, rsv1)
    }

    /// Like [`Reassembler::feed`], for a frame whose payload was only
    /// partly retained: `payload` holds the captured prefix and `wire_len`
    /// the frame's full payload length, which is what `payload_size` sums.
    pub fn feed_frame(
        &mut self,
        payload: &[u8],
        wire_len: u64,
        opcode: u8,
        fin: bool,
        rsv1: bool,
    ) -> Result<Option<Reassembled>> {
        // Control frames are always FIN=1 (parser enforces) and don't
        // participate in reassembly state. Emit them directly.
        if is_control(opcode) {
            return Ok(Some(Reassembled {
                opcode,
                rsv1,
                payload: payload.to_vec(),
                payload_size: payload.len() as u64,
                truncated: false,
            }));
        }

        if opcode == OPCODE_CONTINUATION {
            if self.leading_opcode.is_none() {
                bail!("continuation frame with no leading data frame");
            }
            // RFC 7692 §6: RSV1 is set only on the leading frame.
            if rsv1 {
                bail!("rsv1 set on continuation frame");
            }
        } else if let Some(prev) = self.leading_opcode {
            // New data message. Cannot start one mid-fragmentation.
            bail!(
                "new data frame opcode {:#x} arrived during fragmentation of opcode {:#x}",
                opcode,
                prev,
            );
        } else {
            self.leading_opcode = Some(opcode);
            self.rsv1 = rsv1;
            self.capture_buf.clear();
            self.captured_size = 0;
            self.truncated = false;
        }

        self.check_compressed_size(payload.len() as u64, opcode, rsv1)?;

        // Tally pre-truncation size and append into the capture buffer.
        // For COMPRESSED messages (rsv1=true) we must retain the FULL
        // compressed payload so the inflater's LZ77 window stays in sync
        // (context-takeover). The compressed wire-byte limit is enforced
        // before appending; the capture cap applies to inflated output.
        // For UNCOMPRESSED messages we cap here — no shared window state.
        self.captured_size = self.captured_size.saturating_add(wire_len);
        if self.rsv1 {
            // Compressed: keep the bounded payload for the inflater.
            self.capture_buf.extend_from_slice(payload);
        } else {
            if self.capture_buf.len() < self.max_capture {
                let room = self.max_capture - self.capture_buf.len();
                let take = room.min(payload.len());
                self.capture_buf.extend_from_slice(&payload[..take]);
                if take < payload.len() {
                    self.truncated = true;
                }
            } else if !payload.is_empty() {
                self.truncated = true;
            }
            if wire_len > payload.len() as u64 {
                self.truncated = true;
            }
        }

        if !fin {
            return Ok(None);
        }

        // Message complete — drain state and emit.
        let opcode = self
            .leading_opcode
            .take()
            .expect("leading_opcode set above for data frames");
        let rsv1 = self.rsv1;
        let payload = std::mem::take(&mut self.capture_buf);
        let payload_size = self.captured_size;
        let truncated = self.truncated;
        self.captured_size = 0;
        self.truncated = false;
        self.rsv1 = false;
        Ok(Some(Reassembled {
            opcode,
            rsv1,
            payload,
            payload_size,
            truncated,
        }))
    }
}

/// `permessage-deflate` parameters parsed from the 101 response's
/// `Sec-WebSocket-Extensions` header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeflateNegotiation {
    pub client_no_context_takeover: bool,
    pub server_no_context_takeover: bool,
    /// Valid range 8..=15. Default 15.
    pub client_max_window_bits: u8,
    /// Valid range 8..=15. Default 15.
    pub server_max_window_bits: u8,
}

impl Default for DeflateNegotiation {
    fn default() -> Self {
        Self {
            client_no_context_takeover: false,
            server_no_context_takeover: false,
            client_max_window_bits: 15,
            server_max_window_bits: 15,
        }
    }
}

/// Parse `permessage-deflate` parameters from `Sec-WebSocket-Extensions`
/// response headers. Returns `None` if the extension is absent.
///
/// Tolerant of multiple `Sec-WebSocket-Extensions` headers (per RFC 6455
/// they may be comma-joined or split).
pub fn parse_extensions(headers: &[(String, String)]) -> Option<DeflateNegotiation> {
    let combined = headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("sec-websocket-extensions"))
        .map(|(_, v)| v.as_str())
        .collect::<Vec<_>>()
        .join(",");

    if combined.is_empty() {
        return None;
    }

    // Each extension offer is comma-separated; parameters are semicolon-separated.
    for ext in combined.split(',') {
        let mut parts = ext.split(';').map(|s| s.trim());
        let name = parts.next().unwrap_or("");
        if !name.eq_ignore_ascii_case("permessage-deflate") {
            continue;
        }

        let mut neg = DeflateNegotiation::default();
        for param in parts {
            if param.is_empty() {
                continue;
            }
            let (k, v) = match param.split_once('=') {
                Some((k, v)) => (k.trim(), v.trim().trim_matches('"')),
                None => (param, ""),
            };
            match k {
                "client_no_context_takeover" => neg.client_no_context_takeover = true,
                "server_no_context_takeover" => neg.server_no_context_takeover = true,
                "client_max_window_bits" => {
                    if let Ok(bits) = v.parse::<u8>() {
                        neg.client_max_window_bits = bits.clamp(8, 15);
                    }
                }
                "server_max_window_bits" => {
                    if let Ok(bits) = v.parse::<u8>() {
                        neg.server_max_window_bits = bits.clamp(8, 15);
                    }
                }
                _ => {} // unknown param — ignore (forward compatibility)
            }
        }
        return Some(neg);
    }

    None
}

/// Per-direction `permessage-deflate` inflater. The decompressor's LZ77
/// window state persists across messages by default; if the corresponding
/// `*_no_context_takeover` flag was negotiated, the state resets after
/// each message.
///
/// NOTE: `flate2`'s default `miniz_oxide` backend does not expose a
/// window-bits constructor. We always use the default 15-bit window. RFC 7692
/// permits peers to negotiate smaller windows (`*_max_window_bits`); when they
/// do, the encoder produces output that a 15-bit decoder still inflates
/// correctly (a smaller window is a strict subset). We accept the negotiated
/// value into `window_bits` for diagnostics but do not constrain the decoder.
pub struct Inflater {
    decompress: flate2::Decompress,
    no_context_takeover: bool,
    window_bits: u8,
}

impl std::fmt::Debug for Inflater {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inflater")
            .field("no_context_takeover", &self.no_context_takeover)
            .field("window_bits", &self.window_bits)
            .finish()
    }
}

impl Inflater {
    pub fn new(window_bits: u8, no_context_takeover: bool) -> Self {
        let bits = window_bits.clamp(8, 15);
        Self {
            // `false` = raw DEFLATE (no zlib header).
            decompress: flate2::Decompress::new(false),
            no_context_takeover,
            window_bits: bits,
        }
    }

    /// Inflate the concatenated payload bytes of one logical message.
    ///
    /// `compressed` is the full message payload as it appeared on the wire
    /// (after fragment reassembly, before trailer fixup). Returns the
    /// decompressed bytes (capped at `cap`), a `truncated` flag, and the
    /// pre-cap true decompressed size so callers can record `payload_size`
    /// independently of how much was retained.
    ///
    /// Truncation does NOT abort decompression -- we drain the input fully
    /// to keep the LZ77 window state in sync with the peer for subsequent
    /// messages (when context takeover is enabled).
    pub fn inflate(&mut self, compressed: &[u8], cap: usize) -> Result<(Vec<u8>, bool, u64)> {
        // RFC 7692 §7.2.2: append a non-final empty deflate block before inflation.
        let mut input: Vec<u8> = Vec::with_capacity(compressed.len() + DEFLATE_TRAILER.len());
        input.extend_from_slice(compressed);
        input.extend_from_slice(&DEFLATE_TRAILER);

        let mut output: Vec<u8> = Vec::new();
        let mut truncated = false;
        let mut total_decompressed: u64 = 0;
        let mut input_pos = 0usize;
        let mut scratch = vec![0u8; 16 * 1024];

        loop {
            let in_slice = &input[input_pos..];
            // The decompressor holds output it could not fit in `scratch`;
            // an exhausted input still has to be drained until a call leaves
            // the scratch buffer unfilled.
            let in_before = self.decompress.total_in();
            let out_before = self.decompress.total_out();
            let status = self
                .decompress
                .decompress(in_slice, &mut scratch, flate2::FlushDecompress::Sync)
                .with_context(|| {
                    format!(
                        "permessage-deflate inflate failed at input_pos={} (compressed_len={})",
                        input_pos,
                        compressed.len()
                    )
                })?;

            let consumed = (self.decompress.total_in() - in_before) as usize;
            let produced = (self.decompress.total_out() - out_before) as usize;
            input_pos += consumed;

            if produced > 0 {
                total_decompressed = total_decompressed.saturating_add(produced as u64);
                if output.len() < cap {
                    let room = cap - output.len();
                    let take = room.min(produced);
                    output.extend_from_slice(&scratch[..take]);
                    if take < produced {
                        truncated = true;
                    }
                } else {
                    truncated = true;
                }
            }

            if matches!(status, flate2::Status::StreamEnd) {
                break;
            }
            if input_pos >= input.len() && produced < scratch.len() {
                break;
            }
            if consumed == 0 && produced == 0 {
                // No forward progress — break to avoid an infinite loop.
                // This shouldn't happen with well-formed input + trailer; if
                // it does, we surface what we have and let the caller log.
                break;
            }
        }

        if self.no_context_takeover {
            self.decompress = flate2::Decompress::new(false);
        }

        Ok((output, truncated, total_decompressed))
    }
}

use crate::pipeline::{SessionMetadata, WsDirection, WsOpcode, WsPipelineEvent};
use crate::ratelimit::ExchangeRateLimit;
use bytes::{Bytes, BytesMut};
use common::types::SessionId;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, watch};
use tracing::warn;
use uuid::Uuid;

/// Per-connection context for `proxy_websocket`. All fields are stable for
/// the lifetime of one WebSocket conversation.
pub struct WsContext {
    /// `event_id` of the parent 101 row in `http_captures`. Every captured
    /// WS message links back through this id.
    pub parent_event_id: Uuid,
    pub session_id: SessionId,
    pub proxy_id: String,
    pub org_id: String,
    pub source: String,
    pub source_id: String,
    pub host: String,

    /// Sink for captured messages. Cloned into both directional loops.
    pub capture_tx: mpsc::Sender<WsPipelineEvent>,
    /// Maximum captured payload bytes per logical message. Wire bytes are
    /// forwarded unaffected; this only caps the captured copy.
    pub max_payload_capture: usize,
    /// Maximum compressed wire bytes per frame and logical message.
    /// Exceeding this limit closes both peers with code 1009.
    pub max_compressed_message_bytes: usize,
    /// `permessage-deflate` parameters parsed from the 101 response. `None`
    /// when the extension was not negotiated.
    pub deflate: Option<DeflateNegotiation>,
    /// When false, PING/PONG are forwarded but not captured.
    pub capture_control_frames: bool,
    /// Per-message rate limit applied to client-driven (c2s) messages only.
    /// Server-driven s2c traffic is not rate-limited.
    pub exchange_ratelimit: Option<Arc<dyn ExchangeRateLimit>>,
}

/// Take one client-to-server message token, recording the wait as the
/// `ratelimit_wait` overhead phase for `websocket`.
async fn acquire_rate_limit(
    rl: &dyn ExchangeRateLimit,
) -> Result<std::time::Duration, crate::ratelimit::RateLimitError> {
    let start = std::time::Instant::now();
    let acquired = rl.acquire().await;
    super::observe_overhead("websocket", "ratelimit_wait", start.elapsed());
    acquired
}

/// Proxy a WebSocket conversation between `client` and `upstream`.
///
/// Spawns two directional tasks (c2s, s2c) that share the same capture
/// channel. Wire bytes are forwarded byte-for-byte; capture happens on a
/// parallel buffer.
///
/// `s2c_prefix` carries any bytes the caller already read from the upstream
/// stream past the `\r\n\r\n` of the 101 response (the start of the WS
/// stream). They are both forwarded to the client AND fed to the s2c parser.
///
/// Returns when both directional loops have exited (graceful close or peer
/// EOF). Errors from individual loops are logged with full context and do
/// not abort the other direction -- WS half-close is legal per RFC 6455.
/// A compressed wire-byte limit violation instead closes both directions
/// with code 1009 before buffering the rejected frame's payload.
pub async fn proxy_websocket<C, U>(
    client: C,
    upstream: U,
    s2c_prefix: Vec<u8>,
    ctx: WsContext,
) -> anyhow::Result<()>
where
    C: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    U: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (client_read, client_write) = tokio::io::split(client);
    let (upstream_read, upstream_write) = tokio::io::split(upstream);
    let ctx = Arc::new(ctx);
    let (close_tx, _) = watch::channel(false);

    // s2c: read upstream, write client. Receives s2c_prefix as initial buffer.
    let s2c_ctx = ctx.clone();
    let s2c_close_tx = close_tx.clone();
    let s2c_handle = tokio::spawn(async move {
        direction_loop(
            upstream_read,
            client_write,
            WsDirection::S2c,
            s2c_prefix,
            s2c_ctx,
            s2c_close_tx,
        )
        .await
    });

    // c2s: read client, write upstream.
    let c2s_ctx = ctx.clone();
    let c2s_handle = tokio::spawn(async move {
        direction_loop(
            client_read,
            upstream_write,
            WsDirection::C2s,
            Vec::new(),
            c2s_ctx,
            close_tx,
        )
        .await
    });

    let (s2c_join, c2s_join) = tokio::join!(s2c_handle, c2s_handle);

    match s2c_join {
        Ok(Ok(())) => {}
        Ok(Err(e)) => warn!(
            error = ?e,
            host = %ctx.host,
            session_id = %ctx.session_id,
            "ws s2c loop ended with error"
        ),
        Err(e) => warn!(
            error = ?e,
            host = %ctx.host,
            session_id = %ctx.session_id,
            "ws s2c task panicked"
        ),
    }
    match c2s_join {
        Ok(Ok(())) => {}
        Ok(Err(e)) => warn!(
            error = ?e,
            host = %ctx.host,
            session_id = %ctx.session_id,
            "ws c2s loop ended with error"
        ),
        Err(e) => warn!(
            error = ?e,
            host = %ctx.host,
            session_id = %ctx.session_id,
            "ws c2s task panicked"
        ),
    }

    Ok(())
}

/// One directional loop: parse frames from `reader`, forward raw bytes to
/// `writer`, capture a parallel decoded copy to `ctx.capture_tx`.
async fn direction_loop<R, W>(
    mut reader: R,
    mut writer: W,
    direction: WsDirection,
    initial_buf: Vec<u8>,
    ctx: Arc<WsContext>,
    close_tx: watch::Sender<bool>,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut close_rx = close_tx.subscribe();
    let closing = *close_rx.borrow();
    let result = if closing {
        Ok(())
    } else {
        tokio::select! {
            biased;
            _ = close_rx.changed() => Ok(()),
            result = forward_direction(
                &mut reader,
                &mut writer,
                direction,
                initial_buf,
                ctx,
                close_tx,
            ) => result,
        }
    };
    let closing = *close_rx.borrow();
    if closing {
        // The proxy acts as server toward the client and client toward the
        // upstream. Only the latter CLOSE must carry an RFC 6455 mask.
        let code = 1009u16.to_be_bytes();
        if matches!(direction, WsDirection::C2s) {
            let random = Uuid::new_v4();
            let mask = &random.as_bytes()[..4];
            let frame = [
                0x88,
                0x82,
                mask[0],
                mask[1],
                mask[2],
                mask[3],
                code[0] ^ mask[0],
                code[1] ^ mask[1],
            ];
            writer.write_all(&frame).await?;
        } else {
            writer.write_all(&[0x88, 0x02, code[0], code[1]]).await?;
        }
        writer.shutdown().await?;
    }
    result
}

async fn forward_direction<R, W>(
    reader: &mut R,
    writer: &mut W,
    direction: WsDirection,
    initial_buf: Vec<u8>,
    ctx: Arc<WsContext>,
    close_tx: watch::Sender<bool>,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf: BytesMut = BytesMut::with_capacity(8192);
    // The s2c side may receive bytes the keepalive loop over-read past the
    // 101 \r\n\r\n boundary. Feed them into the parser; the normal
    // forward-after-parse path handles writing them to the client. Pre-
    // forwarding here would duplicate the frame on the wire.
    if !initial_buf.is_empty() {
        buf.extend_from_slice(&initial_buf);
    }

    let mut reassembler =
        Reassembler::new(ctx.max_payload_capture, ctx.max_compressed_message_bytes);
    let mut inflater: Option<Inflater> = match (direction, ctx.deflate) {
        (WsDirection::C2s, Some(d)) => Some(Inflater::new(
            d.client_max_window_bits,
            d.client_no_context_takeover,
        )),
        (WsDirection::S2c, Some(d)) => Some(Inflater::new(
            d.server_max_window_bits,
            d.server_no_context_takeover,
        )),
        _ => None,
    };

    let mut read_chunk = vec![0u8; 16 * 1024];

    // Track whether the in-flight fragmented message is compressed.
    // Set from rsv1 on the leading data frame; continuations inherit it.
    let mut message_is_compressed = false;

    loop {
        // Parse a frame header out of `buf`, reading more from the wire as needed.
        let header = loop {
            match parse_frame_header(&buf) {
                Ok(Some(h)) => break h,
                Ok(None) => {
                    let n = match reader.read(&mut read_chunk).await {
                        Ok(n) => n,
                        Err(e) => {
                            warn!(
                                error = %e,
                                host = %ctx.host,
                                session_id = %ctx.session_id,
                                direction = direction.as_str(),
                                "ws read failed during header"
                            );
                            let _ = writer.shutdown().await;
                            return Err(e.into());
                        }
                    };
                    if n == 0 {
                        // Clean EOF from peer. Half-close our write side so
                        // the other peer also sees EOF on its read side.
                        let _ = writer.shutdown().await;
                        return Ok(());
                    }
                    buf.extend_from_slice(&read_chunk[..n]);
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        host = %ctx.host,
                        session_id = %ctx.session_id,
                        direction = direction.as_str(),
                        "ws frame header parse failed"
                    );
                    let _ = writer.shutdown().await;
                    return Err(e);
                }
            }
        };

        if let Err(error) =
            reassembler.check_compressed_size(header.payload_len, header.opcode, header.rsv1)
        {
            close_tx.send_replace(true);
            return Err(error);
        }

        let payload_len = match usize::try_from(header.payload_len) {
            Ok(n) => n,
            Err(_) => {
                warn!(
                    payload_len = header.payload_len,
                    host = %ctx.host,
                    session_id = %ctx.session_id,
                    "ws frame payload length exceeds usize"
                );
                let _ = writer.shutdown().await;
                anyhow::bail!("ws payload length exceeds usize: {}", header.payload_len);
            }
        };

        // Update compressed-message tracking: leading data frames set the
        // flag from rsv1; continuations inherit; control frames don't affect it.
        if !is_control(header.opcode) && header.opcode != OPCODE_CONTINUATION {
            message_is_compressed = header.rsv1;
        }

        // Decide whether this frame can be streamed incrementally (F2.6).
        //
        // Control frames are always small (≤125 bytes) — buffer as before.
        // Compressed frames need the full compressed payload for
        // permessage-deflate inflation — buffer only within the wire-byte limit.
        // Uncompressed data frames are streamed: forward bytes to the peer as
        // they arrive, capturing only up to max_payload_capture.
        let can_stream = !is_control(header.opcode) && !message_is_compressed;

        if can_stream {
            // ---- Streaming path (F2.6): forward payload incrementally ----

            // Forward the frame header bytes that are already in `buf`.
            if let Err(e) = writer.write_all(&buf[..header.header_len]).await {
                warn!(
                    error = %e,
                    host = %ctx.host,
                    session_id = %ctx.session_id,
                    direction = direction.as_str(),
                    "ws frame header forward failed"
                );
                return Err(e.into());
            }

            // Payload bytes already in `buf` past the header.
            let buffered_payload = buf.len() - header.header_len;
            let mut payload_forwarded: usize = 0;

            // Capture accumulator: only keep up to max_payload_capture bytes
            // for the reassembler. We unmask in-place on capture_buf for c2s.
            let capture_cap = ctx.max_payload_capture;
            let mut capture_buf: Vec<u8> =
                Vec::with_capacity(capture_cap.min(payload_len).min(64 * 1024));
            let mask_key = header.mask_key;

            // c2s: rate limit per logical message (skip continuations and control).
            if matches!(direction, WsDirection::C2s)
                && header.opcode != OPCODE_CONTINUATION
                && let Some(ref rl) = ctx.exchange_ratelimit
                && let Err(e) = acquire_rate_limit(rl.as_ref()).await
            {
                warn!(
                    error = %e,
                    host = %ctx.host,
                    session_id = %ctx.session_id,
                    "ws c2s rate limit exceeded, closing"
                );
                let _ = writer.shutdown().await;
                return Ok(());
            }

            // Forward buffered payload bytes (already in `buf`).
            if buffered_payload > 0 {
                let avail = buffered_payload.min(payload_len);
                let payload_start = header.header_len;
                if let Err(e) = writer
                    .write_all(&buf[payload_start..payload_start + avail])
                    .await
                {
                    warn!(
                        error = %e,
                        host = %ctx.host,
                        session_id = %ctx.session_id,
                        direction = direction.as_str(),
                        "ws frame forward failed"
                    );
                    return Err(e.into());
                }
                // Capture up to cap.
                let take = avail.min(capture_cap);
                capture_buf.extend_from_slice(&buf[payload_start..payload_start + take]);
                payload_forwarded = avail;
            }

            // Drain header + consumed payload from buf. Keep any overshoot
            // (bytes past this frame) for next iteration.
            let consumed = header.header_len + buffered_payload.min(payload_len);
            let _ = buf.split_to(consumed);

            // Stream remaining payload bytes from the reader.
            while payload_forwarded < payload_len {
                let n = match reader.read(&mut read_chunk).await {
                    Ok(n) => n,
                    Err(e) => {
                        warn!(
                            error = %e,
                            host = %ctx.host,
                            session_id = %ctx.session_id,
                            direction = direction.as_str(),
                            "ws read failed during payload"
                        );
                        let _ = writer.shutdown().await;
                        return Err(e.into());
                    }
                };
                if n == 0 {
                    warn!(
                        have = payload_forwarded,
                        need = payload_len,
                        host = %ctx.host,
                        session_id = %ctx.session_id,
                        direction = direction.as_str(),
                        "ws EOF mid-frame"
                    );
                    let _ = writer.shutdown().await;
                    anyhow::bail!("ws EOF mid-frame");
                }

                let remaining = payload_len - payload_forwarded;
                let frame_bytes = n.min(remaining);

                // Forward only payload bytes belonging to this frame.
                if let Err(e) = writer.write_all(&read_chunk[..frame_bytes]).await {
                    warn!(
                        error = %e,
                        host = %ctx.host,
                        session_id = %ctx.session_id,
                        direction = direction.as_str(),
                        "ws frame forward failed"
                    );
                    return Err(e.into());
                }

                // Capture up to cap.
                if capture_buf.len() < capture_cap {
                    let room = capture_cap - capture_buf.len();
                    let take = frame_bytes.min(room);
                    capture_buf.extend_from_slice(&read_chunk[..take]);
                }

                payload_forwarded += frame_bytes;

                // Any bytes beyond this frame belong to the next frame.
                if frame_bytes < n {
                    buf.extend_from_slice(&read_chunk[frame_bytes..n]);
                }
            }

            if let Err(e) = writer.flush().await {
                warn!(
                    error = %e,
                    host = %ctx.host,
                    session_id = %ctx.session_id,
                    direction = direction.as_str(),
                    "ws flush failed (continuing)"
                );
            }

            // Unmask captured bytes for reassembler (c2s frames are masked).
            if let Some(key) = mask_key {
                unmask(&mut capture_buf, key);
            }

            let reassembled = match reassembler.feed_frame(
                &capture_buf,
                payload_len as u64,
                header.opcode,
                header.fin,
                header.rsv1,
            ) {
                Ok(Some(r)) => r,
                Ok(None) => continue, // mid-fragmentation
                Err(e) => {
                    warn!(
                        error = %e,
                        host = %ctx.host,
                        session_id = %ctx.session_id,
                        direction = direction.as_str(),
                        "ws reassembly error, tearing down direction"
                    );
                    let _ = writer.shutdown().await;
                    return Err(e);
                }
            };

            if is_control(reassembled.opcode)
                && reassembled.opcode != OPCODE_CLOSE
                && !ctx.capture_control_frames
            {
                continue;
            }

            emit_message(&ctx, direction, reassembled, inflater.as_mut()).await;
        } else {
            // ---- Buffered path: control frames and compressed data frames ----
            // For compressed frames, permessage-deflate inflation requires
            // the full compressed payload, so we buffer the entire frame.
            // Control frames are always ≤125 bytes.
            let frame_total = header
                .header_len
                .checked_add(payload_len)
                .context("ws frame length exceeds usize")?;
            while buf.len() < frame_total {
                let n = match reader.read(&mut read_chunk).await {
                    Ok(n) => n,
                    Err(e) => {
                        warn!(
                            error = %e,
                            host = %ctx.host,
                            session_id = %ctx.session_id,
                            direction = direction.as_str(),
                            "ws read failed during payload"
                        );
                        let _ = writer.shutdown().await;
                        return Err(e.into());
                    }
                };
                if n == 0 {
                    warn!(
                        have = buf.len(),
                        need = frame_total,
                        host = %ctx.host,
                        session_id = %ctx.session_id,
                        direction = direction.as_str(),
                        "ws EOF mid-frame"
                    );
                    let _ = writer.shutdown().await;
                    anyhow::bail!("ws EOF mid-frame");
                }
                buf.extend_from_slice(&read_chunk[..n]);
            }

            // c2s: rate limit per logical message (skip continuations and control).
            if matches!(direction, WsDirection::C2s)
                && !is_control(header.opcode)
                && header.opcode != OPCODE_CONTINUATION
                && let Some(ref rl) = ctx.exchange_ratelimit
                && let Err(e) = acquire_rate_limit(rl.as_ref()).await
            {
                warn!(
                    error = %e,
                    host = %ctx.host,
                    session_id = %ctx.session_id,
                    "ws c2s rate limit exceeded, closing"
                );
                let _ = writer.shutdown().await;
                return Ok(());
            }

            // Forward the complete frame byte-for-byte.
            if let Err(e) = writer.write_all(&buf[..frame_total]).await {
                warn!(
                    error = %e,
                    host = %ctx.host,
                    session_id = %ctx.session_id,
                    direction = direction.as_str(),
                    "ws frame forward failed"
                );
                return Err(e.into());
            }
            if let Err(e) = writer.flush().await {
                warn!(
                    error = %e,
                    host = %ctx.host,
                    session_id = %ctx.session_id,
                    direction = direction.as_str(),
                    "ws flush failed (continuing)"
                );
            }

            // Capture path: copy the payload, unmask if c2s, hand to reassembler.
            let mut payload_copy = buf[header.header_len..frame_total].to_vec();
            if let Some(key) = header.mask_key {
                unmask(&mut payload_copy, key);
            }

            // Drain consumed bytes from the working buffer.
            let _ = buf.split_to(frame_total);

            let reassembled =
                match reassembler.feed(&payload_copy, header.opcode, header.fin, header.rsv1) {
                    Ok(Some(r)) => r,
                    Ok(None) => continue, // mid-fragmentation
                    Err(e) => {
                        warn!(
                            error = %e,
                            host = %ctx.host,
                            session_id = %ctx.session_id,
                            direction = direction.as_str(),
                            "ws reassembly error, tearing down direction"
                        );
                        let _ = writer.shutdown().await;
                        return Err(e);
                    }
                };

            // Skip non-CLOSE control frames unless capture_control_frames is on.
            if is_control(reassembled.opcode)
                && reassembled.opcode != OPCODE_CLOSE
                && !ctx.capture_control_frames
            {
                continue;
            }

            emit_message(&ctx, direction, reassembled, inflater.as_mut()).await;
        }
    }
}

/// Convert a `Reassembled` message into a `WsPipelineEvent` and send it on
/// the capture channel. Inflates if the message was permessage-deflated.
async fn emit_message(
    ctx: &Arc<WsContext>,
    direction: WsDirection,
    reassembled: Reassembled,
    inflater: Option<&mut Inflater>,
) {
    let was_compressed = reassembled.rsv1;

    // Decompression path. Drops the message and logs if rsv1 was set but no
    // permessage-deflate was negotiated, or if inflate fails.
    let (payload, payload_size, payload_truncated): (Vec<u8>, u64, bool) = if was_compressed {
        match inflater {
            Some(inf) => match inf.inflate(&reassembled.payload, ctx.max_payload_capture) {
                Ok((decompressed, infl_truncated, true_size)) => (
                    decompressed,
                    true_size,
                    infl_truncated || reassembled.truncated,
                ),
                Err(e) => {
                    warn!(
                        error = %e,
                        host = %ctx.host,
                        session_id = %ctx.session_id,
                        direction = direction.as_str(),
                        "ws inflate failed, dropping message"
                    );
                    return;
                }
            },
            None => {
                warn!(
                    host = %ctx.host,
                    session_id = %ctx.session_id,
                    direction = direction.as_str(),
                    "ws frame has rsv1 set but permessage-deflate not negotiated, dropping"
                );
                return;
            }
        }
    } else {
        (
            reassembled.payload,
            reassembled.payload_size,
            reassembled.truncated,
        )
    };

    let opcode = match reassembled.opcode {
        OPCODE_TEXT => WsOpcode::Text,
        OPCODE_BINARY => WsOpcode::Binary,
        OPCODE_CLOSE => WsOpcode::Close,
        OPCODE_PING => WsOpcode::Ping,
        OPCODE_PONG => WsOpcode::Pong,
        other => {
            warn!(
                opcode = other,
                host = %ctx.host,
                session_id = %ctx.session_id,
                direction = direction.as_str(),
                "ws unexpected opcode at emit, dropping"
            );
            return;
        }
    };

    let (close_code, close_reason) = if reassembled.opcode == OPCODE_CLOSE {
        parse_close_payload(&payload)
    } else {
        (None, None)
    };

    let event = WsPipelineEvent {
        event_id: Uuid::now_v7(),
        parent_event_id: ctx.parent_event_id,
        session_id: ctx.session_id,
        proxy_id: ctx.proxy_id.clone(),
        timestamp: time::OffsetDateTime::now_utc(),
        direction,
        opcode,
        payload: Bytes::from(payload),
        payload_size,
        payload_truncated,
        was_compressed,
        close_code,
        close_reason,
        host: ctx.host.clone(),
        metadata: SessionMetadata {
            org_id: ctx.org_id.clone(),
            source: ctx.source.clone(),
            source_id: ctx.source_id.clone(),
        },
    };

    let send_start = tokio::time::Instant::now();
    if ctx.capture_tx.send(event).await.is_err() {
        warn!(
            host = %ctx.host,
            session_id = %ctx.session_id,
            direction = direction.as_str(),
            "ws capture channel closed, message dropped"
        );
    }
    let elapsed = send_start.elapsed();
    if elapsed > std::time::Duration::from_secs(5) {
        warn!(
            elapsed_ms = elapsed.as_millis() as u64,
            host = %ctx.host,
            session_id = %ctx.session_id,
            direction = direction.as_str(),
            "ws capture channel backpressure: send blocked >5s"
        );
    }
}

/// Parse the payload of a CLOSE frame per RFC 6455 section 5.5.1.
///
/// - First 2 bytes (if present) = close code, big-endian.
/// - Remainder = UTF-8 reason. Returns `None` for the reason when the bytes
///   are not valid UTF-8 (rather than dropping the message).
fn parse_close_payload(payload: &[u8]) -> (Option<u16>, Option<String>) {
    if payload.is_empty() {
        return (None, None);
    }
    if payload.len() < 2 {
        // Malformed: a code requires both bytes. Surface as no-code.
        return (None, None);
    }
    let code = u16::from_be_bytes([payload[0], payload[1]]);
    let reason = if payload.len() > 2 {
        match std::str::from_utf8(&payload[2..]) {
            Ok(s) => Some(s.to_string()),
            Err(_) => None,
        }
    } else {
        None
    };
    (Some(code), reason)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compress;

    use crate::ratelimit::RateLimitError;
    use std::pin::Pin;
    use std::time::Duration;

    struct SlowLimit;

    impl ExchangeRateLimit for SlowLimit {
        fn acquire(
            &self,
        ) -> Pin<Box<dyn Future<Output = Result<Duration, RateLimitError>> + Send + '_>> {
            Box::pin(async {
                tokio::time::sleep(Duration::from_millis(20)).await;
                Ok(Duration::from_millis(20))
            })
        }
    }

    #[tokio::test]
    async fn rate_limit_wait_is_recorded_as_overhead_phase() {
        let phase = common::metrics::PROXY_OVERHEAD_SECONDS
            .with_label_values(&["websocket", "ratelimit_wait"]);
        let (count, sum) = (phase.get_sample_count(), phase.get_sample_sum());

        acquire_rate_limit(&SlowLimit).await.unwrap();

        assert_eq!(phase.get_sample_count(), count + 1);
        assert!(phase.get_sample_sum() - sum >= 0.02);
    }

    // -- parser --

    #[test]
    fn parse_short_text_unmasked() {
        // FIN=1, opcode=text, len=5, no mask, "hello"
        let buf = b"\x81\x05hello";
        let h = parse_frame_header(buf).unwrap().unwrap();
        assert!(h.fin);
        assert!(!h.rsv1);
        assert_eq!(h.opcode, OPCODE_TEXT);
        assert_eq!(h.mask_key, None);
        assert_eq!(h.payload_len, 5);
        assert_eq!(h.header_len, 2);
    }

    #[test]
    fn parse_short_text_masked() {
        // FIN=1, opcode=text, MASK=1, len=5, mask=01020304, payload "hello"^mask
        let buf = b"\x81\x85\x01\x02\x03\x04hello";
        let h = parse_frame_header(buf).unwrap().unwrap();
        assert!(h.fin);
        assert_eq!(h.opcode, OPCODE_TEXT);
        assert_eq!(h.mask_key, Some([0x01, 0x02, 0x03, 0x04]));
        assert_eq!(h.payload_len, 5);
        assert_eq!(h.header_len, 6);
    }

    #[test]
    fn parse_extended_16bit_length() {
        // FIN=1, opcode=binary, len=126, then u16 = 200, no mask
        let mut buf = vec![0x82, 126];
        buf.extend_from_slice(&200u16.to_be_bytes());
        let h = parse_frame_header(&buf).unwrap().unwrap();
        assert_eq!(h.opcode, OPCODE_BINARY);
        assert_eq!(h.payload_len, 200);
        assert_eq!(h.header_len, 4);
    }

    #[test]
    fn parse_extended_64bit_length() {
        let mut buf = vec![0x82, 127];
        buf.extend_from_slice(&100_000u64.to_be_bytes());
        let h = parse_frame_header(&buf).unwrap().unwrap();
        assert_eq!(h.payload_len, 100_000);
        assert_eq!(h.header_len, 10);
    }

    #[test]
    fn parse_64bit_high_bit_rejected() {
        let mut buf = vec![0x82, 127];
        buf.extend_from_slice(&(1u64 << 63).to_be_bytes());
        let err = parse_frame_header(&buf).unwrap_err();
        assert!(err.to_string().contains("high bit"));
    }

    #[test]
    fn parse_short_buffer_returns_none() {
        // Header says masked + 16-bit length but buffer is too short.
        let buf = b"\x81\xfe"; // mask=1, len7=126
        assert!(parse_frame_header(buf).unwrap().is_none());
    }

    #[test]
    fn parse_reserved_opcode_rejected() {
        // opcode = 3 (reserved data)
        let buf = b"\x83\x00";
        assert!(parse_frame_header(buf).is_err());
    }

    #[test]
    fn parse_fragmented_control_rejected() {
        // FIN=0, opcode=ping (0x9). Control frame must be FIN=1.
        let buf = b"\x09\x00";
        assert!(parse_frame_header(buf).is_err());
    }

    #[test]
    fn parse_long_control_rejected() {
        // FIN=1, opcode=close (0x8), len=126 (extended) — invalid for control.
        let buf = b"\x88\x7e\x00\x80";
        assert!(parse_frame_header(buf).is_err());
    }

    #[test]
    fn parse_rsv2_rejected() {
        let buf = b"\xa1\x00"; // rsv2 set
        assert!(parse_frame_header(buf).is_err());
    }

    #[test]
    fn unmask_inverse_property() {
        let key = [0xab, 0xcd, 0xef, 0x12];
        let original: Vec<u8> = (0..50).collect();
        let mut masked = original.clone();
        unmask(&mut masked, key);
        assert_ne!(masked, original);
        unmask(&mut masked, key);
        assert_eq!(masked, original);
    }

    // -- Reassembler --

    #[test]
    fn reassembler_single_text() {
        let mut r = Reassembler::new(1024, 1024);
        let m = r
            .feed(b"hello", OPCODE_TEXT, true, false)
            .unwrap()
            .expect("FIN frame must yield a message");
        assert_eq!(m.opcode, OPCODE_TEXT);
        assert_eq!(m.payload, b"hello");
        assert_eq!(m.payload_size, 5);
        assert!(!m.truncated);
        assert!(!m.rsv1);
    }

    #[test]
    fn reassembler_fragmented() {
        let mut r = Reassembler::new(1024, 1024);
        assert!(r.feed(b"he", OPCODE_TEXT, false, true).unwrap().is_none());
        assert!(
            r.feed(b"ll", OPCODE_CONTINUATION, false, false)
                .unwrap()
                .is_none()
        );
        let m = r
            .feed(b"o", OPCODE_CONTINUATION, true, false)
            .unwrap()
            .expect("FIN frame must yield");
        assert_eq!(m.opcode, OPCODE_TEXT);
        assert_eq!(m.payload, b"hello");
        assert_eq!(m.payload_size, 5);
        assert!(m.rsv1, "RSV1 from leading frame should propagate");
    }

    #[test]
    fn reassembler_orphan_continuation_rejected() {
        let mut r = Reassembler::new(1024, 1024);
        assert!(r.feed(b"x", OPCODE_CONTINUATION, true, false).is_err());
    }

    #[test]
    fn reassembler_nested_data_rejected() {
        let mut r = Reassembler::new(1024, 1024);
        r.feed(b"he", OPCODE_TEXT, false, false).unwrap();
        let err = r.feed(b"x", OPCODE_BINARY, true, false).unwrap_err();
        assert!(err.to_string().contains("during fragmentation"));
    }

    #[test]
    fn reassembler_rsv1_on_continuation_rejected() {
        let mut r = Reassembler::new(1024, 1024);
        r.feed(b"he", OPCODE_TEXT, false, true).unwrap();
        let err = r.feed(b"x", OPCODE_CONTINUATION, true, true).unwrap_err();
        assert!(err.to_string().contains("rsv1"));
    }

    #[test]
    fn reassembler_truncates_capture_only() {
        let mut r = Reassembler::new(4, 1024); // tiny capture cap
        let m = r
            .feed(b"hello world", OPCODE_TEXT, true, false)
            .unwrap()
            .unwrap();
        assert_eq!(m.payload, b"hell"); // 4 bytes captured
        assert_eq!(m.payload_size, 11); // pre-truncation tally preserved
        assert!(m.truncated);
    }

    #[test]
    fn reassembler_control_frame_bypasses_state() {
        let mut r = Reassembler::new(1024, 1024);
        // Begin fragmented data message.
        r.feed(b"he", OPCODE_TEXT, false, false).unwrap();
        // Interleaved control frame must not poison reassembly state.
        let ping = r.feed(b"abc", OPCODE_PING, true, false).unwrap().unwrap();
        assert_eq!(ping.opcode, OPCODE_PING);
        // Resume reassembly cleanly.
        let done = r
            .feed(b"llo", OPCODE_CONTINUATION, true, false)
            .unwrap()
            .unwrap();
        assert_eq!(done.payload, b"hello");
    }

    #[test]
    fn reassembler_rejects_compressed_payload_before_appending() {
        let mut r = Reassembler::new(1, 4);
        assert!(r.feed(b"abcde", OPCODE_TEXT, true, true).is_err());
        assert!(r.capture_buf.is_empty());

        let mut r = Reassembler::new(1, 4);
        r.feed(b"abc", OPCODE_TEXT, false, true).unwrap();
        r.feed(b"ping", OPCODE_PING, true, false).unwrap();
        assert!(r.feed(b"de", OPCODE_CONTINUATION, true, false).is_err());
        assert_eq!(r.capture_buf, b"abc");
    }

    #[test]
    fn reassembler_accepts_compressed_message_at_limit_and_resets_budget() {
        let mut r = Reassembler::new(1, 4);
        r.feed(b"ab", OPCODE_TEXT, false, true).unwrap();
        let message = r
            .feed(b"cd", OPCODE_CONTINUATION, true, false)
            .unwrap()
            .unwrap();
        assert_eq!(message.payload, b"abcd");
        assert!(!message.truncated);
        assert_eq!(
            r.feed(b"efgh", OPCODE_BINARY, true, true)
                .unwrap()
                .unwrap()
                .payload,
            b"efgh"
        );
    }

    // -- Inflater --

    /// Compress with raw deflate and STRIP the trailing 4 bytes —
    /// emulates what permessage-deflate sends on the wire per RFC 7692 §7.2.1.
    fn compress_for_wire(input: &[u8], window_bits: u8, ctx: &mut Compress) -> Vec<u8> {
        let _ = window_bits;
        let mut out = vec![0u8; input.len() + 64];
        let in_before = ctx.total_in();
        let out_before = ctx.total_out();
        ctx.compress(input, &mut out, flate2::FlushCompress::Sync)
            .expect("compress");
        let consumed = (ctx.total_in() - in_before) as usize;
        let produced = (ctx.total_out() - out_before) as usize;
        assert_eq!(consumed, input.len(), "compress must consume all input");
        out.truncate(produced);
        // Drop the 4-byte 00 00 ff ff sync trailer that the encoder emits;
        // the inflater appends it back per RFC 7692.
        assert!(out.ends_with(&DEFLATE_TRAILER), "expected sync trailer");
        out.truncate(out.len() - DEFLATE_TRAILER.len());
        out
    }

    #[test]
    fn inflater_round_trip_simple() {
        let mut compressor = Compress::new(flate2::Compression::default(), false);
        let wire = compress_for_wire(b"hello world", 15, &mut compressor);

        let mut inflater = Inflater::new(15, false);
        let (out, truncated, true_size) = inflater.inflate(&wire, 1024).unwrap();
        assert_eq!(true_size, out.len() as u64);
        assert_eq!(out, b"hello world");
        assert!(!truncated);
    }

    #[test]
    fn inflater_context_takeover_across_messages() {
        let mut compressor = Compress::new(flate2::Compression::default(), false);
        let m1 = compress_for_wire(b"the quick brown fox", 15, &mut compressor);
        // Second message reuses the LZ77 window — must be inflated with
        // shared state.
        let m2 = compress_for_wire(b"the quick brown fox jumps", 15, &mut compressor);

        let mut inflater = Inflater::new(15, false);
        let (out1, _, _) = inflater.inflate(&m1, 1024).unwrap();
        let (out2, _, _) = inflater.inflate(&m2, 1024).unwrap();
        assert_eq!(out1, b"the quick brown fox");
        assert_eq!(out2, b"the quick brown fox jumps");
    }

    #[test]
    fn inflater_no_context_takeover_resets_per_message() {
        // When no_context_takeover is negotiated, both peers MUST reset
        // the encoder/decoder per message. We simulate that on the
        // compress side too.
        let mut c1 = Compress::new(flate2::Compression::default(), false);
        let m1 = compress_for_wire(b"the quick brown fox", 15, &mut c1);
        let mut c2 = Compress::new(flate2::Compression::default(), false);
        let m2 = compress_for_wire(b"the quick brown fox jumps", 15, &mut c2);

        let mut inflater = Inflater::new(15, true);
        let (out1, _, _) = inflater.inflate(&m1, 1024).unwrap();
        let (out2, _, _) = inflater.inflate(&m2, 1024).unwrap();
        assert_eq!(out1, b"the quick brown fox");
        assert_eq!(out2, b"the quick brown fox jumps");
    }

    #[test]
    fn inflater_truncates_output_at_cap() {
        let payload: Vec<u8> = b"ABCDEFGHIJ".repeat(200); // 2000 bytes, repetitive → compresses
        let mut compressor = Compress::new(flate2::Compression::default(), false);
        let wire = compress_for_wire(&payload, 15, &mut compressor);

        let mut inflater = Inflater::new(15, false);
        let (out, truncated, _true_size) = inflater.inflate(&wire, 100).unwrap();
        assert_eq!(out.len(), 100);
        assert_eq!(&out[..], &payload[..100]);
        assert!(truncated);
    }

    /// Output the decompressor could not fit in one scratch buffer is still
    /// pending when the input is exhausted: sizes just past multiples of the
    /// 16 KiB scratch must not lose the tail.
    #[test]
    fn inflater_drains_output_pending_after_input_is_consumed() {
        for len in [16 * 1024 + 1, 50_000, 60_000, 65_536] {
            let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let mut compressor = Compress::new(flate2::Compression::default(), false);
            let wire = compress_for_wire(&payload, 15, &mut compressor);

            let (out, truncated, size) = Inflater::new(15, false).inflate(&wire, 1 << 20).unwrap();
            assert_eq!(out, payload, "len {len}");
            assert!(!truncated, "len {len}");
            assert_eq!(size, len as u64);

            let (out, truncated, size) = Inflater::new(15, false).inflate(&wire, 100).unwrap();
            assert_eq!(out, payload[..100], "len {len}");
            assert!(truncated, "len {len}");
            assert_eq!(size, len as u64, "full size survives the cap");
        }
    }

    #[test]
    fn reassembler_counts_the_full_frame_when_only_a_prefix_was_kept() {
        let mut r = Reassembler::new(1024, 4);
        let m = r
            .feed_frame(b"hell", 11, OPCODE_TEXT, true, false)
            .unwrap()
            .unwrap();
        assert_eq!(m.payload, b"hell");
        assert_eq!(m.payload_size, 11);
        assert!(m.truncated);

        // Fragmented: sizes add up across frames.
        let mut r = Reassembler::new(1024, 4);
        assert!(
            r.feed_frame(b"ab", 2, OPCODE_TEXT, false, false)
                .unwrap()
                .is_none()
        );
        let m = r
            .feed_frame(b"cd", 10, OPCODE_CONTINUATION, true, false)
            .unwrap()
            .unwrap();
        assert_eq!(m.payload_size, 12);
        assert!(m.truncated);
    }

    // -- parse_extensions --

    #[test]
    fn parse_extensions_none() {
        assert!(parse_extensions(&[]).is_none());
        assert!(parse_extensions(&[("x-other".into(), "value".into())]).is_none());
    }

    #[test]
    fn parse_extensions_basic() {
        let h = vec![(
            "Sec-WebSocket-Extensions".to_string(),
            "permessage-deflate".to_string(),
        )];
        let neg = parse_extensions(&h).unwrap();
        assert_eq!(neg, DeflateNegotiation::default());
    }

    #[test]
    fn parse_extensions_with_params() {
        let h = vec![(
            "Sec-WebSocket-Extensions".to_string(),
            "permessage-deflate; client_no_context_takeover; server_max_window_bits=10".to_string(),
        )];
        let neg = parse_extensions(&h).unwrap();
        assert!(neg.client_no_context_takeover);
        assert!(!neg.server_no_context_takeover);
        assert_eq!(neg.server_max_window_bits, 10);
        assert_eq!(neg.client_max_window_bits, 15);
    }

    #[test]
    fn parse_extensions_split_headers() {
        // Multiple Sec-WebSocket-Extensions headers — must be combined.
        let h = vec![
            (
                "Sec-WebSocket-Extensions".to_string(),
                "permessage-deflate; client_max_window_bits=12".to_string(),
            ),
            (
                "sec-websocket-extensions".to_string(),
                "x-experimental-foo".to_string(),
            ),
        ];
        let neg = parse_extensions(&h).unwrap();
        assert_eq!(neg.client_max_window_bits, 12);
    }
}

#[cfg(test)]
mod integration_tests {
    //! End-to-end test of `proxy_websocket` against a real `tokio-tungstenite`
    //! echo server. Verifies:
    //!   * Client text messages traverse the proxy and reach the server.
    //!   * Server-echoed messages traverse back to the client.
    //!   * Captured `WsPipelineEvent`s carry the right direction/opcode/payload.
    //!   * Close frames are captured with code + reason.
    use super::*;
    use crate::pipeline::{WsDirection, WsOpcode};
    use futures_util::{SinkExt, StreamExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_tungstenite::WebSocketStream;
    use tokio_tungstenite::tungstenite::Message;
    use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
    use tokio_tungstenite::tungstenite::protocol::{CloseFrame, Role};

    fn make_ctx(
        capture_tx: tokio::sync::mpsc::Sender<crate::pipeline::WsPipelineEvent>,
    ) -> WsContext {
        WsContext {
            parent_event_id: uuid::Uuid::now_v7(),
            session_id: uuid::Uuid::now_v7(),
            proxy_id: "test-proxy".to_string(),
            org_id: "test-org".to_string(),
            source: "test-source".to_string(),
            source_id: "test-source-id".to_string(),
            host: "test.local".to_string(),
            capture_tx,
            max_payload_capture: 1024 * 1024,
            max_compressed_message_bytes: 16 * 1024 * 1024,
            deflate: None,
            capture_control_frames: false,
            exchange_ratelimit: None,
        }
    }

    fn assert_too_big_close(frame: &[u8], masked: bool) {
        let header = parse_frame_header(frame).unwrap().unwrap();
        assert_eq!(header.opcode, OPCODE_CLOSE);
        assert!(header.fin);
        assert_eq!(header.mask_key.is_some(), masked);
        assert_eq!(header.payload_len, 2);
        assert_eq!(frame.len(), header.header_len + 2);
        let mut payload = frame[header.header_len..].to_vec();
        if let Some(key) = header.mask_key {
            unmask(&mut payload, key);
        }
        assert_eq!(parse_close_payload(&payload).0, Some(1009));
    }

    #[tokio::test]
    async fn oversized_compressed_frame_header_closes_both_peers_without_payload() {
        for direction in [WsDirection::C2s, WsDirection::S2c] {
            let (proxy_client, mut client) = tokio::io::duplex(4096);
            let (proxy_upstream, mut upstream) = tokio::io::duplex(4096);
            let (capture_tx, mut capture_rx) = mpsc::channel(8);
            let mut ctx = make_ctx(capture_tx);
            ctx.deflate = Some(DeflateNegotiation::default());
            let advertised_len = u64::try_from(ctx.max_compressed_message_bytes).unwrap() + 1;
            let proxy = tokio::spawn(proxy_websocket(
                proxy_client,
                proxy_upstream,
                Vec::new(),
                ctx,
            ));
            let mut header = vec![0xc1, 127];
            header.extend_from_slice(&advertised_len.to_be_bytes());
            if matches!(direction, WsDirection::C2s) {
                header[1] |= 0x80;
                header.extend_from_slice(&[1, 2, 3, 4]);
                client.write_all(&header).await.unwrap();
            } else {
                upstream.write_all(&header).await.unwrap();
            }

            // Keep both send sides open and send no payload. Rejection must
            // depend only on the advertised length, not EOF or payload reads.
            let (client_bytes, upstream_bytes) =
                tokio::time::timeout(std::time::Duration::from_secs(2), async {
                    let mut client_bytes = Vec::new();
                    let mut upstream_bytes = Vec::new();
                    client.read_to_end(&mut client_bytes).await.unwrap();
                    upstream.read_to_end(&mut upstream_bytes).await.unwrap();
                    proxy.await.unwrap().unwrap();
                    (client_bytes, upstream_bytes)
                })
                .await
                .expect("oversized compressed frame waited for payload");
            assert_too_big_close(&client_bytes, false);
            assert_too_big_close(&upstream_bytes, true);
            assert!(capture_rx.try_recv().is_err());
        }
    }

    #[tokio::test]
    async fn compressed_fragment_budget_rejects_continuation_header_before_payload() {
        let (proxy_client, mut client) = tokio::io::duplex(4096);
        let (proxy_upstream, mut upstream) = tokio::io::duplex(4096);
        let (capture_tx, mut capture_rx) = mpsc::channel(8);
        let mut ctx = make_ctx(capture_tx);
        ctx.max_compressed_message_bytes = 8;
        ctx.deflate = Some(DeflateNegotiation::default());
        // Initial bytes exercise the post-upgrade prefix path. The control
        // frame must neither consume nor reset the compressed message budget.
        let prefix = b"\x41\x04abcd\x89\x01x";
        let proxy = tokio::spawn(proxy_websocket(
            proxy_client,
            proxy_upstream,
            prefix.to_vec(),
            ctx,
        ));
        // Each fragment fits alone, but 4 + 5 exceeds the message limit.
        // Send no continuation payload and keep the send side open.
        upstream.write_all(&[0x80, 5]).await.unwrap();
        let (client_bytes, upstream_bytes) =
            tokio::time::timeout(std::time::Duration::from_secs(2), async {
                let mut client_bytes = Vec::new();
                let mut upstream_bytes = Vec::new();
                client.read_to_end(&mut client_bytes).await.unwrap();
                upstream.read_to_end(&mut upstream_bytes).await.unwrap();
                proxy.await.unwrap().unwrap();
                (client_bytes, upstream_bytes)
            })
            .await
            .expect("oversized continuation waited for payload");
        assert_eq!(&client_bytes[..prefix.len()], prefix);
        assert_too_big_close(&client_bytes[prefix.len()..], false);
        assert_too_big_close(&upstream_bytes, true);
        assert!(capture_rx.try_recv().is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn echo_text_messages_traverse_proxy() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = listener.local_addr().unwrap();

        // Server: accept TCP and treat as already-upgraded WS (Role::Server).
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let mut ws = WebSocketStream::from_raw_socket(sock, Role::Server, None).await;
            while let Some(item) = ws.next().await {
                match item {
                    Ok(msg) if msg.is_text() || msg.is_binary() => {
                        ws.send(msg).await.unwrap();
                    }
                    Ok(Message::Close(_)) => {
                        // Echo close to satisfy RFC 6455.
                        let _ = ws.close(None).await;
                        break;
                    }
                    Ok(_) => {} // ping/pong handled by tungstenite internally
                    Err(_) => break,
                }
            }
        });

        let upstream_stream = TcpStream::connect(upstream_addr).await.unwrap();
        let (client_side, test_end) = tokio::io::duplex(64 * 1024);

        let (cap_tx, mut cap_rx) = tokio::sync::mpsc::channel(64);
        let ctx = make_ctx(cap_tx);

        let proxy = tokio::spawn(async move {
            proxy_websocket(client_side, upstream_stream, Vec::new(), ctx).await
        });

        // Client side: tungstenite over the duplex test_end.
        let mut client_ws = WebSocketStream::from_raw_socket(test_end, Role::Client, None).await;

        client_ws
            .send(Message::Text("hello".to_string()))
            .await
            .unwrap();
        let echoed = tokio::time::timeout(std::time::Duration::from_secs(5), client_ws.next())
            .await
            .expect("echo timed out")
            .unwrap()
            .unwrap();
        assert!(echoed.is_text());
        assert_eq!(echoed.into_text().unwrap(), "hello");

        client_ws
            .send(Message::Binary(vec![1, 2, 3, 4, 5]))
            .await
            .unwrap();
        let echoed_bin = tokio::time::timeout(std::time::Duration::from_secs(5), client_ws.next())
            .await
            .expect("binary echo timed out")
            .unwrap()
            .unwrap();
        assert!(echoed_bin.is_binary());
        assert_eq!(echoed_bin.into_data(), vec![1, 2, 3, 4, 5]);

        // Initiate close from client; server mirrors.
        client_ws
            .send(Message::Close(Some(CloseFrame {
                code: CloseCode::Normal,
                reason: "bye".into(),
            })))
            .await
            .unwrap();
        // Drain remaining frames (server CLOSE).
        while let Ok(Some(Ok(_))) =
            tokio::time::timeout(std::time::Duration::from_secs(2), client_ws.next()).await
        {
        }
        drop(client_ws);

        // Wait for proxy + server to finish.
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), proxy).await;
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), server).await;

        // Collect captures.
        let mut captures = Vec::new();
        while let Ok(c) = cap_rx.try_recv() {
            captures.push(c);
        }

        // We should have:
        //   - 1 c2s text "hello"
        //   - 1 s2c text "hello"
        //   - 1 c2s binary [1,2,3,4,5]
        //   - 1 s2c binary [1,2,3,4,5]
        //   - 1 c2s close (code=1000, reason="bye")
        //   - 1 s2c close (server's mirror)
        let c2s_text = captures
            .iter()
            .find(|c| c.direction == WsDirection::C2s && c.opcode == WsOpcode::Text)
            .expect("missing c2s text capture");
        assert_eq!(&c2s_text.payload[..], b"hello");
        assert_eq!(c2s_text.payload_size, 5);
        assert!(!c2s_text.was_compressed);

        let s2c_text = captures
            .iter()
            .find(|c| c.direction == WsDirection::S2c && c.opcode == WsOpcode::Text)
            .expect("missing s2c text capture");
        assert_eq!(&s2c_text.payload[..], b"hello");

        let c2s_bin = captures
            .iter()
            .find(|c| c.direction == WsDirection::C2s && c.opcode == WsOpcode::Binary)
            .expect("missing c2s binary capture");
        assert_eq!(&c2s_bin.payload[..], &[1u8, 2, 3, 4, 5]);

        let s2c_bin = captures
            .iter()
            .find(|c| c.direction == WsDirection::S2c && c.opcode == WsOpcode::Binary)
            .expect("missing s2c binary capture");
        assert_eq!(&s2c_bin.payload[..], &[1u8, 2, 3, 4, 5]);

        let close = captures
            .iter()
            .find(|c| c.direction == WsDirection::C2s && c.opcode == WsOpcode::Close)
            .expect("missing c2s close");
        assert_eq!(close.close_code, Some(1000));
        assert_eq!(close.close_reason.as_deref(), Some("bye"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn s2c_prefix_bytes_are_forwarded_and_parsed() {
        // Verify the s2c_prefix path: bytes that the keepalive loop already
        // read past the 101 \r\n\r\n must be (a) forwarded to the client and
        // (b) fed into the s2c parser so the first WS message isn't lost.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let mut ws = WebSocketStream::from_raw_socket(sock, Role::Server, None).await;
            // Push one s2c text frame immediately, before any client traffic.
            ws.send(Message::Text("first".to_string())).await.unwrap();
            // Then echo whatever comes.
            while let Some(Ok(msg)) = ws.next().await {
                if msg.is_text() {
                    ws.send(msg).await.unwrap();
                } else if msg.is_close() {
                    let _ = ws.close(None).await;
                    break;
                }
            }
        });

        // Connect a regular TcpStream and let the server write its first frame
        // before we even start the proxy. We then read those bytes as the
        // "prefix" the keepalive loop would have over-read.
        let mut upstream_stream = TcpStream::connect(upstream_addr).await.unwrap();
        // Wait for the server to send its first frame.
        let mut prefix_buf = vec![0u8; 1024];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            use tokio::io::AsyncReadExt;
            upstream_stream.read(&mut prefix_buf).await
        })
        .await
        .expect("prefix read timed out")
        .unwrap();
        let prefix: Vec<u8> = prefix_buf[..n].to_vec();

        let (client_side, test_end) = tokio::io::duplex(64 * 1024);
        let (cap_tx, mut cap_rx) = tokio::sync::mpsc::channel(64);
        let ctx = make_ctx(cap_tx);

        let proxy = tokio::spawn(async move {
            proxy_websocket(client_side, upstream_stream, prefix, ctx).await
        });

        let mut client_ws = WebSocketStream::from_raw_socket(test_end, Role::Client, None).await;

        // The first message the client reads should be the prefix-forwarded
        // "first" text frame.
        let first = tokio::time::timeout(std::time::Duration::from_secs(5), client_ws.next())
            .await
            .expect("prefix-forwarded message timed out")
            .unwrap()
            .unwrap();
        assert!(first.is_text());
        assert_eq!(first.into_text().unwrap(), "first");

        // Round-trip a follow-up to confirm the proxy is still healthy.
        client_ws
            .send(Message::Text("ping".to_string()))
            .await
            .unwrap();
        let pong = tokio::time::timeout(std::time::Duration::from_secs(5), client_ws.next())
            .await
            .expect("echo timed out")
            .unwrap()
            .unwrap();
        assert_eq!(pong.into_text().unwrap(), "ping");

        client_ws.send(Message::Close(None)).await.unwrap();
        while let Ok(Some(Ok(_))) =
            tokio::time::timeout(std::time::Duration::from_secs(2), client_ws.next()).await
        {
        }
        drop(client_ws);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), proxy).await;
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), server).await;

        // The s2c "first" message must have been parsed (it was in the prefix).
        let mut captures = Vec::new();
        while let Ok(c) = cap_rx.try_recv() {
            captures.push(c);
        }
        let s2c_first = captures
            .iter()
            .find(|c| {
                c.direction == WsDirection::S2c
                    && c.opcode == WsOpcode::Text
                    && &c.payload[..] == b"first"
            })
            .expect("s2c prefix-forwarded message must be captured");
        assert_eq!(s2c_first.payload_size, 5);
    }

    /// End-to-end exercise of the `permessage-deflate` capture path through
    /// `proxy_websocket`.
    ///
    /// `tokio-tungstenite` 0.24 doesn't expose a deflate feature, so this
    /// test crafts the s2c WS frame manually: raw deflate of "hello",
    /// trailer stripped per RFC 7692, RSV1=1. The proxy must inflate into
    /// the captured `WsPipelineEvent` and forward the wire bytes untouched.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn permessage_deflate_s2c_message_inflates_into_capture() {
        use flate2::Compress;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = listener.local_addr().unwrap();

        // Server: write a single rsv1+text frame with deflate-compressed
        // "hello", then a CLOSE, then close TCP.
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();

            // Raw deflate of "hello". Strip the 4-byte sync trailer per RFC 7692.
            let mut compressor = Compress::new(
                flate2::Compression::default(),
                /* zlib_header= */ false,
            );
            let mut compressed = vec![0u8; 64];
            let in_before = compressor.total_in();
            let out_before = compressor.total_out();
            compressor
                .compress(b"hello", &mut compressed, flate2::FlushCompress::Sync)
                .unwrap();
            let consumed = (compressor.total_in() - in_before) as usize;
            let produced = (compressor.total_out() - out_before) as usize;
            assert_eq!(consumed, 5);
            compressed.truncate(produced);
            assert!(compressed.ends_with(&DEFLATE_TRAILER));
            let payload = &compressed[..compressed.len() - DEFLATE_TRAILER.len()];

            // Frame byte 0: FIN(1) | RSV1(1) | opcode=text(1) = 0xC1.
            // Byte 1: MASK(0) | len. Server frames are unmasked.
            assert!(
                payload.len() < 126,
                "deflate of 'hello' must fit in 7-bit length"
            );
            let mut frame = vec![0xC1u8, payload.len() as u8];
            frame.extend_from_slice(payload);
            sock.write_all(&frame).await.unwrap();

            // Server-side CLOSE frame: opcode=8, no payload.
            sock.write_all(&[0x88u8, 0x00]).await.unwrap();

            // Drain client traffic until EOF (client's CLOSE echo).
            let mut sink = vec![0u8; 1024];
            while let Ok(n) = sock.read(&mut sink).await {
                if n == 0 {
                    break;
                }
            }
        });

        let upstream_stream = TcpStream::connect(upstream_addr).await.unwrap();
        let (client_side, mut test_end) = tokio::io::duplex(64 * 1024);
        let (cap_tx, mut cap_rx) = tokio::sync::mpsc::channel(64);
        let mut ctx = make_ctx(cap_tx);
        ctx.deflate = Some(DeflateNegotiation::default());

        let proxy = tokio::spawn(async move {
            proxy_websocket(client_side, upstream_stream, Vec::new(), ctx).await
        });

        // Read everything the proxy forwards until EOF.
        let mut received = Vec::new();
        loop {
            let mut buf = [0u8; 1024];
            match tokio::time::timeout(std::time::Duration::from_secs(3), test_end.read(&mut buf))
                .await
            {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => received.extend_from_slice(&buf[..n]),
                Ok(Err(_)) | Err(_) => break,
            }
        }
        drop(test_end);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), proxy).await;
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), server).await;

        // The first byte the client received must be the RSV1 text frame
        // header (0xC1) -- proxy forwards wire bytes untouched.
        assert!(
            received.starts_with(&[0xC1]),
            "client must receive the RSV1 frame untouched, got: {:02x?}",
            received
        );

        let mut captures = Vec::new();
        while let Ok(c) = cap_rx.try_recv() {
            captures.push(c);
        }
        let s2c_text = captures
            .iter()
            .find(|c| c.direction == WsDirection::S2c && c.opcode == WsOpcode::Text)
            .expect("missing s2c text capture");
        assert_eq!(
            &s2c_text.payload[..],
            b"hello",
            "deflate-compressed payload must inflate to 'hello'"
        );
        assert_eq!(s2c_text.payload_size, 5);
        assert!(
            s2c_text.was_compressed,
            "RSV1 frame must mark was_compressed"
        );
        assert!(!s2c_text.payload_truncated);
    }
}
