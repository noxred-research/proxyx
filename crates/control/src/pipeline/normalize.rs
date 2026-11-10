use std::io::Read;

use common::wire;

/// Hard cap on decompressed body size to defeat compression bombs.
/// Bodies that decompress past this limit are stored as the still-compressed
/// (and unreadable) bytes rather than a partial decoding.
pub(crate) const MAX_DECODED_BYTES: u64 = 16 * 1024 * 1024;

const ENCODING_HEADERS: &[&str] = &["content-encoding", "content-length"];

#[derive(Debug, Clone)]
pub(crate) struct NormalizedCapturedRequest {
    pub event_id: uuid::Uuid,
    pub session_id: uuid::Uuid,
    pub proxy_id: String,
    pub org_id: String,
    pub source: String,
    pub source_id: String,
    pub timestamp: time::OffsetDateTime,
    pub session_offset: u64,

    pub method: String,
    pub scheme: String,
    pub host: String,
    pub path: String,
    pub request_headers: Vec<(String, String)>,
    pub request_body: String,
    pub request_size: u64,
    pub status_code: u32,
    pub response_headers: Vec<(String, String)>,
    pub response_body: String,
    pub response_size: u64,
    pub duration_ms: u64,
    pub correlation_id: Option<String>,
    pub parent_correlation_id: Option<String>,
    pub account_id: Option<String>,
    pub tool_call_id: Option<String>,
    pub ratelimit_wait_ms: u64,
}

impl NormalizedCapturedRequest {
    pub(crate) fn from_captured(
        req: &wire::CapturedRequest,
        session_offset: u64,
        correlation_id_header: Option<&str>,
        parent_correlation_id_header: Option<&str>,
        account_id_header: Option<&str>,
        tool_call_id_header: Option<&str>,
    ) -> Self {
        let timestamp =
            time::OffsetDateTime::from_unix_timestamp_nanos(req.timestamp_nanos as i128)
                .unwrap_or_else(|_| time::OffsetDateTime::now_utc());

        let request_headers: Vec<(String, String)> = req
            .request_headers
            .iter()
            .map(|h| (h.name.clone(), h.value.clone()))
            .collect();
        let response_headers: Vec<(String, String)> = req
            .response_headers
            .iter()
            .map(|h| (h.name.clone(), h.value.clone()))
            .collect();

        let (request_headers, request_body) = decode_headers_and_body(
            request_headers,
            &req.request_body,
            req.request_body_truncated,
        );
        let (response_headers, response_body) = decode_headers_and_body(
            response_headers,
            &req.response_body,
            req.response_body_truncated,
        );

        let event_id = uuid::Uuid::from_slice(&req.event_id).unwrap_or_else(|_| uuid::Uuid::nil());
        let session_id =
            uuid::Uuid::from_slice(&req.session_id).unwrap_or_else(|_| uuid::Uuid::nil());

        Self {
            event_id,
            session_id,
            proxy_id: req.proxy_id.clone(),
            org_id: req.org_id.clone(),
            source: req.source.clone(),
            source_id: req.source_id.clone(),
            timestamp,
            session_offset,

            method: req.method.clone(),
            scheme: req.scheme.clone(),
            host: req.host.clone(),
            path: req.path.clone(),
            request_headers,
            request_body,
            request_size: req.request_body_size,
            status_code: req.response_status,
            response_headers,
            response_body,
            response_size: req.response_body_size,
            duration_ms: req.duration_ms,
            correlation_id: extract_header(&req.request_headers, correlation_id_header),
            parent_correlation_id: extract_header(
                &req.request_headers,
                parent_correlation_id_header,
            ),
            account_id: extract_header(&req.request_headers, account_id_header),
            tool_call_id: extract_header(&req.request_headers, tool_call_id_header),
            ratelimit_wait_ms: req.ratelimit_wait_ms,
        }
    }
}

/// Look up the first request header whose name matches `header_name`
/// (case-insensitive) and return its trimmed, non-empty value. Returns
/// `None` if no header name was configured, no matching header exists,
/// or the value is empty after trimming.
fn extract_header(headers: &[wire::Header], header_name: Option<&str>) -> Option<String> {
    let name = header_name?;
    headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(name))
        .map(|h| h.value.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn decode_headers_and_body(
    headers: Vec<(String, String)>,
    body: &[u8],
    truncated: bool,
) -> (Vec<(String, String)>, String) {
    let encoding = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-encoding"))
        .map(|(_, value)| value.trim().to_ascii_lowercase());

    let (decoded, did_decode) = if truncated {
        // A truncated body that was compressed cannot be decoded — the
        // compressed stream is incomplete — and storing the raw compressed
        // bytes is just unreadable garbage. Drop it; the size columns retain
        // the byte-count truth. A truncated *plaintext* body keeps its
        // partial bytes (still useful for search).
        if encoding.is_some() {
            (Vec::new(), false)
        } else {
            (body.to_vec(), false)
        }
    } else {
        match encoding.as_deref() {
            Some("gzip" | "x-gzip") => {
                decompress_gzip(body)
                    .map(|d| (d, true))
                    .unwrap_or_else(|e| {
                        tracing::warn!(encoding = "gzip", error = %e, "decompression failed");
                        (body.to_vec(), false)
                    })
            }
            Some("deflate") => decompress_deflate(body)
                .map(|d| (d, true))
                .unwrap_or_else(|e| {
                    tracing::warn!(encoding = "deflate", error = %e, "decompression failed");
                    (body.to_vec(), false)
                }),
            Some("br") => decompress_brotli(body)
                .map(|d| (d, true))
                .unwrap_or_else(|e| {
                    tracing::warn!(encoding = "br", error = %e, "decompression failed");
                    (body.to_vec(), false)
                }),
            _ => (body.to_vec(), false),
        }
    };

    let normalized_headers: Vec<(String, String)> = headers
        .into_iter()
        .filter(|(name, _)| {
            !(did_decode && ENCODING_HEADERS.contains(&name.to_ascii_lowercase().as_str()))
        })
        .collect();

    // Bodies are stored as plain `String` in ClickHouse so token bloom
    // filter indexes apply. Non-UTF8 / decode-failed bodies become the empty
    // string; the size columns carry the wire byte-count truth. The NUL
    // strip only allocates when a NUL is actually present.
    let body_str = match String::from_utf8(decoded) {
        Ok(s) if s.contains('\0') => s.replace('\0', ""),
        Ok(s) => s,
        Err(_) => String::new(),
    };

    (normalized_headers, body_str)
}

fn decompress_gzip(data: &[u8]) -> std::io::Result<Vec<u8>> {
    let decoder = flate2::read::GzDecoder::new(data);
    read_capped(decoder)
}

fn decompress_deflate(data: &[u8]) -> std::io::Result<Vec<u8>> {
    let decoder = flate2::read::DeflateDecoder::new(data);
    read_capped(decoder)
}

fn decompress_brotli(data: &[u8]) -> std::io::Result<Vec<u8>> {
    let decoder = brotli::Decompressor::new(data, 4096);
    read_capped(decoder)
}

/// Read up to `MAX_DECODED_BYTES + 1`. If the limit is exceeded the read
/// fails so the caller falls back to the raw (compressed) bytes rather than
/// emitting a partial decoding.
fn read_capped<R: Read>(reader: R) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut limited = reader.take(MAX_DECODED_BYTES + 1);
    limited.read_to_end(&mut buf)?;
    if buf.len() as u64 > MAX_DECODED_BYTES {
        tracing::warn!(
            limit = MAX_DECODED_BYTES,
            "decompression rejected: body exceeds cap",
        );
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "decompressed body exceeds size cap",
        ));
    }
    Ok(buf)
}

/// Normalized WebSocket message ready for ClickHouse insert. The proxy
/// already inflated permessage-deflate; we just split text/binary based on
/// UTF-8 validity and strip null bytes from the text path.
#[derive(Debug, Clone)]
pub(crate) struct NormalizedWsMessage {
    pub event_id: uuid::Uuid,
    pub parent_event_id: uuid::Uuid,
    pub session_id: uuid::Uuid,
    pub proxy_id: String,
    pub org_id: String,
    pub source: String,
    pub source_id: String,
    pub host: String,
    pub timestamp: time::OffsetDateTime,
    pub session_offset: u64,
    pub direction: WsDirectionLabel,
    pub opcode: WsOpcodeLabel,
    /// Stored payload bytes. Text payloads hold NUL-stripped UTF-8; binary
    /// payloads hold the raw bytes. Serialized into the CH `String` column
    /// byte-faithfully via `serde_bytes`.
    pub payload: Vec<u8>,
    /// Pre-truncation, post-decompression byte count (carried verbatim from wire).
    pub payload_size: u64,
    pub payload_truncated: bool,
    /// True iff the payload validated as UTF-8 before null-stripping.
    pub payload_is_text: bool,
    pub was_compressed: bool,
    pub close_code: u16,
    pub close_reason: String,
}

/// CH `Enum8` label for direction. Bound to the schema in `ws_init.sql`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WsDirectionLabel {
    C2s,
    S2c,
}

impl WsDirectionLabel {
    #[allow(dead_code)]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::C2s => "c2s",
            Self::S2c => "s2c",
        }
    }

    /// CH `Enum8` discriminant matching `ws_init.sql`:
    /// `Enum8('c2s' = 1, 's2c' = 2)`.  Used at insert time because the
    /// clickhouse-rs RowBinary serializer encodes integers, not strings,
    /// for Enum columns.
    pub(crate) fn discriminant(self) -> i8 {
        match self {
            Self::C2s => 1,
            Self::S2c => 2,
        }
    }
}

/// CH `Enum8` label for opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WsOpcodeLabel {
    Text,
    Binary,
    Close,
    Ping,
    Pong,
}

impl WsOpcodeLabel {
    #[allow(dead_code)]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Binary => "binary",
            Self::Close => "close",
            Self::Ping => "ping",
            Self::Pong => "pong",
        }
    }

    /// CH `Enum8` discriminant matching `ws_init.sql`:
    /// `Enum8('text'=1, 'binary'=2, 'close'=8, 'ping'=9, 'pong'=10)`.
    pub(crate) fn discriminant(self) -> i8 {
        match self {
            Self::Text => 1,
            Self::Binary => 2,
            Self::Close => 8,
            Self::Ping => 9,
            Self::Pong => 10,
        }
    }
}

impl NormalizedWsMessage {
    pub(crate) fn from_wire(msg: &wire::CapturedWsMessage, session_offset: u64) -> Self {
        let timestamp =
            time::OffsetDateTime::from_unix_timestamp_nanos(msg.timestamp_nanos as i128)
                .unwrap_or_else(|_| time::OffsetDateTime::now_utc());

        let event_id = uuid::Uuid::from_slice(&msg.event_id).unwrap_or_else(|_| uuid::Uuid::nil());
        let parent_event_id =
            uuid::Uuid::from_slice(&msg.parent_event_id).unwrap_or_else(|_| uuid::Uuid::nil());
        let session_id =
            uuid::Uuid::from_slice(&msg.session_id).unwrap_or_else(|_| uuid::Uuid::nil());

        let direction = match wire::WsDirection::try_from(msg.direction).unwrap_or_default() {
            wire::WsDirection::C2s => WsDirectionLabel::C2s,
            // Treat unspecified as s2c only as a defensive fallback;
            // proxy never emits Unspecified.
            wire::WsDirection::S2c | wire::WsDirection::Unspecified => WsDirectionLabel::S2c,
        };
        let opcode = match wire::WsOpcode::try_from(msg.opcode).unwrap_or_default() {
            wire::WsOpcode::Text => WsOpcodeLabel::Text,
            wire::WsOpcode::Binary => WsOpcodeLabel::Binary,
            wire::WsOpcode::Close => WsOpcodeLabel::Close,
            wire::WsOpcode::Ping => WsOpcodeLabel::Ping,
            wire::WsOpcode::Pong => WsOpcodeLabel::Pong,
            wire::WsOpcode::Unspecified => {
                tracing::warn!(
                    event_id = %event_id,
                    "ws message with unspecified opcode; coercing to binary"
                );
                WsOpcodeLabel::Binary
            }
        };

        // UTF-8 detection. Text-detected payloads are stored with NUL stripped
        // (CH query convenience). Binary or non-UTF-8 are stored byte-faithfully
        // as raw bytes — no `unsafe`; the row type serializes `Vec<u8>` into the
        // CH `String` column via `serde_bytes`.
        let (payload, payload_is_text): (Vec<u8>, bool) = match std::str::from_utf8(&msg.payload) {
            Ok(s) => (s.replace('\0', "").into_bytes(), true),
            Err(_) => (msg.payload.to_vec(), false),
        };

        Self {
            event_id,
            parent_event_id,
            session_id,
            proxy_id: msg.proxy_id.clone(),
            org_id: msg.org_id.clone(),
            source: msg.source.clone(),
            source_id: msg.source_id.clone(),
            host: msg.host.clone(),
            timestamp,
            session_offset,
            direction,
            opcode,
            payload,
            payload_size: msg.payload_size,
            payload_truncated: msg.payload_truncated,
            payload_is_text,
            was_compressed: msg.was_compressed,
            close_code: msg.close_code.min(u16::MAX as u32) as u16,
            close_reason: msg.close_reason.clone(),
        }
    }
}
