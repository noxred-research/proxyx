//! JSON-RPC 2.0 framing and the Model Context Protocol envelope rules.
//!
//! The server speaks two eras of MCP on the same code path:
//!
//! * **Modern** (revision 2026-07-28): stateless. Every request carries its protocol version
//!   and client capabilities in `params._meta`, results carry `resultType`, and the cacheable
//!   ones carry `ttlMs` and `cacheScope`. There is no handshake and no session.
//! * **Legacy** (2025-11-25 down to 2024-11-05): `initialize` then requests. The server keeps
//!   no per-connection state, so the handshake only negotiates the version it echoes back.
//!
//! The era of a request is a property of the request, never of the connection.

use serde_json::{Map, Value, json};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};

/// The frame is not valid JSON.
pub const PARSE_ERROR: i64 = -32700;
/// The JSON is not a valid JSON-RPC request.
pub const INVALID_REQUEST: i64 = -32600;
/// The method does not exist.
pub const METHOD_NOT_FOUND: i64 = -32601;
/// The parameters are wrong.
pub const INVALID_PARAMS: i64 = -32602;
/// The server failed or is saturated.
pub const INTERNAL_ERROR: i64 = -32603;
/// HTTP headers do not match the request body (MCP 2026-07-28).
pub const HEADER_MISMATCH: i64 = -32020;
/// The request needs a client capability that was not declared (MCP 2026-07-28).
pub const MISSING_CAPABILITY: i64 = -32021;
/// The requested protocol version is not served (MCP 2026-07-28).
pub const UNSUPPORTED_VERSION: i64 = -32022;
/// The legacy "resource not found" code, still sent to legacy clients.
pub const LEGACY_RESOURCE_NOT_FOUND: i64 = -32002;

/// Longest accepted stdio frame. A longer line is discarded up to its newline and answered
/// with [`INVALID_REQUEST`], so a runaway client cannot grow the server's memory.
pub const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;

/// Protocol versions that use per-request metadata and no handshake.
pub const MODERN_VERSIONS: [&str; 1] = ["2026-07-28"];
/// Protocol versions that use the `initialize` handshake, newest first.
pub const LEGACY_VERSIONS: [&str; 4] = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

/// `_meta` key carrying the protocol version of a request.
pub const META_VERSION: &str = "io.modelcontextprotocol/protocolVersion";
/// `_meta` key carrying the client identity.
pub const META_CLIENT_INFO: &str = "io.modelcontextprotocol/clientInfo";
/// `_meta` key carrying the client capabilities.
pub const META_CLIENT_CAPS: &str = "io.modelcontextprotocol/clientCapabilities";
/// `_meta` key carrying the server identity in results.
pub const META_SERVER_INFO: &str = "io.modelcontextprotocol/serverInfo";

/// Every version the server speaks, newest first.
pub fn supported_versions() -> Vec<&'static str> {
    MODERN_VERSIONS
        .iter()
        .chain(LEGACY_VERSIONS.iter())
        .copied()
        .collect()
}

/// A JSON-RPC error object, with the HTTP status the streamable HTTP transport answers with.
#[derive(Debug, Clone, PartialEq)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
    pub data: Option<Value>,
    /// HTTP status for the HTTP transport; `None` means `200` (an ordinary JSON-RPC error).
    pub http_status: Option<u16>,
}

impl RpcError {
    pub fn new(code: i64, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
            http_status: None,
        }
    }

    pub fn invalid_params(message: impl Into<String>) -> Self {
        Self::new(INVALID_PARAMS, message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(INTERNAL_ERROR, message)
    }

    #[must_use]
    pub fn with_data(mut self, data: Value) -> Self {
        self.data = Some(data);
        self
    }

    #[must_use]
    pub fn with_status(mut self, status: u16) -> Self {
        self.http_status = Some(status);
        self
    }

    /// The error object.
    pub fn to_value(&self) -> Value {
        let mut error = Map::new();
        error.insert("code".into(), json!(self.code));
        error.insert("message".into(), json!(self.message));
        if let Some(data) = &self.data {
            error.insert("data".into(), data.clone());
        }
        Value::Object(error)
    }
}

/// A well-formed inbound message.
#[derive(Debug, PartialEq)]
pub enum Incoming {
    Request {
        id: Value,
        method: String,
        params: Option<Value>,
    },
    Notification {
        method: String,
        params: Option<Value>,
    },
    /// A response to a server request. The server sends none, so these are ignored.
    Response,
}

/// Classify one decoded JSON value. The error carries the `id` to answer with (`null` when it
/// is unreadable) and the JSON-RPC error.
pub fn parse_incoming(value: Value) -> Result<Incoming, (Value, RpcError)> {
    let Value::Object(mut map) = value else {
        return Err((
            Value::Null,
            RpcError::new(INVALID_REQUEST, "a message must be a JSON object").with_status(400),
        ));
    };
    let id = match map.remove("id") {
        None => None,
        Some(id @ (Value::String(_) | Value::Number(_))) => Some(id),
        Some(_) => {
            return Err((
                Value::Null,
                RpcError::new(INVALID_REQUEST, "`id` must be a string or an integer")
                    .with_status(400),
            ));
        }
    };
    let reply_id = id.clone().unwrap_or(Value::Null);
    if map.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err((
            reply_id,
            RpcError::new(INVALID_REQUEST, "`jsonrpc` must be \"2.0\"").with_status(400),
        ));
    }
    let method = match map.remove("method") {
        Some(Value::String(method)) => Some(method),
        Some(_) => {
            return Err((
                reply_id,
                RpcError::new(INVALID_REQUEST, "`method` must be a string").with_status(400),
            ));
        }
        None => None,
    };
    let params = match map.remove("params") {
        None | Some(Value::Null) => None,
        Some(params @ Value::Object(_)) => Some(params),
        Some(_) => {
            return Err((
                reply_id,
                RpcError::new(INVALID_PARAMS, "`params` must be an object").with_status(400),
            ));
        }
    };
    match (id, method) {
        (Some(id), Some(method)) => Ok(Incoming::Request { id, method, params }),
        (None, Some(method)) => Ok(Incoming::Notification { method, params }),
        (Some(_), None) if map.contains_key("result") || map.contains_key("error") => {
            Ok(Incoming::Response)
        }
        _ => Err((
            reply_id,
            RpcError::new(INVALID_REQUEST, "a request needs a `method`").with_status(400),
        )),
    }
}

/// Success frame for request `id`.
pub fn result_frame(id: &Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

/// Error frame for request `id` (`null` when the id could not be read).
pub fn error_frame(id: &Value, error: &RpcError) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": error.to_value() })
}

/// What a request's `_meta` says about the protocol in use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestMeta {
    pub modern: bool,
    pub version: String,
    pub client_name: Option<String>,
    pub client_version: Option<String>,
}

impl RequestMeta {
    /// Meta of a request without any `_meta`: legacy semantics.
    pub fn legacy() -> Self {
        Self {
            modern: false,
            version: LEGACY_VERSIONS[2].to_owned(),
            client_name: None,
            client_version: None,
        }
    }
}

fn client_identity(info: Option<&Value>) -> (Option<String>, Option<String>) {
    let text = |key: &str| {
        info.and_then(|info| info.get(key))
            .and_then(Value::as_str)
            .map(|text| text.chars().take(128).collect::<String>())
    };
    (text("name"), text("version"))
}

/// Read and validate the per-request metadata.
///
/// A request with a `protocolVersion` in `_meta` is served per that revision; one without is
/// served with legacy semantics.
///
/// # Errors
/// [`UNSUPPORTED_VERSION`] for a version the server does not speak, [`INVALID_PARAMS`] (HTTP
/// `400`) for a modern request that lacks the required `clientCapabilities`.
pub fn read_meta(params: Option<&Value>) -> Result<RequestMeta, RpcError> {
    let Some(meta) = params
        .and_then(|params| params.get("_meta"))
        .and_then(Value::as_object)
    else {
        return Ok(RequestMeta::legacy());
    };
    let (client_name, client_version) = client_identity(meta.get(META_CLIENT_INFO));
    let Some(version) = meta.get(META_VERSION) else {
        let mut legacy = RequestMeta::legacy();
        legacy.client_name = client_name;
        legacy.client_version = client_version;
        return Ok(legacy);
    };
    let Some(version) = version.as_str() else {
        return Err(
            RpcError::invalid_params(format!("`_meta.{META_VERSION}` must be a string"))
                .with_status(400),
        );
    };
    let modern = MODERN_VERSIONS.contains(&version);
    if !modern && !LEGACY_VERSIONS.contains(&version) {
        return Err(unsupported_version(version));
    }
    if modern && !meta.get(META_CLIENT_CAPS).is_some_and(Value::is_object) {
        return Err(RpcError::invalid_params(format!(
            "`_meta.{META_CLIENT_CAPS}` is required and must be an object"
        ))
        .with_status(400));
    }
    Ok(RequestMeta {
        modern,
        version: version.to_owned(),
        client_name,
        client_version,
    })
}

/// The error for a version the server does not speak, listing the versions it does.
pub fn unsupported_version(requested: &str) -> RpcError {
    RpcError::new(UNSUPPORTED_VERSION, "Unsupported protocol version")
        .with_data(json!({ "supported": supported_versions(), "requested": requested }))
        .with_status(400)
}

/// One line read from the client.
#[derive(Debug, PartialEq, Eq)]
pub enum Frame {
    Message(Vec<u8>),
    Oversized,
    Eof,
}

/// Read the next non-blank line, keeping at most `max` bytes of it in memory. A final line
/// without a newline is still delivered.
pub async fn read_frame<R>(reader: &mut R, max: usize) -> std::io::Result<Frame>
where
    R: AsyncBufRead + Unpin,
{
    loop {
        let mut line: Vec<u8> = Vec::new();
        let mut oversized = false;
        let mut saw_any = false;
        loop {
            let available = reader.fill_buf().await?;
            if available.is_empty() {
                break;
            }
            saw_any = true;
            let (chunk, done) = match available.iter().position(|byte| *byte == b'\n') {
                Some(end) => (&available[..end], Some(end + 1)),
                None => (available, None),
            };
            if !oversized {
                if line.len() + chunk.len() > max {
                    oversized = true;
                    line.clear();
                } else {
                    line.extend_from_slice(chunk);
                }
            }
            let consumed = done.unwrap_or(chunk.len());
            reader.consume(consumed);
            if done.is_some() {
                break;
            }
        }
        if !saw_any {
            return Ok(Frame::Eof);
        }
        if oversized {
            return Ok(Frame::Oversized);
        }
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        return Ok(Frame::Message(line));
    }
}

/// Write `frame` as one line and flush. `serde_json` escapes newlines inside strings, so the
/// output is always exactly one line.
pub async fn write_frame<W>(writer: &mut W, frame: &Value) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut bytes = serde_json::to_vec(frame).map_err(std::io::Error::other)?;
    bytes.push(b'\n');
    writer.write_all(&bytes).await?;
    writer.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::BufReader;

    #[test]
    fn classifies_messages() {
        let request = parse_incoming(json!({"jsonrpc":"2.0","id":1,"method":"ping"}));
        assert_eq!(
            request.ok(),
            Some(Incoming::Request {
                id: json!(1),
                method: "ping".into(),
                params: None
            })
        );
        let note = parse_incoming(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
        assert!(matches!(note, Ok(Incoming::Notification { .. })));
        let response = parse_incoming(json!({"jsonrpc":"2.0","id":3,"result":{}}));
        assert_eq!(response.ok(), Some(Incoming::Response));
    }

    #[test]
    fn rejects_malformed_messages() {
        for bad in [
            json!([]),
            json!({"jsonrpc":"1.0","id":1,"method":"x"}),
            json!({"jsonrpc":"2.0","id":null,"method":"x","params":[]}),
            json!({"jsonrpc":"2.0","id":true,"method":"x"}),
            json!({"jsonrpc":"2.0","id":1}),
        ] {
            assert!(parse_incoming(bad).is_err());
        }
    }

    #[test]
    fn meta_selects_the_era() {
        let none = read_meta(None).expect("no meta is legacy");
        assert!(!none.modern);
        let modern = json!({"_meta": {
            META_VERSION: "2026-07-28",
            META_CLIENT_CAPS: {},
            META_CLIENT_INFO: {"name": "t", "version": "1"}
        }});
        let meta = read_meta(Some(&modern)).expect("modern meta");
        assert!(meta.modern);
        assert_eq!(meta.client_name.as_deref(), Some("t"));
        let missing_caps = json!({"_meta": {META_VERSION: "2026-07-28"}});
        let error = read_meta(Some(&missing_caps)).expect_err("caps are required");
        assert_eq!(error.code, INVALID_PARAMS);
        assert_eq!(error.http_status, Some(400));
        let unknown = json!({"_meta": {META_VERSION: "1900-01-01", META_CLIENT_CAPS: {}}});
        let error = read_meta(Some(&unknown)).expect_err("unknown version");
        assert_eq!(error.code, UNSUPPORTED_VERSION);
        assert_eq!(
            error
                .data
                .as_ref()
                .and_then(|data| data["requested"].as_str()),
            Some("1900-01-01")
        );
    }

    #[tokio::test]
    async fn frames_split_on_newlines_and_cap_the_size() {
        let input = b"{\"a\":1}\r\n\n{\"b\":2}\nxxxxxxxxxxxxxxxxxxxx\n{\"c\":3}";
        let mut reader = BufReader::new(&input[..]);
        assert_eq!(
            read_frame(&mut reader, 16).await.expect("frame 1"),
            Frame::Message(b"{\"a\":1}".to_vec())
        );
        assert_eq!(
            read_frame(&mut reader, 16).await.expect("frame 2"),
            Frame::Message(b"{\"b\":2}".to_vec())
        );
        assert_eq!(
            read_frame(&mut reader, 16).await.expect("oversized"),
            Frame::Oversized
        );
        assert_eq!(
            read_frame(&mut reader, 16).await.expect("last frame"),
            Frame::Message(b"{\"c\":3}".to_vec())
        );
        assert_eq!(read_frame(&mut reader, 16).await.expect("eof"), Frame::Eof);
    }
}
