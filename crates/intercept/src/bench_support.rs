//! Entry points for the benchmarks in `proxyx-bench`. They wrap functions that
//! are private to the crate and change no behaviour. Not a supported API.

use anyhow::Result;

use crate::listener::common;
use crate::mitm::{self, CertificateAuthority, websocket};

/// Rewrite a raw request head the way the interception path does: the request
/// line in origin form, hop-by-hop proxy headers dropped, `inject` appended.
pub fn rewrite_request_head(head: &[u8], inject: &[(String, String)]) -> Vec<u8> {
    mitm::build_request_with_injected_headers(head, inject)
}

/// The request line alone, absolute-form to origin-form.
pub fn origin_form_request_line(line: &[u8]) -> Vec<u8> {
    mitm::origin_form_request_line(line).into_owned()
}

/// Strip `Proxy-Authorization` and `Proxy-Connection` from a request head, as
/// the non-intercepting forward path does.
pub fn strip_hop_by_hop(head: &[u8]) -> Vec<u8> {
    mitm::strip_hop_by_hop_request_headers(head)
}

/// Parse the `host:port` of a CONNECT request line.
pub fn parse_connect_authority(authority: &str) -> Result<(String, u16)> {
    common::parse_host_port(authority)
}

/// Parse the absolute URL of a plain-HTTP forward request.
pub fn parse_forward_url(url: &str) -> Result<(String, u16, String)> {
    common::parse_absolute_url(url)
}

/// Header of one WebSocket frame: `(fin, opcode, payload_len, header_len)`.
/// `Ok(None)` when `buf` holds less than a whole header.
pub fn parse_ws_frame_header(buf: &[u8]) -> Result<Option<(bool, u8, u64, usize)>> {
    Ok(websocket::parse_frame_header(buf)?.map(|h| (h.fin, h.opcode, h.payload_len, h.header_len)))
}

/// Apply the RFC 6455 mask to `payload` in place.
pub fn ws_unmask(payload: &mut [u8], key: [u8; 4]) {
    websocket::unmask(payload, key);
}

/// A reassembler of fragmented WebSocket messages, capped at `max_capture`
/// captured bytes per message.
pub struct WsReassembler(websocket::Reassembler);

impl WsReassembler {
    pub fn new(max_capture: usize) -> Self {
        Self(websocket::Reassembler::new(max_capture, 16 * 1024 * 1024))
    }

    /// Feed one frame's payload. Returns the size of the finished message, or
    /// `None` while fragments are pending.
    pub fn feed(&mut self, payload: &[u8], opcode: u8, fin: bool) -> Result<Option<u64>> {
        Ok(self
            .0
            .feed(payload, opcode, fin, false)?
            .map(|m| m.payload_size))
    }
}

/// The certificate authority that signs interception certificates.
pub struct BenchCa(CertificateAuthority);

impl BenchCa {
    pub fn from_der(cert_der: &[u8], key_der: &[u8]) -> Result<Self> {
        Ok(Self(CertificateAuthority::from_der(cert_der, key_der)?))
    }

    /// The leaf certificate for `hostname`: issued on the first call, then
    /// served from the cache.
    pub fn leaf(&self, hostname: &str) -> Result<usize> {
        Ok(self.0.get_cert(hostname)?.cert.len())
    }
}
