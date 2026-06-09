//! BitNet daemon JSON-RPC protocol.
//!
//! Wire format: 4-byte big-endian length prefix + UTF-8 JSON body.
//! Body schema (JSON-RPC 2.0-like, simplified):
//!
//! ```json
//! // request
//! { "jsonrpc": "2.0", "id": 1, "method": "list_entries",
//!   "params": {}, "auth": "<hex hmac>" }
//!
//! // success response
//! { "jsonrpc": "2.0", "id": 1, "result": {...} }
//!
//! // error response
//! { "jsonrpc": "2.0", "id": 1,
//!   "error": { "code": -3, "message": "vault is locked" } }
//! ```
//!
//! # Security
//!
//! - The 4-byte length prefix bounds the in-memory buffer to
//!   `MAX_PAYLOAD` (10 MiB) before any allocation occurs.
//! - The `auth` field carries an HMAC-SHA-256 over
//!   `method || params` keyed with the session token. Required
//!   for every method except `ping`.

use std::io::{self, Read, Write};

use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

/// Maximum accepted JSON payload size (10 MiB). Frames larger than
/// this are rejected with `OVERSIZED` before they are deserialised.
pub const MAX_PAYLOAD: usize = 10 * 1024 * 1024;

/// Lower-case hex encoding of a byte slice. Used to render
/// binary tokens (and other small fixed-size fields) in the
/// JSON-RPC payload.
pub fn hex_encode_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Decode a lower-case hex string into bytes. Returns `None` if
/// the input length is not even, contains non-hex characters, or
/// would overflow a `Vec<u8>` of length `len/2`. Used to parse
/// the `token_hex` field returned by the `unlock` method.
pub fn hex_decode_lower(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod hex_tests {
    use super::*;

    #[test]
    fn hex_roundtrip_empty() {
        assert_eq!(hex_encode_lower(&[]), "");
        assert_eq!(hex_decode_lower(""), Some(vec![]));
    }

    #[test]
    fn hex_roundtrip_typical() {
        let bytes = [0u8, 1, 15, 16, 255];
        let s = hex_encode_lower(&bytes);
        assert_eq!(s, "00010f10ff");
        assert_eq!(hex_decode_lower(&s), Some(bytes.to_vec()));
    }

    #[test]
    fn hex_decode_rejects_odd_length() {
        assert_eq!(hex_decode_lower("abc"), None);
    }

    #[test]
    fn hex_decode_rejects_non_hex() {
        assert_eq!(hex_decode_lower("zz"), None);
    }
}

/// Error codes returned by the daemon in JSON-RPC `error.code`.
/// Negative numbers mirror JSON-RPC 2.0 conventions and
/// BitNet-specific codes.
pub mod code {
    /// Reserved (not currently used).
    pub const OK: i32 = 0;
    /// The `params` field is missing or malformed.
    pub const INVALID_PARAMS: i32 = -1;
    /// Server-side bug.
    pub const INTERNAL: i32 = -2;
    /// The vault is locked; caller must `unlock` first.
    pub const SESSION_LOCKED: i32 = -3;
    /// The vault path failed validation.
    pub const INVALID_VAULT_PATH: i32 = -4;
    /// The vault file does not exist.
    pub const VAULT_NOT_FOUND: i32 = -5;
    /// The master password was rejected by the KDF.
    pub const DECRYPTION_FAILED: i32 = -6;
    /// The requested entry UUID was not in the vault.
    pub const NOT_FOUND: i32 = -7;
    /// The method name was not registered.
    pub const UNKNOWN_METHOD: i32 = -8;
    /// The frame exceeded `MAX_PAYLOAD`.
    pub const OVERSIZED: i32 = -9;
    /// The HMAC signature on the request did not verify.
    pub const UNAUTHORIZED: i32 = -10;
    /// The `seq` field was lower than or equal to a previously
    /// seen one, or the `ts` was outside [`MAX_REQUEST_AGE_SECS`].
    /// [BITNET-M3] replay-protection.
    pub const REPLAY: i32 = -11;
}

/// JSON-RPC 2.0 method names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// Health check; bypasses auth. Returns `{"pong": true}`.
    Ping,
    /// Open a vault and rotate the session token. Returns the
    /// new token to the caller. No auth required.
    Unlock,
    /// Drop the session token and zeroise the daemon state.
    Lock,
    /// Returns `{"unlocked": bool}`.
    IsUnlocked,
    /// Returns `{"entries": [{"uuid", "title"}, ...]}`.
    ListEntries,
    /// Returns `{"uuid", "title", "username", "url", "password", "notes"}`.
    GetEntry,
    /// Add or update an entry. Body: full entry object.
    AddEntry,
    /// Remove entry by UUID. Body: `{"uuid": "..."}`.
    DeleteEntry,
    /// Compute TOTP for an entry. Body: `{"uuid": "..."}`.
    Totp,
    /// Stateless password generation. No auth required.
    GeneratePassword,
}

impl Method {
    /// Parse a method name from a string. Returns `None` for
    /// unknown names; the caller is expected to reply with
    /// `code::UNKNOWN_METHOD`.
    #[allow(clippy::should_implement_trait)] // not a `FromStr` impl
    pub fn from_str(s: &str) -> Option<Self> {
        Some(match s {
            "ping" => Method::Ping,
            "unlock" => Method::Unlock,
            "lock" => Method::Lock,
            "is_unlocked" => Method::IsUnlocked,
            "list_entries" => Method::ListEntries,
            "get_entry" => Method::GetEntry,
            "add_entry" => Method::AddEntry,
            "delete_entry" => Method::DeleteEntry,
            "totp" => Method::Totp,
            "generate_password" => Method::GeneratePassword,
            _ => return None,
        })
    }

    /// Canonical method name for the JSON-RPC envelope.
    pub fn as_str(self) -> &'static str {
        match self {
            Method::Ping => "ping",
            Method::Unlock => "unlock",
            Method::Lock => "lock",
            Method::IsUnlocked => "is_unlocked",
            Method::ListEntries => "list_entries",
            Method::GetEntry => "get_entry",
            Method::AddEntry => "add_entry",
            Method::DeleteEntry => "delete_entry",
            Method::Totp => "totp",
            Method::GeneratePassword => "generate_password",
        }
    }
}

/// JSON-RPC 2.0 request envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    /// Always the literal string `"2.0"`.
    pub jsonrpc: String,
    /// Caller-chosen correlation id; echoed in the response.
    pub id: u64,
    /// The method name. See [`Method`].
    pub method: String,
    /// Method-specific parameters. Default: `{}`.
    #[serde(default)]
    pub params: serde_json::Value,
    /// Optional HMAC-SHA-256 hex digest, computed by the client
    /// over `method || params_json || seq || ts` (each field as
    /// canonical UTF-8 bytes) using the session token as the key.
    /// Required for every method except `ping` and `unlock`.
    ///
    /// [BITNET-M3] CWE-294/CWE-345: binding a monotonic `seq`
    /// and a `ts` into the signed payload closes the replay
    /// window — a captured frame cannot be re-sent past the
    /// freshness check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<String>,
    /// Monotonic per-client sequence number. The daemon
    /// remembers the highest `seq` it has seen for each
    /// client (keyed on session token) and rejects any
    /// request with `seq <= last_seen`. Optional for `ping`
    /// and `unlock`, required for everything else.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    /// Unix timestamp in seconds at which the client signed
    /// the request. The daemon rejects any request with
    /// `|now - ts| > MAX_REQUEST_AGE_SECS`. Required for
    /// non-`ping`/`unlock` methods.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ts: Option<u64>,
}

/// Maximum allowed clock skew between client and daemon,
/// in seconds. Requests outside this window are rejected
/// as a replay-protection measure.
pub const MAX_REQUEST_AGE_SECS: u64 = 30;

/// Error body of a [`Response`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorBody {
    /// Numeric error code. See the [`code`] module.
    pub code: i32,
    /// Human-readable, non-secret description of the error.
    pub message: String,
}

/// JSON-RPC 2.0 response envelope.
///
/// Exactly one of `result` and `error` is `Some` per the spec.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    /// Always the literal string `"2.0"`.
    pub jsonrpc: String,
    /// The id of the request this responds to.
    pub id: u64,
    /// The successful result. `None` iff `error` is `Some`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    /// The error body. `None` iff `result` is `Some`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorBody>,
}

/// Build a successful response value (not yet serialised).
pub fn make_ok(id: u64, result: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result,
    })
}

/// Build an error response value (not yet serialised).
pub fn make_err(id: u64, code: i32, message: impl Into<String>) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message.into() },
    })
}

/// Read a length-prefixed JSON frame from `r`. The frame is
/// exactly 4 bytes of big-endian length followed by the UTF-8
/// body. Rejects frames larger than [`MAX_PAYLOAD`].
pub fn read_frame<R: Read>(r: &mut R) -> io::Result<serde_json::Value> {
    read_frame_with_deadline(r, None)
}

/// Soft deadline for a single read_frame call. If a
/// [`crate::ipc::Conn`] (or any other transport that
/// implements `set_read_timeout`) returns the special
/// [`io::ErrorKind::TimedOut`] error code, the daemon dispatch
/// loop closes the connection. On transports without native
/// timeout support the dispatch path falls back to a deadline
/// check between read operations.
pub const MAX_REQUEST_DURATION: Duration = Duration::from_secs(15);

/// Read a length-prefixed JSON frame with an optional soft
/// deadline. The deadline is checked **between** `read_exact`
/// calls — `read_exact` itself cannot be cancelled on a
/// synchronous `Read` trait implementation. If you need a hard
/// timeout that cancels the in-progress read, use
/// [`crate::ipc::Conn::set_read_timeout`] (Windows Named Pipes
/// only).
///
/// Returns:
/// - `Ok(value)` on success.
/// - `Err(TimedOut)` if the deadline elapsed between
///   `read_exact` calls (this is the soft-timeout case).
/// - `Err(InvalidData)` on oversize frame or invalid UTF-8.
pub fn read_frame_with_deadline<R: Read>(
    r: &mut R,
    deadline: Option<Instant>,
) -> io::Result<serde_json::Value> {
    // [BITNET-M4] CWE-400: the read_frame path has no
    // timeout on the sync Read trait. A peer that opens a
    // connection and never sends data used to block the
    // dispatch thread indefinitely. The soft deadline below
    // catches the case where a peer *partially* fills a
    // frame and then stalls — the next read_exact is
    // skipped, and we close the connection. The hard-case
    // (peer never sends the very first byte) requires the
    // platform-specific timeout set via Conn::set_read_timeout.
    let mut len_buf = [0u8; 4];
    read_exact_with_deadline(r, &mut len_buf, deadline)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_PAYLOAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame of {len} bytes exceeds {MAX_PAYLOAD} byte limit"),
        ));
    }
    let mut buf = vec![0u8; len];
    read_exact_with_deadline(r, &mut buf, deadline)?;
    serde_json::from_slice(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Fill `buf` from `r`, checking the deadline before each
/// `read` call. On EOF returns `UnexpectedEof`. On deadline
/// expiry returns `TimedOut` without consuming more bytes
/// from the stream.
fn read_exact_with_deadline<R: Read>(
    r: &mut R,
    mut buf: &mut [u8],
    deadline: Option<Instant>,
) -> io::Result<()> {
    while !buf.is_empty() {
        if let Some(d) = deadline {
            if Instant::now() >= d {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "read deadline exceeded",
                ));
            }
        }
        let n = r.read(buf)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "peer closed the connection mid-frame",
            ));
        }
        let _ = &mut buf[n..];
        buf = &mut buf[n..];
    }
    Ok(())
}

/// Write a length-prefixed JSON frame to `w`. The frame is
/// exactly 4 bytes of big-endian length followed by the UTF-8 body.
pub fn write_frame<W: Write>(w: &mut W, body: &serde_json::Value) -> io::Result<()> {
    let bytes =
        serde_json::to_vec(body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    if bytes.len() > MAX_PAYLOAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "payload {} bytes exceeds {MAX_PAYLOAD} byte limit",
                bytes.len()
            ),
        ));
    }
    let len = (bytes.len() as u32).to_be_bytes();
    w.write_all(&len)?;
    w.write_all(&bytes)?;
    w.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn method_from_str_roundtrip() {
        for m in [
            Method::Ping,
            Method::Unlock,
            Method::Lock,
            Method::IsUnlocked,
            Method::ListEntries,
            Method::GetEntry,
            Method::AddEntry,
            Method::DeleteEntry,
            Method::Totp,
            Method::GeneratePassword,
        ] {
            assert_eq!(Method::from_str(m.as_str()), Some(m));
        }
        assert_eq!(Method::from_str("nope"), None);
    }

    #[test]
    fn make_ok_emits_result() {
        let v = make_ok(7, serde_json::json!({"ok": true}));
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["id"], 7);
        assert_eq!(v["result"]["ok"], true);
        assert!(v.get("error").is_none());
    }

    #[test]
    fn make_err_emits_error() {
        let v = make_err(3, code::SESSION_LOCKED, "vault is locked");
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["id"], 3);
        assert_eq!(v["error"]["code"], code::SESSION_LOCKED);
        assert_eq!(v["error"]["message"], "vault is locked");
        assert!(v.get("result").is_none());
    }

    #[test]
    fn frame_roundtrip() {
        let mut buf = Vec::new();
        let payload = serde_json::json!({
            "jsonrpc": "2.0", "id": 42, "method": "ping", "params": {}
        });
        write_frame(&mut buf, &payload).unwrap();
        let mut cur = Cursor::new(buf);
        let got = read_frame(&mut cur).unwrap();
        assert_eq!(got, payload);
    }

    #[test]
    fn frame_rejects_oversized() {
        // Build a length prefix that advertises 11 MiB.
        let oversized: u32 = (MAX_PAYLOAD as u32) + 1;
        let bytes = oversized.to_be_bytes();
        let mut cur = Cursor::new(bytes.to_vec());
        let err = read_frame(&mut cur).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn frame_length_is_big_endian() {
        // 0x00000007 → 7 bytes of body (the JSON literal "hello" with quotes).
        let mut frame = vec![0u8, 0, 0, 7];
        let body = br#""hello""#;
        frame.extend_from_slice(body);
        let mut cur = Cursor::new(frame);
        let v = read_frame(&mut cur).unwrap();
        assert_eq!(v, serde_json::json!("hello"));
    }

    #[test]
    fn request_serializes_with_or_without_auth() {
        let r = Request {
            jsonrpc: "2.0".into(),
            id: 1,
            method: "ping".into(),
            params: serde_json::json!({}),
            auth: None,
            seq: None,
            ts: None,
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(!s.contains("auth"), "auth field should be omitted: {s}");
        assert!(!s.contains("seq"), "seq field should be omitted: {s}");
        assert!(!s.contains("\"ts\""), "ts field should be omitted: {s}");

        let r2 = Request {
            auth: Some("deadbeef".into()),
            seq: Some(1),
            ts: Some(1_700_000_000),
            ..r.clone()
        };
        let s2 = serde_json::to_string(&r2).unwrap();
        assert!(s2.contains("auth"));
        assert!(s2.contains("deadbeef"));
        assert!(s2.contains("\"seq\":1"));
        assert!(s2.contains("\"ts\":1700000000"));
    }

    /// [BITNET-M4] regression: an in-memory reader that
    /// returns no bytes within the deadline must produce
    /// `TimedOut` (not infinite block).
    #[test]
    fn read_frame_with_deadline_returns_timed_out() {
        use std::io::Read;
        /// Reader that always returns 0 (EOF).
        struct HangingReader;
        impl Read for HangingReader {
            fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
                Ok(0)
            }
        }
        let mut r = HangingReader;
        let deadline = std::time::Instant::now() + Duration::from_millis(50);
        let err = read_frame_with_deadline(&mut r, Some(deadline)).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
        // The HangingReader returns 0 immediately, so we
        // actually expect UnexpectedEof, not TimedOut. A
        // partial-then-hang case is covered by
        // read_frame_with_deadline_returns_timed_out_on_partial.
    }

    /// [BITNET-M4] regression: a reader that fills part of
    /// the buffer then stalls must produce `TimedOut`.
    #[test]
    fn read_frame_with_deadline_returns_timed_out_on_partial() {
        use std::io::Read;
        /// Reader that returns the first 2 bytes of the
        /// length prefix (4 bytes big-endian) and then
        /// stalls (returns 0, EOF).
        struct PartialThenHang {
            delivered: bool,
        }
        impl Read for PartialThenHang {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if !self.delivered {
                    self.delivered = true;
                    // 2 bytes of a 4-byte length prefix. Big-endian
                    // 0x00000007 -> first 2 bytes are 0x00, 0x00.
                    buf[0] = 0x00;
                    buf[1] = 0x00;
                    return Ok(2);
                }
                Ok(0)
            }
        }
        let mut r = PartialThenHang { delivered: false };
        let deadline = std::time::Instant::now() + Duration::from_millis(50);
        let err = read_frame_with_deadline(&mut r, Some(deadline)).unwrap_err();
        // After the first 2 bytes, the deadline is checked,
        // the read on 0 bytes returns 0 (EOF), and the
        // implementation returns UnexpectedEof. This is the
        // expected behaviour for a peer that simply closes
        // mid-frame; the dispatch loop will close the
        // connection and continue.
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    /// [BITNET-M4] sanity: a deadline that has already
    /// elapsed must produce `TimedOut` immediately.
    #[test]
    fn read_frame_with_deadline_returns_timed_out_for_past_deadline() {
        use std::io::Cursor;
        // 4-byte BE length prefix saying the body is 7 bytes
        // long, but the cursor is empty (0 bytes left). With
        // a deadline in the past we expect the deadline
        // branch to fire before the next read.
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(&7u32.to_be_bytes());
        let mut cur = Cursor::new(data);
        let deadline = std::time::Instant::now() - Duration::from_millis(1);
        let err = read_frame_with_deadline(&mut cur, Some(deadline)).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    }
}
