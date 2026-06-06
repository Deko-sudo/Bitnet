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

/// Maximum accepted JSON payload size (10 MiB). Frames larger than
/// this are rejected with `OVERSIZED` before they are deserialised.
pub const MAX_PAYLOAD: usize = 10 * 1024 * 1024;

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
    /// over `method || params_json` using the session token as the
    /// key. Required for every method except `ping`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<String>,
}

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
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_PAYLOAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame of {len} bytes exceeds {MAX_PAYLOAD} byte limit"),
        ));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    serde_json::from_slice(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Write a length-prefixed JSON frame to `w`. The frame is
/// exactly 4 bytes of big-endian length followed by the UTF-8 body.
pub fn write_frame<W: Write>(w: &mut W, body: &serde_json::Value) -> io::Result<()> {
    let bytes = serde_json::to_vec(body)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    if bytes.len() > MAX_PAYLOAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("payload {} bytes exceeds {MAX_PAYLOAD} byte limit", bytes.len()),
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
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(!s.contains("auth"), "auth field should be omitted: {s}");

        let r2 = Request {
            auth: Some("deadbeef".into()),
            ..r.clone()
        };
        let s2 = serde_json::to_string(&r2).unwrap();
        assert!(s2.contains("auth"));
        assert!(s2.contains("deadbeef"));
    }
}
