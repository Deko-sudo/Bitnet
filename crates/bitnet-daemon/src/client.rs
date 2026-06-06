//! BitNet daemon client — connects to the running daemon over the
//! IPC transport and issues JSON-RPC requests.

use std::io;

use crate::auth;
use crate::ipc::Client;
use crate::protocol::{self, code, Method, Request};

/// Connect to the daemon and send `request` with an HMAC signed by
/// `token`. Returns the parsed JSON-RPC response value (raw JSON).
pub fn call(token: &[u8], request: &Request) -> io::Result<serde_json::Value> {
    // Connect first; if the daemon is not running, the caller
    // sees an `io::Error` and falls back to direct mode.
    let mut client = Client::connect()?;

    // Re-serialise `params` to canonical bytes for HMAC. We do
    // this before writing the frame so the signed payload matches
    // the bytes the daemon will re-serialise on receipt.
    let params_bytes = serde_json::to_vec(&request.params)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let auth_hex = auth::sign_request(token, &request.method, &params_bytes);
    let mut signed = request.clone();
    signed.auth = Some(auth_hex);

    let frame =
        serde_json::to_value(&signed).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    protocol::write_frame(&mut client, &frame)?;

    protocol::read_frame(&mut client)
}

/// Helper: build a `Request` from `id`, `method`, and `params`.
pub fn make_request(id: u64, method: Method, params: serde_json::Value) -> Request {
    Request {
        jsonrpc: "2.0".into(),
        id,
        method: method.as_str().into(),
        params,
        auth: None, // `call` fills this in.
    }
}

/// Convenience for the CLI: returns `true` if the daemon is
/// reachable AND responds with `pong`. Used to decide whether to
/// fall back to direct mode.
pub fn daemon_alive() -> bool {
    let mut client = match Client::connect() {
        Ok(c) => c,
        Err(_) => return false,
    };
    let req = make_request(0, Method::Ping, serde_json::json!({}));
    let value = match serde_json::to_value(&req) {
        Ok(v) => v,
        Err(_) => return false,
    };
    if protocol::write_frame(&mut client, &value).is_err() {
        return false;
    }
    match protocol::read_frame(&mut client) {
        Ok(response) => response.get("result").and_then(|r| r.get("pong")).is_some(),
        Err(_) => false,
    }
}

/// Pick a short user-meaningful description for an error code.
pub fn describe_error_code(code: i32) -> &'static str {
    match code {
        code::OK => "ok",
        code::INVALID_PARAMS => "invalid params",
        code::INTERNAL => "internal error",
        code::SESSION_LOCKED => "vault is locked",
        code::INVALID_VAULT_PATH => "invalid vault path",
        code::VAULT_NOT_FOUND => "vault not found",
        code::DECRYPTION_FAILED => "wrong password",
        code::NOT_FOUND => "entry not found",
        code::UNKNOWN_METHOD => "unknown method",
        code::OVERSIZED => "payload too large",
        code::UNAUTHORIZED => "auth failed",
        _ => "daemon error",
    }
}

/// Parse a JSON-RPC response value into `(result, error_code)`.
/// Exactly one of the two is `Some`.
pub fn split_response(value: serde_json::Value) -> (Option<serde_json::Value>, Option<i32>) {
    if let Some(err) = value.get("error") {
        let code = err
            .get("code")
            .and_then(|c| c.as_i64())
            .map(|c| c as i32)
            .unwrap_or(code::INTERNAL);
        return (None, Some(code));
    }
    let result = value.get("result").cloned();
    (result, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn make_request_has_no_auth() {
        let req = make_request(1, Method::ListEntries, serde_json::json!({}));
        assert!(req.auth.is_none());
        assert_eq!(req.method, "list_entries");
    }

    #[test]
    fn split_response_success() {
        let v = serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "result": {"ok": true}
        });
        let (result, err) = split_response(v);
        assert_eq!(result.unwrap()["ok"], true);
        assert!(err.is_none());
    }

    #[test]
    fn split_response_error() {
        let v = serde_json::json!({
            "jsonrpc": "2.0", "id": 1,
            "error": {"code": -3, "message": "locked"}
        });
        let (result, err) = split_response(v);
        assert!(result.is_none());
        assert_eq!(err, Some(-3));
    }

    #[test]
    fn describe_error_known_codes() {
        assert_eq!(describe_error_code(code::SESSION_LOCKED), "vault is locked");
        assert_eq!(describe_error_code(code::UNAUTHORIZED), "auth failed");
        assert_eq!(
            describe_error_code(code::DECRYPTION_FAILED),
            "wrong password"
        );
    }

    #[test]
    fn daemon_alive_returns_false_when_no_daemon() {
        // No daemon is running during tests, so this must return
        // `false` (the connect call fails). We rely on the
        // transport returning a connection-refused error.
        assert!(!daemon_alive());
    }
}
