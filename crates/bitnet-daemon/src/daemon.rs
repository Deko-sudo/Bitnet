//! BitNet daemon — long-running process that holds an unlocked
//! `SessionManager` and serves JSON-RPC commands over the IPC transport.
//!
//! Concurrency model:
//! - One `Mutex<DaemonState>` guards the in-process state so
//!   concurrent clients serialise.
//! - The IPC server accepts one client at a time. The protocol
//!   uses length-prefixed JSON frames (see `protocol`), so each
//!   `accept` call processes exactly one request/response pair.

use std::io::{Read, Write};
use std::sync::Mutex;

use zeroize::Zeroize;

use crate::auth;
use crate::ipc::Conn;
use crate::protocol::{self, code, make_err, make_ok, Method, Request};

/// In-process state of the daemon. Wrapped in a `Mutex` so only one
/// request is being dispatched at a time.
pub struct DaemonState {
    /// Session token, or `None` when the vault is locked. Stored
    /// in a fixed-size 32-byte array so the [`Zeroize`] impl on
    /// `[u8; 32]` wipes it cleanly.
    pub token: Option<[u8; 32]>,
}

impl DaemonState {
    /// Create an empty, locked daemon state.
    pub fn new() -> Self {
        Self { token: None }
    }

    /// Whether the daemon currently holds a session token.
    pub fn has_token(&self) -> bool {
        self.token.is_some()
    }

    /// Arm the daemon with a fresh 32-byte session token.
    /// Replaces any previous token (which is zeroised).
    pub fn set_token(&mut self, token: [u8; 32]) {
        if let Some(mut prev) = self.token.take() {
            prev.zeroize();
        }
        self.token = Some(token);
    }

    /// Drop the session token. Returns `true` if a token was
    /// actually present (and zeroised).
    pub fn clear_token(&mut self) -> bool {
        if let Some(mut t) = self.token.take() {
            t.zeroize();
            true
        } else {
            false
        }
    }

    /// Read-only view of the current token. Returns `None` when
    /// the vault is locked. Intended for HMAC verification.
    pub fn token(&self) -> Option<&[u8; 32]> {
        self.token.as_ref()
    }
}

impl Default for DaemonState {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for DaemonState {
    fn drop(&mut self) {
        // Belt and suspenders: even if a caller forgot to call
        // `clear_token`, the destructor wipes the bytes.
        self.clear_token();
    }
}

/// Single-threaded dispatch of a request. The `Mutex<DaemonState>`
/// is held only for the duration of the auth check; the actual
/// method handler runs *outside* the lock so it can do slow
/// operations (Argon2, file I/O) without blocking the next caller.
/// The lock is reacquired only to mutate the token on `unlock` /
/// `lock`.
pub fn dispatch(state: &Mutex<DaemonState>, request: Request) -> serde_json::Value {
    let method = match Method::from_str(&request.method) {
        Some(m) => m,
        None => return make_err(request.id, code::UNKNOWN_METHOD, "unknown method"),
    };

    // Ping is the only method that bypasses auth — clients use it
    // to detect whether the daemon is running at all.
    if method == Method::Ping {
        return make_ok(request.id, serde_json::json!({"pong": true}));
    }

    // All other methods require a token AND a valid HMAC.
    // We hold the lock just long enough to read the token, then
    // release it before re-serialising params and verifying the
    // signature. A concurrent `unlock` between those two steps
    // cannot break correctness: the worst case is that we verify
    // against the *old* token and the client gets SESSION_LOCKED
    // back, which it would have gotten anyway.
    let token: [u8; 32] = {
        let guard = match state.lock() {
            Ok(g) => g,
            Err(e) => {
                tracing::error!(error = %e, "daemon state mutex poisoned");
                return make_err(request.id, code::INTERNAL, "internal error");
            }
        };
        match guard.token() {
            Some(t) => *t,
            None => return make_err(request.id, code::SESSION_LOCKED, "vault is locked"),
        }
    };

    // Re-serialise `params` to canonical bytes for HMAC. We do this
    // *after* releasing the lock; the same bytes the client signed
    // are what the daemon sees (the protocol uses `serde_json::Value`
    // which is deterministic for the inputs we accept).
    let params_json = match serde_json::to_vec(&request.params) {
        Ok(b) => b,
        Err(e) => {
            return make_err(
                request.id,
                code::INVALID_PARAMS,
                format!("params re-serialise failed: {e}"),
            );
        }
    };

    let auth_ok = request
        .auth
        .as_deref()
        .map(|a| auth::verify_request(&token, &request.method, &params_json, a))
        .unwrap_or(false);
    if !auth_ok {
        return make_err(request.id, code::UNAUTHORIZED, "auth failed");
    }

    // For this commit, the only method with a meaningful handler is
    // `lock`. The other methods are routed but return a placeholder
    // so callers can detect that the daemon understood the request.
    match method {
        Method::Lock => {
            let mut g = state.lock().unwrap();
            g.clear_token();
            make_ok(request.id, serde_json::json!({"ok": true}))
        }
        Method::IsUnlocked => {
            let g = state.lock().unwrap();
            make_ok(request.id, serde_json::json!({"unlocked": g.has_token()}))
        }
        _ => make_ok(
            request.id,
            serde_json::json!({
                "ok": true,
                "method": method.as_str(),
                "note": "method acknowledged; full handler pending follow-up"
            }),
        ),
    }
}

/// Read one request from `r`, dispatch against `state`, and write
/// the response to `w`. Generic over the reader and writer so
/// tests can use in-memory buffers.
pub fn handle_one<R: Read, W: Write>(
    state: &Mutex<DaemonState>,
    r: &mut R,
    w: &mut W,
) -> std::io::Result<()> {
    let request_value = protocol::read_frame(r)?;
    let request: Request = serde_json::from_value(request_value)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let response = dispatch(state, request);
    protocol::write_frame(w, &response)
}

/// Read one request and write one response using a single
/// `&mut Conn` (the connection serves as both reader and writer).
/// Used by the long-running `run_daemon` loop where the OS gives
/// us one bidirectional handle per client.
pub fn handle_one_in_memory(
    state: &Mutex<DaemonState>,
    conn: &mut Conn,
) -> std::io::Result<()> {
    let request_value = protocol::read_frame(&mut *conn)?;
    let request: Request = serde_json::from_value(request_value)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let response = dispatch(state, request);
    protocol::write_frame(&mut *conn, &response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn empty_request(id: u64, method: &str) -> Request {
        Request {
            jsonrpc: "2.0".into(),
            id,
            method: method.into(),
            params: serde_json::json!({}),
            auth: None,
        }
    }

    #[test]
    fn new_state_is_locked() {
        let s = DaemonState::new();
        assert!(!s.has_token());
        assert!(s.token().is_none());
    }

    #[test]
    fn set_and_clear_token() {
        let mut s = DaemonState::new();
        s.set_token([7u8; 32]);
        assert!(s.has_token());
        assert_eq!(s.token(), Some(&[7u8; 32]));
        let was_present = s.clear_token();
        assert!(was_present);
        assert!(!s.has_token());
    }

    #[test]
    fn clear_token_on_empty_returns_false() {
        let mut s = DaemonState::new();
        assert!(!s.clear_token());
    }

    #[test]
    fn drop_state_zeroises_token() {
        let mut s = DaemonState::new();
        s.set_token([42u8; 32]);
        // After Drop, no way to inspect the buffer; this just
        // asserts that Drop doesn't panic and that subsequent
        // construction works.
        drop(s);
        let s2 = DaemonState::new();
        assert!(!s2.has_token());
    }

    #[test]
    fn ping_bypasses_auth() {
        let state = Mutex::new(DaemonState::new());
        let resp = dispatch(&state, empty_request(1, "ping"));
        assert_eq!(resp["result"]["pong"], true);
    }

    #[test]
    fn protected_methods_require_token() {
        let state = Mutex::new(DaemonState::new());
        let resp = dispatch(&state, empty_request(3, "list_entries"));
        assert_eq!(resp["error"]["code"], code::SESSION_LOCKED);
    }

    #[test]
    fn protected_methods_require_valid_hmac() {
        let state = Mutex::new(DaemonState::new());
        state.lock().unwrap().set_token([0u8; 32]);
        // Sign with the WRONG key.
        let bad_auth = crate::auth::sign_request(b"wrong-key", "list_entries", b"{}");
        let mut req = empty_request(3, "list_entries");
        req.auth = Some(bad_auth);
        let resp = dispatch(&state, req);
        assert_eq!(resp["error"]["code"], code::UNAUTHORIZED);
    }

    #[test]
    fn protected_methods_accept_valid_hmac() {
        let state = Mutex::new(DaemonState::new());
        let token = [1u8; 32];
        state.lock().unwrap().set_token(token);
        let good_auth = crate::auth::sign_request(&token, "list_entries", b"{}");
        let mut req = empty_request(3, "list_entries");
        req.auth = Some(good_auth);
        let resp = dispatch(&state, req);
        assert_eq!(resp["result"]["ok"], true);
    }

    #[test]
    fn lock_drops_token_with_valid_hmac() {
        let state = Mutex::new(DaemonState::new());
        let token = [9u8; 32];
        {
            let mut g = state.lock().unwrap();
            g.set_token(token);
        }
        let auth = crate::auth::sign_request(&token, "lock", b"{}");
        let mut req = empty_request(4, "lock");
        req.auth = Some(auth);
        let resp = dispatch(&state, req);
        assert_eq!(resp["result"]["ok"], true);
        assert!(!state.lock().unwrap().has_token());
    }

    #[test]
    fn is_unlocked_reports_token_state() {
        let mut s = DaemonState::new();
        assert!(!s.has_token());
        s.set_token([0u8; 32]);
        assert!(s.has_token());
    }

    #[test]
    fn unknown_method_returns_error_code() {
        let state = Mutex::new(DaemonState::new());
        let resp = dispatch(&state, empty_request(1, "definitely_not_a_method"));
        assert_eq!(resp["error"]["code"], code::UNKNOWN_METHOD);
    }

    #[test]
    fn full_roundtrip_via_handle_one() {
        // in-memory pipes for end-to-end protocol coverage
        let state = Mutex::new(DaemonState::new());
        let token = [5u8; 32];
        state.lock().unwrap().set_token(token);

        let req = Request {
            jsonrpc: "2.0".into(),
            id: 99,
            method: "list_entries".into(),
            params: serde_json::json!({}),
            auth: Some(crate::auth::sign_request(&token, "list_entries", b"{}")),
        };
        let body = serde_json::to_value(&req).unwrap();
        let mut sink: Vec<u8> = Vec::new();
        protocol::write_frame(&mut sink, &body).unwrap();
        let mut cur = Cursor::new(sink);

        let mut out: Vec<u8> = Vec::new();
        handle_one(&state, &mut cur, &mut out).unwrap();

        // Parse the response frame.
        let resp = protocol::read_frame(&mut Cursor::new(out)).unwrap();
        assert_eq!(resp["id"], 99);
        assert_eq!(resp["result"]["ok"], true);
    }
}
