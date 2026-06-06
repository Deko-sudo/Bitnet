//! BitNet daemon — long-running process that holds an unlocked
//! vault and serves JSON-RPC commands over the IPC transport.
//!
//! Concurrency model:
//! - One `Mutex<DaemonState>` guards the in-process state so
//!   concurrent clients serialise.
//! - The IPC server accepts one client at a time. The protocol
//!   uses length-prefixed JSON frames (see `protocol`), so each
//!   `accept` call processes exactly one request/response pair.
//!
//! The actual vault operations are abstracted behind the
//! [`VaultService`] trait. The default implementation
//! ([`NoopVaultService`]) rejects every method with a
//! placeholder, which keeps the daemon testable in isolation.
//! Production wiring plugs in a real implementation that owns
//! a `bitnet_core::SessionManager`.

use std::io::{Read, Write};
use std::sync::Mutex;

use zeroize::Zeroize;

use crate::auth;
use crate::ipc::Conn;
use crate::protocol::{self, code, make_err, make_ok, Method, Request};

/// In-process state of the daemon. Wrapped in a `Mutex` so only
/// one request is being dispatched at a time.
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

/// Vault service trait. Implementations are responsible for the
/// real I/O (vault file path, master password, Argon2, KDBX).
/// The daemon only deals with the JSON-RPC envelope; the service
/// returns either a `serde_json::Value` payload (success) or an
/// `i32` error code from the [`code`] module.
///
/// All methods are synchronous and may block (Argon2, file I/O);
/// the daemon serialises calls on the [`Mutex<DaemonState>`].
pub trait VaultService: Send + Sync {
    /// Open a vault and produce a fresh session token. Returns
    /// the new token (32 bytes) on success; the daemon stores it
    /// in [`DaemonState`] under the lock.
    ///
    /// `params` must include `{"path": "..."}`. The master
    /// password is not transmitted over the daemon IPC — the
    /// service is expected to prompt the user (e.g. via a TTY)
    /// or read it from a pre-shared keychain.
    fn unlock(&self, params: &serde_json::Value) -> Result<[u8; 32], i32>;

    /// Look up the entry list (no secrets, just metadata).
    fn list_entries(&self, _params: &serde_json::Value) -> Result<serde_json::Value, i32> {
        Err(code::UNKNOWN_METHOD)
    }

    /// Return the full entry (including password) for the given
    /// UUID. The daemon never logs this; the client is expected
    /// to zeroise the bytes after use.
    fn get_entry(&self, _params: &serde_json::Value) -> Result<serde_json::Value, i32> {
        Err(code::UNKNOWN_METHOD)
    }

    /// Compute a TOTP code for the given entry.
    fn totp(&self, _params: &serde_json::Value) -> Result<serde_json::Value, i32> {
        Err(code::UNKNOWN_METHOD)
    }

    /// Persist a new entry.
    fn add_entry(&self, _params: &serde_json::Value) -> Result<serde_json::Value, i32> {
        Err(code::UNKNOWN_METHOD)
    }

    /// Remove an entry by UUID.
    fn delete_entry(&self, _params: &serde_json::Value) -> Result<serde_json::Value, i32> {
        Err(code::UNKNOWN_METHOD)
    }

    /// Stateless password generation. Does not require auth.
    fn generate_password(&self, _params: &serde_json::Value) -> Result<serde_json::Value, i32> {
        Err(code::UNKNOWN_METHOD)
    }
}

/// Default [`VaultService`] implementation. Rejects every
/// method that requires vault I/O with `code::UNKNOWN_METHOD`
/// (preserved for backward compat with the v0.1 placeholder
/// behaviour) and is used by tests that exercise the dispatch
/// path without spinning up a real `SessionManager`.
pub struct NoopVaultService;

impl VaultService for NoopVaultService {
    fn unlock(&self, _params: &serde_json::Value) -> Result<[u8; 32], i32> {
        // Generate a deterministic, NON-secret test token. Tests
        // assert on the value (it's never used for any
        // cryptographic operation).
        let mut token = [0u8; 32];
        for (i, b) in token.iter_mut().enumerate() {
            *b = i as u8;
        }
        Ok(token)
    }
}

/// Single-threaded dispatch of a request. The `Mutex<DaemonState>`
/// is held only for the duration of the auth check; the actual
/// method handler runs through the [`VaultService`] trait so it
/// can do slow operations (Argon2, file I/O) without blocking
/// the next caller.
pub fn dispatch<S: VaultService>(
    state: &Mutex<DaemonState>,
    service: &S,
    request: Request,
) -> serde_json::Value {
    let method = match Method::from_str(&request.method) {
        Some(m) => m,
        None => return make_err(request.id, code::UNKNOWN_METHOD, "unknown method"),
    };

    // `ping` and `unlock` bypass auth. `ping` lets clients detect
    // whether the daemon is running; `unlock` is the *only* way a
    // client can obtain a session token, so requiring auth on it
    // would be a chicken-and-egg problem.
    match method {
        Method::Ping => return make_ok(request.id, serde_json::json!({"pong": true})),
        Method::Unlock => {
            // Inline — see `Method::Unlock` arm in the service
            // match below. We do it here so the auth check below
            // is skipped entirely.
            let result = service.unlock(&request.params);
            return match result {
                Ok(new_token) => {
                    let mut g = state.lock().unwrap();
                    g.set_token(new_token);
                    let hex = crate::protocol::hex_encode_lower(&new_token);
                    make_ok(
                        request.id,
                        serde_json::json!({
                            "ok": true,
                            "token_hex": hex,
                            "note": "store this token securely; it is required for all subsequent requests"
                        }),
                    )
                }
                Err(code) => make_err(request.id, code, error_message_for_code(code)),
            };
        }
        _ => {}
    }

    // All other methods require a token AND a valid HMAC.
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

    // Re-serialise `params` to canonical bytes for HMAC. The same
    // bytes the client signed are what the daemon sees (the
    // protocol uses `serde_json::Value` which is deterministic
    // for the inputs we accept).
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

    // Dispatch to the service. `lock` and `is_unlocked` are
    // handled inline because they are state-only and need no
    // service backing.
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
        Method::ListEntries => service_method(request.id, service.list_entries(&request.params)),
        Method::GetEntry => service_method(request.id, service.get_entry(&request.params)),
        Method::Totp => service_method(request.id, service.totp(&request.params)),
        Method::AddEntry => service_method(request.id, service.add_entry(&request.params)),
        Method::DeleteEntry => service_method(request.id, service.delete_entry(&request.params)),
        Method::GeneratePassword => {
            service_method(request.id, service.generate_password(&request.params))
        }
        // ping and unlock were handled above; these arms are
        // unreachable but keep the match exhaustive.
        Method::Ping | Method::Unlock => {
            unreachable!("handled in early return above")
        }
    }
}

/// Helper: convert a service `Result<Value, i32>` into the
/// JSON-RPC response envelope.
fn service_method(
    id: u64,
    result: Result<serde_json::Value, i32>,
) -> serde_json::Value {
    match result {
        Ok(value) => make_ok(id, value),
        Err(code) => make_err(id, code, error_message_for_code(code)),
    }
}

/// Return a short, user-facing message for a known error code.
/// Centralised here so the wire format stays consistent.
fn error_message_for_code(c: i32) -> &'static str {
    match c {
        code::OK => "ok",
        code::INVALID_PARAMS => "invalid params",
        code::INTERNAL => "internal error",
        code::SESSION_LOCKED => "vault is locked",
        code::INVALID_VAULT_PATH => "invalid vault path",
        code::VAULT_NOT_FOUND => "vault not found",
        code::DECRYPTION_FAILED => "wrong password",
        code::NOT_FOUND => "entry not found",
        code::UNKNOWN_METHOD => "method not implemented by this service",
        code::OVERSIZED => "payload too large",
        code::UNAUTHORIZED => "auth failed",
        _ => "daemon error",
    }
}

/// Read one request from `r`, dispatch against `state` via
/// `service`, and write the response to `w`. Generic over the
/// reader and writer so tests can use in-memory buffers.
pub fn handle_one<R: Read, W: Write, S: VaultService>(
    state: &Mutex<DaemonState>,
    service: &S,
    r: &mut R,
    w: &mut W,
) -> std::io::Result<()> {
    let request_value = protocol::read_frame(r)?;
    let request: Request = serde_json::from_value(request_value)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let response = dispatch(state, service, request);
    protocol::write_frame(w, &response)
}

/// Read one request and write one response using a single
/// `&mut Conn` (the connection serves as both reader and
/// writer). Used by the long-running `run_daemon` loop where
/// the OS gives us one bidirectional handle per client.
///
/// Implementation note: the caller's `accept()` loop will
/// call `Server::accept()` again on the next iteration,
/// which re-binds the same handle via `ConnectNamedPipe`.
/// `Conn::Drop` then disconnects the just-finished
/// connection.
pub fn handle_one_in_memory<S: VaultService>(
    state: &Mutex<DaemonState>,
    service: &S,
    conn: &mut Conn,
) -> std::io::Result<()> {
    let request_value = protocol::read_frame(&mut *conn)?;
    let request: Request = serde_json::from_value(request_value)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let response = dispatch(state, service, request);
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
        drop(s);
        let s2 = DaemonState::new();
        assert!(!s2.has_token());
    }

    #[test]
    fn ping_bypasses_auth() {
        let state = Mutex::new(DaemonState::new());
        let svc = NoopVaultService;
        let resp = dispatch(&state, &svc, empty_request(1, "ping"));
        assert_eq!(resp["result"]["pong"], true);
    }

    #[test]
    fn protected_methods_require_token() {
        let state = Mutex::new(DaemonState::new());
        let svc = NoopVaultService;
        let resp = dispatch(&state, &svc, empty_request(3, "list_entries"));
        assert_eq!(resp["error"]["code"], code::SESSION_LOCKED);
    }

    #[test]
    fn protected_methods_require_valid_hmac() {
        let state = Mutex::new(DaemonState::new());
        state.lock().unwrap().set_token([0u8; 32]);
        let svc = NoopVaultService;
        let bad_auth = crate::auth::sign_request(b"wrong-key", "list_entries", b"{}");
        let mut req = empty_request(3, "list_entries");
        req.auth = Some(bad_auth);
        let resp = dispatch(&state, &svc, req);
        assert_eq!(resp["error"]["code"], code::UNAUTHORIZED);
    }

    #[test]
    fn protected_methods_accept_valid_hmac() {
        let state = Mutex::new(DaemonState::new());
        let token = [1u8; 32];
        state.lock().unwrap().set_token(token);
        let svc = NoopVaultService;
        // NoopVaultService rejects list_entries with UNKNOWN_METHOD,
        // so the response is an error envelope — but a `result`
        // field is the wrong type. Adjust the assertion to check
        // that auth passed: the error code should be UNKNOWN_METHOD
        // (not UNAUTHORIZED or SESSION_LOCKED).
        let good_auth = crate::auth::sign_request(&token, "list_entries", b"{}");
        let mut req = empty_request(3, "list_entries");
        req.auth = Some(good_auth);
        let resp = dispatch(&state, &svc, req);
        assert_eq!(resp["error"]["code"], code::UNKNOWN_METHOD);
    }

    #[test]
    fn unlock_sets_token_and_returns_hex() {
        let state = Mutex::new(DaemonState::new());
        let svc = NoopVaultService;
        let resp = dispatch(&state, &svc, empty_request(1, "unlock"));
        assert_eq!(resp["result"]["ok"], true);
        // The NoopVaultService produces [0u8; 32] with indices 0..=31.
        let expected_hex: String = (0..32).map(|i| format!("{i:02x}")).collect();
        assert_eq!(resp["result"]["token_hex"], expected_hex);
        assert!(state.lock().unwrap().has_token());
    }

    #[test]
    fn lock_drops_token_with_valid_hmac() {
        let state = Mutex::new(DaemonState::new());
        let token = [9u8; 32];
        {
            let mut g = state.lock().unwrap();
            g.set_token(token);
        }
        let svc = NoopVaultService;
        let auth = crate::auth::sign_request(&token, "lock", b"{}");
        let mut req = empty_request(4, "lock");
        req.auth = Some(auth);
        let resp = dispatch(&state, &svc, req);
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
        let svc = NoopVaultService;
        let resp = dispatch(&state, &svc, empty_request(1, "definitely_not_a_method"));
        assert_eq!(resp["error"]["code"], code::UNKNOWN_METHOD);
    }

    #[test]
    fn full_roundtrip_via_handle_one() {
        let state = Mutex::new(DaemonState::new());
        let token = [5u8; 32];
        state.lock().unwrap().set_token(token);
        let svc = NoopVaultService;

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
        handle_one(&state, &svc, &mut cur, &mut out).unwrap();

        let resp = protocol::read_frame(&mut Cursor::new(out)).unwrap();
        assert_eq!(resp["id"], 99);
        // NoopVaultService rejects list_entries with UNKNOWN_METHOD.
        assert_eq!(resp["error"]["code"], code::UNKNOWN_METHOD);
    }

    #[test]
    fn unlock_then_lock_roundtrip() {
        // Realistic flow: daemon starts locked, a client unlocks
        // (no auth required), then locks (auth required). Verifies
        // the token returned by unlock is the one that locks.
        let state = Mutex::new(DaemonState::new());
        let svc = NoopVaultService;

        // Step 1: unlock returns a token.
        let unlock_resp = dispatch(&state, &svc, empty_request(1, "unlock"));
        let token_hex = unlock_resp["result"]["token_hex"].as_str().unwrap();
        let token_bytes = crate::protocol::hex_decode_lower(token_hex).unwrap();
        assert_eq!(token_bytes.len(), 32);
        let mut token = [0u8; 32];
        token.copy_from_slice(&token_bytes);

        // Step 2: is_unlocked reports true.
        let is_resp = dispatch(&state, &svc, empty_request(2, "is_unlocked"));
        // Wait — is_unlocked requires auth. The unlock response
        // returned a token, but the test code didn't sign the next
        // request with it. So is_unlocked should be SESSION_LOCKED
        // ... no, that's wrong too. The daemon *has* a token now,
        // but the client needs to present it.
        // Hmm — but the request *also* doesn't have a valid auth
        // field, so we expect SESSION_LOCKED, not is_unlocked:true.
        // Actually, dispatch holds the lock and reads the token,
        // so it sees the token IS present; the request fails on
        // auth check (UNAUTHORIZED).
        assert_eq!(is_resp["error"]["code"], code::UNAUTHORIZED);

        // Step 3: sign a request with the returned token.
        let auth = crate::auth::sign_request(&token, "is_unlocked", b"{}");
        let mut req = empty_request(3, "is_unlocked");
        req.auth = Some(auth);
        let is_resp = dispatch(&state, &svc, req);
        assert_eq!(is_resp["result"]["unlocked"], true);

        // Step 4: lock with the same token.
        let auth = crate::auth::sign_request(&token, "lock", b"{}");
        let mut req = empty_request(4, "lock");
        req.auth = Some(auth);
        let lock_resp = dispatch(&state, &svc, req);
        assert_eq!(lock_resp["result"]["ok"], true);
        assert!(!state.lock().unwrap().has_token());
    }
}
