//! BitNet daemon authentication.
//!
//! After a successful `unlock` the daemon stores a 32-byte token
//! (the `SessionToken.token` field). Every protected method must
//! present an HMAC-SHA-256 of `method || params_json` keyed with
//! the session token. Verification is constant-time.
//!
//! The signed payload intentionally does not include the frame
//! length or any other transport metadata so that the same
//! signature works for any transport that delivers the same body
//! bytes.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Compute the HMAC-SHA-256 of `msg` under `key` and return it as
/// lower-case hex. Used for the `auth` field on every request.
pub fn hmac_hex(key: &[u8], msg: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts keys of any size");
    mac.update(msg);
    let bytes = mac.finalize().into_bytes();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Compute the canonical request signature. Equivalent to
/// `hmac_hex(key, method.as_bytes()) || hmac_hex(key, params_json)`
/// in spirit, but the daemon signs a single concatenated buffer
/// `method || params_json` so the client and the server cannot
/// disagree on the boundary.
pub fn sign_request(key: &[u8], method: &str, params_json: &[u8]) -> String {
    let mut buf = Vec::with_capacity(method.len() + params_json.len());
    buf.extend_from_slice(method.as_bytes());
    buf.extend_from_slice(params_json);
    hmac_hex(key, &buf)
}

/// Constant-time string comparison. Returns `false` if the two
/// strings differ in length, but does not leak which one was
/// longer (the length is not security-sensitive: hex output is
/// always 64 chars for SHA-256).
fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.bytes().zip(b.bytes()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Verify a request's `auth` field against the expected HMAC.
/// Returns `true` if the auth matches, `false` otherwise.
pub fn verify_request(
    key: &[u8],
    method: &str,
    params_json: &[u8],
    presented_auth: &str,
) -> bool {
    let expected = sign_request(key, method, params_json);
    constant_time_eq(&expected, presented_auth)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_hex_is_lowercase_64_chars() {
        let hex = hmac_hex(b"key", b"msg");
        assert_eq!(hex.len(), 64);
        assert!(
            hex.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "expected lowercase hex: {hex}"
        );
    }

    #[test]
    fn hmac_is_deterministic() {
        assert_eq!(hmac_hex(b"k", b"m"), hmac_hex(b"k", b"m"));
        assert_ne!(hmac_hex(b"k", b"m"), hmac_hex(b"k", b"n"));
    }

    #[test]
    fn hmac_known_vector() {
        // RFC 4231 test case 1 (key=20 bytes 0x0b, data="Hi There").
        let key = [0x0b; 20];
        let msg = b"Hi There";
        let hex = hmac_hex(&key, msg);
        assert_eq!(
            hex,
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn sign_request_matches_hmac_concat() {
        let key = b"0123456789abcdef0123456789abcdef";
        let method = "list_entries";
        let params = b"{}";
        let s = sign_request(key, method, params);
        let mut manual = Vec::new();
        manual.extend_from_slice(method.as_bytes());
        manual.extend_from_slice(params);
        assert_eq!(s, hmac_hex(key, &manual));
    }

    #[test]
    fn verify_request_accepts_matching_signature() {
        let key = b"key";
        let s = sign_request(key, "ping", b"{}");
        assert!(verify_request(key, "ping", b"{}", &s));
    }

    #[test]
    fn verify_request_rejects_wrong_key() {
        let s = sign_request(b"key1", "ping", b"{}");
        assert!(!verify_request(b"key2", "ping", b"{}", &s));
    }

    #[test]
    fn verify_request_rejects_tampered_method() {
        let s = sign_request(b"key", "ping", b"{}");
        assert!(!verify_request(b"key", "list", b"{}", &s));
    }

    #[test]
    fn verify_request_rejects_tampered_params() {
        let s = sign_request(b"key", "ping", b"{}");
        assert!(!verify_request(b"key", "ping", b"{\"x\":1}", &s));
    }

    #[test]
    fn verify_request_rejects_empty_auth() {
        assert!(!verify_request(b"key", "ping", b"{}", ""));
    }

    #[test]
    fn verify_request_rejects_wrong_length() {
        let s = sign_request(b"key", "ping", b"{}");
        // Truncate to half-length; should fail without panic.
        let half = &s[..s.len() / 2];
        assert!(!verify_request(b"key", "ping", b"{}", half));
    }
}
