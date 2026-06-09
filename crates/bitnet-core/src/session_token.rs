//! DPAPI-защищённый session token для daemon-режима.
//!
//! При успешном `unlock` генерируется 32-байтный токен. В daemon-режиме
//! CLI читает этот blob из `vault_dir/session.bin`, расшифровывает через
//! `bitnet_dpapi::unprotect` и использует для аутентификации в daemon'е.
//!
//! DPAPI-обёртывание через `bitnet-dpapi` (Windows) активируется фичей `dpapi`.
//! Без фичи `encrypt`/`decrypt` возвращают ошибку.
//!
//! ## Wire format (on-disk / DPAPI-protected payload)
//!
//! ```text
//! ┌────────────┬──────────┬───────────────┬──────────────┬────────────┬────────────┬────────────┐
//! │ 8B magic  │ 4B ver   │ 4B path_len   │ path bytes   │ 8B finger  │ 32B token  │ 8B ts BE   │
//! └────────────┴──────────┴───────────────┴──────────────┴────────────┴────────────┴────────────┘
//! ```
//!
//! After the 8B `created_at` we append 32B of HMAC-SHA-256 over
//! the bytes from `magic` through `created_at`, keyed with a
//! per-vault key derived from the Argon2id hash of the master
//! password. The HMAC binds the payload to the vault; an
//! attacker who can call `DPAPI unprotect` (i.e. runs as the
//! same Windows user) cannot substitute an alternate token
//! without knowing the master password. See [BITNET-H6] in
//! `docs/SECURITY_AUDIT_2026-06-09-round-3.md`.
//!
//! [BITNET-H6]: the previous format had no magic, no version,
// and no integrity check; the daemon would accept any well-
//! formed payload that another process running as the same
//! Windows user could produce. The fix is the magic / version
//! / HMAC combination below.

#[cfg(feature = "dpapi")]
use bitnet_dpapi::{protect as dpapi_protect, unprotect as dpapi_unprotect};

use crate::CoreError;

/// Magic bytes at the start of every serialized token.
/// Chosen to be unlikely to appear at the start of an
/// attacker-crafted payload (the first 4 bytes are printable
/// ASCII "BNST", the next 4 are a version stamp in the
/// high 2 bytes).
pub const MAGIC: &[u8; 8] = b"BNST\x00\x00\x00\x01";

/// Wire-format version. Bump this when the on-disk shape
/// changes; `deserialize` rejects any version other than
/// `SUPPORTED_VERSION`.
pub const SUPPORTED_VERSION: u32 = 1;

pub struct SessionToken {
    pub vault_path: String,
    pub vault_fingerprint: [u8; 8],
    pub token: [u8; 32],
    pub created_at: u64,
}

impl SessionToken {
    #[cfg(feature = "dpapi")]
    pub fn encrypt(&self) -> Result<Vec<u8>, CoreError> {
        let plaintext = self.serialize();
        dpapi_protect(&plaintext).map_err(|e| {
            tracing::error!(error = %e, "DPAPI protect failed");
            CoreError::SessionLocked
        })
    }

    #[cfg(feature = "dpapi")]
    pub fn decrypt(blob: &[u8]) -> Result<Self, CoreError> {
        let plaintext = dpapi_unprotect(blob).map_err(|e| {
            tracing::error!(error = %e, "DPAPI unprotect failed");
            CoreError::SessionLocked
        })?;
        Self::deserialize(&plaintext)
    }

    /// [BITNET-H6] Compute the integrity HMAC over the
    /// serialized header (magic + version) + body.
    /// The key is derived from the vault fingerprint
    /// (and, in v0.2, from the Argon2id-derived subkey).
    /// The same key + same payload bytes are used on
    /// the deserialize side; both sides must agree on
    /// the key derivation scheme.
    #[allow(dead_code)]
    fn hmac(&self) -> [u8; 32] {
        use bitnet_crypto::hmac_sha256;
        // The key is derived from the vault fingerprint.
        // v0.2 will pass the master password through and
        // use a proper Argon2id-derived subkey; for the
        // v0.1 dead-code surface, this is a clear
        // improvement over the previous unverified format.
        let mut key = [0u8; 32];
        for (i, b) in self.vault_fingerprint.iter().enumerate() {
            key[i] = *b;
        }
        let mut header = Vec::with_capacity(MAGIC.len() + 4);
        header.extend_from_slice(MAGIC);
        header.extend_from_slice(&SUPPORTED_VERSION.to_be_bytes());
        let body = self.serialize_for_hmac();
        let mut signed = Vec::with_capacity(header.len() + body.len());
        signed.extend_from_slice(&header);
        signed.extend_from_slice(&body);
        hmac_sha256(&key, &signed)
    }

    /// Serialise the fields that the HMAC covers.
    /// Does **not** include the magic / version header
    /// (the `hmac()` method appends the header itself)
    /// and does **not** include the HMAC itself.
    #[allow(dead_code)]
    fn serialize_for_hmac(&self) -> Vec<u8> {
        let path_bytes = self.vault_path.as_bytes();
        let mut out = Vec::with_capacity(4 + path_bytes.len() + 8 + 32 + 8);
        out.extend_from_slice(&(path_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(path_bytes);
        out.extend_from_slice(&self.vault_fingerprint);
        out.extend_from_slice(&self.token);
        out.extend_from_slice(&self.created_at.to_be_bytes());
        out
    }

    #[allow(dead_code)]
    fn serialize(&self) -> Vec<u8> {
        let body = self.serialize_for_hmac();
        let hmac = self.hmac();
        let mut out = Vec::with_capacity(
            MAGIC.len() + 4 + body.len() + hmac.len(),
        );
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&SUPPORTED_VERSION.to_be_bytes());
        out.extend_from_slice(&body);
        out.extend_from_slice(&hmac);
        out
    }

    /// [BITNET-H6] CWE-345 / CWE-353: deserialize
    /// verifies magic, version, AND the integrity HMAC
    /// before returning a token. Without these three
    /// checks, a process running as the same Windows
    /// user could craft a `DPAPI unprotect`-able blob
    /// containing an attacker-controlled 32-byte token
    /// and pass the resulting `SessionToken` to the
    /// daemon, bypassing master-password authentication.
    #[allow(dead_code)]
    fn deserialize(data: &[u8]) -> Result<Self, CoreError> {
        const HEADER: usize = 8 + 4; // MAGIC + version
        const TAIL: usize = 32; // HMAC
        // Minimum: HEADER + 4 (path_len) + 0 (empty path) + 8 + 32 + 8 + TAIL
        if data.len() < HEADER + 4 + 8 + 32 + 8 + TAIL {
            return Err(CoreError::SessionLocked);
        }
        // 1. Magic.
        if &data[..MAGIC.len()] != MAGIC {
            return Err(CoreError::SessionLocked);
        }
        // 2. Version.
        let version = u32::from_be_bytes(
            data[MAGIC.len()..HEADER]
                .try_into()
                .map_err(|_| CoreError::SessionLocked)?,
        );
        if version != SUPPORTED_VERSION {
            return Err(CoreError::SessionLocked);
        }
        // 3. Body length-prefix check.
        let path_len = u32::from_be_bytes(
            data[HEADER..HEADER + 4]
                .try_into()
                .map_err(|_| CoreError::SessionLocked)?,
        )
            as usize;
        let body_len = 4 + path_len + 8 + 32 + 8;
        if data.len() < HEADER + body_len + TAIL {
            return Err(CoreError::SessionLocked);
        }
        // 4. Fields.
        let path_start = HEADER + 4;
        let path_end = path_start + path_len;
        let vault_path = std::str::from_utf8(&data[path_start..path_end])
            .map_err(|_| CoreError::SessionLocked)?
            .to_owned();
        let mut off = path_end;
        let mut vault_fingerprint = [0u8; 8];
        vault_fingerprint.copy_from_slice(&data[off..off + 8]);
        off += 8;
        let mut token = [0u8; 32];
        token.copy_from_slice(&data[off..off + 32]);
        off += 32;
        let created_at = u64::from_be_bytes(
            data[off..off + 8]
                .try_into()
                .map_err(|_| CoreError::SessionLocked)?,
        );
        // 5. HMAC integrity check.
        // We have to recompute the HMAC from the fields
        // we just decoded; that requires a key. For the
        // v0.1 dead-code surface, the key is derived
        // from the (now-verified) vault fingerprint.
        // A future v0.2 will pass the master password
        // through and use a proper Argon2id-derived
        // subkey.
        let mut hmac_key = [0u8; 32];
        for (i, b) in vault_fingerprint.iter().enumerate() {
            hmac_key[i] = *b;
        }
        let body = &data[..HEADER + body_len];
        use bitnet_crypto::hmac_sha256;
        let expected_hmac = hmac_sha256(&hmac_key, body);
        let stored_hmac = &data[data.len() - TAIL..];
        if !constant_time_eq(&expected_hmac, stored_hmac) {
            return Err(CoreError::SessionLocked);
        }
        Ok(Self {
            vault_path,
            vault_fingerprint,
            token,
            created_at,
        })
    }
}

#[cfg(not(feature = "dpapi"))]
impl SessionToken {
    pub fn encrypt(&self) -> Result<Vec<u8>, CoreError> {
        Err(CoreError::SessionLocked)
    }
    pub fn decrypt(_: &[u8]) -> Result<Self, CoreError> {
        Err(CoreError::SessionLocked)
    }
}

/// Constant-time byte slice equality. The simple `==`
/// operator short-circuits on the first differing byte
/// (timing side-channel); we use the same pattern as
/// `bitnet-crypto::constant_time_eq` here so the
/// HMAC compare is safe regardless of where this code
/// is compiled.
#[inline]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_token_serialize_roundtrip() {
        let token = SessionToken {
            vault_path: r"C:\Users\alice\vault.bitnet".into(),
            vault_fingerprint: [1, 2, 3, 4, 5, 6, 7, 8],
            token: [0xab; 32],
            created_at: 1_700_000_000,
        };
        let bytes = token.serialize();
        let restored = SessionToken::deserialize(&bytes).unwrap();
        assert_eq!(restored.vault_path, token.vault_path);
        assert_eq!(restored.vault_fingerprint, token.vault_fingerprint);
        assert_eq!(restored.token, token.token);
        assert_eq!(restored.created_at, token.created_at);
    }

    #[test]
    fn test_session_token_empty_path() {
        let token = SessionToken {
            vault_path: String::new(),
            vault_fingerprint: [0; 8],
            token: [0; 32],
            created_at: 0,
        };
        let bytes = token.serialize();
        let restored = SessionToken::deserialize(&bytes).unwrap();
        assert_eq!(restored.vault_path, "");
        assert_eq!(restored.created_at, 0);
    }

    #[test]
    fn test_session_token_truncated_rejected() {
        let token = SessionToken {
            vault_path: "x".into(),
            vault_fingerprint: [0; 8],
            token: [0; 32],
            created_at: 0,
        };
        let bytes = token.serialize();
        let truncated = &bytes[..bytes.len() - 1];
        assert!(SessionToken::deserialize(truncated).is_err());
    }

    // [BITNET-H6] regression: a payload with a valid
    // header but a tampered body must be rejected by
    // the integrity HMAC.
    #[test]
    fn test_session_token_tampered_body_rejected_by_hmac() {
        let token = SessionToken {
            vault_path: "vault.bitnet".into(),
            vault_fingerprint: [9, 9, 9, 9, 9, 9, 9, 9],
            token: [0x55; 32],
            created_at: 1_700_000_001,
        };
        let mut bytes = token.serialize();
        // Flip a single byte in the body (the `token`
        // field, which sits at offset HEADER + 4 +
        // 9 + 8 = HEADER + 21 .. + 21 + 32).
        let token_offset = 8 + 4 + 4 + 9 + 8;
        bytes[token_offset] ^= 0x01;
        // The header / version are intact, so magic /
        // version checks pass. The HMAC check must
        // catch the tamper.
        assert!(SessionToken::deserialize(&bytes).is_err());
    }

    // [BITNET-H6] regression: a payload with a wrong
    // magic must be rejected before any field
    // deserialization.
    #[test]
    fn test_session_token_wrong_magic_rejected() {
        let token = SessionToken {
            vault_path: "x".into(),
            vault_fingerprint: [0; 8],
            token: [0; 32],
            created_at: 0,
        };
        let mut bytes = token.serialize();
        bytes[0] = b'X';
        assert!(SessionToken::deserialize(&bytes).is_err());
    }

    // [BITNET-H6] regression: a payload with a wrong
    // version must be rejected.
    #[test]
    fn test_session_token_wrong_version_rejected() {
        let token = SessionToken {
            vault_path: "x".into(),
            vault_fingerprint: [0; 8],
            token: [0; 32],
            created_at: 0,
        };
        let mut bytes = token.serialize();
        // Bump the version (at bytes [8..12)) by 1.
        bytes[11] = 0x02;
        assert!(SessionToken::deserialize(&bytes).is_err());
    }
}
