//! DPAPI-защищённый session token для daemon-режима.
//!
//! При успешном `unlock` генерируется 32-байтный токен. В daemon-режиме
//! CLI читает этот blob из `vault_dir/session.bin`, расшифровывает через
//! `bitnet_dpapi::unprotect` и использует для аутентификации в daemon'е.
//!
//! DPAPI-обёртывание через `bitnet-dpapi` (Windows) активируется фичей `dpapi`.
//! Без фичи `encrypt`/`decrypt` возвращают ошибку.

#[cfg(feature = "dpapi")]
use bitnet_dpapi::{protect as dpapi_protect, unprotect as dpapi_unprotect};

use crate::CoreError;

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
        let plaintext =
            dpapi_unprotect(blob).map_err(|e| {
                tracing::error!(error = %e, "DPAPI unprotect failed");
                CoreError::SessionLocked
            })?;
        Self::deserialize(&plaintext)
    }

    #[allow(dead_code)]
    fn serialize(&self) -> Vec<u8> {
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
    fn deserialize(data: &[u8]) -> Result<Self, CoreError> {
        if data.len() < 4 + 8 + 32 + 8 {
            return Err(CoreError::SessionLocked);
        }
        let path_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if data.len() < 4 + path_len + 8 + 32 + 8 {
            return Err(CoreError::SessionLocked);
        }
        let vault_path = String::from_utf8(data[4..4 + path_len].to_vec())
            .map_err(|_| CoreError::SessionLocked)?;
        let mut off = 4 + path_len;
        let mut vault_fingerprint = [0u8; 8];
        vault_fingerprint.copy_from_slice(&data[off..off + 8]);
        off += 8;
        let mut token = [0u8; 32];
        token.copy_from_slice(&data[off..off + 32]);
        off += 32;
        let created_at = u64::from_be_bytes([
            data[off],
            data[off + 1],
            data[off + 2],
            data[off + 3],
            data[off + 4],
            data[off + 5],
            data[off + 6],
            data[off + 7],
        ]);
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
}
