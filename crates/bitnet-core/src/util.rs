//! Утилиты общего назначения: UUID ↔ hex, валидация путей, hex-кодирование.

use std::path::Path;

/// Декодирует UUID из hex-строки (с/без дефисов).
pub fn uuid_from_hex(hex: &str) -> Option<[u8; 16]> {
    let cleaned: String = hex.chars().filter(|c| *c != '-').collect();
    if cleaned.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for i in 0..16 {
        let hi = u8::from_str_radix(&cleaned[2 * i..2 * i + 1], 16).ok()?;
        let lo = u8::from_str_radix(&cleaned[2 * i + 1..2 * i + 2], 16).ok()?;
        bytes[i] = (hi << 4) | lo;
    }
    Some(bytes)
}

/// Кодирует байты в hex-строку в нижнем регистре.
pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Length bounds for a vault path. 7 covers the shortest absolute path
/// (e.g. `C:\a.b`) but the typical minimum is `C:\x.bitnet` = 11 bytes.
/// Upper bound 4096 matches Windows MAX_PATH for backward compatibility.
const MIN_VAULT_PATH_LEN: usize = 7;
const MAX_VAULT_PATH_LEN: usize = 4096;
const REQUIRED_SUFFIX: &[u8; 7] = b".bitnet";

/// Проверяет, что путь — абсолютный, имеет расширение `.bitnet`,
/// не содержит parent-traversal и не ведёт в системные каталоги Windows.
///
/// Hardening (see [BITNET-H3] audit):
/// 1. Length is checked first to prevent ridiculously long inputs from
///    being fed into `String::contains` (which can be slow on long strings).
/// 2. NTFS Alternate Data Streams (`file:stream`) are rejected — they bypass
///    the `.bitnet` extension check on Windows because `Path::extension()`
///    returns `None` for `vault.bitnet:$DATA`.
/// 3. Wildcards (`*`, `?`) and reserved characters (`<`, `>`, `|`, NUL) are
///    rejected so the path cannot be interpreted as a glob by the shell.
/// 4. Windows protected directories are checked case-insensitively.
pub fn validate_vault_path(path: &str) -> bool {
    // 1. Length bounds (cheap reject, no heap allocation)
    let bytes = path.as_bytes();
    if bytes.len() < MIN_VAULT_PATH_LEN || bytes.len() > MAX_VAULT_PATH_LEN {
        return false;
    }

    let p = Path::new(path);
    if !p.is_absolute() {
        return false;
    }

    // 2. Suffix check (case-insensitive, rejects `file:stream` because the
    //    byte after `.bitnet` would have to be end-of-string, a NUL, or a
    //    path separator for the suffix to match; ADS uses `:`).
    if bytes.len() < REQUIRED_SUFFIX.len() {
        return false;
    }
    let tail = &bytes[bytes.len() - REQUIRED_SUFFIX.len()..];
    if !tail.eq_ignore_ascii_case(REQUIRED_SUFFIX) {
        return false;
    }
    // Reject NTFS ADS, wildcards, control chars, and shell metachars in the
    // whole path. We iterate bytes to keep this O(n) without heap allocation.
    let mut colon_count = 0;
    for &b in bytes {
        match b {
            // NUL
            0 => return false,
            // Control chars (0x01..=0x1F)
            1..=0x1F => return false,
            // NTFS stream separator (drive letter allowed, ADS rejected)
            b':' => colon_count += 1,
            // Wildcards and shell metachars
            b'*' | b'?' | b'<' | b'>' | b'|' | b'"' => return false,
            _ => {}
        }
    }
    // More than one `:` indicates an NTFS ADS like `C:\file.bitnet:stream`.
    if colon_count > 1 {
        return false;
    }

    // 3. Parent-traversal check
    if path.contains("..") {
        return false;
    }

    // 4. Windows protected directories
    #[cfg(windows)]
    {
        let lower = path.to_ascii_lowercase();
        for protected in &[
            "\\windows\\",
            "\\program files",
            "\\program files (x86)",
            "\\programdata",
            "\\system32",
            "\\syswow64",
        ] {
            if lower.contains(protected) {
                return false;
            }
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_from_hex_valid() {
        let u = uuid_from_hex("550e8400e29b41d4a716446655440000").unwrap();
        assert_eq!(u[0], 0x55);
        assert_eq!(u[15], 0x00);
    }

    #[test]
    fn uuid_from_hex_with_dashes() {
        let u = uuid_from_hex("550e8400-e29b-41d4-a716-446655440000").unwrap();
        assert_eq!(u[7], 0xd4);
    }

    #[test]
    fn uuid_from_hex_invalid_length() {
        assert!(uuid_from_hex("short").is_none());
        assert!(uuid_from_hex(&"a".repeat(31)).is_none());
        assert!(uuid_from_hex(&"a".repeat(33)).is_none());
    }

    #[test]
    fn uuid_from_hex_invalid_chars() {
        assert!(uuid_from_hex("zz".repeat(16).as_str()).is_none());
    }

    #[test]
    fn hex_encode_roundtrip() {
        let bytes: [u8; 16] = [
            0x55, 0x0e, 0x84, 0x00, 0xe2, 0x9b, 0x41, 0xd4, 0xa7, 0x16, 0x44, 0x66, 0x55, 0x44,
            0x00, 0x00,
        ];
        let hex = hex_encode(&bytes);
        assert_eq!(hex, "550e8400e29b41d4a716446655440000");
        assert_eq!(uuid_from_hex(&hex).unwrap(), bytes);
    }

    #[test]
    fn validate_vault_path_accepts_bitnet() {
        assert!(validate_vault_path(r"C:\Users\alice\vault.bitnet"));
        #[cfg(not(windows))]
        assert!(validate_vault_path("/home/alice/vault.bitnet"));
    }

    #[test]
    fn validate_vault_path_rejects_traversal() {
        assert!(!validate_vault_path(r"C:\Users\..\vault.bitnet"));
        assert!(!validate_vault_path("../vault.bitnet"));
    }

    #[test]
    fn validate_vault_path_rejects_wrong_extension() {
        assert!(!validate_vault_path(r"C:\vault.txt"));
        assert!(!validate_vault_path("vault"));
    }

    #[test]
    fn validate_vault_path_rejects_windows_system_dirs() {
        assert!(!validate_vault_path(
            r"C:\Windows\System32\config\SAM.bitnet"
        ));
        assert!(!validate_vault_path(r"C:\Program Files\app\vault.bitnet"));
    }

    #[test]
    fn validate_vault_path_rejects_relative() {
        assert!(!validate_vault_path("vault.bitnet"));
        assert!(!validate_vault_path("./vault.bitnet"));
    }

    // [BITNET-H3] NTFS Alternate Data Streams are rejected. `Path::extension()`
    // would return None for `vault.bitnet:$DATA` (no real extension), so the
    // suffix check must be done manually with `ends_with(.bitnet)`.
    #[cfg(windows)]
    #[test]
    fn validate_vault_path_rejects_ntfs_ads() {
        assert!(!validate_vault_path(r"C:\Users\alice\vault.bitnet:$DATA"));
        assert!(!validate_vault_path(r"C:\Users\alice\vault.bitnet:hidden"));
        // UNC ADS
        assert!(!validate_vault_path(
            r"\\?\C:\Users\alice\vault.bitnet:stream"
        ));
    }

    // [BITNET-H3] Wildcards and shell metachars are rejected.
    #[cfg(windows)]
    #[test]
    fn validate_vault_path_rejects_wildcards() {
        assert!(!validate_vault_path(r"C:\vault*.bitnet"));
        assert!(!validate_vault_path(r"C:\vault?.bitnet"));
        assert!(!validate_vault_path(r"C:\vault<test>.bitnet"));
        assert!(!validate_vault_path(r"C:\vault|pipe.bitnet"));
        assert!(!validate_vault_path("C:\\vault\x00.bitnet"));
        // Control char (TAB)
        assert!(!validate_vault_path("C:\\vault\x09.bitnet"));
    }

    // [BITNET-H3] Length bounds.
    #[test]
    fn validate_vault_path_length_bounds() {
        // Too short
        assert!(!validate_vault_path(""));
        assert!(!validate_vault_path("a.bitnet"));
        // Too long
        let long = format!("C:\\{}.bitnet", "a".repeat(5000));
        assert!(!validate_vault_path(&long));
    }
}
