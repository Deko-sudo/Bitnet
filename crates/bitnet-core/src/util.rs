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

/// Проверяет, что путь — абсолютный, имеет расширение `.bitnet`,
/// не содержит parent-traversal и не ведёт в системные каталоги Windows.
pub fn validate_vault_path(path: &str) -> bool {
    let p = Path::new(path);
    if !p.is_absolute() {
        return false;
    }
    if p.extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
        != Some("bitnet".to_string())
    {
        return false;
    }
    if path.contains("..") {
        return false;
    }
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
}
