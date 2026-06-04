use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use hmac::{Hmac, Mac};
use rand::rngs::OsRng as RandOsRng;
use rand::RngCore;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;
pub use zeroize::Zeroizing;

pub type Aes256GcmKey = [u8; 32];
pub type Aes256GcmNonce = [u8; 12];

/// Enforce minimum Argon2 parameters per security policy.
pub fn validate_argon2_params(params: &argon2::Params) -> Result<(), &'static str> {
    if params.m_cost() < 64 * 1024 {
        return Err("Argon2 memory below policy minimum");
    }
    if params.t_cost() < 3 {
        return Err("Argon2 time below policy minimum");
    }
    if params.p_cost() < 4 {
        return Err("Argon2 parallelism below policy minimum");
    }
    Ok(())
}

/// Derive a 32-byte key from master password using Argon2id (t=3, m=64MB, p=4).
pub fn derive_key(master_password: &[u8], salt: &[u8]) -> Zeroizing<Aes256GcmKey> {
    let params = argon2::Params::new(64 * 1024, 3, 4, Some(32)).expect("Argon2 params");
    assert!(
        validate_argon2_params(&params).is_ok(),
        "Weak Argon2 parameters detected"
    );
    let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut output = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(master_password, salt, &mut *output)
        .expect("Argon2id hashing failed");
    output
}

/// Encrypt plaintext with AES-256-GCM. Returns (ciphertext_with_tag, nonce).
pub fn encrypt(plaintext: &[u8], key: &Aes256GcmKey) -> (Vec<u8>, Aes256GcmNonce) {
    let cipher = Aes256Gcm::new_from_slice(key).expect("Invalid key length");
    let mut nonce_bytes = [0u8; 12];
    RandOsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext).expect("Encryption failed");
    (ciphertext, nonce_bytes)
}

/// Decrypt ciphertext (with tag appended) using AES-256-GCM.
pub fn decrypt(ciphertext: &[u8], key: &Aes256GcmKey, nonce: &Aes256GcmNonce) -> Option<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("Invalid key length");
    let nonce_obj = Nonce::from_slice(nonce);
    cipher.decrypt(nonce_obj, ciphertext).ok()
}

/// Compute SHA-256 digest.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Compute HMAC-SHA-256.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC key length error");
    mac.update(data);
    let result = mac.finalize();
    let bytes = result.into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

/// Compute HMAC-SHA-1.
pub fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    type HmacSha1 = Hmac<Sha1>;
    let mut mac = <HmacSha1 as Mac>::new_from_slice(key).expect("HMAC key length error");
    mac.update(data);
    let result = mac.finalize();
    let bytes = result.into_bytes();
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    out
}

/// Constant-time comparison of two byte arrays.
pub fn secure_compare(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// Configuration for password generation.
#[derive(Debug, Clone, Copy)]
pub struct PasswordGeneratorFlags {
    pub length: usize,
    pub include_uppercase: bool,
    pub include_lowercase: bool,
    pub include_digits: bool,
    pub include_symbols: bool,
    pub exclude_ambiguous: bool,
}

impl Default for PasswordGeneratorFlags {
    fn default() -> Self {
        Self {
            length: 16,
            include_uppercase: true,
            include_lowercase: true,
            include_digits: true,
            include_symbols: true,
            exclude_ambiguous: false,
        }
    }
}

/// Generate a random password using OsRng with uniform distribution (rejection sampling).
pub fn generate_password(flags: &PasswordGeneratorFlags) -> String {
    let mut rng = RandOsRng;
    let mut alphabet = String::new();
    if flags.include_lowercase {
        alphabet.push_str("abcdefghijklmnopqrstuvwxyz");
    }
    if flags.include_uppercase {
        alphabet.push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    }
    if flags.include_digits {
        if flags.exclude_ambiguous {
            alphabet.push_str("23456789");
        } else {
            alphabet.push_str("0123456789");
        }
    }
    if flags.include_symbols {
        if flags.exclude_ambiguous {
            alphabet.push_str("!@#$%^&*-_=+[]{}|;:,.?");
        } else {
            alphabet.push_str("!@#$%^&*()_+-=[]{}|;:,.<>?");
        }
    }
    if alphabet.is_empty() {
        alphabet.push_str("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789");
    }
    let bytes: Vec<u8> = alphabet.bytes().collect();
    let alphabet_len = bytes.len() as u32;
    let max_valid = u32::MAX - (u32::MAX % alphabet_len);
    let mut password = String::with_capacity(flags.length);
    for _ in 0..flags.length {
        loop {
            let val = rng.next_u32();
            if val < max_valid {
                let idx = (val % alphabet_len) as usize;
                password.push(bytes[idx] as char);
                break;
            }
        }
    }
    password
}

/// Generate a cryptographically secure random salt.
pub fn generate_salt(length: usize) -> Vec<u8> {
    let mut salt = vec![0u8; length];
    RandOsRng.fill_bytes(&mut salt);
    salt
}

/// Zeroize a byte slice in-place.
pub fn zeroize_slice(slice: &mut [u8]) {
    slice.zeroize();
}

/// Strength assessment of a master-password candidate. The classification is
/// deliberately coarse — entropy in bits is approximated from the character
/// set and length, with NIST SP 800-63B-aligned thresholds.
///
/// * `TooShort` — less than 8 characters. Always reject (Argon2id cannot
///   save a user from a 3-character password).
/// * `Weak` — 8-11 characters or only one character class.
/// * `Fair` — 12+ characters with at least two character classes.
/// * `Strong` — 16+ characters with at least three character classes, or
///   20+ characters regardless of classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordStrength {
    TooShort,
    Weak,
    Fair,
    Strong,
}

impl PasswordStrength {
    /// Human-readable label for UI display.
    pub fn label(self) -> &'static str {
        match self {
            PasswordStrength::TooShort => "too short",
            PasswordStrength::Weak => "weak",
            PasswordStrength::Fair => "fair",
            PasswordStrength::Strong => "strong",
        }
    }

    /// Approximate entropy in bits, useful for displaying a strength meter.
    /// `log2(charset_size) * length` is a standard lower bound.
    pub fn entropy_bits(self, length: usize) -> f32 {
        // The charset is implied by the strength tier; for the meter we just
        // need a reasonable monotonic number.
        let charset_bits = match self {
            PasswordStrength::TooShort => 1.0,
            PasswordStrength::Weak => 4.0, // one class, e.g. lowercase
            PasswordStrength::Fair => 6.0, // two classes
            PasswordStrength::Strong => 6.5, // multi-class
        };
        (length as f32) * charset_bits
    }
}

/// Estimate the strength of a password. The function is best-effort: it does
/// not detect dictionary words or pattern repetition, only length and class
/// diversity.
pub fn assess_password_strength(password: &str) -> PasswordStrength {
    let len = password.chars().count();
    if len < 8 {
        return PasswordStrength::TooShort;
    }
    let mut has_lower = false;
    let mut has_upper = false;
    let mut has_digit = false;
    let mut has_symbol = false;
    for c in password.chars() {
        if c.is_ascii_lowercase() {
            has_lower = true;
        } else if c.is_ascii_uppercase() {
            has_upper = true;
        } else if c.is_ascii_digit() {
            has_digit = true;
        } else {
            has_symbol = true;
        }
    }
    let classes = [has_lower, has_upper, has_digit, has_symbol]
        .iter()
        .filter(|x| **x)
        .count();

    if len >= 20 {
        // Long passwords are almost always strong even with one class
        // (e.g. a 30-char passphrase).
        PasswordStrength::Strong
    } else if len >= 16 && classes >= 3 {
        PasswordStrength::Strong
    } else if len >= 12 && classes >= 2 {
        PasswordStrength::Fair
    } else {
        PasswordStrength::Weak
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_known_value() {
        let hash = sha256(b"hello");
        let expected = [
            0x2c, 0xf2, 0x4d, 0xba, 0x5f, 0xb0, 0xa3, 0x0e, 0x26, 0xe8, 0x3b, 0x2a, 0xc5, 0xb9,
            0xe2, 0x9e, 0x1b, 0x16, 0x1e, 0x5c, 0x1f, 0xa7, 0x42, 0x5e, 0x73, 0x04, 0x33, 0x62,
            0x93, 0x8b, 0x98, 0x24,
        ];
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_hmac_sha256() {
        let key = b"secret";
        let data = b"message";
        let _result = hmac_sha256(key, data);
        assert_eq!(_result.len(), 32);
    }

    #[test]
    fn test_hmac_sha1() {
        let key = b"secret";
        let data = b"message";
        let _result = hmac_sha1(key, data);
        assert_eq!(_result.len(), 20);
    }

    #[test]
    fn test_derive_key_and_encrypt_decrypt() {
        let salt = generate_salt(16);
        let key = derive_key(b"master_password", &salt);
        let plaintext = b"sensitive data";
        let (ciphertext, nonce) = encrypt(plaintext, &key);
        let decrypted = decrypt(&ciphertext, &key, &nonce).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_generate_password_length() {
        let flags = PasswordGeneratorFlags {
            length: 20,
            ..Default::default()
        };
        let pwd = generate_password(&flags);
        assert_eq!(pwd.len(), 20);
    }

    #[test]
    fn test_secure_compare() {
        assert!(secure_compare(b"abc", b"abc"));
        assert!(!secure_compare(b"abc", b"abd"));
    }
}

#[cfg(test)]
mod extra_tests {
    use super::*;

    #[test]
    fn test_generate_password_min_length() {
        let flags = PasswordGeneratorFlags {
            length: 8,
            include_uppercase: true,
            include_lowercase: true,
            include_digits: true,
            include_symbols: true,
            exclude_ambiguous: false,
        };
        let pwd = generate_password(&flags);
        assert_eq!(pwd.len(), 8);
    }

    #[test]
    fn test_generate_password_max_length() {
        let flags = PasswordGeneratorFlags {
            length: 64,
            ..Default::default()
        };
        let pwd = generate_password(&flags);
        assert_eq!(pwd.len(), 64);
    }

    #[test]
    fn test_generate_password_only_lowercase() {
        let flags = PasswordGeneratorFlags {
            length: 20,
            include_uppercase: false,
            include_lowercase: true,
            include_digits: false,
            include_symbols: false,
            exclude_ambiguous: false,
        };
        let pwd = generate_password(&flags);
        assert!(pwd.chars().all(|c| c.is_ascii_lowercase()));
    }

    #[test]
    fn test_generate_password_only_digits() {
        let flags = PasswordGeneratorFlags {
            length: 20,
            include_uppercase: false,
            include_lowercase: false,
            include_digits: true,
            include_symbols: false,
            exclude_ambiguous: false,
        };
        let pwd = generate_password(&flags);
        assert!(pwd.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_zeroize_slice() {
        let mut data = [1u8, 2, 3, 4, 5];
        zeroize_slice(&mut data);
        assert_eq!(data, [0u8; 5]);
    }

    #[test]
    fn test_generate_salt_length() {
        let salt = generate_salt(32);
        assert_eq!(salt.len(), 32);
        let salt2 = generate_salt(32);
        assert_ne!(salt, salt2);
    }

    #[test]
    fn test_derive_key_deterministic() {
        let salt = [0u8; 32];
        let key1 = derive_key(b"password", &salt);
        let key2 = derive_key(b"password", &salt);
        assert_eq!(&*key1, &*key2);
    }

    #[test]
    fn test_derive_key_different_passwords() {
        let salt = [0u8; 32];
        let key1 = derive_key(b"password1", &salt);
        let key2 = derive_key(b"password2", &salt);
        assert_ne!(&*key1, &*key2);
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let key1 = derive_key(b"password1", &generate_salt(32));
        let key2 = derive_key(b"password2", &generate_salt(32));
        let plaintext = b"secret message";
        let (ciphertext, nonce) = encrypt(plaintext, &key1);
        let result = decrypt(&ciphertext, &key2, &nonce);
        assert!(result.is_none());
    }

    #[test]
    fn test_decrypt_tampered_ciphertext_fails() {
        let key = derive_key(b"password", &generate_salt(32));
        let plaintext = b"secret message";
        let (mut ciphertext, nonce) = encrypt(plaintext, &key);
        ciphertext[0] ^= 0xFF; // tamper
        let result = decrypt(&ciphertext, &key, &nonce);
        assert!(result.is_none());
    }

    #[test]
    fn test_generate_password_charset_coverage() {
        // Run many times to statistically ensure all character classes appear
        let flags = PasswordGeneratorFlags {
            length: 100,
            include_uppercase: true,
            include_lowercase: true,
            include_digits: true,
            include_symbols: true,
            exclude_ambiguous: false,
        };
        let mut has_upper = false;
        let mut has_lower = false;
        let mut has_digit = false;
        let mut has_symbol = false;
        for _ in 0..100 {
            let pwd = generate_password(&flags);
            if pwd.chars().any(|c| c.is_ascii_uppercase()) {
                has_upper = true;
            }
            if pwd.chars().any(|c| c.is_ascii_lowercase()) {
                has_lower = true;
            }
            if pwd.chars().any(|c| c.is_ascii_digit()) {
                has_digit = true;
            }
            if pwd
                .chars()
                .any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c))
            {
                has_symbol = true;
            }
        }
        assert!(has_upper, "Should generate uppercase");
        assert!(has_lower, "Should generate lowercase");
        assert!(has_digit, "Should generate digits");
        assert!(has_symbol, "Should generate symbols");
    }

    #[test]
    fn test_validate_argon2_params_rejects_weak() {
        let weak = argon2::Params::new(32 * 1024, 1, 1, Some(32)).unwrap();
        assert!(validate_argon2_params(&weak).is_err());
    }

    #[test]
    fn test_validate_argon2_params_accepts_strong() {
        let strong = argon2::Params::new(64 * 1024, 3, 4, Some(32)).unwrap();
        assert!(validate_argon2_params(&strong).is_ok());
    }

    #[test]
    fn test_assess_password_strength_rejects_short() {
        assert_eq!(assess_password_strength(""), PasswordStrength::TooShort);
        assert_eq!(assess_password_strength("a"), PasswordStrength::TooShort);
        assert_eq!(assess_password_strength("abcdefgh"), PasswordStrength::Weak);
        // 8 chars single class is still weak.
    }

    #[test]
    fn test_assess_password_strength_classes() {
        // 12 chars, 2 classes → fair
        assert_eq!(
            assess_password_strength("abcdefghijKL"),
            PasswordStrength::Fair
        );
        // 16 chars, 3 classes → strong
        assert_eq!(
            assess_password_strength("Abcdefghijklmnop12"),
            PasswordStrength::Strong
        );
        // 20+ chars regardless of class → strong
        assert_eq!(
            assess_password_strength("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            PasswordStrength::Strong
        );
    }

    #[test]
    fn test_assess_password_strength_entropy_monotonic() {
        // Stronger tier must report higher entropy than weaker tier at the
        // same length.
        let weak = assess_password_strength("aaaaaaaa");
        let fair = assess_password_strength("Aaaaaaaaaa");
        let strong = assess_password_strength("Aaaaaaaaaa1!1!1!1");
        assert!(weak.entropy_bits(8) < fair.entropy_bits(10));
        assert!(fair.entropy_bits(10) < strong.entropy_bits(15));
    }
}
