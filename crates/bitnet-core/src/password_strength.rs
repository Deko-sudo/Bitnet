//! Password strength validator for master passwords.
//!
//! The validator is intentionally **opt-in** so that existing
//! integrations and tests using simple passwords (e.g. `b"master"`) keep
//! working. Callers that want enforcement should call
//! `validate_strength()` before `create_vault()` and surface any
//! `Weakness` to the user.

/// Minimum master password length.
pub const MIN_LENGTH: usize = 12;

/// Top-N most common passwords (subset of SecLists top 100; covers the
/// obvious cases without dragging in a 100 KB list).
const COMMON_PASSWORDS: &[&str] = &[
    "password",
    "12345678",
    "123456789",
    "1234567890",
    "qwerty",
    "qwerty123",
    "letmein",
    "admin",
    "welcome",
    "monkey",
    "dragon",
    "111111",
    "baseball",
    "iloveyou",
    "trustno1",
    "sunshine",
    "princess",
    "football",
    "charlie",
    "shadow",
];

/// A specific weakness the validator detected.
#[derive(Debug, PartialEq, Eq)]
pub enum Weakness {
    TooShort,
    CommonPassword,
    NoUpperCase,
    NoLowerCase,
    NoDigit,
    NoSymbol,
    SingleClass,
}

/// Validate a master password. Returns the first weakness found, or `None`
/// if the password is considered strong enough.
pub fn validate_strength(pw: &[u8]) -> Option<Weakness> {
    // Length check
    if pw.len() < MIN_LENGTH {
        return Some(Weakness::TooShort);
    }

    // Common-password check (case-insensitive ASCII substring)
    if let Ok(s) = std::str::from_utf8(pw) {
        let lower = s.to_ascii_lowercase();
        if COMMON_PASSWORDS.iter().any(|c| lower.contains(c)) {
            return Some(Weakness::CommonPassword);
        }
    }

    // Character class counting (4 classes: upper, lower, digit, symbol)
    let mut has_upper = false;
    let mut has_lower = false;
    let mut has_digit = false;
    let mut has_symbol = false;

    for &b in pw {
        if b.is_ascii_uppercase() {
            has_upper = true;
        } else if b.is_ascii_lowercase() {
            has_lower = true;
        } else if b.is_ascii_digit() {
            has_digit = true;
        } else {
            // Non-alphanumeric ASCII byte, or high-bit UTF-8 byte
            has_symbol = true;
        }
    }

    // Count satisfied classes
    let mut classes = 0;
    if has_upper {
        classes += 1;
    }
    if has_lower {
        classes += 1;
    }
    if has_digit {
        classes += 1;
    }
    if has_symbol {
        classes += 1;
    }

    if classes < 2 {
        return Some(Weakness::SingleClass);
    }

    // If we have only lower+upper, also demand at least one digit OR symbol
    if classes == 2 && !has_digit && !has_symbol {
        return Some(Weakness::NoDigit);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_too_short() {
        assert_eq!(validate_strength(b"abc"), Some(Weakness::TooShort));
        // 12 chars, all digits, no common substring - SingleClass
        assert_eq!(
            validate_strength(b"222244445555"),
            Some(Weakness::SingleClass)
        );
    }

    #[test]
    fn rejects_common_password() {
        assert_eq!(
            validate_strength(b"password1234"),
            Some(Weakness::CommonPassword)
        );
        assert_eq!(
            validate_strength(b"PASSWORD1234"),
            Some(Weakness::CommonPassword)
        );
    }

    #[test]
    fn accepts_strong_passwords() {
        assert_eq!(validate_strength(b"MyS3cretP@ssw0rd"), None);
        assert_eq!(
            validate_strength(b"correct horse battery staple"),
            None
        );
        assert_eq!(validate_strength(b"Tr0ub4dor&3xx"), None);
    }

    #[test]
    fn rejects_single_class() {
        assert_eq!(
            validate_strength(b"aaaaaaaaaaaa"),
            Some(Weakness::SingleClass)
        );
        assert_eq!(
            validate_strength(b"777788889999"),
            Some(Weakness::SingleClass)
        );
    }

    #[test]
    fn rejects_two_letter_only_classes() {
        // Two classes (lower + upper) but no digit/symbol — still weak
        assert_eq!(
            validate_strength(b"abcdefghijKL"),
            Some(Weakness::NoDigit)
        );
    }
}
