use bitnet_crypto::{hmac_sha1, hmac_sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use url::Url;

/// Supported TOTP hash algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TotpAlgorithm {
    #[default]
    Sha1,
    Sha256,
}


impl std::str::FromStr for TotpAlgorithm {
    type Err = TotpError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "SHA1" => Ok(TotpAlgorithm::Sha1),
            "SHA256" => Ok(TotpAlgorithm::Sha256),
            _ => Err(TotpError::UnsupportedAlgorithm(s.to_string())),
        }
    }
}

#[derive(Debug, Error)]
pub enum TotpError {
    #[error("Invalid Base32 encoding")]
    InvalidBase32,
    #[error("Invalid OTPAuth URI: {0}")]
    InvalidUri(String),
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
}

/// Decode a Base32 string (RFC 4648) into bytes.
pub fn decode_base32(input: &str) -> Result<Vec<u8>, TotpError> {
    let cleaned: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &cleaned)
        .ok_or(TotpError::InvalidBase32)
}

/// Compute HOTP value according to RFC 4226.
/// `digits` controls the truncation width (typically 6 or 8).
pub fn hotp(secret: &[u8], counter: u64, algorithm: TotpAlgorithm, digits: u32) -> u32 {
    let counter_bytes = counter.to_be_bytes();
    let mac = match algorithm {
        TotpAlgorithm::Sha1 => hmac_sha1(secret, &counter_bytes).to_vec(),
        TotpAlgorithm::Sha256 => hmac_sha256(secret, &counter_bytes).to_vec(),
    };
    let offset = (mac.last().unwrap() & 0x0f) as usize;
    let code = ((mac[offset] & 0x7f) as u32) << 24
        | ((mac[offset + 1]) as u32) << 16
        | ((mac[offset + 2]) as u32) << 8
        | ((mac[offset + 3]) as u32);
    let modulus = 10u32.checked_pow(digits).unwrap_or(1_000_000);
    code % modulus
}

/// Generate a TOTP code and remaining seconds for the current time window.
/// `digits` defaults to 6, `period` defaults to 30 (per RFC 6238).
pub fn generate_totp(
    secret: &str,
    timestamp: u64,
    algorithm: TotpAlgorithm,
) -> Result<(String, u8), TotpError> {
    generate_totp_with_params(secret, timestamp, algorithm, 6, 30)
}

/// Generate a TOTP code with explicit digits and period, useful for non-RFC
/// defaults declared via `otpauth://...?digits=8&period=60`.
pub fn generate_totp_with_params(
    secret: &str,
    timestamp: u64,
    algorithm: TotpAlgorithm,
    digits: u32,
    period: u64,
) -> Result<(String, u8), TotpError> {
    if digits == 0 || digits > 10 {
        return Err(TotpError::UnsupportedAlgorithm(format!(
            "unsupported digits: {}",
            digits
        )));
    }
    if period == 0 {
        return Err(TotpError::UnsupportedAlgorithm("period must be > 0".into()));
    }
    let secret_bytes = decode_base32(secret)?;
    let counter = timestamp / period;
    let remaining = (period - (timestamp % period)) as u8;
    let code = hotp(&secret_bytes, counter, algorithm, digits);
    Ok((format!("{:0width$}", code, width = digits as usize), remaining))
}

/// Verify a user-supplied TOTP code with ±1 window tolerance.
pub fn verify_totp(
    secret: &str,
    timestamp: u64,
    code: &str,
    algorithm: TotpAlgorithm,
) -> Result<bool, TotpError> {
    verify_totp_with_params(secret, timestamp, code, algorithm, 6, 30)
}

/// Verify with explicit digits/period. Length must match the supplied code.
pub fn verify_totp_with_params(
    secret: &str,
    timestamp: u64,
    code: &str,
    algorithm: TotpAlgorithm,
    digits: u32,
    period: u64,
) -> Result<bool, TotpError> {
    use subtle::ConstantTimeEq;
    if digits == 0 || digits > 10 || period == 0 {
        return Err(TotpError::UnsupportedAlgorithm("invalid TOTP params".into()));
    }
    let secret_bytes = decode_base32(secret)?;
    let counter = timestamp / period;
    let code_bytes = code.as_bytes();
    if code_bytes.len() != digits as usize {
        return Ok(false);
    }
    for window in -1i64..=1i64 {
        let test_counter = ((counter as i64) + window) as u64;
        let expected_code = hotp(&secret_bytes, test_counter, algorithm, digits);
        let expected = format!("{:0width$}", expected_code, width = digits as usize);
        let expected_bytes = expected.as_bytes();
        if expected_bytes.ct_eq(code_bytes).into() {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Parsed OTPAuth URI parameters.
#[derive(Debug, Clone)]
pub struct OtpAuthParams {
    pub secret: String,
    pub issuer: Option<String>,
    pub account: Option<String>,
    pub algorithm: TotpAlgorithm,
    pub digits: u32,
    pub period: u32,
}

/// Parse an otpauth:// URI.
pub fn parse_otpauth_uri(uri: &str) -> Result<OtpAuthParams, TotpError> {
    let url = Url::parse(uri).map_err(|e| TotpError::InvalidUri(e.to_string()))?;
    if url.scheme() != "otpauth" {
        return Err(TotpError::InvalidUri("Scheme must be otpauth".into()));
    }

    let secret = url
        .query_pairs()
        .find(|(k, _)| k == "secret")
        .map(|(_, v)| v.to_string())
        .ok_or_else(|| TotpError::InvalidUri("Missing secret".into()))?;

    let algorithm = url
        .query_pairs()
        .find(|(k, _)| k == "algorithm")
        .map(|(_, v)| v.parse::<TotpAlgorithm>())
        .transpose()?
        .unwrap_or_default();

    let digits = url
        .query_pairs()
        .find(|(k, _)| k == "digits")
        .and_then(|(_, v)| v.parse::<u32>().ok())
        .unwrap_or(6);

    let period = url
        .query_pairs()
        .find(|(k, _)| k == "period")
        .and_then(|(_, v)| v.parse::<u32>().ok())
        .unwrap_or(30);

    let issuer = url
        .query_pairs()
        .find(|(k, _)| k == "issuer")
        .map(|(_, v)| v.to_string());

    let path = url.path().trim_start_matches('/');
    let account = if path.is_empty() {
        None
    } else {
        Some(path.to_string())
    };

    Ok(OtpAuthParams {
        secret,
        issuer,
        account,
        algorithm,
        digits,
        period,
    })
}

/// Convenience: generate TOTP for the current system time.
pub fn generate_totp_now(secret: &str, algorithm: TotpAlgorithm) -> Result<(String, u8), TotpError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    generate_totp(secret, now, algorithm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hotp_sha1() {
        let secret = decode_base32("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap();
        let code = hotp(&secret, 1, TotpAlgorithm::Sha1, 6);
        // HOTP with this secret and counter=1 produces a 6-digit code
        assert!(code < 1_000_000);
    }

    #[test]
    fn test_totp_generation_sha1() {
        // Known test vector from RFC 6238 Appendix B
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let (code, _) = generate_totp(secret, 59, TotpAlgorithm::Sha1).unwrap();
        assert_eq!(code, "287082");
    }

    #[test]
    fn test_totp_generation_sha256() {
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let (code, _) = generate_totp(secret, 59, TotpAlgorithm::Sha256).unwrap();
        // SHA-256 produces different code than SHA-1
        assert_ne!(code, "287082");
        assert_eq!(code.len(), 6);
    }

    #[test]
    fn test_verify_totp_with_tolerance() {
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let now = 59u64;
        let (code, _) = generate_totp(secret, now, TotpAlgorithm::Sha1).unwrap();
        assert!(verify_totp(secret, now, &code, TotpAlgorithm::Sha1).unwrap());
    }

    #[test]
    fn test_parse_otpauth_uri() {
        let uri = "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example";
        let params = parse_otpauth_uri(uri).unwrap();
        assert_eq!(params.secret, "JBSWY3DPEHPK3PXP");
        assert_eq!(params.issuer, Some("Example".to_string()));
        assert_eq!(params.account, Some("Example:alice@google.com".to_string()));
        assert_eq!(params.algorithm, TotpAlgorithm::Sha1);
        assert_eq!(params.digits, 6);
        assert_eq!(params.period, 30);
    }

    #[test]
    fn test_parse_otpauth_uri_with_sha256() {
        let uri = "otpauth://totp/test?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256";
        let params = parse_otpauth_uri(uri).unwrap();
        assert_eq!(params.algorithm, TotpAlgorithm::Sha256);
    }
}


#[cfg(test)]
mod extra_tests {
    use super::*;

    #[test]
    fn test_totp_time_drift_tolerance() {
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let base_time = 60u64; // exactly at window boundary
        // Code at time=60 should be valid at 60, 30, 90 (±1 window)
        let (code, _) = generate_totp(secret, base_time, TotpAlgorithm::Sha1).unwrap();
        assert!(verify_totp(secret, base_time, &code, TotpAlgorithm::Sha1).unwrap());
        assert!(verify_totp(secret, base_time + 30, &code, TotpAlgorithm::Sha1).unwrap());
        assert!(verify_totp(secret, base_time - 30, &code, TotpAlgorithm::Sha1).unwrap());
        // Should fail at +60 (two windows away)
        assert!(!verify_totp(secret, base_time + 60, &code, TotpAlgorithm::Sha1).unwrap());
    }

    #[test]
    fn test_totp_invalid_code() {
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let now = 59u64;
        assert!(!verify_totp(secret, now, "000000", TotpAlgorithm::Sha1).unwrap());
        assert!(!verify_totp(secret, now, "999999", TotpAlgorithm::Sha1).unwrap());
    }

    #[test]
    fn test_parse_otpauth_uri_8_digits() {
        let uri = "otpauth://totp/test?secret=JBSWY3DPEHPK3PXP&digits=8";
        let params = parse_otpauth_uri(uri).unwrap();
        assert_eq!(params.digits, 8);
    }

    #[test]
    fn test_parse_otpauth_uri_period_60() {
        let uri = "otpauth://totp/test?secret=JBSWY3DPEHPK3PXP&period=60";
        let params = parse_otpauth_uri(uri).unwrap();
        assert_eq!(params.period, 60);
    }

    #[test]
    fn test_totp_now() {
        let secret = "JBSWY3DPEHPK3PXP";
        let (code, remaining) = generate_totp_now(secret, TotpAlgorithm::Sha1).unwrap();
        assert_eq!(code.len(), 6);
        assert!(remaining <= 30);
        // Verify the code we just generated
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(verify_totp(secret, now, &code, TotpAlgorithm::Sha1).unwrap());
    }

    #[test]
    fn test_totp_8_digits() {
        // otpauth://...?digits=8 should produce 8-character codes.
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let (code, _) =
            generate_totp_with_params(secret, 59, TotpAlgorithm::Sha1, 8, 30).unwrap();
        assert_eq!(code.len(), 8);
        // verify must accept the same length
        assert!(verify_totp_with_params(secret, 59, &code, TotpAlgorithm::Sha1, 8, 30).unwrap());
        // and must reject a 6-digit code at the same instant
        assert!(!verify_totp_with_params(secret, 59, "287082", TotpAlgorithm::Sha1, 8, 30).unwrap());
    }

    #[test]
    fn test_totp_period_60() {
        // otpauth://...?period=60 doubles the time step.
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let (code_30, _) = generate_totp_with_params(secret, 60, TotpAlgorithm::Sha1, 6, 30).unwrap();
        // At t=60 the period-30 counter is 2; the period-60 counter is 1.
        // The codes must therefore differ (different counter → different code).
        let (code_60, _) = generate_totp_with_params(secret, 60, TotpAlgorithm::Sha1, 6, 60).unwrap();
        assert_ne!(code_30, code_60);
    }

    #[test]
    fn test_totp_invalid_params() {
        let secret = "JBSWY3DPEHPK3PXP";
        assert!(generate_totp_with_params(secret, 0, TotpAlgorithm::Sha1, 0, 30).is_err());
        assert!(generate_totp_with_params(secret, 0, TotpAlgorithm::Sha1, 11, 30).is_err());
        assert!(generate_totp_with_params(secret, 0, TotpAlgorithm::Sha1, 6, 0).is_err());
    }
}

