use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
};

#[derive(Debug, thiserror::Error)]
pub enum DpapiError {
    #[error("DPAPI protection failed")]
    ProtectFailed,
    #[error("DPAPI unprotection failed")]
    UnprotectFailed,
}

/// Protect data with Windows DPAPI (current user context).
pub fn protect(data: &[u8]) -> Result<Vec<u8>, DpapiError> {
    let in_blob = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    };
    let mut out_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    unsafe {
        CryptProtectData(
            &in_blob,
            None,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        )
        .map_err(|_| DpapiError::ProtectFailed)?;
        let result = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec();
        let _ = LocalFree(HLOCAL(out_blob.pbData as *mut std::ffi::c_void));
        Ok(result)
    }
}

/// Unprotect data with Windows DPAPI.
pub fn unprotect(data: &[u8]) -> Result<Vec<u8>, DpapiError> {
    let in_blob = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    };
    let mut out_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    unsafe {
        CryptUnprotectData(
            &in_blob,
            None,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        )
        .map_err(|_| DpapiError::UnprotectFailed)?;
        let result = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec();
        let _ = LocalFree(HLOCAL(out_blob.pbData as *mut std::ffi::c_void));
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dpapi_roundtrip() {
        let original = b"sensitive data to protect";
        let protected = protect(original).expect("DPAPI protect failed");
        assert_ne!(protected, original);
        let unprotected = unprotect(&protected).expect("DPAPI unprotect failed");
        assert_eq!(unprotected, original);
    }

    #[test]
    fn test_dpapi_empty_data() {
        let original = b"";
        let protected = protect(original).unwrap();
        let unprotected = unprotect(&protected).unwrap();
        assert_eq!(unprotected, original);
    }

    #[test]
    fn test_dpapi_binary_data() {
        let original: Vec<u8> = (0..=255).collect();
        let protected = protect(&original).unwrap();
        let unprotected = unprotect(&protected).unwrap();
        assert_eq!(unprotected, original);
    }
}
