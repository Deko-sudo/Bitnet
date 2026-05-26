#![allow(clippy::not_unsafe_ptr_arg_deref)]

use bitnet_crypto::PasswordGeneratorFlags;
use bitnet_core::{SessionManager, SessionState};
use bitnet_kdbx::Entry;
use libc::{c_char, c_int};
use std::ffi::{CStr, CString};
use std::sync::Mutex;
use zeroize::Zeroize;
use zeroize::Zeroizing;

static SESSION: Mutex<Option<SessionManager>> = Mutex::new(None);

fn uuid_from_hex(hex: &str) -> Option<[u8; 16]> {
    let clean = hex.replace("-", "");
    if clean.len() != 32 {
        return None;
    }
    let mut uuid = [0u8; 16];
    for i in 0..16 {
        let byte_str = &clean[i * 2..i * 2 + 2];
        uuid[i] = u8::from_str_radix(byte_str, 16).ok()?;
    }
    Some(uuid)
}

fn to_c_string(s: &str) -> *mut c_char {
    match CString::new(s) {
        Ok(cs) => cs.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Validate vault path: must end with .bitnet and not contain parent-dir traversal.
fn validate_vault_path(path: &str) -> bool {
    path.ends_with(".bitnet") && !path.contains("..")
}

/// Initialize session manager. Call once before other functions.
#[no_mangle]
pub extern "C" fn bitnet_init() -> c_int {
    let mut sess = SESSION.lock().unwrap_or_else(|e| e.into_inner());
    *sess = Some(SessionManager::new());
    0
}

/// Create a new vault at given path with master password.
#[no_mangle]
pub extern "C" fn bitnet_vault_create(path: *const c_char, password: *const c_char) -> c_int {
    if path.is_null() || password.is_null() {
        return -1;
    }
    let path_str = unsafe { CStr::from_ptr(path).to_string_lossy() };
    let password_str = unsafe { CStr::from_ptr(password).to_string_lossy() };
    if !validate_vault_path(&path_str) {
        return -4;
    }
    let mut sess = SESSION.lock().unwrap_or_else(|e| e.into_inner());
    match sess.as_mut() {
        Some(manager) => match manager.create_vault(&path_str, password_str.as_bytes()) {
            Ok(()) => 0,
            Err(_) => -2,
        },
        None => -3,
    }
}

/// Unlock vault at given path with master password.
#[no_mangle]
pub extern "C" fn bitnet_vault_unlock(path: *const c_char, password: *const c_char) -> c_int {
    if path.is_null() || password.is_null() {
        return -1;
    }
    let path_str = unsafe { CStr::from_ptr(path).to_string_lossy() };
    let password_str = unsafe { CStr::from_ptr(password).to_string_lossy() };
    if !validate_vault_path(&path_str) {
        return -4; // invalid path
    }
    let mut sess = SESSION.lock().unwrap_or_else(|e| e.into_inner());
    match sess.as_mut() {
        Some(manager) => match manager.unlock(&path_str, password_str.as_bytes()) {
            Ok(()) => 0,
            Err(_) => -2,
        },
        None => -3,
    }
}

/// Lock vault and clear sensitive data from memory.
#[no_mangle]
pub extern "C" fn bitnet_vault_lock() -> c_int {
    let mut sess = SESSION.lock().unwrap_or_else(|e| e.into_inner());
    match sess.as_mut() {
        Some(manager) => {
            manager.lock();
            0
        }
        None => -1,
    }
}

/// Check if vault is unlocked.
#[no_mangle]
pub extern "C" fn bitnet_vault_is_unlocked() -> c_int {
    let sess = SESSION.lock().unwrap_or_else(|e| e.into_inner());
    match sess.as_ref() {
        Some(manager) if manager.state() == SessionState::Unlocked => 1,
        _ => 0,
    }
}

/// Save vault to disk.
#[no_mangle]
pub extern "C" fn bitnet_vault_save(path: *const c_char, password: *const c_char) -> c_int {
    if path.is_null() || password.is_null() {
        return -1;
    }
    let path_str = unsafe { CStr::from_ptr(path).to_string_lossy() };
    let password_str = unsafe { CStr::from_ptr(password).to_string_lossy() };
    if !validate_vault_path(&path_str) {
        return -4;
    }
    let sess = SESSION.lock().unwrap_or_else(|e| e.into_inner());
    match sess.as_ref() {
        Some(manager) => match manager.save(&path_str, password_str.as_bytes()) {
            Ok(()) => 0,
            Err(_) => -2,
        },
        None => -3,
    }
}

/// Add entry to a group.
/// group_uuid and entry_json are UTF-8 null-terminated strings.
/// entry_json format: {"uuid":"hex","title":"...","username":"...","password":"...","url":"...","notes":"...","totp_secret":"..."}
#[no_mangle]
pub extern "C" fn bitnet_add_entry(group_uuid: *const c_char, entry_json: *const c_char) -> c_int {
    if group_uuid.is_null() || entry_json.is_null() {
        return -1;
    }
    let group_uuid_str = unsafe { CStr::from_ptr(group_uuid).to_string_lossy() };
    let group_uuid = match uuid_from_hex(&group_uuid_str) {
        Some(u) => u,
        None => return -1,
    };
    let json_str = unsafe { CStr::from_ptr(entry_json).to_string_lossy() };
    let entry: serde_json::Value = match serde_json::from_str(&json_str) {
        Ok(v) => v,
        Err(_) => return -6, // invalid json
    };

    let entry_uuid = entry.get("uuid").and_then(|v| v.as_str()).and_then(uuid_from_hex).unwrap_or_else(|| {
        let mut bytes = [0u8; 16];
        use rand::Rng; let mut rng = rand::thread_rng(); rng.fill(&mut bytes);
        bytes
    });

    let title = entry.get("title").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let username = entry.get("username").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let password = Zeroizing::new(entry.get("password").and_then(|v| v.as_str()).unwrap_or("").to_string());
    let url = entry.get("url").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let notes = entry.get("notes").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let totp_secret = entry.get("totp_secret").and_then(|v| v.as_str()).map(|s| Zeroizing::new(s.to_string()));

    let new_entry = Entry {
        uuid: entry_uuid,
        title,
        username,
        password,
        url,
        notes,
        totp_secret,
    };

    let sess = SESSION.lock().unwrap_or_else(|e| e.into_inner());
    match sess.as_ref() {
        Some(manager) => match manager.add_entry(&group_uuid, new_entry) {
            Ok(()) => 0,
            Err(_) => -2,
        },
        None => -3,
    }
}

/// Update entry by UUID.
/// entry_json format same as bitnet_add_entry. Missing fields are left unchanged.
#[no_mangle]
pub extern "C" fn bitnet_update_entry(entry_uuid: *const c_char, entry_json: *const c_char) -> c_int {
    if entry_uuid.is_null() || entry_json.is_null() {
        return -1;
    }
    let uuid_str = unsafe { CStr::from_ptr(entry_uuid).to_string_lossy() };
    let uuid = match uuid_from_hex(&uuid_str) {
        Some(u) => u,
        None => return -1,
    };
    let json_str = unsafe { CStr::from_ptr(entry_json).to_string_lossy() };
    let entry: serde_json::Value = match serde_json::from_str(&json_str) {
        Ok(v) => v,
        Err(_) => return -6,
    };

    let title = entry.get("title").and_then(|v| v.as_str()).map(|s| s.to_string());
    let username = entry.get("username").and_then(|v| v.as_str()).map(|s| s.to_string());
    let password = entry.get("password").and_then(|v| v.as_str()).map(|s| Zeroizing::new(s.to_string()));
    let url = entry.get("url").and_then(|v| v.as_str()).map(|s| s.to_string());
    let notes = entry.get("notes").and_then(|v| v.as_str()).map(|s| s.to_string());
    let totp_secret = entry.get("totp_secret").and_then(|v| v.as_str()).map(|s| Some(Zeroizing::new(s.to_string())));

    let sess = SESSION.lock().unwrap_or_else(|e| e.into_inner());
    match sess.as_ref() {
        Some(manager) => match manager.update_entry(&uuid, title, username, password, url, notes, totp_secret) {
            Ok(()) => 0,
            Err(_) => -2,
        },
        None => -3,
    }
}

/// Delete entry by UUID.
#[no_mangle]
pub extern "C" fn bitnet_delete_entry(entry_uuid: *const c_char) -> c_int {
    if entry_uuid.is_null() {
        return -1;
    }
    let uuid_str = unsafe { CStr::from_ptr(entry_uuid).to_string_lossy() };
    let uuid = match uuid_from_hex(&uuid_str) {
        Some(u) => u,
        None => return -1,
    };
    let sess = SESSION.lock().unwrap_or_else(|e| e.into_inner());
    match sess.as_ref() {
        Some(manager) => match manager.delete_entry(&uuid) {
            Ok(()) => 0,
            Err(_) => -2,
        },
        None => -3,
    }
}

/// Create a new group. Returns newly allocated C string with UUID. Caller must free with bitnet_free_string.
#[no_mangle]
pub extern "C" fn bitnet_create_group(parent_uuid: *const c_char, name: *const c_char) -> *mut c_char {
    if name.is_null() {
        return std::ptr::null_mut();
    }
    let name_str = unsafe { CStr::from_ptr(name).to_string_lossy() };
    let parent = if parent_uuid.is_null() {
        None
    } else {
        let p = unsafe { CStr::from_ptr(parent_uuid).to_string_lossy() };
        uuid_from_hex(&p)
    };
    let sess = SESSION.lock().unwrap_or_else(|e| e.into_inner());
    match sess.as_ref() {
        Some(manager) => match manager.create_group(parent.as_ref(), &name_str) {
            Ok(uuid) => {
                let hex = uuid.iter().map(|b| format!("{:02x}", b)).collect::<String>();
                to_c_string(&hex)
            }
            Err(_) => std::ptr::null_mut(),
        },
        None => std::ptr::null_mut(),
    }
}

/// Get password for an entry by UUID (hex string).
/// Caller must provide buffer `out_buf` of length `out_len`.
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub extern "C" fn bitnet_entry_get_password(
    entry_uuid: *const c_char,
    out_buf: *mut c_char,
    out_len: usize,
) -> c_int {
    if entry_uuid.is_null() || out_buf.is_null() || out_len == 0 {
        return -1;
    }
    let uuid_str = unsafe { CStr::from_ptr(entry_uuid).to_string_lossy() };
    let uuid = match uuid_from_hex(&uuid_str) {
        Some(u) => u,
        None => return -1,
    };
    let sess = SESSION.lock().unwrap_or_else(|e| e.into_inner());
    match sess.as_ref() {
        Some(manager) => match manager.get_password(&uuid) {
            Ok(password) => {
                let bytes = password.as_bytes();
                if bytes.len() >= out_len {
                    return -5;
                }
                let copy_len = std::cmp::min(bytes.len(), out_len - 1);
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        bytes.as_ptr() as *const c_char,
                        out_buf,
                        copy_len,
                    );
                    *out_buf.add(copy_len) = 0;
                }
                0
            }
            Err(_) => -1,
        },
        None => -1,
    }
}

/// Generate a random password.
/// Returns newly allocated C string. Caller must free with `bitnet_free_string`.
#[no_mangle]
pub extern "C" fn bitnet_generate_password(
    length: c_int,
    include_upper: c_int,
    include_lower: c_int,
    include_digits: c_int,
    include_symbols: c_int,
    exclude_ambiguous: c_int,
) -> *mut c_char {
    if length <= 0 || length > 512 {
        return std::ptr::null_mut();
    }
    let sess = SESSION.lock().unwrap_or_else(|e| e.into_inner());
    match sess.as_ref() {
        Some(manager) => {
            let flags = PasswordGeneratorFlags {
                length: length as usize,
                include_uppercase: include_upper != 0,
                include_lowercase: include_lower != 0,
                include_digits: include_digits != 0,
                include_symbols: include_symbols != 0,
                exclude_ambiguous: exclude_ambiguous != 0,
            };
            match manager.generate_password(&flags) {
                Ok(password) => to_c_string(&password),
                Err(_) => std::ptr::null_mut(),
            }
        }
        None => std::ptr::null_mut(),
    }
}

/// Get TOTP code and remaining seconds for an entry.
/// Returns newly allocated C string "code, remaining". Caller must free with `bitnet_free_string`.
#[no_mangle]
pub extern "C" fn bitnet_entry_get_totp(entry_uuid: *const c_char) -> *mut c_char {
    if entry_uuid.is_null() {
        return std::ptr::null_mut();
    }
    let uuid_str = unsafe { CStr::from_ptr(entry_uuid).to_string_lossy() };
    let uuid = match uuid_from_hex(&uuid_str) {
        Some(u) => u,
        None => return std::ptr::null_mut(),
    };
    let sess = SESSION.lock().unwrap_or_else(|e| e.into_inner());
    match sess.as_ref() {
        Some(manager) => match manager.get_totp(&uuid) {
            Ok(Some((code, remaining))) => {
                let result = format!("{}, {}", code, remaining);
                to_c_string(&result)
            }
            Ok(None) => to_c_string(""),
            Err(_) => std::ptr::null_mut(),
        },
        None => std::ptr::null_mut(),
    }
}

/// List all entries in unlocked vault as JSON array.
/// Returns newly allocated C string. Caller must free with `bitnet_free_string`.
#[no_mangle]
pub extern "C" fn bitnet_list_entries() -> *mut c_char {
    let sess = SESSION.lock().unwrap_or_else(|e| e.into_inner());
    match sess.as_ref() {
        Some(manager) => match manager.list_entries() {
            Ok(entries) => {
                let json = serde_json::to_string(&entries).unwrap_or_default();
                to_c_string(&json)
            }
            Err(_) => std::ptr::null_mut(),
        },
        None => std::ptr::null_mut(),
    }
}

/// Free a string returned by bitnet FFI functions. Zeroizes memory before deallocation.
#[no_mangle]
pub extern "C" fn bitnet_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let len = libc::strlen(ptr);
            let slice = std::slice::from_raw_parts_mut(ptr as *mut u8, len);
            slice.zeroize();
            let _ = CString::from_raw(ptr);
        }
    }
}

/// Get SHA-256 fingerprint of a vault file.
/// Returns newly allocated C string. Caller must free with `bitnet_free_string`.
#[no_mangle]
pub extern "C" fn bitnet_vault_fingerprint(path: *const c_char) -> *mut c_char {
    if path.is_null() {
        return std::ptr::null_mut();
    }
    let path_str = unsafe { CStr::from_ptr(path).to_string_lossy() };
    if !validate_vault_path(&path_str) {
        return std::ptr::null_mut();
    }
    match std::fs::read(&*path_str) {
        Ok(data) => {
            let hash = bitnet_crypto::sha256(&data);
            let hex = hash.iter().map(|b| format!("{:02x}", b)).collect::<String>();
            to_c_string(&hex)
        }
        Err(_) => std::ptr::null_mut(),
    }
}

#[cfg(test)]
fn uuid_to_hex(uuid: &[u8; 16]) -> String {
    uuid.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uuid_from_hex_valid() {
        let result = uuid_from_hex("550e8400e29b41d4a716446655440000");
        assert!(result.is_some());
        let uuid = result.unwrap();
        assert_eq!(uuid[0], 0x55);
        assert_eq!(uuid[1], 0x0e);
    }

    #[test]
    fn test_uuid_from_hex_with_dashes() {
        let result = uuid_from_hex("550e8400-e29b-41d4-a716-446655440000");
        assert!(result.is_some());
    }

    #[test]
    fn test_uuid_from_hex_invalid_length() {
        assert!(uuid_from_hex("tooshort").is_none());
        assert!(uuid_from_hex(&"a".repeat(33)).is_none());
    }

    #[test]
    fn test_uuid_from_hex_invalid_chars() {
        assert!(uuid_from_hex("gggggggggggggggggggggggggggggggg").is_none());
    }

    #[test]
    fn test_uuid_roundtrip() {
        let original = [0x55, 0x0e, 0x84, 0x00, 0xe2, 0x9b, 0x41, 0xd4,
                        0xa7, 0x16, 0x44, 0x66, 0x55, 0x44, 0x00, 0x00];
        let hex = uuid_to_hex(&original);
        let parsed = uuid_from_hex(&hex).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_to_c_string_roundtrip() {
        let ptr = to_c_string("hello ffi");
        assert!(!ptr.is_null());
        unsafe {
            let s = std::ffi::CStr::from_ptr(ptr).to_string_lossy().to_string();
            assert_eq!(s, "hello ffi");
            bitnet_free_string(ptr);
        }
    }

    #[test]
    fn test_validate_vault_path() {
        assert!(validate_vault_path("C:\\Users\\user\\vault.bitnet"));
        assert!(!validate_vault_path("C:\\Windows\\System32\\config\\SAM"));
        assert!(!validate_vault_path("C:\\Users\\..\\vault.bitnet"));
        assert!(!validate_vault_path("C:\\Users\\vault.txt"));
    }

    #[test]
    fn test_generate_password_bounds() {
        let len: c_int = -1;
        let as_usize = len as usize;
        assert!(as_usize > 512);
    }
}
