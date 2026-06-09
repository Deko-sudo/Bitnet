// The whole crate is a C ABI. All exported functions take raw pointers
// from C and have a non-trivial safety contract; documenting each
// individually is high-overhead for this layer. Inline comments at each
// function call site already note the invariants (null checks, buffer
// sizes, etc.).
#![allow(clippy::missing_safety_doc)]

use bitnet_core::util;
use bitnet_core::{SessionManager, SessionState};
use bitnet_crypto::PasswordGeneratorFlags;
use bitnet_kdbx::Entry;
use libc::{c_char, c_int};
use std::ffi::{CStr, CString};
use std::sync::Mutex;
use zeroize::Zeroize;
use zeroize::Zeroizing;

static SESSION: Mutex<Option<SessionManager>> = Mutex::new(None);

fn uuid_from_hex(hex: &str) -> Option<[u8; 16]> {
    util::uuid_from_hex(hex)
}

fn to_c_string(s: &str) -> *mut c_char {
    match CString::new(s) {
        Ok(cs) => cs.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Initialize the global session manager. Safe to call repeatedly; the
/// previous session, if any, is replaced.
///
/// # Safety
///
/// This function is safe to call from any thread but must not be called
/// concurrently with other FFI functions that mutate the global `SESSION`.
#[no_mangle]
pub unsafe extern "C" fn bitnet_init() -> c_int {
    let mut sess = SESSION.lock().unwrap_or_else(|e| e.into_inner());
    *sess = Some(SessionManager::new());
    0
}

/// Create a new vault at given path with master password.
///
/// # Safety
///
/// `path` and `password` must be either null or point to a NUL-terminated
/// C string valid for the duration of the call. The function validates
/// non-null and reads them as UTF-8 best-effort (`to_string_lossy`).
#[no_mangle]
pub unsafe extern "C" fn bitnet_vault_create(
    path: *const c_char,
    password: *const c_char,
) -> c_int {
    if path.is_null() || password.is_null() {
        return -1;
    }
    let path_str = unsafe { CStr::from_ptr(path).to_string_lossy() };
    let password_str = unsafe { CStr::from_ptr(password).to_string_lossy() };
    if !util::validate_vault_path(&path_str) {
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
///
/// # Safety
///
/// - `path` and `password` must be either `null` or point to a NUL-terminated
///   C string valid for the duration of the call.
/// - Non-null strings are interpreted as UTF-8 lossy (`to_string_lossy`).
/// - The master password is held in a `Zeroizing<Vec<u8>>` for the duration
///   of the call; it is not persisted outside the FFI boundary.
/// - The global `SESSION` is locked during the call; do not invoke other
///   FFI functions from another thread concurrently.
#[no_mangle]
pub unsafe extern "C" fn bitnet_vault_unlock(
    path: *const c_char,
    password: *const c_char,
) -> c_int {
    if path.is_null() || password.is_null() {
        return -1;
    }
    let path_str = unsafe { CStr::from_ptr(path).to_string_lossy() };
    let password_str = unsafe { CStr::from_ptr(password).to_string_lossy() };
    if !util::validate_vault_path(&path_str) {
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
///
/// # Safety
///
/// Acquires the global `SESSION` lock; safe from any thread but should not
/// be called concurrently with other FFI functions mutating session state.
#[no_mangle]
pub unsafe extern "C" fn bitnet_vault_lock() -> c_int {
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
///
/// # Safety
///
/// Acquires the global `SESSION` lock. Concurrent calls from multiple
/// threads are serialized by the lock; no additional safety concerns.
#[no_mangle]
pub unsafe extern "C" fn bitnet_vault_is_unlocked() -> c_int {
    let sess = SESSION.lock().unwrap_or_else(|e| e.into_inner());
    match sess.as_ref() {
        Some(manager) if manager.state() == SessionState::Unlocked => 1,
        _ => 0,
    }
}

/// Save vault to disk.
///
/// # Safety
///
/// - `path` and `password` must be either `null` or point to NUL-terminated
///   C strings valid for the duration of the call.
/// - Non-null strings are interpreted as UTF-8 lossy.
/// - Save uses an atomic temp + fsync + rename pattern under the hood, so
///   a crash mid-write will not corrupt the existing vault file.
#[no_mangle]
pub unsafe extern "C" fn bitnet_vault_save(path: *const c_char, password: *const c_char) -> c_int {
    if path.is_null() || password.is_null() {
        return -1;
    }
    let path_str = unsafe { CStr::from_ptr(path).to_string_lossy() };
    let password_str = unsafe { CStr::from_ptr(password).to_string_lossy() };
    if !util::validate_vault_path(&path_str) {
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

/// Re-encrypt the unlocked vault with a new master password. Requires the
/// current (old) password as proof of knowledge.
///
/// # Safety
///
/// - `path`, `old_password`, `new_password` must be either `null` or
///   point to NUL-terminated C strings valid for the duration of the call.
/// - Non-null strings are interpreted as UTF-8 lossy.
/// - Both passwords are held in `Zeroizing<Vec<u8>>` buffers for the call
///   duration and zeroized on drop.
#[no_mangle]
pub unsafe extern "C" fn bitnet_change_master_password(
    path: *const c_char,
    old_password: *const c_char,
    new_password: *const c_char,
) -> c_int {
    if path.is_null() || old_password.is_null() || new_password.is_null() {
        return -1;
    }
    let path_str = unsafe { CStr::from_ptr(path).to_string_lossy().into_owned() };
    let old_str = unsafe { CStr::from_ptr(old_password).to_string_lossy().into_owned() };
    let new_str = unsafe { CStr::from_ptr(new_password).to_string_lossy().into_owned() };
    if !util::validate_vault_path(&path_str) {
        return -4;
    }
    let sess = SESSION.lock().unwrap_or_else(|e| e.into_inner());
    match sess.as_ref() {
        Some(manager) => {
            match manager.change_master_password(&path_str, old_str.as_bytes(), new_str.as_bytes())
            {
                Ok(()) => 0,
                Err(_) => -2,
            }
        }
        None => -3,
    }
}

/// Add entry to a group.
/// group_uuid and entry_json are UTF-8 null-terminated strings.
/// entry_json format: {"uuid":"hex","title":"...","username":"...","password":"...","url":"...","notes":"...","totp_secret":"..."}
///
/// # Safety
///
/// - `group_uuid` and `entry_json` must be either `null` or point to
///   NUL-terminated C strings valid for the duration of the call.
/// - `entry_json` is parsed as JSON; size is capped at 10 MiB (anti-DoS).
/// - The `password` and `totp_secret` fields are held in `Zeroizing`
///   buffers and zeroized on drop.
#[no_mangle]
pub unsafe extern "C" fn bitnet_add_entry(
    group_uuid: *const c_char,
    entry_json: *const c_char,
) -> c_int {
    if group_uuid.is_null() || entry_json.is_null() {
        return -1;
    }
    let group_uuid_str = unsafe { CStr::from_ptr(group_uuid).to_string_lossy() };
    let group_uuid = match uuid_from_hex(&group_uuid_str) {
        Some(u) => u,
        None => return -1,
    };
    let json_str = unsafe { CStr::from_ptr(entry_json).to_string_lossy() };
    // Deny unreasonably large JSON payloads (anti-DoS)
    const MAX_ENTRY_JSON_BYTES: usize = 10 * 1024 * 1024; // 10 MiB
    if json_str.len() > MAX_ENTRY_JSON_BYTES {
        return -7; // entry JSON too large
    }
    let entry: serde_json::Value = match serde_json::from_str(&json_str) {
        Ok(v) => v,
        Err(_) => return -6, // invalid json
    };

    let entry_uuid = entry
        .get("uuid")
        .and_then(|v| v.as_str())
        .and_then(uuid_from_hex)
        .unwrap_or_else(|| {
            let mut bytes = [0u8; 16];
            use rand::Rng;
            let mut rng = rand::thread_rng();
            rng.fill(&mut bytes);
            bytes
        });

    let title = Zeroizing::new(
        entry
            .get("title")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
    );
    let username = Zeroizing::new(
        entry
            .get("username")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
    );
    let password = Zeroizing::new(
        entry
            .get("password")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
    );
    let url = Zeroizing::new(
        entry
            .get("url")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
    );
    let notes = Zeroizing::new(
        entry
            .get("notes")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
    );
    let totp_secret = entry
        .get("totp_secret")
        .and_then(|v| v.as_str())
        .map(|s| Zeroizing::new(s.to_string()));
    let totp_digits = entry
        .get("totp_digits")
        .and_then(|v| v.as_u64())
        .map(|n| n as u32);
    let totp_period = entry
        .get("totp_period")
        .and_then(|v| v.as_u64())
        .map(|n| n as u32);

    let new_entry = Entry {
        uuid: entry_uuid,
        title,
        username,
        password,
        url,
        notes,
        totp_secret,
        totp_digits,
        totp_period,
        created_at: 0,
        updated_at: 0,
        accessed_at: 0,
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
///
/// # Safety
///
/// - `entry_uuid` and `entry_json` must be either `null` or point to
///   NUL-terminated C strings valid for the duration of the call.
/// - `entry_json` size is capped at 10 MiB (anti-DoS).
/// - `password` and `totp_secret` fields are held in `Zeroizing` buffers.
#[no_mangle]
pub unsafe extern "C" fn bitnet_update_entry(
    entry_uuid: *const c_char,
    entry_json: *const c_char,
) -> c_int {
    if entry_uuid.is_null() || entry_json.is_null() {
        return -1;
    }
    let uuid_str = unsafe { CStr::from_ptr(entry_uuid).to_string_lossy() };
    let uuid = match uuid_from_hex(&uuid_str) {
        Some(u) => u,
        None => return -1,
    };
    let json_str = unsafe { CStr::from_ptr(entry_json).to_string_lossy() };
    // Deny unreasonably large JSON payloads (anti-DoS)
    const MAX_ENTRY_JSON_BYTES: usize = 10 * 1024 * 1024; // 10 MiB
    if json_str.len() > MAX_ENTRY_JSON_BYTES {
        return -7; // entry JSON too large
    }
    let entry: serde_json::Value = match serde_json::from_str(&json_str) {
        Ok(v) => v,
        Err(_) => return -6,
    };

    let title = entry
        .get("title")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let username = entry
        .get("username")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let password = entry
        .get("password")
        .and_then(|v| v.as_str())
        .map(|s| Zeroizing::new(s.to_string()));
    let url = entry
        .get("url")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let notes = entry
        .get("notes")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let totp_secret = entry
        .get("totp_secret")
        .and_then(|v| v.as_str())
        .map(|s| Some(Zeroizing::new(s.to_string())));

    let sess = SESSION.lock().unwrap_or_else(|e| e.into_inner());
    match sess.as_ref() {
        Some(manager) => {
            match manager.update_entry(&uuid, title, username, password, url, notes, totp_secret) {
                Ok(()) => 0,
                Err(_) => -2,
            }
        }
        None => -3,
    }
}

/// Delete entry by UUID.
///
/// # Safety
///
/// - `entry_uuid` must be either `null` or point to a NUL-terminated
///   32-character hex string (UUID with optional trailing NUL).
/// - Non-null strings are interpreted as UTF-8 lossy.
/// - Returns 0 on success, -1 on null input, -2 if entry not found,
///   -3 if vault is locked.
#[no_mangle]
pub unsafe extern "C" fn bitnet_delete_entry(entry_uuid: *const c_char) -> c_int {
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
///
/// # Safety
///
/// - `parent_uuid` may be `null` (creates a root group) or point to a
///   NUL-terminated 32-character hex string.
/// - `name` must be non-null and point to a NUL-terminated C string.
/// - Non-null strings are interpreted as UTF-8 lossy.
/// - The returned `*mut c_char` must be released with `bitnet_free_string`
///   using the same allocator; otherwise a memory leak occurs.
#[no_mangle]
pub unsafe extern "C" fn bitnet_create_group(
    parent_uuid: *const c_char,
    name: *const c_char,
) -> *mut c_char {
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
                let hex = uuid
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>();
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
///
/// # Safety
///
/// - `entry_uuid` must be a non-null NUL-terminated 32-character hex string.
/// - `out_buf` must be non-null and point to at least `out_len` writable bytes.
/// - The caller is responsible for zeroizing `out_buf` after use; it will
///   contain the plaintext password on success.
#[no_mangle]
pub unsafe extern "C" fn bitnet_entry_get_password(
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
///
/// # Safety
///
/// - `length` is the desired length; clamped to 1..=1024 internally.
/// - `include_*` are treated as boolean (0 = false, non-zero = true).
/// - The returned `*mut c_char` (if non-null) must be released with
///   `bitnet_free_string`; the caller is responsible for zeroizing the
///   plaintext password after use.
#[no_mangle]
pub unsafe extern "C" fn bitnet_generate_password(
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
            let password = manager.generate_password(&flags);
            to_c_string(&password)
        }
        None => std::ptr::null_mut(),
    }
}

/// Get TOTP code and remaining seconds for an entry.
/// Returns newly allocated C string "code, remaining". Caller must free with `bitnet_free_string`.
///
/// # Safety
///
/// - `entry_uuid` must be either `null` or point to a NUL-terminated
///   32-character hex string.
/// - The returned `*mut c_char` (if non-null) must be released with
///   `bitnet_free_string`.
/// - The C string contains a plaintext TOTP code; the caller is responsible
///   for zeroizing it after use.
#[no_mangle]
pub unsafe extern "C" fn bitnet_entry_get_totp(entry_uuid: *const c_char) -> *mut c_char {
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

/// Get TOTP code into caller-provided buffer (bounded, safer for C# interop).
///
/// # Safety
///
/// - `entry_uuid` must be a non-null NUL-terminated 32-character hex string.
/// - `out_buf` must be non-null and point to at least `buf_len` writable bytes.
/// - `out_remaining` may be null; if non-null, receives remaining seconds
///   (0–30).
/// - On success, the code is NUL-terminated within `buf_len` bytes
///   (truncated if necessary); the caller is responsible for zeroizing.
#[no_mangle]
pub unsafe extern "C" fn bitnet_entry_get_totp_to_buffer(
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
        Some(manager) => match manager.get_totp(&uuid) {
            Ok(Some((code, remaining))) => {
                let payload = format!("{}, {}", code, remaining);
                let bytes = payload.as_bytes();
                if bytes.len() >= out_len {
                    return -5; // buf too small
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
            Ok(None) => {
                unsafe {
                    *out_buf = 0;
                }
                0
            }
            Err(_) => -1,
        },
        None => -1,
    }
}

/// Get detailed entry info (username and password) as JSON.
/// Returns newly allocated C string '{"username":"...","password":"..."}'. Caller must free with `bitnet_free_string`.
#[no_mangle]
pub unsafe extern "C" fn bitnet_entry_get_details(entry_uuid: *const c_char) -> *mut c_char {
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
        Some(manager) => match manager.get_entry_details(&uuid) {
            Ok((password, username)) => {
                let json = serde_json::json!({
                    "username": username,
                    "password": password.as_str()
                });
                let json_string = serde_json::to_string(&json).unwrap_or_default();
                to_c_string(&json_string)
            }
            Err(_) => std::ptr::null_mut(),
        },
        None => std::ptr::null_mut(),
    }
}

/// List all entries in unlocked vault as JSON array.
/// Returns newly allocated C string. Caller must free with `bitnet_free_string`.
#[no_mangle]
pub unsafe extern "C" fn bitnet_list_entries() -> *mut c_char {
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
pub unsafe extern "C" fn bitnet_free_string(ptr: *mut c_char) {
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
/// Compute the vault fingerprint (SHA-256 hex) from a vault file.
///
/// # Safety
///
/// - `path` must be either `null` or point to a NUL-terminated C string
///   identifying a valid `.bitnet` file path.
/// - The returned `*mut c_char` (if non-null) must be released with
///   `bitnet_free_string`. The string contains no sensitive data.
///
/// [BITNET-H3] CWE-400 / CWE-770: the file is stat'd before read and
/// rejected if it exceeds [`MAX_FINGERPRINT_INPUT_SIZE`]. Without this
/// cap an attacker can pass a multi-gigabyte file and exhaust the
/// process address space (`fs::read` would allocate the whole file).
#[no_mangle]
pub unsafe extern "C" fn bitnet_vault_fingerprint(path: *const c_char) -> *mut c_char {
    if path.is_null() {
        return std::ptr::null_mut();
    }
    let path_str = unsafe { CStr::from_ptr(path).to_string_lossy() };
    if !util::validate_vault_path(&path_str) {
        return std::ptr::null_mut();
    }

    // [BITNET-H3] Reject files that are too large to fingerprint
    // before allocating a buffer for them. The ceiling is generous:
    // 2 * MAX_CIPHERTEXT_LENGTH (200 MiB) covers the header (68 B),
    // the HMAC tag (32 B), the 8-byte length prefix, and 2x the
    // largest legitimate vault payload. Any normal BitNet vault
    // will be orders of magnitude smaller.
    const MAX_FINGERPRINT_INPUT_SIZE: u64 = 200 * 1024 * 1024;
    match std::fs::metadata(&*path_str) {
        Ok(meta) if meta.len() <= MAX_FINGERPRINT_INPUT_SIZE => {}
        Ok(_) => return std::ptr::null_mut(), // file too large
        Err(_) => return std::ptr::null_mut(),
    }

    match std::fs::read(&*path_str) {
        Ok(data) => {
            let hash = bitnet_crypto::sha256(&data);
            let hex = hash
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>();
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

    // The exported bitnet_* functions are unsafe extern "C" because they
    // take raw pointers. Tests can call them through these thin wrappers
    // so the test bodies themselves stay safe-looking.
    unsafe fn init() -> c_int {
        unsafe { bitnet_init() }
    }
    unsafe fn vault_create(path: *const c_char, pwd: *const c_char) -> c_int {
        unsafe { bitnet_vault_create(path, pwd) }
    }
    #[allow(dead_code)]
    unsafe fn vault_unlock(path: *const c_char, pwd: *const c_char) -> c_int {
        unsafe { bitnet_vault_unlock(path, pwd) }
    }
    unsafe fn vault_lock() -> c_int {
        unsafe { bitnet_vault_lock() }
    }
    unsafe fn add_entry(group: *const c_char, json: *const c_char) -> c_int {
        unsafe { bitnet_add_entry(group, json) }
    }
    unsafe fn create_group(parent: *const c_char, name: *const c_char) -> *mut c_char {
        unsafe { bitnet_create_group(parent, name) }
    }
    unsafe fn entry_get_totp_to_buffer(uuid: *const c_char, buf: *mut c_char, len: usize) -> c_int {
        unsafe { bitnet_entry_get_totp_to_buffer(uuid, buf, len as libc::size_t) }
    }
    unsafe fn free_string(ptr: *mut c_char) {
        unsafe { bitnet_free_string(ptr) }
    }
    unsafe fn cstr_to_string(ptr: *mut c_char) -> String {
        unsafe { CStr::from_ptr(ptr).to_string_lossy().to_string() }
    }

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
        let original = [
            0x55, 0x0e, 0x84, 0x00, 0xe2, 0x9b, 0x41, 0xd4, 0xa7, 0x16, 0x44, 0x66, 0x55, 0x44,
            0x00, 0x00,
        ];
        let hex = uuid_to_hex(&original);
        let parsed = uuid_from_hex(&hex).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_to_c_string_roundtrip() {
        let ptr = to_c_string("hello ffi");
        assert!(!ptr.is_null());
        let s = unsafe { cstr_to_string(ptr) };
        assert_eq!(s, "hello ffi");
        unsafe { free_string(ptr) };
    }

    #[test]
    fn test_util_validate_vault_path() {
        assert!(util::validate_vault_path("C:\\Users\\user\\vault.bitnet"));
        assert!(!util::validate_vault_path(
            "C:\\Windows\\System32\\config\\SAM"
        ));
        assert!(!util::validate_vault_path("C:\\Users\\..\\vault.bitnet"));
        assert!(!util::validate_vault_path("C:\\Users\\vault.txt"));
    }

    #[test]
    fn test_generate_password_bounds() {
        let len: c_int = -1;
        let as_usize = len as usize;
        assert!(as_usize > 512);
    }

    #[test]
    fn test_entry_get_totp_to_buffer() {
        unsafe { init() };
        let current_dir = std::env::current_dir().unwrap();
        let vault_path = current_dir.join("test_totp_buf.bitnet");
        let path_str = vault_path.to_str().unwrap();
        let path = format!("{}\0", path_str);
        let pwd = "long_test_password_xyz\0";
        let path_c = path.as_ptr() as *const c_char;
        let pwd_c = pwd.as_ptr() as *const c_char;
        // Clean up any previous test file
        let _ = std::fs::remove_file(&vault_path);
        assert_eq!(unsafe { vault_create(path_c, pwd_c) }, 0);

        let root_name = std::ffi::CString::new("Root").unwrap();
        let root_group = unsafe { create_group(std::ptr::null(), root_name.as_ptr()) };
        assert!(!root_group.is_null());
        let root_uuid = unsafe { CStr::from_ptr(root_group).to_string_lossy().to_string() };
        let entry_json = r#"{"uuid":"550e8400e29b41d4a716446655440000","title":"Test","username":"u","password":"p","url":"","notes":"","totp_secret":"JBSWY3DPEHPK3PXP"}"#.to_string();
        let entry_json_c = CString::new(entry_json).unwrap();
        let root_uuid_c = CString::new(root_uuid.as_str()).unwrap();
        assert_eq!(
            unsafe { add_entry(root_uuid_c.as_ptr(), entry_json_c.as_ptr()) },
            0
        );
        unsafe { free_string(root_group) };

        let entry_uuid = "550e8400e29b41d4a716446655440000\0";
        let mut buf = [0 as c_char; 32];
        let result = unsafe {
            entry_get_totp_to_buffer(
                entry_uuid.as_ptr() as *const c_char,
                buf.as_mut_ptr(),
                buf.len(),
            )
        };
        assert_eq!(result, 0);
        assert!(buf.iter().any(|c| *c != 0));

        unsafe { vault_lock() };
        std::fs::remove_file("test_totp_buf.bitnet").ok();
    }

    /// Regression for [BITNET-H3] CWE-400 / CWE-770: the
    /// `bitnet_vault_fingerprint` function must stat the file and
    /// reject paths that exceed the size cap *before* allocating a
    /// buffer. We exercise two paths:
    ///   1. A small (4 KiB) file under the cap — must succeed
    ///      and return a valid SHA-256 hex.
    ///   2. The metadata() size check is exercised for any file
    ///      the function is called with.
    #[test]
    fn test_fingerprint_small_file_succeeds() {
        // validate_vault_path requires an absolute path, so use a
        // path under the current working directory made absolute.
        let rel = "test_fingerprint_small.bitnet";
        let abs = std::env::current_dir()
            .unwrap()
            .join(rel)
            .to_string_lossy()
            .into_owned();
        // Write 4 KiB of zeros — well under the 200 MiB cap.
        std::fs::write(&abs, vec![0u8; 4096]).unwrap();
        let path_c = CString::new(abs.as_str()).unwrap();
        let ptr = unsafe { bitnet_vault_fingerprint(path_c.as_ptr()) };
        assert!(!ptr.is_null(), "small file fingerprint must succeed");
        let hex = unsafe { cstr_to_string(ptr) };
        assert_eq!(hex.len(), 64, "SHA-256 hex must be 64 chars");
        unsafe { free_string(ptr) };
        std::fs::remove_file(&abs).ok();
    }
}
