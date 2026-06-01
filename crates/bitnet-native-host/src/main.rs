use serde::{Deserialize, Serialize};
use std::ffi::CString;
use std::io::{self, Read, Write};

#[derive(Debug, Deserialize)]
struct Request {
    action: String,
    uuid: Option<String>,
}

#[derive(Debug, Serialize)]
struct Response {
    success: bool,
    data: Option<String>,
    error: Option<String>,
}

fn main() {
    bitnet_ffi::bitnet_init();

    loop {
        let mut len_buf = [0u8; 4];
        if io::stdin().read_exact(&mut len_buf).is_err() {
            break;
        }
        let msg_len = u32::from_ne_bytes(len_buf) as usize;
        if msg_len > 1_000_000 {
            let _ = send_response(false, None, Some("Message too large".into()));
            // Drain remaining bytes to keep protocol in sync
            let mut discard = vec![0u8; msg_len];
            let _ = io::stdin().read_exact(&mut discard);
            continue;
        }
        let mut msg_buf = vec![0u8; msg_len];
        if io::stdin().read_exact(&mut msg_buf).is_err() {
            break;
        }

        let request: Request = match serde_json::from_slice(&msg_buf) {
            Ok(req) => req,
            Err(_e) => {
                let _ = send_response(false, None, Some("Invalid request format".into()));
                continue;
            }
        };

        if request.action.len() > 64 {
            let _ = send_response(false, None, Some("Action name too long".into()));
            continue;
        }

        match request.action.as_str() {
            "is_unlocked" => {
                let unlocked = bitnet_ffi::bitnet_vault_is_unlocked() != 0;
                let _ = send_response(unlocked, None, None);
            }
            "get_entry" => {
                if let Some(uuid) = request.uuid {
                    let c_uuid = match CString::new(uuid) {
                        Ok(s) => s,
                        Err(_) => {
                            let _ = send_response(false, None, Some("Invalid UUID".into()));
                            continue;
                        }
                    };
                    let ptr = bitnet_ffi::bitnet_entry_get_details(c_uuid.as_ptr());
                    if ptr.is_null() {
                        let _ = send_response(false, None, Some("Failed to get entry details".into()));
                    } else {
                        let json = unsafe {
                            std::ffi::CStr::from_ptr(ptr)
                                .to_string_lossy()
                                .to_string()
                        };
                        bitnet_ffi::bitnet_free_string(ptr);
                        let _ = send_response(true, Some(json), None);
                    }
                } else {
                    let _ = send_response(false, None, Some("Missing UUID".into()));
                }
            }
            "get_password" => {
                if let Some(uuid) = request.uuid {
                    let c_uuid = match CString::new(uuid) {
                        Ok(s) => s,
                        Err(_) => {
                            let _ = send_response(false, None, Some("Invalid UUID".into()));
                            continue;
                        }
                    };
                    let mut buf = vec![0i8; 1024];
                    let result = bitnet_ffi::bitnet_entry_get_password(
                        c_uuid.as_ptr(),
                        buf.as_mut_ptr(),
                        buf.len(),
                    );
                    match result {
                        0 => {
                            let pwd = unsafe {
                                std::ffi::CStr::from_ptr(buf.as_ptr())
                                    .to_string_lossy()
                                    .to_string()
                            };
                            let _ = send_response(true, Some(pwd), None);
                        }
                        -5 => {
                            let _ = send_response(false, None, Some("Password too long for buffer".into()));
                        }
                        _ => {
                            let _ = send_response(false, None, Some("Failed to get password".into()));
                        }
                    }
                } else {
                    let _ = send_response(false, None, Some("Missing UUID".into()));
                }
            }
            "list_entries" => {
                let ptr = bitnet_ffi::bitnet_list_entries();
                if ptr.is_null() {
                    let _ = send_response(false, None, Some("Failed to list entries".into()));
                } else {
                    let json = unsafe {
                        std::ffi::CStr::from_ptr(ptr)
                            .to_string_lossy()
                            .to_string()
                    };
                    bitnet_ffi::bitnet_free_string(ptr);
                    let _ = send_response(true, Some(json), None);
                }
            }
            _ => {
                let _ = send_response(false, None, Some("Unknown action".into()));
            }
        }
    }
}

fn send_response(success: bool, data: Option<String>, error: Option<String>) -> io::Result<()> {
    let response = Response { success, data, error };
    let json = serde_json::to_string(&response).unwrap_or_default();
    let len = json.len() as u32;
    let mut stdout = io::stdout();
    stdout.write_all(&len.to_ne_bytes())?;
    stdout.write_all(json.as_bytes())?;
    stdout.flush()
}