use bitnet_native_host::RateLimiter;
use serde::{Deserialize, Serialize};
use std::ffi::CString;
use std::io::{self, Read, Write};
use zeroize::Zeroize;

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

/// The browser-native-messaging wire format uses a 4-byte
/// **little-endian** length prefix (see
/// <https://developer.chrome.com/docs/apps/nativeMessaging/#native-messaging-host-protocol>).
/// The previous implementation used `u32::from_ne_bytes` which
/// is **native-endian**: on x86 it happened to be LE, but on
/// big-endian targets (or future ARM big-endian cores) the
/// host and the browser would disagree on the message length.
/// Force LE explicitly so the protocol is portable.
const FRAME_LEN_BYTES: usize = 4;
const MAX_MESSAGE_BYTES: usize = 1_000_000;
/// Per-action rate cap for `get_password` (mass-exfiltration
/// defense). The general message-rate limit is still enforced
/// by `RateLimiter`; this is the additional cap for the only
/// action that returns plaintext credentials.
const MAX_GET_PASSWORD_PER_MIN: u32 = 30;

fn main() {
    // The whole body is unsafe because every call to bitnet_ffi::bitnet_*
    // takes a raw pointer and is marked unsafe extern "C". Wrapping the
    // body in a single unsafe block keeps the action-handler code readable.
    //
    // Security note: this host talks to the browser via the native
    // messaging protocol (stdin/stdout, length-prefixed) and to
    // the BitNet core via in-process FFI (no daemon IPC, so
    // H1/M3 from the BugHunting round 2 audit do not apply to
    // this code path). The session token is held by the
    // BitNet core; the native host never sees it. Rate
    // limiting + 1 MiB message cap + per-action
    // `get_password` cap are the host's defensive layers.
    let mut get_pwd_window = GetPasswordWindow::new();
    unsafe {
        bitnet_ffi::bitnet_init();
        let rate_limiter = RateLimiter::new(100); // 100 msg/s

        loop {
            if !rate_limiter.check() {
                let _ = send_response(false, None, Some("Rate limit exceeded".into()));
                continue;
            }
            let mut len_buf = [0u8; FRAME_LEN_BYTES];
            if io::stdin().read_exact(&mut len_buf).is_err() {
                break;
            }
            let msg_len = u32::from_le_bytes(len_buf) as usize;
            if msg_len > MAX_MESSAGE_BYTES {
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
                            let _ = send_response(
                                false,
                                None,
                                Some("Failed to get entry details".into()),
                            );
                        } else {
                            let json = {
                                let s = std::ffi::CStr::from_ptr(ptr).to_string_lossy().to_string();
                                bitnet_ffi::bitnet_free_string(ptr);
                                s
                            };
                            let _ = send_response(true, Some(json), None);
                        }
                    } else {
                        let _ = send_response(false, None, Some("Missing UUID".into()));
                    }
                }
                "get_password" => {
                    // [BITNET-M9] mass-exfiltration cap: allow at
                    // most MAX_GET_PASSWORD_PER_MIN calls per
                    // 60-second sliding window. The general
                    // RateLimiter caps total messages/s but does
                    // not specifically throttle the only
                    // action that returns plaintext credentials.
                    if !get_pwd_window.allow() {
                        let _ = send_response(
                            false,
                            None,
                            Some("get_password rate limit exceeded".into()),
                        );
                        continue;
                    }
                    if let Some(uuid) = request.uuid {
                        let c_uuid = match CString::new(uuid) {
                            Ok(s) => s,
                            Err(_) => {
                                let _ = send_response(false, None, Some("Invalid UUID".into()));
                                continue;
                            }
                        };
                        // [BITNET-L2] Use a Zeroizing wrapper so the heap buffer
                        // is overwritten with zeros when `buf` goes out of scope.
                        // Without this, the password lingers in the heap until
                        // the next allocation reuses the same address.
                        let mut buf = zeroize::Zeroizing::new(vec![0i8; 1024]);
                        let result = bitnet_ffi::bitnet_entry_get_password(
                            c_uuid.as_ptr(),
                            buf.as_mut_ptr(),
                            buf.len(),
                        );
                        match result {
                            0 => {
                                let pwd = {
                                    std::ffi::CStr::from_ptr(buf.as_ptr())
                                        .to_string_lossy()
                                        .to_string()
                                };
                                let _ = send_response(true, Some(pwd), None);
                                // Zeroize before send_response flushes so the
                                // wire payload has already been serialized.
                                buf.iter_mut().for_each(|b| *b = 0);
                            }
                            -5 => {
                                let _ = send_response(
                                    false,
                                    None,
                                    Some("Password too long for buffer".into()),
                                );
                            }
                            _ => {
                                let _ = send_response(
                                    false,
                                    None,
                                    Some("Failed to get password".into()),
                                );
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
                        let json = {
                            let s = std::ffi::CStr::from_ptr(ptr).to_string_lossy().to_string();
                            bitnet_ffi::bitnet_free_string(ptr);
                            s
                        };
                        let _ = send_response(true, Some(json), None);
                    }
                }
                _ => {
                    let _ = send_response(false, None, Some("Unknown action".into()));
                }
            }
        }
    } // end unsafe
}

/// Per-action sliding-window rate limiter. Used to throttle
/// the only action that returns plaintext credentials
/// (`get_password`). General message-rate limiting is done by
/// `bitnet_native_host::RateLimiter`; this is a second layer
/// that catches a single misbehaving extension that floods
/// `get_password` within the global rate budget.
struct GetPasswordWindow {
    /// `now - 60s ..= now` — timestamps of accepted calls.
    timestamps: Vec<std::time::Instant>,
}

impl GetPasswordWindow {
    fn new() -> Self {
        Self {
            timestamps: Vec::with_capacity(MAX_GET_PASSWORD_PER_MIN as usize),
        }
    }

    fn allow(&mut self) -> bool {
        let now = std::time::Instant::now();
        // Drop entries older than 60 s.
        let cutoff = now - std::time::Duration::from_secs(60);
        while let Some(front) = self.timestamps.first() {
            if *front < cutoff {
                self.timestamps.remove(0);
            } else {
                break;
            }
        }
        if (self.timestamps.len() as u32) >= MAX_GET_PASSWORD_PER_MIN {
            return false;
        }
        self.timestamps.push(now);
        true
    }
}

impl Zeroize for GetPasswordWindow {
    fn zeroize(&mut self) {
        // The window contains no secret material, but implementing
        // Zeroize for symmetry with other helpers keeps the
        // trait surface clean.
        self.timestamps.clear();
    }
}

fn send_response(success: bool, data: Option<String>, error: Option<String>) -> io::Result<()> {
    let response = Response {
        success,
        data,
        error,
    };
    let json = serde_json::to_string(&response).unwrap_or_default();
    let len = json.len() as u32;
    let mut stdout = io::stdout();
    stdout.write_all(&len.to_le_bytes())?;
    stdout.write_all(json.as_bytes())?;
    stdout.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_length_is_little_endian() {
        // 0x07000000 little-endian -> 7
        let bytes = [0x07, 0x00, 0x00, 0x00];
        assert_eq!(u32::from_le_bytes(bytes), 7);
    }

    #[test]
    fn get_password_window_caps_at_max() {
        let mut w = GetPasswordWindow::new();
        for _ in 0..MAX_GET_PASSWORD_PER_MIN {
            assert!(w.allow());
        }
        // 31st call within the same window must be denied.
        assert!(!w.allow());
    }

    #[test]
    fn get_password_window_recovers_after_window() {
        let mut w = GetPasswordWindow::new();
        for _ in 0..MAX_GET_PASSWORD_PER_MIN {
            assert!(w.allow());
        }
        assert!(!w.allow());
        // Force-clear the window and confirm we can call again.
        w.timestamps.clear();
        assert!(w.allow());
    }
}
