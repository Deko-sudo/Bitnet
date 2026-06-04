use std::io::{Read, Write};
use std::process::{Command, Stdio};

fn find_native_host_exe() -> Option<std::path::PathBuf> {
    // Try target directory relative to manifest
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").ok()?;
    let target_dir = std::path::Path::new(&manifest_dir)
        .join("..")
        .join("..")
        .join("target")
        .join("debug");
    let exe = target_dir.join("bitnet-native-host.exe");
    if exe.exists() {
        return Some(exe);
    }

    // Fallback: target/debug from current exe
    let exe2 = std::env::current_exe()
        .ok()?
        .ancestors()
        .nth(3)?
        .join("bitnet-native-host.exe");
    if exe2.exists() {
        return Some(exe2);
    }

    None
}

fn start_native_host() -> std::process::Child {
    let exe = find_native_host_exe()
        .expect("bitnet-native-host.exe not found. Build with: cargo build --workspace");
    Command::new(exe)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to start bitnet-native-host")
}

fn send_message(stdin: &mut std::process::ChildStdin, data: &[u8]) {
    let len = data.len() as u32;
    stdin.write_all(&len.to_ne_bytes()).unwrap();
    stdin.write_all(data).unwrap();
    stdin.flush().unwrap();
}

fn read_response(stdout: &mut std::process::ChildStdout) -> Option<serde_json::Value> {
    let mut len_buf = [0u8; 4];
    stdout.read_exact(&mut len_buf).ok()?;
    let len = u32::from_ne_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    stdout.read_exact(&mut buf).ok()?;
    serde_json::from_slice(&buf).ok()
}

#[test]
fn test_oversized_message_rejected() {
    let mut child = start_native_host();
    let stdin = child.stdin.as_mut().unwrap();
    let stdout = child.stdout.as_mut().unwrap();

    let payload = b"{\"action\":\"list_entries\"}";
    let mut oversized = vec![b' '; 1_000_001];
    let mut msg = payload.to_vec();
    msg.append(&mut oversized);
    send_message(stdin, &msg);

    let resp = read_response(stdout);
    assert!(
        resp.is_some(),
        "Should get a response for oversized message"
    );
    let resp = resp.unwrap();
    assert_eq!(resp["success"], false);
    let error = resp["error"].as_str().unwrap_or("");
    assert!(
        error.contains("too large") || error.contains("large"),
        "Expected 'too large' error, got: {}",
        error
    );

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn test_small_message_accepted() {
    let mut child = start_native_host();
    let stdin = child.stdin.as_mut().unwrap();
    let stdout = child.stdout.as_mut().unwrap();

    let msg = br#"{"action":"is_unlocked"}"#;
    send_message(stdin, msg);

    let resp = read_response(stdout);
    assert!(resp.is_some());
    let resp = resp.unwrap();
    assert!(resp.get("success").is_some());

    child.kill().ok();
    child.wait().ok();
}
