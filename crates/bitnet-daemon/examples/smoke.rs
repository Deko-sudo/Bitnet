use bitnet_daemon::{protocol, Client, DaemonState, NoopVaultService, Request, Server};
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

fn main() {
    let server = Server::bind().expect("bind");
    let state = Arc::new(Mutex::new(DaemonState::new()));
    let state_t = Arc::clone(&state);
    let svc = NoopVaultService;
    let _ = thread::spawn(move || loop {
        match server.accept() {
            Ok(mut c) => {
                let _ = bitnet_daemon::handle_one_in_memory(&state_t, &svc, &mut c);
            }
            Err(e) => {
                println!("accept err: {e}");
                break;
            }
        }
    });
    thread::sleep(Duration::from_millis(100));
    let mut client = Client::connect().expect("connect");

    let req = Request {
        jsonrpc: "2.0".into(),
        id: 1,
        method: "ping".into(),
        params: serde_json::json!({}),
        auth: None,
        seq: None,
        ts: None,
    };
    let body = serde_json::to_value(&req).unwrap();
    protocol::write_frame(&mut client, &body).expect("write");
    let resp = protocol::read_frame(&mut client).expect("read");
    println!("ping: {resp}");

    // [BITNET-H1] unlock with a client-supplied token.
    let supplied_token = [0x22u8; 32];
    let token_hex: String = (0..32)
        .map(|i| format!("{:02x}", supplied_token[i]))
        .collect();
    let req2 = Request {
        jsonrpc: "2.0".into(),
        id: 2,
        method: "unlock".into(),
        params: serde_json::json!({
            "path": "/vault.bitnet",
            "token_hex": token_hex,
        }),
        auth: None,
        seq: None,
        ts: None,
    };
    let body2 = serde_json::to_value(&req2).unwrap();
    protocol::write_frame(&mut client, &body2).expect("write2");
    let resp2 = protocol::read_frame(&mut client).expect("read2");
    println!("unlock: {resp2}");
}
