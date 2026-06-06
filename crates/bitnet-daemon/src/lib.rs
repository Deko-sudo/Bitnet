//! BitNet daemon — long-running process that holds an unlocked
//! `SessionManager` and serves JSON-RPC commands over the IPC transport.
//!
//! # Architecture
//!
//! ```text
//!         ┌──────────────┐   JSON-RPC over Named Pipe
//!         │  bitnet-cli  │◀──────────────or──────────────▶  ┌──────────┐
//!         │   (client)   │      abstract Unix socket        │  daemon  │
//!         └──────────────┘                                    └─────┬────┘
//!                                                                    │
//!                                                          SessionManager
//! ```
//!
//! The daemon never touches the network. All traffic is local
//! and protected by an HMAC-SHA-256 over the request body
//! keyed with a 32-byte session token. The token is rotated on
//! every `unlock` and zeroised on every `lock` / daemon shutdown.
//!
//! # Concurrency model
//!
//! - One `Mutex<DaemonState>` guards the in-process state so
//!   that concurrent clients serialise.
//! - The IPC server accepts one client at a time. The protocol
//!   uses length-prefixed JSON frames (see `protocol`), so each
//!   `accept` call processes exactly one request/response pair.
//!
//! # Modules
//!
//! - [`protocol`] — JSON-RPC 2.0 wire format (length-prefixed
//!   frames, request/response enums, error codes).
//! - [`ipc`]      — Cross-platform IPC transport: Named Pipe on
//!   Windows, abstract Unix domain socket on Unix.
//! - [`auth`]     — HMAC-SHA-256 request signing/verification.
//! - [`daemon`]   — `DaemonState` and the request dispatch loop.

#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

pub mod auth;
pub mod client;
pub mod daemon;
pub mod ipc;
pub mod protocol;

// Re-exports for ergonomics.
pub use auth::{hmac_hex, sign_request, verify_request};
pub use client::{daemon_alive, describe_error_code, make_request, split_response};
pub use daemon::{dispatch, handle_one, handle_one_in_memory, DaemonState};
pub use protocol::{Method, code, make_err, make_ok, ErrorBody, Request, Response};
pub use ipc::{Client, Conn, Server};
