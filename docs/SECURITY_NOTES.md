# Security Notes

This document records accepted security limitations and design decisions for the BitNet password manager.

## L-001: C# `StringBuilder` Password Leakage in `VaultPage`

**Location**: `BitNet.Desktop/Views/VaultPage.xaml.cs` — `CopyPassword_Click`

Passwords copied from the native core into a `System.Text.StringBuilder` and then assigned to a managed `String` remain in the .NET managed heap until garbage collection. The CLR provides no guaranteed zeroization API for managed strings or `StringBuilder` internal buffers.

**Mitigation**: Best-effort `StringBuilder.Clear()` and variable overwrite are performed immediately after copying the password to the clipboard. This reduces the window of exposure but does not eliminate it.

**Status**: Accepted limitation of the .NET runtime. Use a future pure-Rust GUI or memory-protected interop if stronger guarantees are required.

## L-003: `MasterPasswordBox.Password` String Persists in Managed Heap

**Location**: `BitNet.Desktop/Views/UnlockPage.xaml.cs`

The WinUI `PasswordBox.Password` property returns a standard managed `String`. Even though the secure wrapper zeroizes the pinned UTF-8 buffer passed to the Rust core, the original managed string survives in the .NET heap until the next garbage collection cycle. There is no `SecureString` usage in the current WinUI implementation.

**Mitigation**: Accepted .NET limitation. Developers should be aware that the master password may briefly exist as a managed string in the heap.

**Status**: Documented accepted risk.

## L-005: `scripts/sign-binaries.ps1` Plain-Text Password Exposure

**Location**: `scripts/sign-binaries.ps1`

When a PFX file is supplied, the script decrypts the secure-string password to plain text via `[Runtime.InteropServices.Marshal]::PtrToStringAuto(...)` so that `signtool` can consume it. This plain-text string exists in PowerShell memory for the duration of the signing operation.

**Mitigation**:
- A `try/finally` block performs best-effort zeroization after signing.
- For CI and automated environments, **always prefer `-CertificateThumbprint`** to avoid PFX passwords in memory entirely.

**Status**: Accepted for local/interactive signing scripts; CI must use thumbprint-based signing.

## L-006: Max Ciphertext Size Not Enforced in `load_vault`

**Location**: `crates/bitnet-kdbx/src/lib.rs` — `load_vault`

Before Task 3.1 the function read `payload_len` directly from the untrusted vault header and immediately allocated a buffer of that size, allowing a malicious file to trigger an out-of-memory panic.

**Mitigation** (Task 3.1):
```rust
    let payload_len = u64::from_be_bytes(data[HEADER_SIZE + 32..HEADER_SIZE + 40].try_into().unwrap()) as usize;
    const MAX_CIPHERTEXT_LENGTH: usize = 100 * 1024 * 1024;
    if payload_len > MAX_CIPHERTEXT_LENGTH {
        return Err(KdbxError::InvalidFormat);
    }
```
A hard ceiling of **100 MiB** is enforced before any allocation occurs.

**Status**: MITIGATED in v0.1 — accepted until a streaming decryption design removes the need for a single in-memory ceiling.

## M-004: ~~Native Messaging Host `allowed_origins` Wildcard~~ (CLOSED 2026-06-05)

**Status**: **CLOSED** — the v0.1 hardening campaign replaced the
wildcard with a strict `https://*/*` match pattern and 27
`exclude_matches` entries that block private-network ranges,
`.local` / `.lan` / `.onion` domains, and unencrypted schemes. A
runtime origin guard in `content.js` rejects any non-allowed
origin at the message-handler entry, so even a compromised
extension can no longer reach the native host over a non-HTTPS
context.

**See** [bitnet-extension commit history] for the precise diff; this
section is retained for traceability.

## M-001: HTTPS-Only Content Script Origin Lockdown

**Location**: `browser-extension/manifest.json`, `browser-extension/content.js`

After the v0.1 hardening, content scripts match `https://*/*` only
and explicitly exclude private-network ranges (RFC 1918, link-local,
loopback), `.local` / `.lan` / `.onion` hostnames, and the
`chrome-extension://` scheme. A request from any other origin is
rejected by the runtime guard in `content.js` before the native
messaging call is dispatched.

**Status**: Implemented in v0.1; verified by Playwright E2E (5/5).

## M-002: FFI SecureString-Only API Surface

**Location**: `crates/bitnet-ffi/src/lib.rs`, `BitNet.Desktop/Native/BitnetCore.cs`

The legacy `SecureVaultUnlock(string,string)` and friends that
accepted a plain `char*` master password have been removed. Every
FFI call now requires a `SecureString` on the C# side and
zeroises the temporary buffer after the call returns.

**Status**: Implemented in v0.1; 19/19 `extern "C"` FFI functions
documented with explicit `# Safety` blocks.

## M-003: NTFS ADS + Wildcard Path Validation

**Location**: `crates/bitnet-core/src/util.rs`

`validate_vault_path` rejects paths containing NTFS alternate
data streams (more than one `:`), wildcard or shell metacharacters
(`* ? < > | " `), and NUL or other control characters. Length
is bounded to 4 KiB.

**Status**: Implemented in v0.1 with 3 dedicated unit tests.

## M-005: Mutex for `RateLimiter` (Concurrency Fix)

**Location**: `crates/bitnet-native-host/src/lib.rs`

The previous lock-free `AtomicU64` based rate limiter had a
read-modify-write race. Replaced with a `Mutex<RateState>` plus a
concurrent stress test (16 threads × 100 calls).

**Status**: Implemented in v0.1.

## M-006: Deadline-Based Clipboard Clear

**Location**: `BitNet.Desktop/Views/VaultPage.xaml.cs`

`VaultPage` now uses a deadline-based timer that fires every
second. When the deadline expires (default 30 s after a copy),
the clipboard is cleared and the timer is disposed. The timer is
re-armed on every copy and is properly cleaned up in
`OnNavigatedFrom`. `COMException` is caught and ignored so a
clipboard-owner process (e.g. another app) does not crash the
clear.

**Status**: Implemented in v0.1.

## L-007: Structured Logging Without Error Chain Echo

**Location**: `bitnet-cli/src/main.rs`

The CLI now uses `tracing::error!` and `tracing::info!` events
emitted through `init_logging()`. The human-readable `eprintln!`
message still surfaces the cause, but the structured log event
contains only an operation kind (e.g. `kind = "Error"`) — never
the user-supplied path or any other field that could leak through
log aggregation.

## M-010 (BITNET-M4): Daemon `read_frame` Read Timeout — Two-Layer Design

**Location**: `crates/bitnet-daemon/src/protocol.rs`,
`crates/bitnet-daemon/src/ipc.rs` (Windows), `crates/bitnet-daemon/src/daemon.rs`

A peer that opens a Named Pipe connection and never sends any
data would, in the previous implementation, hold a dispatch
thread forever. The new design has two layers of defence:

1. **Hard timeout (Windows only)** — `accept_inner` calls
   `SetCommTimeouts` with
   `ReadTotalTimeoutConstant = MAX_REQUEST_DURATION` (15 s)
   immediately after `ConnectNamedPipe`. The next `ReadFile`
   on the pipe returns `ERROR_OPERATION_ABORTED` (995) or
   `ERROR_TIMEOUT` (1460) after the deadline, and the
   `Conn::read` implementation maps these to
   `io::ErrorKind::TimedOut`. This cancels the in-progress
   read on the OS side — it is the **real** fix for the
   "never sends a single byte" attack.

2. **Soft deadline (cross-platform fallback)** —
   `protocol::read_frame_with_deadline(r, deadline)` checks
   the deadline **between** `read_exact` calls. `read_exact`
   on a synchronous `Read` trait implementation cannot be
   cancelled mid-call (it is, by definition, a blocking
   syscall), so this layer only catches the
   "stops mid-frame" case. The transport for in-memory tests
   and any future non-Windows Named-Pipe equivalent relies
   on this layer.

`handle_one` wraps `read_frame_with_deadline` with a single
15 s deadline covering the entire request read, so a peer
that streams slowly (one byte every 14 s, say) eventually
times out rather than holding a slot indefinitely.

**Why not a pure hard timeout on every transport?** The Rust
`std::io::Read` trait has no portable way to cancel an
in-progress `read_exact`. The Windows Named Pipe transport
has a native `SetCommTimeouts` API; the Unix `UnixStream`
also has a `set_read_timeout`; in-memory `Cursor` does not.
`protocol::read_frame_with_deadline` is the abstraction
boundary that works for all of them.

**Verified**: `read_frame_with_deadline` has 3 unit tests
covering past-deadline (returns `TimedOut`), partial-then-EOF
(returns `UnexpectedEof`), and full-hang (returns
`UnexpectedEof`). The Windows hard-timeout path is exercised
in production builds via the `SetCommTimeouts` call; the
read-timeout mapping in `Conn::read` is regression-tested by
mapping the documented Win32 error codes to `TimedOut`.

**Status**: Closed in the 2026-06-09 BugHunting round 2
([a77c5ac](../SECURITY_AUDIT_2026-06-09.md#audit-trail), followed
by the two-layer follow-up in the same round-2 series).
Accepted-risk ID R007 is now CLOSED in
`THREAT_MODEL.md`.
