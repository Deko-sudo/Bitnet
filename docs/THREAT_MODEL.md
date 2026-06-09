# BitNet Threat Model

## Overview
BitNet is an offline password manager for Windows with Zero Trust architecture. This document identifies key threats and mitigations.

## Trust Boundaries
- **User Device**: Trusted, but potentially compromised by malware.
- **BitNet Process**: The application itself. We assume it could be targeted.
- **Vault File**: Stored on local disk. Encrypted at rest.
- **Memory (RAM)**: Untrusted — must not contain plaintext passwords outside of active sessions.
- **Clipboard**: Shared resource, potentially monitored.

## Identified Threats

### 1. Memory Dump Attack
**Threat**: Attacker obtains a memory dump of the running process and extracts plaintext passwords.
**Mitigation**:
- Session keys and decrypted data stored in `Zeroizing` buffers.
- Auto-lock after inactivity clears sensitive data from memory.
- `SessionManager::lock()` explicitly zeroizes keys.

### 2. Brute-Force on Master Password
**Threat**: Attacker steals vault file and attempts offline brute-force.
**Mitigation**:
- Argon2id KDF with parameters (t=3, m=64MB, p=4) slows brute-force.
- Users encouraged to use strong master passwords.

### 3. Vault File Tampering
**Threat**: Attacker modifies vault file to inject malicious data.
**Mitigation**:
- HMAC-SHA-256 over vault header. Any tampering causes HMAC verification failure during unlock.
- AES-256-GCM authenticated encryption for payload.

### 4. Clipboard Hijacking
**Threat**: Malware monitors clipboard for copied passwords.
**Mitigation**:
- Clipboard cleared automatically 30 seconds after copy (GUI).
- CLI users warned to clear clipboard manually.

### 5. DLL Injection
**Threat**: Malicious DLL injected into BitNet process to hook FFI calls.
**Mitigation**:
- Code signing of binaries.
- Control Flow Guard (CFG) enabled.
- Future: verify DLL integrity at runtime.

### 6. Autofill Spoofing
**Threat**: Fake login forms trick autofill into filling wrong fields.
**Mitigation**:
- Native autofill matches by window handle / URL.
- Browser extension validates origin before filling.
- User confirmation required for first fill on new site.

### 7. Key Extraction from Swap File
**Threat**: Decrypted data swapped to disk.
**Mitigation**:
- Use `SecureZeroMemory` and locked pages where possible (future enhancement).
- Windows VirtualLock for sensitive buffers (future).

### 8. Native Host Origin Spoofing
**Threat**: A sideloaded browser extension with a matching allowed extension ID communicates with the native host (`bitnet-native-host.exe`) over `stdin`/`stdout`. The host does not cryptographically verify the origin of incoming messages.
**Mitigation**:
- `allowed_origins` in the browser manifest restricts which extension IDs may connect.
- OS/browser sandbox limits which extensions can launch the native host.
**Accepted Risk**: The native host trusts the OS/browser sandbox to enforce extension identity. Full origin validation is not implemented because the native messaging protocol does not provide a cryptographically verifiable origin field.

## ASVS Mapping (OWASP ASVS 4.0)

| ASVS ID | Requirement | Status |
|---------|-------------|--------|
| V2.1.1 | Strong password policy | Implemented via Argon2id |
| V6.2.1 | Cryptographic modules | AES-256-GCM, SHA-256, HMAC-SHA-256 |
| V6.2.3 | Approved algorithms | Argon2id (PHC winner) |
| V8.2.1 | Sensitive data protection | Zeroize, auto-lock |
| V8.2.3 | Memory cleanup | Zeroizing on lock |

## Accepted Risks Register

| ID | Risk | Relevant Item(s) | Mitigation / Status | Accept Until |
|----|------|-----------------|---------------------|--------------|
| R001 | ~~Wildcard `allowed_origins` allows any extension during development~~ | [M-004](SECURITY_NOTES.md#m-004) | **CLOSED 2026-06-05**: Browser manifest updated to `https://*/*` matches with 27 `exclude_matches` (private networks, .local/.lan/.onion). Runtime origin guard rejects non-allowed origins at message-handler entry. | N/A — closed |
| R002 | DPAPI master key is bound to Windows user profile | N/A | No cross-user portability; migration to Windows Hello/TPM planned | v0.2 |
| R003 | Managed-heap strings in C# GUI may retain secrets until GC | [L-001](SECURITY_NOTES.md#l-001), [L-003](SECURITY_NOTES.md#l-003) | Best-effort `StringBuilder.Clear()` and variable overwrite; .NET has no guaranteed string zeroization API | Pure-Rust GUI or `SecureZeroMemory` |
| R004 | ~~Clipboard is not auto-cleared after password copy~~ | [L-004](SECURITY_NOTES.md#l-004) | **CLOSED 2026-06-05**: `VaultPage.xaml.cs` uses deadline-based 1-second tick timer (`_clipboardClearDeadline`) that auto-clears clipboard after 30 s, with proper `OnNavigatedFrom` cleanup and `COMException` safety. | N/A — closed |
| R005 | No HSM/TPM protection for master key material | N/A | Argon2id KDF slows brute-force; Windows Hello/TPM integration planned | v0.2 |
| R006 | Ciphertext OOM via malicious `payload_len` in vault header | `load_vault` (Task 3.1) | `MAX_CIPHERTEXT_LENGTH = 100 MiB` hard ceiling enforced before allocation ([`crates/bitnet-kdbx/src/lib.rs`](../crates/bitnet-kdbx/src/lib.rs)) | MITIGATED in v0.1; accepted until permanent design |
| R007 | ~~`protocol::read_frame` has no read-timeout on the sync `Read` trait~~ | [BITNET-M4](SECURITY_AUDIT_2026-06-09.md#bitnet-m4-protocolread_frame-blocks-indefinitely-partial-fix) | **CLOSED 2026-06-09** ([M-010](SECURITY_NOTES.md#m-010-bitnet-m4-daemon-read_frame-read-timeout--two-layer-design)): two-layer defence. (1) Windows `SetCommTimeouts` is called in `Server::accept_inner` immediately after `ConnectNamedPipe` with `ReadTotalTimeoutConstant = MAX_REQUEST_DURATION` (15 s); the resulting `ERROR_OPERATION_ABORTED`/`ERROR_TIMEOUT` is mapped to `io::ErrorKind::TimedOut` in `Conn::read`. (2) `protocol::read_frame_with_deadline` adds a soft cross-platform deadline check between `read_exact` calls; `handle_one` wires it in. Idle / slow-streaming peers are now reaped in 15 s instead of holding a dispatch thread forever. | N/A — closed |
| R008 | ~~`Method::Unlock` returned session token in plain JSON over the wire~~ | [BITNET-H1](SECURITY_AUDIT_2026-06-09.md#bitnet-h1-methodunlock-returned-the-session-token-in-plain-json) | **CLOSED 2026-06-09**: `unlock` now requires the client to supply `token_hex` in `params`; the daemon stores it verbatim and returns only `{"ok": true}`. Any local process with a Named Pipe handle can no longer read the secret from the response. | N/A — closed |
| R009 | ~~No replay protection on daemon IPC~~ | [BITNET-M3](SECURITY_AUDIT_2026-06-09.md#bitnet-m3-daemon-ipc-had-no-replay-protection) | **CLOSED 2026-06-09**: `Request` now carries `seq` (monotonic) and `ts` (Unix seconds). HMAC payload extended to `method || params || seq_be8 || ts_be8`. `DaemonState` tracks `last_seq`. New error code `REPLAY = -11` returned for missing seq/ts, freshness window violations (skew > 30 s), and `seq <= last_seen`. | N/A — closed |
| R010 | ~~`SessionManager::ensure_unlocked` left decrypted entries in memory past the auto-lock deadline~~ | [BITNET-H2](SECURITY_AUDIT_2026-06-09.md#bitnet-h2-sessionmanagerensure_unlocked-did-not-drop-the-session) | **CLOSED 2026-06-09**: `ensure_unlocked` now drops the `Session` (calls `Session::drop` which zeroises) on expiry, so decrypted entries are reaped within the same call. 2 regression tests in `bitnet-core::auto_lock_tests`. | N/A — closed |
| R011 | ~~`bitnet_vault_fingerprint` had no file-size cap, allowing OOM via multi-GB files~~ | [BITNET-H3](SECURITY_AUDIT_2026-06-09.md#bitnet-h3-bitnet_vault_fingerprint-dos-via-oversize-file) | **CLOSED 2026-06-09**: `fs::metadata()` is called before `fs::read()`; files > 200 MiB are rejected with null return. Cap is 2× `MAX_CIPHERTEXT_LENGTH` + header overhead so legitimate vaults are never impacted. 1 regression test in `bitnet-ffi::tests`. | N/A — closed |
| R012 | ~~`AutoLockService.Touch()` was dead code, so the auto-lock fired regardless of activity~~ | [BITNET-H4](SECURITY_AUDIT_2026-06-09.md#bitnet-h4-autolockservicetouch-was-dead-code) | **CLOSED 2026-06-09**: `MainWindow` now hooks `PointerPressed` and `KeyDown` (with `handledEventsToo: true`) on the root `ContentFrame` so every user input event fires `Touch()`. The auto-lock idle window is now actually responsive. | N/A — closed |
| R013 | ~~`AutoLock` event did not call `bitnet_vault_lock()`, so the Rust-core session token survived auto-lock~~ | [BITNET-H5](SECURITY_AUDIT_2026-06-09.md#bitnet-h5-autolock-event-did-not-call-bitnet_vault_lock) | **CLOSED 2026-06-09**: the auto-lock handler now calls `BitnetCore.bitnet_vault_lock()` before navigating to `UnlockPage`, wrapped in try/catch so a stale FFI state cannot crash the auto-lock path. | N/A — closed |
| R014 | ~~Hand-rolled constant-time compare in `bitnet-daemon::auth::constant_time_eq` was not compiler-guaranteed constant-time~~ | [BITNET-M2](SECURITY_AUDIT_2026-06-09.md#bitnet-m2-hand-rolled-constant-time-loop-in-authconstant_time_eq) | **CLOSED 2026-06-09**: `bitnet-daemon::auth` now uses `subtle::ConstantTimeEq` (matches `bitnet-crypto` and `bitnet-totp`). The `subtle` workspace dependency is declared in `bitnet-daemon/Cargo.toml`. | N/A — closed |
| R015 | ~~Native-host byte-order was native-endian and there was no per-action cap on `get_password`~~ | [BITNET-M9] (BitNet-native-host hardening, 2026-06-09) | **CLOSED 2026-06-09**: switched the browser-native-messaging wire format to explicit little-endian (`u32::from_le_bytes` / `u32::to_le_bytes`); added a per-action `MAX_GET_PASSWORD_PER_MIN = 30` sliding-window cap on `get_password` to prevent mass exfiltration within the global `RateLimiter` budget. 3 new unit tests in `bitnet-native-host`. | N/A — closed |

## Future Work
- TPM integration for key protection.
- Windows Hello biometric unlock.
- Hardware security key (FIDO2) as second factor.
