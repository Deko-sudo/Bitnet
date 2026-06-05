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

## Future Work
- TPM integration for key protection.
- Windows Hello biometric unlock.
- Hardware security key (FIDO2) as second factor.
