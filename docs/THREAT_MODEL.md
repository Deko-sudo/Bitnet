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

## ASVS Mapping (OWASP ASVS 4.0)

| ASVS ID | Requirement | Status |
|---------|-------------|--------|
| V2.1.1 | Strong password policy | Implemented via Argon2id |
| V6.2.1 | Cryptographic modules | AES-256-GCM, SHA-256, HMAC-SHA-256 |
| V6.2.3 | Approved algorithms | Argon2id (PHC winner) |
| V8.2.1 | Sensitive data protection | Zeroize, auto-lock |
| V8.2.3 | Memory cleanup | Zeroizing on lock |

## Future Work
- TPM integration for key protection.
- Windows Hello biometric unlock.
- Hardware security key (FIDO2) as second factor.
