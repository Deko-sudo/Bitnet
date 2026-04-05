# Threat Model v1.0

**Date:** April 2026  
**Author:** Nikita (BE1)  
**Scope:** Local Windows password manager — all data encrypted on disk, no cloud.

---

## 1. Assets

| Asset | Sensitivity | Location | Protection |
|---|---|---|---|
| Master password | CRITICAL | User memory (ephemeral) | Argon2id derivation, zero_memory(), per-request lifecycle |
| Master key (32-byte) | CRITICAL | RAM (ephemeral, per-operation) | bytearray + ctypes.memset zeroing, MemoryGuard |
| Password entries (plaintext) | CRITICAL | RAM (per-decrypt operation) | MemoryGuard, zeroed after use |
| Password entries (encrypted) | HIGH | SQLite file on disk | AES-256-GCM with unique nonce per entry |
| Argon2 salt | MEDIUM | SQLite file (stored with user record) | Non-secret, but unique per user |
| Audit log | MEDIUM | SQLite file (separate table) | No sensitive data stored (sanitized) |
| HIBP API key | HIGH | Environment variable | Never logged, never stored in code |
| TOTP secret | HIGH | User's authenticator app | Stored as base32, not in database |
| Recovery codes | HIGH | User's secure storage | Stored as SHA-256 hashes, one-time use |

---

## 2. Attackers & Capabilities

| Attacker | Capability | Goal |
|---|---|---|
| **Casual user** | Physical access to unlocked machine | Read passwords from open session |
| **Local attacker** | Access to running process, can read disk | Extract master key from RAM or SQLite file |
| **Sophisticated attacker** | Memory dump tools, forensic analysis | Extract keys from RAM dump, hibernation file, or pagefile |
| **Network attacker** | Can intercept HIBP API calls | Learn which passwords or emails are being checked |
| **Supply chain attacker** | Compromised Python package | Execute arbitrary code, exfiltrate keys |
| **Malicious insider** | Access to source code repository | Introduce backdoor in crypto code |

---

## 3. Attack Scenarios

### Scenario 1: Disk Image Extraction of SQLite File

**Attack:** Attacker obtains a copy of the SQLite database file (via disk imaging, backup theft, or file theft) and attempts to extract password data.

**Attack path:**
1. Obtain `passwords.db` from disk
2. Read `_cipher` fields (hex-encoded AES-256-GCM ciphertext)
3. Attempt brute-force of master key or offline decryption

**Mitigations:**
- All sensitive fields encrypted with AES-256-GCM (AEAD — authenticated encryption)
- 256-bit key requires 2^128 operations to brute-force (Grover's algorithm reduces to 2^128, still infeasible)
- Argon2id key derivation with 64MB memory cost makes each guess ~400ms
- Nonces are unique per entry (12-byte random)

**Residual risk:** LOW — AES-256-GCM is computationally infeasible to break without the master key.

---

### Scenario 2: RAM Dump During Unlocked Session

**Attack:** Attacker with local access dumps process memory while the password manager is unlocked and running.

**Attack path:**
1. Use tool (e.g., `winpmem`, `DumpIt`) to capture process memory
2. Search memory dump for 32-byte master key or decrypted passwords
3. Use recovered key to decrypt SQLite data

**Mitigations:**
- Master key is stored as `bytearray` and zeroed via `ctypes.memset` after each use
- Ephemeral key mode: key is derived per-request, not stored for session duration
- `MemoryGuard` context manager ensures zeroing even on exception paths
- Auto-lock timer clears key material after inactivity

**Residual risk:** MEDIUM — CPython GC does not guarantee immediate deallocation. String interning, copy-on-write, or OS pagefile may retain copies. `zero_memory()` is best-effort. Mitigation: minimize session duration, use auto-lock.

---

### Scenario 3: Brute-Force of Master Password

**Attack:** Attacker obtains the SQLite file and attempts to guess the master password by deriving keys and testing decryption.

**Attack path:**
1. Obtain SQLite file with encrypted entries
2. For each password guess: derive key via Argon2id, attempt decryption
3. Check if decryption succeeds (valid AES-GCM tag)

**Mitigations:**
- Argon2id with time_cost=3, memory_cost=64MB, parallelism=4 — each guess takes ~400ms
- At 400ms/guess: 2.5 guesses/second, 150 guesses/minute, 9,000 guesses/hour
- 8-character random password (95^8 ≈ 6.6×10^15 combinations) would take ~83 billion years
- Rate limiter on login endpoint (5 attempts, then 30-minute block)

**Residual risk:** LOW for strong passwords. MEDIUM for weak passwords (<8 chars, dictionary words). Mitigation: enforce minimum 12 characters with mixed case, digits, and special characters.

---

### Scenario 4: Malicious Import File (CSV/JSON/KDBX)

**Attack:** Attacker provides a crafted import file that exploits parsing vulnerabilities or injects malicious data.

**Attack path:**
1. User imports a malicious CSV/JSON file
2. Parser crashes or executes arbitrary code (e.g., via JSON deserialization attack)
3. Malicious entries overwrite or corrupt existing data

**Mitigations:**
- All imported data validated through Pydantic schemas before processing
- File size limit: 10MB maximum
- Entry count limit: 1,000 entries maximum per import
- CSV import uses Python's built-in `csv` module (no code execution)
- JSON import uses `json.loads()` (safe — no `eval()` or `pickle`)
- Path traversal protection on import/export file paths
- KDBX import deferred to Sprint 7+ (not yet implemented)

**Residual risk:** LOW — standard library parsers are safe, Pydantic validation prevents malformed data.

---

### Scenario 5: Compromised Python Dependency

**Attack:** A Python package in `requirements.txt` is compromised (supply chain attack) and exfiltrates master keys or passwords.

**Attack path:**
1. Attacker compromises `cryptography`, `argon2-cffi`, or another dependency
2. Malicious code captures master key during derivation or encryption
3. Key is exfiltrated via network call

**Mitigations:**
- Minimal dependency surface: only `cryptography`, `argon2-cffi`, `PyNaCl`, `fastapi`, `sqlalchemy`, `pydantic`
- All dependencies pinned to specific minimum versions
- `safety check` in CI pipeline detects known vulnerable packages
- No network calls at runtime (except optional HIBP checks)
- Master key is ephemeral — derived per-request, zeroed after use
- Code review mandatory for any dependency changes

**Residual risk:** MEDIUM — supply chain attacks are difficult to fully mitigate. Mitigation: pin versions, monitor CVEs, use `safety check`, review dependency changes.

---

### Scenario 6: OS Hibernation / Pagefile Extraction

**Attack:** Attacker obtains the Windows hibernation file (`hiberfil.sys`) or pagefile (`pagefile.sys`) and extracts key material from swapped-out memory pages.

**Attack path:**
1. Obtain `hiberfil.sys` or `pagefile.sys` from disk
2. Search for master key or decrypted password data
3. Use recovered key to decrypt SQLite database

**Mitigations:**
- Ephemeral key mode minimizes key lifetime in RAM
- `zero_memory()` clears key material before it can be swapped
- Auto-lock timer reduces window of exposure
- Windows BitLocker encryption of system drive protects hibernation file

**Residual risk:** MEDIUM — OS-level memory management is outside application control. Full disk encryption (BitLocker) is recommended.

---

### Scenario 7: Timing Attack on Password Verification

**Attack:** Attacker measures response time of login attempts to determine correct password character-by-character.

**Attack path:**
1. Send many login requests with different passwords
2. Measure response time for each attempt
3. Use timing differences to infer correct password

**Mitigations:**
- Argon2id derivation time is deliberately variable (400ms ± 50ms) — masks timing differences
- `hmac.compare_digest()` used for all secret comparisons (constant-time)
- Rate limiter blocks after 5 failed attempts

**Residual risk:** LOW — Argon2id timing variance dominates any timing signal from comparison.

---

## 4. Mitigations Summary

| Threat | Primary Mitigation | Secondary Mitigation |
|---|---|---|
| Disk extraction | AES-256-GCM field-level encryption | Argon2id key derivation (400ms/guess) |
| RAM dump | Ephemeral key mode + zero_memory() | MemoryGuard context manager |
| Brute-force | Argon2id (64MB memory cost) | Rate limiter + password strength policy |
| Malicious import | Pydantic validation + file size limits | Standard library parsers only |
| Supply chain | Minimal dependencies + safety check | Pinned versions + code review |
| Hibernation file | Ephemeral key mode | Recommend BitLocker |
| Timing attack | Argon2id timing variance | hmac.compare_digest() |

---

## 5. Residual Risks

| Risk | Severity | Acceptance |
|---|---|---|
| CPython GC may retain copies of key material in memory | MEDIUM | Accepted — `zero_memory()` is best-effort; mitigated by ephemeral key mode |
| SSD wear-leveling may retain deleted data | MEDIUM | Accepted — field-level encryption protects data; secure deletion is best-effort on SSDs |
| Windows pagefile/hibernation file may contain key material | MEDIUM | Accepted — recommend full disk encryption (BitLocker) |
| Supply chain attack on dependency | MEDIUM | Accepted — mitigated by minimal dependencies, safety check, pinned versions |
| Master password sent in HTTP header (X-Master-Password) | LOW | Accepted — local-only application, no network traffic; header not logged by default |
| Double-hash pattern (Argon2 → SHA-256) for login | LOW | Accepted — doesn't reduce security, only adds negligible overhead |

---

## 6. Recommendations

1. **Enable Windows BitLocker** — protects hibernation file and pagefile
2. **Use strong master password** — minimum 12 characters, mixed case, digits, special characters
3. **Enable auto-lock** — default 5 minutes, reduce for high-security environments
4. **Keep dependencies updated** — run `safety check` regularly
5. **Review audit logs** — check `AuditLog` table for suspicious activity
6. **Backup encrypted database** — SQLite file can be safely backed up (data remains encrypted)
