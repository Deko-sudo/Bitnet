# Security Policy

## Contributor Security Rules

This document defines mandatory security practices for all contributors to this project.
Violation of these rules will result in PR rejection.

---

## 1. No Hand-Rolled Cryptography

**All cryptographic operations MUST use approved libraries only.**

| Approved | Forbidden |
|---|---|
| `cryptography` (AES-GCM, HMAC, HKDF) | Custom AES implementations |
| `argon2-cffi` (key derivation) | PBKDF2 with custom loops |
| `PyNaCl` (additional primitives) | `hashlib` for password hashing |
| `secrets` (CSPRNG) | `random` for any security purpose |
| `hmac` (constant-time compare) | `==` for secret comparison |

**Rationale:** Hand-rolled crypto is the #1 cause of security vulnerabilities in applications. Even experts make subtle mistakes in nonce generation, padding, or timing.

---

## 2. Pydantic Secrets

**All password and key fields in Pydantic models MUST use `SecretStr`.**

```python
# ✅ CORRECT
from pydantic import SecretStr

class UserCreate(BaseModel):
    password: SecretStr

# ❌ WRONG
class UserCreate(BaseModel):
    password: str  # Will appear in logs, repr, error messages
```

**All Pydantic security config models MUST use `frozen=True`.**

```python
# ✅ CORRECT
class CryptoConfig(BaseModel):
    key_size: int = 32
    model_config = {"frozen": True, "extra": "forbid"}

# ❌ WRONG
class CryptoConfig(BaseModel):
    key_size: int = 32  # Mutable — can be changed after construction
```

---

## 3. Key Material in Memory

**All sensitive byte data (keys, passwords, tokens) MUST use `bytearray` — never `bytes` or `str`.**

```python
# ✅ CORRECT
key = bytearray(derived_key)  # Mutable — can be zeroed
zero_memory(key)              # Securely erase

# ❌ WRONG
key = bytes(derived_key)      # Immutable — cannot be zeroed
key = "password"              # String — may be interned, copied by GC
```

**Rationale:** `bytearray` is mutable and can be securely zeroed via `ctypes.memset`. `bytes` and `str` are immutable — Python may retain copies in intern pools or GC generations.

---

## 4. `zero_memory()` Contract

**All key material MUST be zeroed via `zero_memory()` after use.**

```python
# ✅ CORRECT
key = auth.get_master_key()
try:
    encrypted = crypto.encrypt(data, bytes(key))
finally:
    zero_memory(key)

# ❌ WRONG
key = auth.get_master_key()
encrypted = crypto.encrypt(data, bytes(key))
# key is never zeroed — remains in memory until GC
```

### CPython GC Limitation Warning

> `zero_memory()` writes zeros directly to the underlying C buffer of the `bytearray` via `ctypes.memset`.
> However, CPython's garbage collector does **NOT** guarantee immediate deallocation of the memory.
> The following may retain copies of key material:
> - String interning pools (if key was ever converted to `str`)
> - GC generations (young/old generation objects)
> - OS pagefile / hibernation file
> - Copy-on-write page mappings
>
> `zero_memory()` is **best-effort**. It provides stronger guarantees than simple `del`, but does not eliminate all risk of key recovery from memory dumps.
> For maximum security: minimize key lifetime, use auto-lock, and enable full disk encryption.

---

## 5. Zero Plaintext Secrets in Logs

**No plaintext secrets in ANY log output, including `DEBUG` level.**

```python
# ✅ CORRECT
logger.info("User %s logged in", user_id)
logger.debug("Encryption completed for entry %s", entry_id)

# ❌ WRONG
logger.info("Password: %s", password)
logger.debug("Key: %s", key.hex())
logger.debug("Decrypting: %s", entry_data)
```

**The `AuditLogger` sanitizes all event data before logging.** It checks for patterns like `password`, `secret`, `key`, `token`, `auth` in field names and redacts their values. Do not bypass this sanitization.

---

## 6. Code Review Gate for `backend/core/`

**Every PR that modifies files in `backend/core/` requires mandatory code review by Nikita (BE1) before merge.**

- No exceptions — even typo fixes
- Reviewer must verify:
  - No plaintext secrets in code or logs
  - All key material uses `bytearray` + `zero_memory()`
  - All crypto uses approved libraries
  - No new dependencies without security review
  - `bandit` scan passes with zero HIGH findings

---

## 7. Input Validation

**All external input MUST pass through a Pydantic schema before reaching any service layer.**

```python
# ✅ CORRECT
entry_data = EntryCreateSchema(**request_data)
service.create(user_id, entry_data)

# ❌ WRONG
service.create(user_id, request_data)  # Raw dict — no validation
```

---

## 8. Dependency Management

- All dependencies pinned in `requirements.txt` with minimum versions
- Run `safety check` before merging any dependency change
- No new dependencies without security review
- No `git+https://` URLs in production requirements

---

## 9. Reporting Security Issues

If you discover a security vulnerability:

1. **DO NOT** open a public issue
2. Email the security team directly
3. Include: affected file, reproduction steps, severity assessment
4. Wait for response before any public disclosure

---

## 10. Checklist for PR Authors

Before submitting a PR, verify:

- [ ] No `print()` statements with sensitive data
- [ ] No passwords/keys in log messages
- [ ] All new Pydantic models use `SecretStr` for secrets
- [ ] All new config models use `frozen=True`
- [ ] All key material uses `bytearray` + `zero_memory()`
- [ ] No raw SQL with user-supplied data
- [ ] All external input validated through Pydantic schema
- [ ] `bandit -r backend/` passes with zero HIGH findings
- [ ] `mypy --strict` passes with zero errors
- [ ] If touching `backend/core/`: requested review from Nikita (BE1)
