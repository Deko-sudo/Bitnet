# Cryptographic Algorithm Selection Rationale

**Version:** 2.0  
**Date:** April 2026  
**Author:** Nikita (BE1)

---

## 1. AES-256-GCM

### Why chosen
AES-256 in Galois/Counter Mode provides authenticated encryption (AEAD) — confidentiality and integrity in a single operation. It is the industry standard for data-at-rest encryption, used in TLS 1.3, disk encryption, and password managers (KeePassXC, Bitwarden).

### What it protects against
- **Confidentiality:** Prevents reading password data without the master key
- **Integrity:** Detects any tampering with ciphertext (authentication tag)
- **Nonce misuse resistance:** 12-byte random nonces make collisions astronomically unlikely (2^96 space)
- **Quantum resistance:** 256-bit key provides 128-bit security against Grover's algorithm

### Parameter values
| Parameter | Value | Justification |
|---|---|---|
| Key size | 32 bytes (256-bit) | Maximum AES key size; 128-bit post-quantum security |
| Nonce size | 12 bytes (96-bit) | NIST SP 800-38D recommended for GCM |
| Auth tag | 16 bytes (128-bit) | Full tag length; truncation reduces security margin |

### CPython vs PyPy performance
- **CPython:** Uses `cryptography` library which calls OpenSSL C implementation. Hardware AES-NI instructions provide 3-5x speedup on modern CPUs. ~0.1ms per encrypt/decrypt cycle.
- **PyPy 7.3+:** Same C library calls — no JIT benefit since crypto is in C extensions. Performance identical to CPython within ±5%.
- **Note:** For CPU-bound bulk operations (import/export of 1000+ entries), PyPy's JIT may help with Python-level overhead (JSON serialization, loop iteration) but not the crypto itself.

---

## 2. Argon2id

### Why chosen
Argon2id won the Password Hashing Competition (2015) and is recommended by OWASP for password storage and key derivation. The hybrid mode combines Argon2i's side-channel resistance with Argon2d's GPU/ASIC resistance.

### What it protects against
- **Brute-force attacks:** Deliberately slow (~400ms per derivation) makes guessing impractical
- **GPU/ASIC attacks:** 64MB memory cost makes parallel hardware attacks expensive
- **Side-channel attacks:** Argon2i phase protects against cache-timing attacks
- **Rainbow tables:** Unique 16-byte salt per user prevents precomputation

### Parameter values
| Parameter | Value | Justification |
|---|---|---|
| Time cost | 3 iterations | OWASP recommended minimum for interactive login |
| Memory cost | 65536 KB (64 MB) | OWASP recommended; balances security vs. memory usage |
| Parallelism | 4 threads | Matches typical desktop CPU core count |
| Hash length | 32 bytes (256-bit) | Matches AES-256 key size |
| Salt length | 16 bytes (128-bit) | Sufficient to prevent collisions (2^128 space) |

### CPython vs PyPy performance
- **CPython:** ~400-500ms per derivation with default parameters. The `argon2-cffi` library uses the reference C implementation — no Python overhead in the hot path.
- **PyPy 7.3+:** ~250-350ms after JIT warmup. The C library call is identical, but Python-level wrapper code (parameter validation, encoding) benefits from JIT compilation.
- **Note:** The deliberate slowness is a security feature, not a bug. Reducing parameters to improve performance weakens brute-force resistance.

---

## 3. HMAC-SHA256

### Why chosen
HMAC-SHA256 provides message authentication codes for data integrity verification. It is a NIST standard (FIPS 198-1) and is used for signing audit log entries and verifying data integrity.

### What it protects against
- **Data tampering:** Detects any modification of signed data
- **Replay attacks:** Unique keys per context prevent signature reuse
- **Length extension attacks:** HMAC construction is immune (unlike raw SHA-256)

### Parameter values
| Parameter | Value | Justification |
|---|---|---|
| Hash function | SHA-256 | NIST FIPS 180-4; 256-bit output |
| Key size | 32 bytes (256-bit) | Derived from master key via HKDF |
| Output size | 32 bytes (256-bit) | Full HMAC output; no truncation |

### CPython vs PyPy performance
- **CPython:** Uses Python's built-in `hmac` module (C implementation). ~0.01ms per operation.
- **PyPy 7.3+:** Identical performance — `hmac` module is C-based, no JIT benefit.
- **Note:** HMAC is not a performance bottleneck. Both interpreters handle millions of operations per second.

---

## 4. HKDF (HMAC-based Key Derivation Function)

### Why chosen
HKDF (RFC 5869) derives multiple independent subkeys from a single master key. Each subsystem (encryption, signing, export) gets its own subkey with a unique context string, preventing key reuse across purposes.

### What it protects against
- **Key separation:** Prevents a key used for encryption from being reused for signing
- **Context binding:** Each subkey is bound to its purpose via the `info` parameter
- **Master key isolation:** Compromise of a subkey does not reveal the master key

### Parameter values
| Parameter | Value | Justification |
|---|---|---|
| Hash function | SHA-256 | Matches HMAC-SHA256; consistent security level |
| Output length | 32 bytes (256-bit) | Matches AES-256 key size |
| Salt | Master key | Derives subkeys from master |
| Info | Context string (e.g., `b"encryption"`) | Binds subkey to specific purpose |

### CPython vs PyPy performance
- **CPython:** Uses `cryptography` library's HKDF implementation (C-based). ~0.01ms per derivation.
- **PyPy 7.3+:** Identical performance — C library call, no JIT benefit.
- **Note:** HKDF is called once per operation, not in tight loops. Performance is negligible.

---

## 5. Algorithm Comparison Matrix

| Algorithm | Security | Performance (CPython) | Performance (PyPy) | Standard | Status |
|---|---|---|---|---|---|
| **AES-256-GCM** | 5/5 | 5/5 (AES-NI) | 5/5 (AES-NI) | NIST SP 800-38D | Primary |
| ChaCha20-Poly1305 | 5/5 | 4/5 (no AES-NI needed) | 4/5 | RFC 8439 | Alternative |
| **Argon2id** | 5/5 | 3/5 (deliberately slow) | 4/5 (JIT helps wrapper) | RFC 9106 | Primary |
| bcrypt | 4/5 | 3/5 | 3/5 | — | Alternative |
| PBKDF2 | 3/5 | 4/5 | 4/5 | NIST SP 800-132 | Deprecated |
| **HMAC-SHA256** | 5/5 | 5/5 | 5/5 | FIPS 198-1 | Primary |
| **HKDF-SHA256** | 5/5 | 5/5 | 5/5 | RFC 5869 | Primary |

---

## 6. Security Configuration

### Pydantic Config Model

```python
from pydantic import BaseModel, Field, field_validator
from typing import Literal

class CryptoConfig(BaseModel):
    """Cryptographic parameter configuration."""

    # AES-GCM
    key_size: int = Field(default=32, ge=16, le=64)
    nonce_size: int = Field(default=12, ge=12, le=16)

    # Argon2id
    argon2_time_cost: int = Field(default=3, ge=1)
    argon2_memory_cost: int = Field(default=65536, ge=1024)
    argon2_parallelism: int = Field(default=4, ge=1)
    argon2_hash_len: int = Field(default=32, ge=16)
    argon2_salt_len: int = Field(default=16, ge=8)

    # HMAC
    hmac_algorithm: Literal["sha256", "sha384", "sha512"] = "sha256"

    model_config = {"frozen": True, "extra": "forbid"}

    @field_validator("argon2_memory_cost")
    @classmethod
    def validate_memory_cost(cls, v: int) -> int:
        if v < 65536:
            raise ValueError("argon2_memory_cost must be >= 64MB (OWASP minimum)")
        return v
```

---

## 7. Dependency Versions

| Library | Minimum Version | Purpose |
|---|---|---|
| `cryptography` | 41.0.0 | AES-GCM, HMAC, HKDF |
| `argon2-cffi` | 23.1.0 | Argon2id key derivation |
| `PyNaCl` | 1.5.0 | Additional primitives (optional) |

---

## 8. Post-Quantum Considerations

- **AES-256:** Resistant to Grover's algorithm (256-bit key → 128-bit post-quantum security). No immediate migration needed.
- **Argon2id:** Memory-hard function remains effective against quantum attacks.
- **SHA-256:** 256-bit output provides 128-bit collision resistance against quantum attacks.
- **HMAC-SHA256:** Security reduces to 128-bit against quantum adversaries — still secure.
- **Future:** Monitor NIST PQC standardization (ML-KEM, ML-DSA). Consider hybrid schemes when standards mature.

---

**Approved by:** Nikita (BE1) — Security Architect  
**Date:** April 2026
