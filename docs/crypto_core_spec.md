# crypto_core.py Specification

## Module Purpose

The crypto_core.py module provides:
- Key derivation from password (Argon2id)
- Data encryption/decryption (AES-256-GCM)
- Hashing and HMAC signatures
- Memory protection utilities

## CryptoCore Class

### Constructor
```python
class CryptoCore:
    def __init__(self, config: CryptoConfig)
```

### Key Derivation Methods

#### generate_salt()
```python
def generate_salt(self, length: int = 16) -> bytes:
    """Generate cryptographically secure salt."""
```

#### derive_master_key()
```python
def derive_master_key(self, password: str, salt: bytes) -> bytes:
    """Derive master key from password using Argon2id."""
```

#### derive_subkey()
```python
def derive_subkey(self, master_key: bytes, context: bytes) -> bytes:
    """Derive subkey from master key using HKDF."""
```

### Encryption Methods

#### encrypt()
```python
def encrypt(self, plaintext: bytes, key: bytes) -> bytes:
    """Encrypt data using AES-256-GCM."""
```

#### decrypt()
```python
def decrypt(self, ciphertext: bytes, key: bytes) -> bytes:
    """Decrypt data using AES-256-GCM."""
```

### Data Integrity Methods

#### sign()
```python
def sign(self, data: bytes, key: bytes) -> bytes:
    """Create HMAC signature of data."""
```

#### verify_signature()
```python
def verify_signature(self, data: bytes, signature: bytes, key: bytes) -> bool:
    """Verify HMAC signature using constant-time comparison."""
```

### Memory Protection Methods

#### zero_memory()
```python
def zero_memory(self, data: bytearray) -> None:
    """Securely zero sensitive data in memory."""
```

#### generate_random_bytes()
```python
def generate_random_bytes(self, length: int) -> bytes:
    """Generate cryptographically secure random bytes."""
```

#### generate_token()
```python
def generate_token(self, length: int = 32) -> str:
    """Generate URL-safe token."""
```

## Exceptions

- CryptoError (base)
- EncryptionError
- AuthenticationError

## Usage Example

```python
from backend.core.crypto_core import CryptoCore
from backend.core.config import CryptoConfig

config = CryptoConfig()
crypto = CryptoCore(config)

# Key derivation
salt = crypto.generate_salt()
master_key = crypto.derive_master_key(password, salt)

# Encryption
encrypted = crypto.encrypt(data, master_key)
decrypted = crypto.decrypt(encrypted, master_key)

# Zero the key
crypto.zero_memory(bytearray(master_key))
```
