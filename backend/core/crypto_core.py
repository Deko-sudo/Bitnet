# -*- coding: utf-8 -*-
"""
Crypto Core - Cryptographic Core Module

Provides low-level cryptographic operations:
- Key derivation (Argon2id)
- Encryption/Decryption (AES-256-GCM)
- Hashing and HMAC signatures
- Memory protection utilities

Author: Nikita (BE1)
Version: 2.0
"""

import secrets
import hashlib
import hmac
import ctypes
from typing import Optional, Any, Literal, Union

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidTag

from pydantic import SecretStr
from argon2.low_level import hash_secret_raw, Type

from .config import (
    CryptoConfig,
    get_crypto_config,
    RateLimitConfig,
    PasswordStrengthConfig,
)


# =============================================================================
# Exceptions
# =============================================================================


class CryptoError(Exception):
    """Base exception for cryptographic errors."""

    pass


class EncryptionError(CryptoError):
    """Encryption operation failed."""

    pass


class DecryptionError(CryptoError):
    """Decryption operation failed."""

    pass


class AuthenticationError(CryptoError):
    """Authentication failed (wrong HMAC or auth tag)."""

    pass


class KeyDerivationError(CryptoError):
    """Key derivation failed."""

    pass


# =============================================================================
# Memory Protection Utilities — Authoritative zero_memory
# =============================================================================


def zero_memory(data: Union[bytearray, memoryview]) -> None:
    """
    Securely zero sensitive data in memory using ctypes.memset.

    This is the single authoritative implementation. All other modules
    must import this function rather than duplicating it.

    Supports both bytearray and memoryview for flexible buffer handling.

    Args:
        data: bytearray or memoryview to zero (modified in-place)

    Warning:
        CPython's garbage collector does NOT guarantee immediate
        deallocation of the zeroed memory. String interning pools,
        GC generations, and OS pagefiles may retain copies of key
        material. This function is best-effort protection against
        casual memory dumps.

    Example:
        >>> key = bytearray(secret_key)
        >>> # ... use key ...
        >>> zero_memory(key)
    """
    if isinstance(data, memoryview):
        if not data.contiguous:
            raise ValueError("memoryview must be contiguous")
        buf = bytearray(data)
        length = len(buf)
    elif isinstance(data, bytearray):
        length = len(data)
        buf = data
    else:
        raise TypeError(
            "data must be bytearray or memoryview, not " + type(data).__name__
        )

    if length == 0:
        return

    # Overwrite underlying C buffer directly for stronger guarantees.
    buf_type = ctypes.c_char * length
    buf_ref = buf_type.from_buffer(buf)
    ctypes.memset(ctypes.addressof(buf_ref), 0, length)


class MemoryGuard:
    """
    Context manager for automatic memory zeroing.

    Ensures sensitive data is zeroed after use, even if exception occurs.

    Args:
        data: bytearray to protect

    Example:
        >>> with MemoryGuard(bytearray(secret_key)) as key:
        ...     # use key
        ...     process_data(key)
        # key is automatically zeroed here
    """

    def __init__(self, data: bytearray) -> None:
        if not isinstance(data, bytearray):
            raise TypeError("data must be bytearray")
        self._data = data

    def __enter__(self) -> bytearray:
        return self._data

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> Literal[False]:
        zero_memory(self._data)
        return False


# =============================================================================
# CryptoCore Class
# =============================================================================


class CryptoCore:
    """
    Cryptographic Core - main class for all crypto operations.

    Provides:
    - Key derivation using Argon2id
    - Encryption/Decryption using AES-256-GCM
    - HMAC signing and verification
    - Hashing utilities
    - Memory protection

    Thread-safe: All methods are stateless and thread-safe.

    Example:
        >>> config = CryptoConfig()
        >>> crypto = CryptoCore(config)
        >>> salt = crypto.generate_salt()
        >>> master_key = crypto.derive_master_key("password", salt)
        >>> encrypted = crypto.encrypt(b"data", master_key)
        >>> decrypted = crypto.decrypt(encrypted, master_key)
    """

    def __init__(self, config: Optional[CryptoConfig] = None):
        """
        Initialize CryptoCore with configuration.

        Args:
            config: CryptoConfig object. Uses defaults if None.
        """
        self._config = config or get_crypto_config()

    @property
    def config(self) -> CryptoConfig:
        """Get current configuration."""
        return self._config

    # ==========================================================================
    # Key Derivation Methods
    # ==========================================================================

    def generate_salt(self, length: Optional[int] = None) -> bytes:
        """
        Generate cryptographically secure random salt.

        Args:
            length: Salt length in bytes (default: 16 = 128 bits)

        Returns:
            Random bytes of specified length

        Raises:
            ValueError: If length < 8

        Example:
            >>> salt = crypto.generate_salt()  # 16 bytes
            >>> salt = crypto.generate_salt(32)  # 32 bytes
        """
        if length is None:
            length = self._config.argon2_salt_len

        if length < 8:
            raise ValueError("Salt length must be at least 8 bytes")

        return secrets.token_bytes(length)

    def derive_master_key(self, password: Union[SecretStr, str], salt: Union[bytes, bytearray]) -> bytearray:
        """
        Derive master key from password using Argon2id.

        Argon2id is the winner of Password Hashing Competition (2015)
        and recommended by OWASP for password hashing.

        Args:
            password: User master password (Unicode string)
            salt: Salt for derivation (minimum 8 bytes)

        Returns:
            Master key bytes (hash_len bytes, typically 32)

        Raises:
            ValueError: If password is empty or salt too short
            KeyDerivationError: If Argon2 computation fails

        Performance:
            - CPython: ~400-500ms
            - PyPy 7.3+: ~250-350ms (after JIT warmup)

        Example:
            >>> salt = crypto.generate_salt()
            >>> master_key = crypto.derive_master_key("my_password", salt)
        """
        password_str = password.get_secret_value() if isinstance(password, SecretStr) else password
        if not password_str:
            raise ValueError("Password cannot be empty")

        if len(salt) < 8:
            raise ValueError("Salt must be at least 8 bytes")

        password_bytes = bytearray(password_str.encode("utf-8"))
        try:
            key = hash_secret_raw(
                secret=bytes(password_bytes),
                salt=bytes(salt),
                time_cost=self._config.argon2_time_cost,
                memory_cost=self._config.argon2_memory_cost,
                parallelism=self._config.argon2_parallelism,
                hash_len=self._config.argon2_hash_len,
                type=Type.ID,  # Argon2id (hybrid)
            )
            return bytearray(key)
        except Exception as e:
            raise KeyDerivationError(f"Failed to derive key: {e}")
        finally:
            zero_memory(password_bytes)

    def derive_subkey(self, master_key: Union[bytes, bytearray], context: bytes) -> bytearray:
        """
        Derive subkey from master key using HKDF.

        Used to create separate keys for different purposes:
        - Encryption key
        - HMAC key
        - Backup key

        Args:
            master_key: Master key (32 bytes recommended)
            context: Context for key separation (e.g., b"encryption")

        Returns:
            Derived subkey (key_size bytes)

        Raises:
            ValueError: If master_key is too short

        Example:
            >>> encryption_key = crypto.derive_subkey(master_key, b"encryption")
            >>> hmac_key = crypto.derive_subkey(master_key, b"hmac")
        """
        if len(master_key) < 16:
            raise ValueError("Master key must be at least 16 bytes")

        try:
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=self._config.key_size,
                salt=None,
                info=context,
            )
            return bytearray(hkdf.derive(bytes(master_key)))
        except Exception as e:
            raise KeyDerivationError(f"Failed to derive subkey: {e}")

    # ==========================================================================
    # Encryption Methods
    # ==========================================================================

    def encrypt(self, plaintext: Union[bytes, bytearray], key: Union[bytes, bytearray]) -> bytearray:
        """
        Encrypt data using AES-256-GCM.

        AES-GCM is an AEAD (Authenticated Encryption with Associated Data)
        cipher that provides both confidentiality and authenticity.

        Output format: nonce (12 bytes) + auth_tag (16 bytes) + ciphertext

        Args:
            plaintext: Data to encrypt
            key: Encryption key (32 bytes for AES-256)

        Returns:
            Encrypted data (nonce + auth_tag + ciphertext)

        Raises:
            ValueError: If key has wrong length
            EncryptionError: If encryption fails

        Example:
            >>> key = secrets.token_bytes(32)
            >>> encrypted = crypto.encrypt(b"secret data", key)
        """
        if len(key) != self._config.key_size:
            raise ValueError(f"Key must be {self._config.key_size} bytes")

        try:
            aesgcm = AESGCM(bytes(key))
            nonce = secrets.token_bytes(self._config.nonce_size)
            ciphertext = aesgcm.encrypt(nonce, bytes(plaintext), None)
            # Format: nonce + auth_tag (included in ciphertext) + data
            return bytearray(nonce + ciphertext)
        except Exception as e:
            raise EncryptionError(f"Encryption failed: {e}")

    def decrypt(self, ciphertext: Union[bytes, bytearray], key: Union[bytes, bytearray]) -> bytearray:
        """
        Decrypt data using AES-256-GCM.

        Args:
            ciphertext: Encrypted data (nonce + auth_tag + ciphertext)
            key: Decryption key (32 bytes for AES-256)

        Returns:
            Decrypted plaintext

        Raises:
            ValueError: If ciphertext format is invalid
            AuthenticationError: If auth tag doesn't match (tampered data)
            DecryptionError: If decryption fails

        Example:
            >>> decrypted = crypto.decrypt(encrypted, key)
            >>> assert decrypted == b"secret data"
        """
        if len(key) != self._config.key_size:
            raise ValueError(f"Key must be {self._config.key_size} bytes")

        if len(ciphertext) < self._config.nonce_size + self._config.tag_size:
            raise ValueError("Ciphertext too short")

        try:
            aesgcm = AESGCM(bytes(key))
            nonce = ciphertext[: self._config.nonce_size]
            actual_ciphertext = ciphertext[self._config.nonce_size :]
            plaintext = aesgcm.decrypt(bytes(nonce), bytes(actual_ciphertext), None)
            return bytearray(plaintext)
        except InvalidTag:
            raise AuthenticationError("Authentication failed - data may be tampered")
        except Exception as e:
            raise DecryptionError(f"Decryption failed: {e}")

    # ==========================================================================
    # Data Integrity Methods
    # ==========================================================================

    def sign(self, data: bytes, key: bytes) -> bytes:
        """
        Create HMAC-SHA256 signature of data.

        HMAC provides message authentication - verifies both
        data integrity and authenticity.

        Args:
            data: Data to sign
            key: HMAC key (32 bytes recommended)

        Returns:
            HMAC-SHA256 signature (32 bytes)

        Example:
            >>> signature = crypto.sign(b"data", hmac_key)
        """
        return hmac.new(key, data, hashlib.sha256).digest()

    def verify_signature(self, data: bytes, signature: bytes, key: bytes) -> bool:
        """
        Verify HMAC-SHA256 signature.

        Uses constant-time comparison to prevent timing attacks.

        Args:
            data: Original data
            signature: Signature to verify
            key: HMAC key

        Returns:
            True if signature is valid, False otherwise

        Example:
            >>> if crypto.verify_signature(data, signature, key):
            ...     print("Signature valid")
            ... else:
            ...     print("Signature invalid!")
        """
        expected = self.sign(data, key)
        return hmac.compare_digest(expected, signature)

    def hash_file(self, filepath: str) -> str:
        """
        Compute SHA-256 hash of a file.

        Reads file in chunks to handle large files efficiently.

        Args:
            filepath: Path to file

        Returns:
            Hex string of SHA-256 hash (64 characters)

        Raises:
            FileNotFoundError: If file doesn't exist
            IOError: If file cannot be read

        Example:
            >>> file_hash = crypto.hash_file("backup.zip")
            >>> print(f"SHA-256: {file_hash}")
        """
        sha256 = hashlib.sha256()

        with open(filepath, "rb") as f:
            # Read in 8KB chunks
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)

        return sha256.hexdigest()

    # ==========================================================================
    # Random Generation Utilities
    # ==========================================================================

    def generate_random_bytes(self, length: int) -> bytes:
        """
        Generate cryptographically secure random bytes.

        Uses OS CSPRNG (secrets module).

        Args:
            length: Number of bytes

        Returns:
            Random bytes

        Example:
            >>> random_data = crypto.generate_random_bytes(32)
        """
        return secrets.token_bytes(length)

    def generate_token(self, length: int = 32) -> str:
        """
        Generate URL-safe random token.

        Used for:
        - Recovery codes
        - Session tokens
        - API keys

        Args:
            length: Token length in bytes (default 32)

        Returns:
            URL-safe base64-encoded string

        Example:
            >>> token = crypto.generate_token()
            >>> print(token)  # e.g., "abc123xyz..."
        """
        return secrets.token_urlsafe(length)

    # ==========================================================================
    # Constant-Time Comparison
    # ==========================================================================

    @staticmethod
    def constant_time_compare(a: bytes, b: bytes) -> bool:
        """
        Compare two byte strings in constant time.

        Prevents timing attacks by ensuring comparison time
        is independent of where strings differ.

        Args:
            a: First byte string
            b: Second byte string

        Returns:
            True if equal, False otherwise

        Example:
            >>> if CryptoCore.constant_time_compare(hash1, hash2):
            ...     print("Equal")
        """
        return hmac.compare_digest(a, b)


# =============================================================================
# Convenience Functions
# =============================================================================


def quick_encrypt(plaintext: Union[bytes, bytearray], password: Union[str, SecretStr]) -> bytearray:
    """
    Quick encryption with password.

    Convenience function that handles key derivation internally.
    Not recommended for production - use CryptoCore class instead.

    Args:
        plaintext: Data to encrypt
        password: Password for encryption

    Returns:
        Encrypted data (includes salt)
    """
    crypto = CryptoCore()
    salt = crypto.generate_salt()
    key = crypto.derive_master_key(password, salt)
    try:
        encrypted = crypto.encrypt(plaintext, key)
        return bytearray(salt + encrypted)
    finally:
        zero_memory(key)


def quick_decrypt(ciphertext: Union[bytes, bytearray], password: Union[str, SecretStr]) -> bytearray:
    """
    Quick decryption with password.

    Args:
        ciphertext: Encrypted data (salt + encrypted)
        password: Password for decryption

    Returns:
        Decrypted data
    """
    crypto = CryptoCore()
    salt_len = crypto.config.argon2_salt_len
    salt = ciphertext[:salt_len]
    encrypted = ciphertext[salt_len:]
    key = crypto.derive_master_key(password, salt)
    try:
        return crypto.decrypt(encrypted, key)
    finally:
        zero_memory(key)


# =============================================================================
# Module Exports
# =============================================================================

__all__ = [
    # Exceptions
    "CryptoError",
    "EncryptionError",
    "DecryptionError",
    "AuthenticationError",
    "KeyDerivationError",
    # Main class
    "CryptoCore",
    # Memory protection
    "zero_memory",
    "MemoryGuard",
    # Convenience functions
    "quick_encrypt",
    "quick_decrypt",
]
