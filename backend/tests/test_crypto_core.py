# -*- coding: utf-8 -*-
"""
Unit Tests for CryptoCore Module

Tests cover:
- Key derivation (Argon2id)
- Encryption/Decryption (AES-256-GCM)
- HMAC signing and verification
- Memory protection utilities
- Random generation

Coverage goal: >95%
"""

import pytest
import secrets
import os
import tempfile

from backend.core.crypto_core import (
    CryptoCore,
    CryptoError,
    EncryptionError,
    DecryptionError,
    AuthenticationError,
    KeyDerivationError,
    zero_memory,
    MemoryGuard,
    quick_encrypt,
    quick_decrypt,
)
from backend.core.config import CryptoConfig


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def crypto():
    """Create CryptoCore instance with default config."""
    return CryptoCore()


@pytest.fixture
def crypto_custom():
    """Create CryptoCore instance with custom config."""
    config = CryptoConfig(
        key_size=32,
        argon2_time_cost=3,
        argon2_memory_cost=65536,
        argon2_parallelism=4,
    )
    return CryptoCore(config)


@pytest.fixture
def sample_key():
    """Generate a sample 256-bit key."""
    return secrets.token_bytes(32)


@pytest.fixture
def sample_password():
    """Sample password for testing."""
    return "test_password_123!@#"


@pytest.fixture
def sample_data():
    """Sample data for encryption."""
    return b"This is secret data for testing encryption."


# =============================================================================
# Test: Key Derivation - generate_salt
# =============================================================================

class TestGenerateSalt:
    """Tests for salt generation."""
    
    def test_generate_salt_default_length(self, crypto):
        """Test salt generation with default length."""
        salt = crypto.generate_salt()
        assert len(salt) == 16  # Default from config
        assert isinstance(salt, bytes)
    
    def test_generate_salt_custom_length(self, crypto):
        """Test salt generation with custom length."""
        salt = crypto.generate_salt(32)
        assert len(salt) == 32
        assert isinstance(salt, bytes)
    
    def test_generate_salt_minimum_length(self, crypto):
        """Test salt generation with minimum length."""
        salt = crypto.generate_salt(8)
        assert len(salt) == 8
    
    def test_generate_salt_too_short(self, crypto):
        """Test that salt < 8 bytes raises error."""
        with pytest.raises(ValueError, match="at least 8 bytes"):
            crypto.generate_salt(4)
    
    def test_generate_salt_uniqueness(self, crypto):
        """Test that generated salts are unique."""
        salts = [crypto.generate_salt() for _ in range(100)]
        # All salts should be unique
        assert len(set(salts)) == 100
    
    def test_generate_salt_randomness(self, crypto):
        """Test salt randomness using entropy check."""
        salt = crypto.generate_salt(32)
        # Check that salt is not all zeros or all same byte
        assert len(set(salt)) > 10  # Should have variety


# =============================================================================
# Test: Key Derivation - derive_master_key
# =============================================================================

class TestDeriveMasterKey:
    """Tests for master key derivation."""
    
    def test_derive_master_key_basic(self, crypto, sample_password):
        """Test basic key derivation."""
        salt = crypto.generate_salt()
        key = crypto.derive_master_key(sample_password, salt)
        assert len(key) == 32
        assert isinstance(key, bytes)
    
    def test_derive_master_key_deterministic(self, crypto, sample_password):
        """Test that same password+salt produces same key."""
        salt = crypto.generate_salt()
        key1 = crypto.derive_master_key(sample_password, salt)
        key2 = crypto.derive_master_key(sample_password, salt)
        assert key1 == key2
    
    def test_derive_master_key_different_salts(self, crypto, sample_password):
        """Test that different salts produce different keys."""
        salt1 = crypto.generate_salt()
        salt2 = crypto.generate_salt()
        key1 = crypto.derive_master_key(sample_password, salt1)
        key2 = crypto.derive_master_key(sample_password, salt2)
        assert key1 != key2
    
    def test_derive_master_key_empty_password(self, crypto):
        """Test that empty password raises error."""
        salt = crypto.generate_salt()
        with pytest.raises(ValueError, match="cannot be empty"):
            crypto.derive_master_key("", salt)
    
    def test_derive_master_key_short_salt(self, crypto, sample_password):
        """Test that salt < 8 bytes raises error."""
        short_salt = secrets.token_bytes(4)
        with pytest.raises(ValueError, match="at least 8 bytes"):
            crypto.derive_master_key(sample_password, short_salt)
    
    def test_derive_master_key_unicode_password(self, crypto):
        """Test key derivation with Unicode password."""
        salt = crypto.generate_salt()
        unicode_password = "пароль_密码🔐"
        key = crypto.derive_master_key(unicode_password, salt)
        assert len(key) == 32


# =============================================================================
# Test: Key Derivation - derive_subkey
# =============================================================================

class TestDeriveSubkey:
    """Tests for subkey derivation."""
    
    def test_derive_subkey_basic(self, crypto, sample_key):
        """Test basic subkey derivation."""
        subkey = crypto.derive_subkey(sample_key, b"encryption")
        assert len(subkey) == 32
        assert isinstance(subkey, bytes)
    
    def test_derive_subkey_different_contexts(self, crypto, sample_key):
        """Test that different contexts produce different subkeys."""
        enc_key = crypto.derive_subkey(sample_key, b"encryption")
        hmac_key = crypto.derive_subkey(sample_key, b"hmac")
        assert enc_key != hmac_key
    
    def test_derive_subkey_deterministic(self, crypto, sample_key):
        """Test subkey derivation is deterministic."""
        subkey1 = crypto.derive_subkey(sample_key, b"context")
        subkey2 = crypto.derive_subkey(sample_key, b"context")
        assert subkey1 == subkey2
    
    def test_derive_subkey_short_master_key(self, crypto):
        """Test that master key < 16 bytes raises error."""
        short_key = secrets.token_bytes(8)
        with pytest.raises(ValueError, match="at least 16 bytes"):
            crypto.derive_subkey(short_key, b"context")


# =============================================================================
# Test: Encryption - encrypt/decrypt
# =============================================================================

class TestEncryptDecrypt:
    """Tests for AES-256-GCM encryption/decryption."""
    
    def test_encrypt_decrypt_basic(self, crypto, sample_key, sample_data):
        """Test basic encrypt-decrypt cycle."""
        encrypted = crypto.encrypt(sample_data, sample_key)
        decrypted = crypto.decrypt(encrypted, sample_key)
        assert decrypted == sample_data
    
    def test_encrypt_output_format(self, crypto, sample_key, sample_data):
        """Test encrypted output includes nonce."""
        encrypted = crypto.encrypt(sample_data, sample_key)
        # Should be: nonce (12) + auth_tag (16) + ciphertext
        assert len(encrypted) > len(sample_data)
        assert len(encrypted) >= 12 + 16  # nonce + auth_tag minimum
    
    def test_encrypt_different_keys(self, crypto, sample_data):
        """Test encryption with different keys."""
        key1 = secrets.token_bytes(32)
        key2 = secrets.token_bytes(32)
        enc1 = crypto.encrypt(sample_data, key1)
        enc2 = crypto.encrypt(sample_data, key2)
        assert enc1 != enc2
    
    def test_decrypt_wrong_key(self, crypto, sample_data):
        """Test decryption with wrong key raises error."""
        key1 = secrets.token_bytes(32)
        key2 = secrets.token_bytes(32)
        encrypted = crypto.encrypt(sample_data, key1)
        with pytest.raises(AuthenticationError):
            crypto.decrypt(encrypted, key2)
    
    def test_decrypt_tampered_data(self, crypto, sample_key, sample_data):
        """Test decryption of tampered data raises error."""
        encrypted = crypto.encrypt(sample_data, sample_key)
        # Tamper with the ciphertext
        tampered = bytearray(encrypted)
        tampered[5] ^= 0xFF  # Flip bits
        with pytest.raises(AuthenticationError):
            crypto.decrypt(bytes(tampered), sample_key)
    
    def test_decrypt_invalid_ciphertext_short(self, crypto, sample_key):
        """Test decryption of too-short ciphertext."""
        short_data = secrets.token_bytes(10)
        with pytest.raises(ValueError, match="too short"):
            crypto.decrypt(short_data, sample_key)
    
    def test_encrypt_wrong_key_size(self, crypto, sample_data):
        """Test encryption with wrong key size."""
        wrong_key = secrets.token_bytes(16)  # 128 bits instead of 256
        with pytest.raises(ValueError, match="must be"):
            crypto.encrypt(sample_data, wrong_key)
    
    def test_decrypt_wrong_key_size(self, crypto):
        """Test decryption with wrong key size."""
        wrong_key = secrets.token_bytes(16)
        with pytest.raises(ValueError, match="must be"):
            crypto.decrypt(b"some_data", wrong_key)
    
    def test_encrypt_empty_data(self, crypto, sample_key):
        """Test encryption of empty data."""
        encrypted = crypto.encrypt(b"", sample_key)
        decrypted = crypto.decrypt(encrypted, sample_key)
        assert decrypted == b""
    
    def test_encrypt_large_data(self, crypto, sample_key):
        """Test encryption of large data."""
        large_data = secrets.token_bytes(1024 * 1024)  # 1 MB
        encrypted = crypto.encrypt(large_data, sample_key)
        decrypted = crypto.decrypt(encrypted, sample_key)
        assert decrypted == large_data


# =============================================================================
# Test: HMAC - sign/verify_signature
# =============================================================================

class TestHMACSignature:
    """Tests for HMAC-SHA256 signing."""
    
    def test_sign_basic(self, crypto, sample_key):
        """Test basic signing."""
        data = b"test data"
        signature = crypto.sign(data, sample_key)
        assert len(signature) == 32  # SHA-256 output
        assert isinstance(signature, bytes)
    
    def test_verify_signature_valid(self, crypto, sample_key):
        """Test verification of valid signature."""
        data = b"test data"
        signature = crypto.sign(data, sample_key)
        assert crypto.verify_signature(data, signature, sample_key) is True
    
    def test_verify_signature_invalid(self, crypto, sample_key):
        """Test verification of invalid signature."""
        data = b"test data"
        wrong_signature = secrets.token_bytes(32)
        assert crypto.verify_signature(data, wrong_signature, sample_key) is False
    
    def test_verify_signature_tampered_data(self, crypto, sample_key):
        """Test verification with tampered data."""
        data = b"test data"
        signature = crypto.sign(data, sample_key)
        tampered_data = b"tampered data"
        assert crypto.verify_signature(tampered_data, signature, sample_key) is False
    
    def test_verify_signature_wrong_key(self, crypto, sample_key):
        """Test verification with wrong key."""
        data = b"test data"
        signature = crypto.sign(data, sample_key)
        wrong_key = secrets.token_bytes(32)
        assert crypto.verify_signature(data, signature, wrong_key) is False
    
    def test_sign_deterministic(self, crypto, sample_key):
        """Test signing is deterministic."""
        data = b"test data"
        sig1 = crypto.sign(data, sample_key)
        sig2 = crypto.sign(data, sample_key)
        assert sig1 == sig2


# =============================================================================
# Test: Hash File
# =============================================================================

class TestHashFile:
    """Tests for file hashing."""
    
    def test_hash_file_basic(self, crypto):
        """Test basic file hashing."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test content")
            temp_path = f.name
        
        try:
            file_hash = crypto.hash_file(temp_path)
            assert len(file_hash) == 64  # SHA-256 hex = 64 chars
            assert all(c in '0123456789abcdef' for c in file_hash)
        finally:
            os.unlink(temp_path)
    
    def test_hash_file_same_content(self, crypto):
        """Test same content produces same hash."""
        with tempfile.NamedTemporaryFile(delete=False) as f1:
            f1.write(b"test content")
            path1 = f1.name
        
        with tempfile.NamedTemporaryFile(delete=False) as f2:
            f2.write(b"test content")
            path2 = f2.name
        
        try:
            hash1 = crypto.hash_file(path1)
            hash2 = crypto.hash_file(path2)
            assert hash1 == hash2
        finally:
            os.unlink(path1)
            os.unlink(path2)
    
    def test_hash_file_different_content(self, crypto):
        """Test different content produces different hash."""
        with tempfile.NamedTemporaryFile(delete=False) as f1:
            f1.write(b"content 1")
            path1 = f1.name
        
        with tempfile.NamedTemporaryFile(delete=False) as f2:
            f2.write(b"content 2")
            path2 = f2.name
        
        try:
            hash1 = crypto.hash_file(path1)
            hash2 = crypto.hash_file(path2)
            assert hash1 != hash2
        finally:
            os.unlink(path1)
            os.unlink(path2)
    
    def test_hash_file_not_found(self, crypto):
        """Test hashing non-existent file."""
        with pytest.raises(FileNotFoundError):
            crypto.hash_file("/nonexistent/file.txt")


# =============================================================================
# Test: Memory Protection - zero_memory
# =============================================================================

class TestZeroMemory:
    """Tests for memory zeroing."""
    
    def test_zero_memory_basic(self):
        """Test basic memory zeroing."""
        data = bytearray(b"secret data")
        zero_memory(data)
        assert data == bytearray(len(data))
    
    def test_zero_memory_all_zeros(self):
        """Test zeroing already-zero data."""
        data = bytearray(16)
        zero_memory(data)
        assert data == bytearray(16)
    
    def test_zero_memory_not_bytearray(self):
        """Test zeroing bytes raises error."""
        with pytest.raises(TypeError, match="must be bytearray"):
            zero_memory(b"immutable bytes")
    
    def test_zero_memory_length(self):
        """Test zeroing various lengths."""
        for length in [1, 8, 32, 1024]:
            data = bytearray(secrets.token_bytes(length))
            zero_memory(data)
            assert data == bytearray(length)


# =============================================================================
# Test: Memory Protection - MemoryGuard
# =============================================================================

class TestMemoryGuard:
    """Tests for MemoryGuard context manager."""
    
    def test_memory_guard_basic(self):
        """Test basic MemoryGuard usage."""
        data = bytearray(b"secret")
        with MemoryGuard(data) as guarded:
            assert guarded == data
        # After context, data should be zeroed
        assert data == bytearray(len(data))
    
    def test_memory_guard_exception(self):
        """Test MemoryGuard zeros memory even on exception."""
        data = bytearray(b"secret")
        try:
            with MemoryGuard(data):
                raise ValueError("Test exception")
        except ValueError:
            pass
        # Data should still be zeroed
        assert data == bytearray(len(data))
    
    def test_memory_guard_not_bytearray(self):
        """Test MemoryGuard with non-bytearray raises error."""
        with pytest.raises(TypeError, match="must be bytearray"):
            with MemoryGuard(b"immutable"):
                pass


# =============================================================================
# Test: Random Generation
# =============================================================================

class TestRandomGeneration:
    """Tests for random generation utilities."""
    
    def test_generate_random_bytes(self, crypto):
        """Test random bytes generation."""
        random_bytes = crypto.generate_random_bytes(32)
        assert len(random_bytes) == 32
        assert isinstance(random_bytes, bytes)
    
    def test_generate_random_bytes_uniqueness(self, crypto):
        """Test generated bytes are unique."""
        bytes_list = [crypto.generate_random_bytes(16) for _ in range(100)]
        assert len(set(bytes_list)) == 100
    
    def test_generate_token(self, crypto):
        """Test URL-safe token generation."""
        token = crypto.generate_token()
        assert len(token) >= 32
        # URL-safe base64 should only contain these chars
        valid_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_')
        assert all(c in valid_chars for c in token)
    
    def test_generate_token_custom_length(self, crypto):
        """Test token with custom length."""
        token = crypto.generate_token(64)
        assert len(token) >= 64


# =============================================================================
# Test: Constant-Time Compare
# =============================================================================

class TestConstantTimeCompare:
    """Tests for constant-time comparison."""
    
    def test_constant_time_compare_equal(self):
        """Test comparison of equal values."""
        data = b"test data"
        assert CryptoCore.constant_time_compare(data, data) is True
    
    def test_constant_time_compare_different(self):
        """Test comparison of different values."""
        a = b"data a"
        b_data = b"data b"
        assert CryptoCore.constant_time_compare(a, b_data) is False
    
    def test_constant_time_compare_different_length(self):
        """Test comparison of different lengths."""
        a = b"short"
        b_data = b"much longer data"
        assert CryptoCore.constant_time_compare(a, b_data) is False


# =============================================================================
# Test: Convenience Functions
# =============================================================================

class TestConvenienceFunctions:
    """Tests for quick_encrypt/quick_decrypt."""
    
    def test_quick_encrypt_decrypt(self):
        """Test basic quick encrypt-decrypt cycle."""
        password = "test_password"
        data = b"secret data"
        encrypted = quick_encrypt(data, password)
        decrypted = quick_decrypt(encrypted, password)
        assert decrypted == data
    
    def test_quick_encrypt_includes_salt(self):
        """Test that quick_encrypt includes salt."""
        password = "test_password"
        encrypted = quick_encrypt(b"data", password)
        # Should include 16-byte salt
        assert len(encrypted) > 16
    
    def test_quick_decrypt_wrong_password(self):
        """Test quick_decrypt with wrong password."""
        password1 = "password1"
        password2 = "password2"
        encrypted = quick_encrypt(b"data", password1)
        # Wrong password should raise AuthenticationError
        with pytest.raises(AuthenticationError):
            quick_decrypt(encrypted, password2)


# =============================================================================
# Test: Configuration
# =============================================================================

class TestConfiguration:
    """Tests for CryptoCore configuration."""
    
    def test_default_config(self):
        """Test default configuration values."""
        crypto = CryptoCore()
        config = crypto.config
        assert config.key_size == 32
        assert config.nonce_size == 12
        assert config.argon2_time_cost == 3
        assert config.argon2_memory_cost == 65536
    
    def test_custom_config(self):
        """Test custom configuration."""
        config = CryptoConfig(
            key_size=32,
            argon2_time_cost=2,
            argon2_memory_cost=65536,  # Must be >= 64MB per OWASP
        )
        crypto = CryptoCore(config)
        assert crypto.config.argon2_time_cost == 2
        assert crypto.config.argon2_memory_cost == 65536


# =============================================================================
# Test: Exception Handling
# =============================================================================

class TestExceptions:
    """Tests for exception types."""
    
    def test_crypto_error_base(self):
        """Test CryptoError is base exception."""
        assert issubclass(EncryptionError, CryptoError)
        assert issubclass(DecryptionError, CryptoError)
        assert issubclass(AuthenticationError, CryptoError)
        assert issubclass(KeyDerivationError, CryptoError)


# =============================================================================
# Integration Tests
# =============================================================================

class TestIntegration:
    """Integration tests for complete workflows."""
    
    def test_full_workflow(self, crypto, sample_password):
        """Test complete encryption workflow."""
        # 1. Generate salt
        salt = crypto.generate_salt()
        
        # 2. Derive master key
        master_key = crypto.derive_master_key(sample_password, salt)
        
        # 3. Derive subkeys
        enc_key = crypto.derive_subkey(master_key, b"encryption")
        hmac_key = crypto.derive_subkey(master_key, b"hmac")
        
        # 4. Encrypt data
        plaintext = b"Top secret message!"
        ciphertext = crypto.encrypt(plaintext, enc_key)
        
        # 5. Sign ciphertext
        signature = crypto.sign(ciphertext, hmac_key)
        
        # 6. Verify signature
        assert crypto.verify_signature(ciphertext, signature, hmac_key)
        
        # 7. Decrypt
        decrypted = crypto.decrypt(ciphertext, enc_key)
        assert decrypted == plaintext
        
        # 8. Zero sensitive data
        zero_memory(bytearray(master_key))
        zero_memory(bytearray(enc_key))
        zero_memory(bytearray(hmac_key))
    
    def test_multiple_encryptions_same_key(self, crypto, sample_key):
        """Test multiple encryptions with same key produce different output."""
        plaintext = b"same message"
        ciphertexts = [crypto.encrypt(plaintext, sample_key) for _ in range(10)]
        # All should be different (random nonce)
        assert len(set(ciphertexts)) == 10
        
        # But all should decrypt to same plaintext
        for ct in ciphertexts:
            assert crypto.decrypt(ct, sample_key) == plaintext
