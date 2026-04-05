# -*- coding: utf-8 -*-
"""
Performance Benchmarks for CryptoCore

Benchmarks compare:
- Key derivation (Argon2id) performance
- Encryption/Decryption throughput
- Memory protection overhead

Run with: pytest --benchmark-only backend/tests/test_benchmarks.py
"""

import pytest
import secrets
import time

from backend.core.crypto_core import CryptoCore, zero_memory
from backend.core.config import CryptoConfig


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def crypto():
    """Create CryptoCore instance."""
    return CryptoCore()


@pytest.fixture
def sample_password():
    """Sample password for benchmarks."""
    return "benchmark_password_123!@#"


@pytest.fixture
def sample_salt():
    """Pre-generated salt for consistent benchmarks."""
    return secrets.token_bytes(16)


@pytest.fixture
def sample_key():
    """Pre-generated key for encryption benchmarks."""
    return secrets.token_bytes(32)


@pytest.fixture
def sample_data_1kb():
    """1 KB of sample data."""
    return secrets.token_bytes(1024)


@pytest.fixture
def sample_data_1mb():
    """1 MB of sample data."""
    return secrets.token_bytes(1024 * 1024)


# =============================================================================
# Benchmark: Key Derivation
# =============================================================================

class TestBenchmarkKeyDerivation:
    """Benchmarks for key derivation performance."""
    
    def test_derive_master_key_time(self, crypto, sample_password, sample_salt, benchmark):
        """Benchmark master key derivation time."""
        def derive():
            return crypto.derive_master_key(sample_password, sample_salt)
        
        result = benchmark(derive)
        assert len(result) == 32
    
    def test_derive_subkey_time(self, crypto, sample_key, benchmark):
        """Benchmark subkey derivation time."""
        context = b"encryption"
        
        def derive():
            return crypto.derive_subkey(sample_key, context)
        
        result = benchmark(derive)
        assert len(result) == 32
    
    def test_generate_salt_time(self, crypto, benchmark):
        """Benchmark salt generation time."""
        result = benchmark(crypto.generate_salt)
        assert len(result) == 16


# =============================================================================
# Benchmark: Encryption/Decryption
# =============================================================================

class TestBenchmarkEncryption:
    """Benchmarks for encryption/decryption performance."""
    
    def test_encrypt_1kb(self, crypto, sample_key, sample_data_1kb, benchmark):
        """Benchmark encryption of 1 KB data."""
        result = benchmark(crypto.encrypt, sample_data_1kb, sample_key)
        assert len(result) > len(sample_data_1kb)
    
    def test_decrypt_1kb(self, crypto, sample_key, sample_data_1kb, benchmark):
        """Benchmark decryption of 1 KB data."""
        encrypted = crypto.encrypt(sample_data_1kb, sample_key)
        
        result = benchmark(crypto.decrypt, encrypted, sample_key)
        assert result == sample_data_1kb
    
    def test_encrypt_1mb(self, crypto, sample_key, sample_data_1mb, benchmark):
        """Benchmark encryption of 1 MB data."""
        result = benchmark(crypto.encrypt, sample_data_1mb, sample_key)
        assert len(result) > len(sample_data_1mb)
    
    def test_decrypt_1mb(self, crypto, sample_key, sample_data_1mb, benchmark):
        """Benchmark decryption of 1 MB data."""
        encrypted = crypto.encrypt(sample_data_1mb, sample_key)
        
        result = benchmark(crypto.decrypt, encrypted, sample_key)
        assert result == sample_data_1mb
    
    def test_encrypt_decrypt_roundtrip_1kb(self, crypto, sample_key, sample_data_1kb, benchmark):
        """Benchmark full encrypt-decrypt roundtrip for 1 KB."""
        def roundtrip():
            encrypted = crypto.encrypt(sample_data_1kb, sample_key)
            return crypto.decrypt(encrypted, sample_key)
        
        result = benchmark(roundtrip)
        assert result == sample_data_1kb


# =============================================================================
# Benchmark: HMAC
# =============================================================================

class TestBenchmarkHMAC:
    """Benchmarks for HMAC operations."""
    
    def test_sign_1kb(self, crypto, sample_key, sample_data_1kb, benchmark):
        """Benchmark signing of 1 KB data."""
        result = benchmark(crypto.sign, sample_data_1kb, sample_key)
        assert len(result) == 32
    
    def test_verify_signature_1kb(self, crypto, sample_key, sample_data_1kb, benchmark):
        """Benchmark signature verification of 1 KB data."""
        signature = crypto.sign(sample_data_1kb, sample_key)
        
        result = benchmark(crypto.verify_signature, sample_data_1kb, signature, sample_key)
        assert result is True


# =============================================================================
# Benchmark: Memory Protection
# =============================================================================

class TestBenchmarkMemoryProtection:
    """Benchmarks for memory protection utilities."""
    
    def test_zero_memory_32_bytes(self, benchmark):
        """Benchmark zeroing 32 bytes."""
        data = bytearray(secrets.token_bytes(32))
        
        def zero():
            data[:] = bytearray(len(data))
        
        benchmark(zero)
    
    def test_zero_memory_1kb(self, benchmark):
        """Benchmark zeroing 1 KB."""
        data = bytearray(secrets.token_bytes(1024))
        
        def zero():
            data[:] = bytearray(len(data))
        
        benchmark(zero)
    
    def test_zero_memory_1mb(self, benchmark):
        """Benchmark zeroing 1 MB."""
        data = bytearray(secrets.token_bytes(1024 * 1024))
        
        def zero():
            data[:] = bytearray(len(data))
        
        benchmark(zero)


# =============================================================================
# Benchmark: Hash File
# =============================================================================

class TestBenchmarkHashFile:
    """Benchmarks for file hashing."""
    
    def test_hash_file_1kb(self, crypto, tmp_path, benchmark):
        """Benchmark hashing 1 KB file."""
        file_path = tmp_path / "test_1kb.bin"
        file_path.write_bytes(secrets.token_bytes(1024))
        
        result = benchmark(crypto.hash_file, str(file_path))
        assert len(result) == 64
    
    def test_hash_file_1mb(self, crypto, tmp_path, benchmark):
        """Benchmark hashing 1 MB file."""
        file_path = tmp_path / "test_1mb.bin"
        file_path.write_bytes(secrets.token_bytes(1024 * 1024))
        
        result = benchmark(crypto.hash_file, str(file_path))
        assert len(result) == 64


# =============================================================================
# Comparative Benchmarks
# =============================================================================

class TestBenchmarkComparative:
    """Comparative benchmarks for different configurations."""
    
    def test_derive_key_low_memory(self, sample_password, sample_salt, benchmark):
        """Benchmark key derivation with low memory config."""
        config = CryptoConfig(
            argon2_time_cost=1,
            argon2_memory_cost=65536,  # 64 MB minimum
            argon2_parallelism=1,
        )
        crypto = CryptoCore(config)
        
        result = benchmark(crypto.derive_master_key, sample_password, sample_salt)
        assert len(result) == 32
    
    def test_derive_key_standard_memory(self, sample_password, sample_salt, benchmark):
        """Benchmark key derivation with standard memory config (64 MB)."""
        config = CryptoConfig(
            argon2_time_cost=3,
            argon2_memory_cost=65536,  # 64 MB
            argon2_parallelism=4,
        )
        crypto = CryptoCore(config)
        
        result = benchmark(crypto.derive_master_key, sample_password, sample_salt)
        assert len(result) == 32
    
    def test_derive_key_high_memory(self, sample_password, sample_salt, benchmark):
        """Benchmark key derivation with high memory config (256 MB)."""
        config = CryptoConfig(
            argon2_time_cost=4,
            argon2_memory_cost=262144,  # 256 MB
            argon2_parallelism=4,
        )
        crypto = CryptoCore(config)
        
        result = benchmark(crypto.derive_master_key, sample_password, sample_salt)
        assert len(result) == 32


# =============================================================================
# Warmup Benchmark (for PyPy JIT)
# =============================================================================

class TestBenchmarkWarmup:
    """Benchmarks for JIT warmup on PyPy."""
    
    def test_warmup_crypto_operations(self, crypto, sample_key, sample_data_1kb):
        """
        Warmup benchmark for PyPy JIT.
        
        Run this first to warm up the JIT compiler.
        Measures time for 100 crypto operations.
        """
        start_time = time.time()
        
        # Warmup: 100 encrypt-decrypt cycles
        for i in range(100):
            encrypted = crypto.encrypt(sample_data_1kb, sample_key)
            decrypted = crypto.decrypt(encrypted, sample_key)
            assert decrypted == sample_data_1kb
        
        elapsed = time.time() - start_time
        
        # Report warmup time
        print(f"\nWarmup completed in {elapsed:.3f} seconds")
        print(f"Average operation time: {elapsed/100*1000:.3f} ms")
        
        # This is just for warmup, no assertion needed
        assert elapsed < 10  # Should complete in reasonable time
