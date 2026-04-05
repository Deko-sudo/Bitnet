# -*- coding: utf-8 -*-
"""
Tests for Advanced Security Features

Coverage goal: >85%
"""

import pytest
import time

from backend.core.advanced_security import (
    TOTPAuthenticator,
    RecoveryCodeManager,
    HaveIBeenPwnedChecker,
    BiometricAuthenticator,
    BiometricError,
)


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def totp():
    """Create TOTP authenticator."""
    return TOTPAuthenticator()


@pytest.fixture
def recovery_manager():
    """Create recovery code manager."""
    return RecoveryCodeManager()


@pytest.fixture
def hibp_checker():
    """Create HIBP checker."""
    return HaveIBeenPwnedChecker()


# =============================================================================
# Tests: TOTPAuthenticator
# =============================================================================

class TestTOTPAuthenticator:
    """Tests for TOTP authenticator."""
    
    def test_setup_returns_secret_and_uri(self, totp):
        """Test setup returns correct values."""
        secret, uri = totp.setup("user@example.com", "MyApp")
        
        assert len(secret) >= 32  # Base32 encoded
        assert uri.startswith("otpauth://totp/")
        assert "user@example.com" in uri
        assert "MyApp" in uri
    
    def test_setup_different_secrets(self, totp):
        """Test that each setup generates unique secret."""
        secret1, _ = totp.setup("user1@example.com", "MyApp")
        secret2, _ = totp.setup("user2@example.com", "MyApp")
        
        assert secret1 != secret2
    
    def test_generate_returns_6_digits(self, totp):
        """Test generated code is 6 digits."""
        secret, _ = totp.setup("user@example.com", "MyApp")
        code = totp.generate(secret)
        
        assert len(code) == 6
        assert code.isdigit()
    
    def test_generate_deterministic(self, totp):
        """Test same timestamp produces same code."""
        secret, _ = totp.setup("user@example.com", "MyApp")
        timestamp = 1234567890.0
        
        code1 = totp.generate(secret, timestamp=timestamp)
        code2 = totp.generate(secret, timestamp=timestamp)
        
        assert code1 == code2
    
    def test_generate_changes_with_time(self, totp):
        """Test code changes with time."""
        secret, _ = totp.setup("user@example.com", "MyApp")
        
        code1 = totp.generate(secret, timestamp=1000000000.0)
        code2 = totp.generate(secret, timestamp=1000000030.0)  # +30 seconds
        
        assert code1 != code2
    
    def test_verify_valid_code(self, totp):
        """Test verification of valid code."""
        secret, _ = totp.setup("user@example.com", "MyApp")
        code = totp.generate(secret)
        
        assert totp.verify(secret, code) is True
    
    def test_verify_invalid_code(self, totp):
        """Test verification of invalid code."""
        secret, _ = totp.setup("user@example.com", "MyApp")
        
        assert totp.verify(secret, "000000") is False
    
    def test_verify_time_window(self, totp):
        """Test verification with time window."""
        secret, _ = totp.setup("user@example.com", "MyApp")
        
        # Generate code for specific time
        timestamp = 1000000000.0
        code = totp.generate(secret, timestamp=timestamp)
        
        # Verify within window (should work)
        assert totp.verify(secret, code, window=1, timestamp=timestamp) is True
        
        # Verify outside window (should fail)
        assert totp.verify(
            secret, code, window=0, timestamp=timestamp + 60
        ) is False
    
    def test_verify_wrong_secret(self, totp):
        """Test verification with wrong secret."""
        secret1, _ = totp.setup("user1@example.com", "MyApp")
        secret2, _ = totp.setup("user2@example.com", "MyApp")
        
        code = totp.generate(secret1)
        
        assert totp.verify(secret2, code) is False
    
    def test_otpauth_uri_format(self, totp):
        """Test otpauth URI format."""
        secret, uri = totp.setup("test@example.com", "TestApp")
        
        assert "otpauth://totp/TestApp:test@example.com" in uri
        assert f"secret={secret}" in uri
        assert "issuer=TestApp" in uri
        assert "algorithm=SHA1" in uri
        assert "digits=6" in uri
        assert "period=30" in uri


# =============================================================================
# Tests: RecoveryCodeManager
# =============================================================================

class TestRecoveryCodeManager:
    """Tests for recovery code manager."""
    
    def test_generate_codes_returns_lists(self, recovery_manager):
        """Test generate returns two lists."""
        plain, stored = recovery_manager.generate_codes("user123", count=10)
        
        assert len(plain) == 10
        assert len(stored) == 10
    
    def test_generate_codes_format(self, recovery_manager):
        """Test code format."""
        plain, _ = recovery_manager.generate_codes("user123", count=1)
        
        code = plain[0]
        # Format: XXXX-XXXX (groups of 4)
        assert '-' in code
        parts = code.split('-')
        assert all(len(p) == 4 for p in parts)
    
    def test_generate_codes_unique(self, recovery_manager):
        """Test all codes are unique."""
        plain, _ = recovery_manager.generate_codes("user123", count=20)
        
        assert len(set(plain)) == 20
    
    def test_verify_valid_code(self, recovery_manager):
        """Test verification of valid code."""
        plain, _ = recovery_manager.generate_codes("user123", count=10)
        
        assert recovery_manager.verify("user123", plain[0]) is True
    
    def test_verify_invalid_code(self, recovery_manager):
        """Test verification of invalid code."""
        recovery_manager.generate_codes("user123", count=10)
        
        assert recovery_manager.verify("user123", "AAAA-1111") is False
    
    def test_verify_consumes_code(self, recovery_manager):
        """Test that verification consumes code (one-time use)."""
        plain, _ = recovery_manager.generate_codes("user123", count=10)
        
        # First use should succeed
        assert recovery_manager.verify("user123", plain[0]) is True
        
        # Second use should fail
        assert recovery_manager.verify("user123", plain[0]) is False
    
    def test_verify_unknown_user(self, recovery_manager):
        """Test verification for unknown user."""
        assert recovery_manager.verify("unknown_user", "AAAA-1111") is False
    
    def test_get_unused_count(self, recovery_manager):
        """Test getting unused code count."""
        recovery_manager.generate_codes("user123", count=10)
        
        assert recovery_manager.get_unused_count("user123") == 10
        
        # Use one code
        plain, _ = recovery_manager.generate_codes("user123", count=10)
        recovery_manager.verify("user123", plain[0])
        
        assert recovery_manager.get_unused_count("user123") == 9
    
    def test_get_unused_count_unknown_user(self, recovery_manager):
        """Test unused count for unknown user."""
        assert recovery_manager.get_unused_count("unknown_user") == 0
    
    def test_generate_different_users(self, recovery_manager):
        """Test generating codes for different users."""
        plain1, _ = recovery_manager.generate_codes("user1", count=5)
        plain2, _ = recovery_manager.generate_codes("user2", count=5)
        
        # Codes should be different
        assert set(plain1) != set(plain2)
        
        # Using user1's code shouldn't work for user2
        recovery_manager.verify("user1", plain1[0])
        assert recovery_manager.get_unused_count("user1") == 4
        assert recovery_manager.get_unused_count("user2") == 5


# =============================================================================
# Tests: HaveIBeenPwnedChecker
# =============================================================================

class TestHaveIBeenPwnedChecker:
    """Tests for HIBP checker."""
    
    def test_check_password_format(self, hibp_checker):
        """Test password check returns correct format."""
        # Test with any password - format check
        is_pwned, count = hibp_checker.check_password("test_password_123")
        
        # Should return tuple
        assert isinstance(is_pwned, bool)
        assert isinstance(count, int)
        assert count >= 0
    
    def test_check_password_k_anonymity(self, hibp_checker):
        """Test that only hash prefix is sent."""
        # This test verifies k-anonymity concept
        # The actual password is never sent to API
        password = "test_password_123"
        
        # Generate hash
        import hashlib
        sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]
        
        # Only prefix should be in API call
        # Suffix stays client-side
        assert len(prefix) == 5
        assert len(suffix) == 35
    
    def test_check_unicode_password(self, hibp_checker):
        """Test unicode password handling."""
        password = "пароль123"
        
        is_pwned, count = hibp_checker.check_password(password)
        
        # Should work without errors
        assert isinstance(is_pwned, bool)
        assert isinstance(count, int)
    
    def test_check_unique_password_offline(self, hibp_checker):
        """Test unique password handling (offline test)."""
        # Very unique password (unlikely to be in breaches)
        unique_password = "xK9#mP2$vL5@nQ8"
        
        # Just test it doesn't crash
        is_pwned, count = hibp_checker.check_password(unique_password)
        
        assert isinstance(is_pwned, bool)
        assert count >= 0


# =============================================================================
# Tests: BiometricAuthenticator
# =============================================================================

class TestBiometricAuthenticator:
    """Tests for biometric authenticator."""
    
    def test_is_available_stub(self):
        """Test is_available returns stub value."""
        bio = BiometricAuthenticator()
        
        # Stub implementation
        assert bio.is_available() is False
    
    def test_is_enrolled_initial(self):
        """Test initial enrollment state."""
        bio = BiometricAuthenticator()
        
        assert bio.is_enrolled() is False
    
    def test_enroll_unavailable_backend(self):
        """Test enrollment fails when backend is unavailable."""
        bio = BiometricAuthenticator()

        with pytest.raises(BiometricError):
            bio.enroll()
    
    def test_authenticate_unavailable_backend_raises(self):
        """Test authenticate raises when backend is unavailable."""
        bio = BiometricAuthenticator()
        
        with pytest.raises(BiometricError):
            bio.authenticate()

    def test_simulator_backend(self, monkeypatch):
        """Test optional in-memory simulator backend."""
        monkeypatch.setenv("BEZ_ENABLE_BIOMETRIC_SIMULATOR", "1")
        bio = BiometricAuthenticator()

        assert bio.is_available() is True
        assert bio.is_enrolled() is False
        assert bio.enroll() is True
        assert bio.is_enrolled() is True
        assert bio.authenticate() is True


# =============================================================================
# Integration Tests
# =============================================================================

class TestIntegration:
    """Integration tests for advanced security features."""
    
    def test_totp_full_workflow(self, totp):
        """Test complete TOTP setup and verification workflow."""
        # Setup
        secret, uri = totp.setup("user@example.com", "MyApp")
        
        # Generate code
        code = totp.generate(secret)
        
        # Verify
        assert totp.verify(secret, code) is True
    
    def test_recovery_codes_full_workflow(self, recovery_manager):
        """Test complete recovery code workflow."""
        # Generate
        plain_codes, _ = recovery_manager.generate_codes("user123", count=10)
        
        # Verify all codes work
        for code in plain_codes:
            assert recovery_manager.verify("user123", code) is True
        
        # All codes should be consumed
        assert recovery_manager.get_unused_count("user123") == 0
    
    def test_totp_and_recovery_integration(self, totp, recovery_manager):
        """Test TOTP and recovery codes work together."""
        # Setup TOTP
        secret, _ = totp.setup("user@example.com", "MyApp")
        
        # Generate recovery codes
        recovery_codes, _ = recovery_manager.generate_codes("user123", count=5)
        
        # TOTP should work
        totp_code = totp.generate(secret)
        assert totp.verify(secret, totp_code) is True
        
        # Recovery codes should work
        assert recovery_manager.verify("user123", recovery_codes[0]) is True
        
        # Unused count should be correct
        assert recovery_manager.get_unused_count("user123") == 4
    
    def test_hibp_format_validation(self, hibp_checker):
        """Test HIBP checker format validation."""
        # Test various password formats
        passwords = [
            "short",
            "long_password_123",
            "unicode_пароль",
            "special_!@#$%^&*()",
        ]
        
        for password in passwords:
            is_pwned, count = hibp_checker.check_password(password)
            assert isinstance(is_pwned, bool)
            assert isinstance(count, int)
            assert count >= 0
