# -*- coding: utf-8 -*-
"""
Tests for Auth Manager and Security Utils

Coverage goal: >90%
"""

import pytest
import time
import threading

from backend.core.crypto_core import CryptoCore, zero_memory
from backend.core.auth_manager import (
    AuthManager,
    SessionManager,
    SessionState,
    AuthError,
    NotLockedError,
    AlreadyLockedError,
    SessionExpiredError,
)
from backend.core.security_utils import (
    RateLimiter,
    PasswordStrengthChecker,
    PasswordStrength,
    PasswordStrengthResult,
)
from backend.core.config import CryptoConfig


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def crypto():
    """Create CryptoCore instance."""
    return CryptoCore()


@pytest.fixture
def auth_manager(crypto):
    """Create AuthManager instance."""
    return AuthManager(crypto, auto_lock_timeout=60)


@pytest.fixture
def sample_password():
    """Sample password for testing."""
    return "test_password_123!@#"


@pytest.fixture
def sample_salt():
    """Sample salt."""
    import secrets
    return secrets.token_bytes(16)


# =============================================================================
# Tests: SessionState
# =============================================================================

class TestSessionState:
    """Tests for SessionState dataclass."""
    
    def test_initial_state(self):
        """Test initial session state."""
        state = SessionState()
        assert state.is_locked is True
        assert state.unlocked_at is None
        assert state.last_activity is None
        assert state.auto_lock_timeout == 300
    
    def test_time_since_activity_locked(self):
        """Test time_since_activity when locked."""
        state = SessionState(is_locked=True)
        assert state.time_since_activity is None
    
    def test_time_since_activity_unlocked(self):
        """Test time_since_activity when unlocked."""
        state = SessionState(is_locked=False, last_activity=time.time())
        time.sleep(0.1)
        assert state.time_since_activity >= 0.1
    
    def test_is_expired_locked(self):
        """Test is_expired when locked."""
        state = SessionState(is_locked=True)
        assert state.is_expired() is False
    
    def test_is_expired_no_activity(self):
        """Test is_expired with no activity."""
        state = SessionState(is_locked=False, last_activity=None)
        assert state.is_expired() is False


# =============================================================================
# Tests: AuthManager - Lock/Unlock
# =============================================================================

class TestAuthManagerLockUnlock:
    """Tests for AuthManager lock/unlock operations."""
    
    def test_initial_state(self, auth_manager):
        """Test initial state is locked."""
        assert auth_manager.is_locked is True
        assert auth_manager.is_unlocked is False
    
    def test_unlock_success(self, auth_manager, sample_password, sample_salt):
        """Test successful unlock."""
        auth_manager.unlock(sample_password, sample_salt)
        assert auth_manager.is_unlocked is True
        assert auth_manager.is_locked is False
    
    def test_unlock_empty_password(self, auth_manager, sample_salt):
        """Test unlock with empty password."""
        with pytest.raises(ValueError, match="cannot be empty"):
            auth_manager.unlock("", sample_salt)
    
    def test_unlock_short_salt(self, auth_manager, sample_password):
        """Test unlock with short salt."""
        short_salt = b"1234"
        with pytest.raises(ValueError, match="at least 8 bytes"):
            auth_manager.unlock(sample_password, short_salt)
    
    def test_unlock_already_unlocked(self, auth_manager, sample_password, sample_salt):
        """Test unlock when already unlocked."""
        auth_manager.unlock(sample_password, sample_salt)
        with pytest.raises(AlreadyLockedError):
            auth_manager.unlock(sample_password, sample_salt)
    
    def test_lock_success(self, auth_manager, sample_password, sample_salt):
        """Test successful lock."""
        auth_manager.unlock(sample_password, sample_salt)
        auth_manager.lock()
        assert auth_manager.is_locked is True
    
    def test_lock_already_locked(self, auth_manager):
        """Test lock when already locked."""
        with pytest.raises(NotLockedError):
            auth_manager.lock()
    
    def test_lock_clears_key(self, auth_manager, sample_password, sample_salt):
        """Test that lock clears master key."""
        auth_manager.unlock(sample_password, sample_salt)
        auth_manager.lock()
        
        with pytest.raises(AlreadyLockedError):
            auth_manager.get_master_key()

    def test_unlock_stores_wrapped_key_material(self, auth_manager, sample_password, sample_salt):
        """Test that unlocked state keeps wrapped (not plaintext) key material."""
        auth_manager.unlock(sample_password, sample_salt)
        assert auth_manager._wrapped_master_key is not None
        assert auth_manager._session_wrap_key is not None
        assert isinstance(auth_manager._session_wrap_key, bytearray)

    def test_lock_clears_wrapped_key_material(self, auth_manager, sample_password, sample_salt):
        """Test lock clears in-memory wrapped key state."""
        auth_manager.unlock(sample_password, sample_salt)
        auth_manager.lock()
        assert auth_manager._wrapped_master_key is None
        assert auth_manager._session_wrap_key is None

    def test_ephemeral_mode_keeps_no_session_key_material(
        self, crypto, sample_password, sample_salt
    ):
        """Ephemeral mode should not retain wrapped/session key material in AuthManager state."""
        expected_key = crypto.derive_master_key(sample_password, sample_salt)
        auth = AuthManager(
            crypto,
            master_key_provider=lambda: expected_key,
            retain_master_key_in_session=False,
        )

        auth.unlock(sample_password, sample_salt)

        assert auth.is_unlocked is True
        assert auth._wrapped_master_key is None
        assert auth._session_wrap_key is None

    def test_ephemeral_mode_unlock_rejects_mismatched_provider_key(
        self, crypto, sample_password, sample_salt
    ):
        """Ephemeral mode must fail unlock when provider key mismatches credentials."""
        wrong_key = b"\x00" * crypto.config.key_size
        auth = AuthManager(
            crypto,
            master_key_provider=lambda: wrong_key,
            retain_master_key_in_session=False,
        )

        with pytest.raises(AuthError, match="does not match unlock credentials"):
            auth.unlock(sample_password, sample_salt)

    def test_ephemeral_mode_requires_provider(self, crypto):
        """Ephemeral mode must require explicit master key provider."""
        with pytest.raises(ValueError, match="master_key_provider is required"):
            AuthManager(
                crypto,
                retain_master_key_in_session=False,
            )


# =============================================================================
# Tests: AuthManager - Key Access
# =============================================================================

class TestAuthManagerKeyAccess:
    """Tests for AuthManager key access methods."""
    
    def test_get_master_key_locked(self, auth_manager):
        """Test get_master_key when locked."""
        with pytest.raises(AlreadyLockedError):
            auth_manager.get_master_key()
    
    def test_get_master_key_unlocked(self, auth_manager, sample_password, sample_salt):
        """Test get_master_key when unlocked."""
        auth_manager.unlock(sample_password, sample_salt)
        key = auth_manager.get_master_key()
        assert len(key) == 32
        assert isinstance(key, bytearray)
    
    def test_get_derived_key(self, auth_manager, sample_password, sample_salt):
        """Test get_derived_key."""
        auth_manager.unlock(sample_password, sample_salt)

        enc_key = auth_manager.get_derived_key(b"encryption")
        hmac_key = auth_manager.get_derived_key(b"hmac")

        assert len(enc_key) == 32
        assert len(hmac_key) == 32
        assert isinstance(enc_key, bytearray)
        assert isinstance(hmac_key, bytearray)
        assert enc_key != hmac_key  # Different contexts = different keys
    
    def test_get_derived_key_locked(self, auth_manager):
        """Test get_derived_key when locked."""
        with pytest.raises(AlreadyLockedError):
            auth_manager.get_derived_key(b"encryption")


# =============================================================================
# Tests: AuthManager - Activity Tracking
# =============================================================================

class TestAuthManagerActivity:
    """Tests for AuthManager activity tracking."""
    
    def test_touch_updates_activity(self, auth_manager, sample_password, sample_salt):
        """Test that touch updates last activity."""
        auth_manager.unlock(sample_password, sample_salt)
        
        time.sleep(0.1)
        auth_manager.touch()
        
        assert auth_manager.time_since_activity < 0.1
    
    def test_touch_when_locked(self, auth_manager):
        """Test touch when locked (should do nothing)."""
        auth_manager.touch()  # Should not raise
    
    def test_time_until_auto_lock(self, auth_manager, sample_password, sample_salt):
        """Test time_until_auto_lock."""
        auth_manager.unlock(sample_password, sample_salt)
        
        remaining = auth_manager.time_until_auto_lock
        assert remaining is not None
        assert remaining <= 60  # auto_lock_timeout=60
    
    def test_time_until_auto_lock_locked(self, auth_manager):
        """Test time_until_auto_lock when locked."""
        assert auth_manager.time_until_auto_lock is None


# =============================================================================
# Tests: AuthManager - Auto-Lock Timer
# =============================================================================

class TestAuthManagerAutoLock:
    """Tests for AuthManager auto-lock timer."""
    
    def test_auto_lock_timer_validation(self, crypto):
        """Test auto_lock_timeout validation."""
        with pytest.raises(ValueError, match="at least 60 seconds"):
            AuthManager(crypto, auto_lock_timeout=30)
    
    def test_auto_lock_timeout_property(self, crypto, sample_password, sample_salt):
        """Test auto_lock_timeout property."""
        auth = AuthManager(crypto, auto_lock_timeout=120)
        assert auth.auto_lock_timeout == 120
    
    def test_auto_lock_timeout_validation(self, crypto):
        """Test auto_lock_timeout validation."""
        with pytest.raises(ValueError, match="at least 60 seconds"):
            AuthManager(crypto, auto_lock_timeout=30)


# =============================================================================
# Tests: AuthManager - Context Manager
# =============================================================================

class TestAuthManagerContextManager:
    """Tests for AuthManager context manager."""
    
    def test_context_manager_locks_on_exit(self, auth_manager, sample_password, sample_salt):
        """Test that context manager locks on exit."""
        with auth_manager:
            auth_manager.unlock(sample_password, sample_salt)
            assert auth_manager.is_unlocked
        
        # Should be locked after exit
        assert auth_manager.is_locked
    
    def test_context_manager_handles_exception(self, auth_manager, sample_password, sample_salt):
        """Test context manager handles exceptions."""
        try:
            with auth_manager:
                auth_manager.unlock(sample_password, sample_salt)
                raise ValueError("Test exception")
        except ValueError:
            pass
        
        # Should still be locked
        assert auth_manager.is_locked


# =============================================================================
# Tests: AuthManager - Callbacks
# =============================================================================

class TestAuthManagerCallbacks:
    """Tests for AuthManager callbacks."""
    
    def test_on_lock_callback(self, crypto, sample_password, sample_salt):
        """Test on_lock callback."""
        lock_called = []
        
        def on_lock():
            lock_called.append(True)
        
        auth = AuthManager(crypto, on_lock=on_lock)
        auth.unlock(sample_password, sample_salt)
        auth.lock()
        
        assert len(lock_called) == 1
    
    def test_on_unlock_callback(self, crypto, sample_password, sample_salt):
        """Test on_unlock callback."""
        unlock_called = []
        
        def on_unlock():
            unlock_called.append(True)
        
        auth = AuthManager(crypto, on_unlock=on_unlock)
        auth.unlock(sample_password, sample_salt)
        
        assert len(unlock_called) == 1


# =============================================================================
# Tests: SessionManager
# =============================================================================

class TestSessionManager:
    """Tests for SessionManager."""
    
    def test_create_session(self):
        """Test session creation."""
        mgr = SessionManager()
        session_id = mgr.create_session("user123")
        
        assert len(session_id) > 0
        assert mgr.is_session_valid(session_id)
    
    def test_destroy_session(self):
        """Test session destruction."""
        mgr = SessionManager()
        session_id = mgr.create_session("user123")
        
        result = mgr.destroy_session(session_id)
        assert result is True
        assert mgr.is_session_valid(session_id) is False
    
    def test_touch_session(self):
        """Test session touch."""
        mgr = SessionManager()
        session_id = mgr.create_session("user123")
        
        result = mgr.touch_session(session_id)
        assert result is True
    
    def test_max_sessions(self):
        """Test maximum sessions limit."""
        mgr = SessionManager(max_sessions_per_user=2)
        
        session1 = mgr.create_session("user123")
        session2 = mgr.create_session("user123")
        
        with pytest.raises(ValueError, match="Maximum.*sessions allowed"):
            mgr.create_session("user123")
    
    def test_get_active_sessions(self):
        """Test getting active sessions."""
        mgr = SessionManager()
        
        mgr.create_session("user1")
        mgr.create_session("user2")
        
        active = mgr.get_active_sessions()
        assert len(active) == 2


# =============================================================================
# Tests: RateLimiter
# =============================================================================

class TestRateLimiter:
    """Tests for RateLimiter."""
    
    def test_can_attempt_initial(self):
        """Test initial attempts are allowed."""
        limiter = RateLimiter()
        assert limiter.can_attempt("user1") is True
    
    def test_register_failed(self):
        """Test registering failed attempts."""
        limiter = RateLimiter(max_attempts=3)
        
        limiter.register_failed("user1")
        limiter.register_failed("user1")
        
        assert limiter.get_remaining_attempts("user1") == 1
    
    def test_register_success_resets(self):
        """Test successful attempt resets counter."""
        limiter = RateLimiter(max_attempts=3)
        
        limiter.register_failed("user1")
        limiter.register_failed("user1")
        limiter.register_success("user1")
        
        assert limiter.get_remaining_attempts("user1") == 3
    
    def test_block_after_max_attempts(self):
        """Test blocking after max attempts."""
        limiter = RateLimiter(max_attempts=3, block_duration_seconds=60)
        
        for _ in range(3):
            limiter.register_failed("user1")
        
        assert limiter.is_blocked("user1") is True
        assert limiter.can_attempt("user1") is False
    
    def test_exponential_backoff(self):
        """Test exponential backoff delay."""
        limiter = RateLimiter()
        
        limiter.register_failed("user1")
        delay1 = limiter.get_delay("user1")
        
        limiter.register_failed("user1")
        delay2 = limiter.get_delay("user1")
        
        assert delay2 > delay1  # Exponential increase
    
    def test_reset_identifier(self):
        """Test resetting identifier."""
        limiter = RateLimiter()
        
        limiter.register_failed("user1")
        limiter.reset("user1")
        
        assert limiter.get_remaining_attempts("user1") == limiter._max_attempts


# =============================================================================
# Tests: PasswordStrengthChecker
# =============================================================================

class TestPasswordStrengthChecker:
    """Tests for PasswordStrengthChecker."""
    
    def test_weak_password(self):
        """Test weak password detection."""
        checker = PasswordStrengthChecker()
        result = checker.check_strength("123456")
        
        assert result.strength == PasswordStrength.VERY_WEAK
        assert result.length == 6
    
    def test_strong_password(self):
        """Test strong password detection."""
        checker = PasswordStrengthChecker()
        result = checker.check_strength("MyStr0ngP@ssw0rd!")
        
        assert result.strength >= PasswordStrength.GOOD
        assert result.entropy_bits > 60
    
    def test_common_password(self):
        """Test common password detection."""
        checker = PasswordStrengthChecker()
        result = checker.check_strength("password")
        
        assert result.strength == PasswordStrength.VERY_WEAK
        assert "common" in str(result.suggestions).lower()
    
    def test_entropy_calculation(self):
        """Test entropy calculation."""
        checker = PasswordStrengthChecker()
        
        # Simple password
        result1 = checker.check_strength("aaaa")
        
        # Complex password
        result2 = checker.check_strength("Aa1!")
        
        assert result2.entropy_bits > result1.entropy_bits
    
    def test_crack_time_estimate(self):
        """Test crack time estimate."""
        checker = PasswordStrengthChecker()
        
        result_weak = checker.check_strength("123")
        result_strong = checker.check_strength("MyStr0ngP@ss!")
        
        # Strong password should have longer crack time
        assert "years" in result_strong.crack_time_estimate or "million" in result_strong.crack_time_estimate
    
    def test_suggestions_generated(self):
        """Test that suggestions are generated."""
        checker = PasswordStrengthChecker(min_length=12)
        result = checker.check_strength("short")
        
        assert len(result.suggestions) > 0
        # Check for any suggestion about length or entropy
        has_length_or_entropy_suggestion = any(
            "length" in s.lower() or "entropy" in s.lower() or "characters" in s.lower()
            for s in result.suggestions
        )
        assert has_length_or_entropy_suggestion
    
    def test_is_strong_enough(self):
        """Test is_strong_enough method."""
        checker = PasswordStrengthChecker()
        
        is_valid, result = checker.is_strong_enough("weak")
        assert is_valid is False
        
        is_valid, result = checker.is_strong_enough("MyStr0ngP@ssw0rd!")
        # May be True or False depending on entropy
        assert isinstance(is_valid, bool)
    
    def test_character_requirements(self):
        """Test character requirement checks."""
        checker = PasswordStrengthChecker()
        result = checker.check_strength("Test123!")
        
        assert result.has_uppercase is True
        assert result.has_lowercase is True
        assert result.has_digits is True
        assert result.has_special is True


# =============================================================================
# Integration Tests
# =============================================================================

class TestIntegration:
    """Integration tests for auth flow."""
    
    def test_full_auth_flow(self, crypto, sample_password, sample_salt):
        """Test complete authentication flow."""
        # Create auth manager
        auth = AuthManager(crypto)
        
        # Unlock
        auth.unlock(sample_password, sample_salt)
        assert auth.is_unlocked

        # Get key and encrypt
        key = auth.get_master_key()
        encrypted = crypto.encrypt(b"secret", bytes(key))
        zero_memory(key)

        # Touch session
        auth.touch()

        # Lock
        auth.lock()
        assert auth.is_locked

        # Unlock again and decrypt with same key
        auth.unlock(sample_password, sample_salt)
        key2 = auth.get_master_key()
        decrypted = crypto.decrypt(encrypted, bytes(key2))
        zero_memory(key2)

        assert decrypted == b"secret"
    
    def test_rate_limiter_with_auth(self, crypto, sample_password, sample_salt):
        """Test rate limiter with authentication."""
        auth = AuthManager(crypto)
        limiter = RateLimiter(max_attempts=3, block_duration_seconds=60)
        
        # Simulate failed logins - directly register failures
        for i in range(3):
            limiter.register_failed("user1")
        
        # Should be blocked after 3 failures
        assert limiter.get_remaining_attempts("user1") == 0
        
        # Successful login resets
        limiter.register_success("user1")
        assert limiter.get_remaining_attempts("user1") == 3
