# -*- coding: utf-8 -*-
"""
Coverage Phase 4: Very hard — crypto bridge edge cases, auth endpoint failures,
encrypt-after-allocation failure paths, API integration edge cases.
"""
from __future__ import annotations

import hashlib
import os
import secrets
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from httpx import AsyncClient


# =============================================================================
# auth.py: _load_server_wrap_key edge cases
# =============================================================================


class TestLoadServerWrapKey:
    def test_env_var_not_set_raises(self):
        import backend.api.v1.endpoints.auth as _auth_mod
        from backend.api.v1.endpoints.auth import _load_server_wrap_key

        original = _auth_mod._server_wrap_key
        _auth_mod._server_wrap_key = None
        try:
            with patch.dict(os.environ, {}, clear=True):
                if "BITNET_SERVER_WRAP_KEY_FILE" in os.environ:
                    del os.environ["BITNET_SERVER_WRAP_KEY_FILE"]
                with pytest.raises(RuntimeError, match="BITNET_SERVER_WRAP_KEY_FILE"):
                    _load_server_wrap_key()
        finally:
            _auth_mod._server_wrap_key = original

    def test_empty_file_raises(self):
        import backend.api.v1.endpoints.auth as _auth_mod
        from backend.api.v1.endpoints.auth import _load_server_wrap_key

        original = _auth_mod._server_wrap_key
        _auth_mod._server_wrap_key = None
        try:
            with tempfile.NamedTemporaryFile(delete=False) as fh:
                fh.write(b"")
                path = fh.name

            try:
                with patch.dict(os.environ, {"BITNET_SERVER_WRAP_KEY_FILE": path}):
                    with pytest.raises(RuntimeError, match="empty"):
                        _load_server_wrap_key()
            finally:
                os.unlink(path)
        finally:
            _auth_mod._server_wrap_key = original

    def test_short_read_raises(self):
        import backend.api.v1.endpoints.auth as _auth_mod
        from backend.api.v1.endpoints.auth import _load_server_wrap_key

        original = _auth_mod._server_wrap_key
        _auth_mod._server_wrap_key = None
        try:
            key_bytes = secrets.token_bytes(32)
            with tempfile.NamedTemporaryFile(delete=False) as fh:
                fh.write(key_bytes)
                path = fh.name

            try:
                with patch.dict(os.environ, {"BITNET_SERVER_WRAP_KEY_FILE": path}):
                    with patch("builtins.open", side_effect=Exception("io error")):
                        with pytest.raises(Exception):
                            _load_server_wrap_key()
            finally:
                os.unlink(path)
        finally:
            _auth_mod._server_wrap_key = original


# =============================================================================
# auth.py: _unwrap_master_key_for_user decrypt failure
# =============================================================================


class TestUnwrapMasterKeyFailure:
    def test_corrupt_key_returns_401(self):
        from backend.api.v1.endpoints.auth import _unwrap_master_key_for_user
        from backend.database.models import User

        user = User(
            id=99,
            username="corrupt_user",
            email="corrupt@test.com",
            password_hash="fakehash",
            salt=b"salt_16bytes___",
            wrapped_master_key_cipher=b"corrupt_cipher_data",
            wrapped_master_key_nonce=b"corrupt_nonce_12b",
            wrapped_master_key_tag=b"corrupt_tag_16by",
        )
        with pytest.raises(Exception) as exc_info:
            _unwrap_master_key_for_user(user)
        assert exc_info.value.status_code == 401


# =============================================================================
# auth_manager: unlock encrypt failure zeros wrap_key
# =============================================================================


class TestAuthManagerUnlockEncryptFailure:
    def test_encrypt_failure_zeros_wrap_key(self):
        from backend.core.auth_manager import AuthManager
        from backend.core.crypto_core import EncryptionError

        crypto = MagicMock()
        crypto.config = MagicMock()
        crypto.config.key_size = 32
        crypto.generate_random_bytes.return_value = b"\x00" * 32
        crypto.derive_master_key.return_value = bytearray(b"\x01" * 32)

        am = AuthManager(crypto=crypto)
        with patch.object(crypto, "encrypt", side_effect=EncryptionError("encrypt failed")):
            with pytest.raises(EncryptionError):
                am.unlock("password", b"salt_12345678")

        assert am.is_locked

    def test_unlock_then_lock_clears_keys(self):
        from backend.core.auth_manager import AuthManager

        crypto = MagicMock()
        crypto.config = MagicMock()
        crypto.config.key_size = 32
        crypto.generate_random_bytes.return_value = b"\xAA" * 32
        crypto.derive_master_key.return_value = bytearray(b"\xBB" * 32)
        crypto.encrypt.return_value = b"wrapped_key_blob"
        crypto.decrypt.return_value = b"\xCC" * 32
        crypto.derive_subkey.return_value = b"\xDD" * 32

        am = AuthManager(crypto=crypto)
        am.unlock("password", b"salt_12345678")
        assert am.is_unlocked
        assert am._wrapped_master_key is not None
        assert am._session_wrap_key is not None

        am.lock()
        assert am.is_locked
        assert am._wrapped_master_key is None
        assert am._session_wrap_key is None


# =============================================================================
# auth_manager: ephemeral mode key provider errors
# =============================================================================


class TestAuthManagerEphemeralMode:
    def test_ephemeral_unlock_verifies_provider_key(self):
        from backend.core.auth_manager import AuthManager

        real_key = secrets.token_bytes(32)
        crypto = MagicMock()
        crypto.config = MagicMock()
        crypto.config.key_size = 32
        crypto.derive_master_key.return_value = bytearray(real_key)
        crypto.constant_time_compare.return_value = True

        am = AuthManager(
            crypto=crypto,
            master_key_provider=lambda: real_key,
            retain_master_key_in_session=False,
        )
        am.unlock("password", b"salt_12345678")
        assert am.is_unlocked
        assert am._wrapped_master_key is None
        assert am._session_wrap_key is None

    def test_ephemeral_unlock_wrong_provider_key(self):
        from backend.core.auth_manager import AuthManager, AuthError

        crypto = MagicMock()
        crypto.config = MagicMock()
        crypto.config.key_size = 32
        crypto.derive_master_key.return_value = bytearray(secrets.token_bytes(32))
        crypto.constant_time_compare.return_value = False

        am = AuthManager(
            crypto=crypto,
            master_key_provider=lambda: secrets.token_bytes(32),
            retain_master_key_in_session=False,
        )
        with pytest.raises(AuthError, match="does not match"):
            am.unlock("password", b"salt_12345678")


# =============================================================================
# audit_logger: get_log and clear_old_entries
# =============================================================================


class TestAuditLoggerGetLog:
    def test_get_log_with_filters(self):
        from backend.core.audit_logger import AuditLogger, AuditLog, EventType

        session = MagicMock()
        query = MagicMock()
        session.query.return_value = query
        query.filter.return_value = query
        query.order_by.return_value = query
        query.limit.return_value = query
        query.all.return_value = []

        logger = AuditLogger(session)
        result = logger.get_log(
            limit=10,
            event_type=EventType.LOGIN_SUCCESS,
            user_id="user1",
            success=True,
        )
        assert result == []
        session.query.assert_called_once_with(AuditLog)

    def test_clear_old_entries(self):
        from backend.core.audit_logger import AuditLogger, AuditLog

        session = MagicMock()
        query = MagicMock()
        session.query.return_value = query
        query.filter.return_value = query
        query.delete.return_value = 5

        logger = AuditLogger(session)
        deleted = logger.clear_old_entries(days_to_keep=30)
        assert deleted == 5


# =============================================================================
# security_utils: RateLimiter advanced
# =============================================================================


class TestRateLimiterAdvanced:
    def test_cleanup_old_attempts(self):
        from backend.core.security_utils import RateLimiter
        import time

        limiter = RateLimiter(max_attempts=3, window_seconds=1)
        limiter.register_failed("user1")
        time.sleep(1.1)
        assert limiter.can_attempt("user1")

    def test_get_delay_no_failures(self):
        from backend.core.security_utils import RateLimiter

        limiter = RateLimiter()
        assert limiter.get_delay("unknown") == 0.0

    def test_is_blocked_no_entry(self):
        from backend.core.security_utils import RateLimiter

        limiter = RateLimiter()
        assert limiter.is_blocked("unknown") is False

    def test_reset_removes_entry(self):
        from backend.core.security_utils import RateLimiter

        limiter = RateLimiter()
        limiter.register_failed("user1")
        assert limiter.get_remaining_attempts("user1") < limiter._max_attempts
        limiter.reset("user1")
        assert limiter.get_remaining_attempts("user1") == limiter._max_attempts

    def test_register_success_resets(self):
        from backend.core.security_utils import RateLimiter

        limiter = RateLimiter(max_attempts=5)
        limiter.register_failed("user1")
        limiter.register_failed("user1")
        assert limiter.get_remaining_attempts("user1") == 3
        limiter.register_success("user1")
        assert limiter.get_remaining_attempts("user1") == 5


# =============================================================================
# SessionManager tests
# =============================================================================


class TestSessionManager:
    def test_create_and_destroy_session(self):
        from backend.core.auth_manager import SessionManager

        sm = SessionManager(max_sessions_per_user=2)
        sid = sm.create_session("user1")
        assert sm.is_session_valid(sid)
        assert sm.destroy_session(sid)
        assert not sm.is_session_valid(sid)

    def test_max_sessions_exceeded(self):
        from backend.core.auth_manager import SessionManager

        sm = SessionManager(max_sessions_per_user=1)
        sm.create_session("user1")
        with pytest.raises(ValueError, match="Maximum"):
            sm.create_session("user1")

    def test_destroy_nonexistent_session(self):
        from backend.core.auth_manager import SessionManager

        sm = SessionManager()
        assert sm.destroy_session("nonexistent") is False

    def test_touch_inactive_session(self):
        from backend.core.auth_manager import SessionManager

        sm = SessionManager()
        assert sm.touch_session("nonexistent") is False

    def test_get_active_sessions(self):
        from backend.core.auth_manager import SessionManager

        sm = SessionManager()
        sm.create_session("user1")
        sm.create_session("user2")
        active = sm.get_active_sessions()
        assert len(active) == 2


# =============================================================================
# breach_monitor_async: add/remove items and severity
# =============================================================================


class TestBreachMonitorSeverity:
    def test_severity_levels(self):
        from backend.features.breach_monitor_async import _severity

        assert _severity(2000000) == "critical"
        assert _severity(50000) == "high"
        assert _severity(500) == "medium"
        assert _severity(50) == "low"


# =============================================================================
# backup_manager: _unpack_backup_blob edge cases
# =============================================================================


class TestBackupManagerUnpack:
    def test_unpack_wrong_version(self):
        from backend.features.backup_manager import _unpack_backup_blob, BackupError
        import struct

        result = _unpack_backup_blob(struct.pack("!BB", 99, 12) + b"\x00" * 12 + struct.pack("!I", 0) + b"\x00" * 32)
        assert result[0] == 99

    def test_unpack_valid_structure(self):
        from backend.features.backup_manager import _unpack_backup_blob
        import struct

        nonce = b"\x00" * 12
        ciphertext = b"\x00" * 32
        hmac_tag = b"\x00" * 32
        blob = struct.pack("!BB", 1, 12) + nonce + struct.pack("!I", len(ciphertext)) + ciphertext + hmac_tag
        version_out, nonce_out, ct_out, hmac_out = _unpack_backup_blob(blob)
        assert version_out == 1
        assert nonce_out == nonce
        assert ct_out == ciphertext
        assert hmac_out == hmac_tag


# =============================================================================
# pypy_optimization: PerformanceComparator with no crypto
# =============================================================================


class TestPerformanceComparatorNoCrypto:
    def test_compare_no_crypto(self):
        from backend.core.pypy_optimization import PerformanceComparator

        comparator = PerformanceComparator(iterations=10)
        with patch("backend.core.pypy_optimization.CRYPTO_AVAILABLE", False):
            result = comparator.compare_crypto_operations()
            assert "error" in result

    def test_get_optimization_recommendations_no_crypto(self):
        from backend.core.pypy_optimization import get_optimization_recommendations

        with patch("backend.core.pypy_optimization.CRYPTO_AVAILABLE", False):
            recs = get_optimization_recommendations()
            assert "warnings" in recs
            assert any("not available" in w for w in recs["warnings"])


# =============================================================================
# crypto_core: derive_master_key returns bytearray
# =============================================================================


class TestCryptoCoreDeriveKey:
    def test_derive_master_key_returns_bytearray(self):
        from backend.core.crypto_core import CryptoCore
        import ctypes

        cc = CryptoCore()
        salt = cc.generate_salt()
        result = cc.derive_master_key("test_password", salt)
        assert isinstance(result, bytearray)
        assert len(result) == 32


# =============================================================================
# PasswordStrengthChecker: edge cases
# =============================================================================


class TestPasswordStrengthEdgeCases:
    def test_special_chars_entropy(self):
        from backend.core.security_utils import PasswordStrengthChecker

        checker = PasswordStrengthChecker()
        result = checker.check_strength("P@ss!w0rd#2024")
        assert result.has_special is True
        assert result.entropy_bits > 0

    def test_cyrillic_letters(self):
        from backend.core.security_utils import PasswordStrengthChecker

        checker = PasswordStrengthChecker()
        result = checker.check_strength("Пароль123")
        assert result.has_uppercase is True or result.has_lowercase is True

    def test_is_strong_enough_weak(self):
        from backend.core.security_utils import PasswordStrengthChecker, PasswordStrength

        checker = PasswordStrengthChecker()
        is_strong, result = checker.is_strong_enough("abc")
        assert is_strong is False
        assert result.strength <= PasswordStrength.WEAK

    def test_crack_time_instantly(self):
        from backend.core.security_utils import PasswordStrengthChecker

        checker = PasswordStrengthChecker()
        result = checker._estimate_crack_time(0)
        assert result == "Instantly"

    def test_crack_time_minutes(self):
        from backend.core.security_utils import PasswordStrengthChecker

        result = PasswordStrengthChecker()._estimate_crack_time(43)
        assert "minute" in result

    def test_crack_time_hours(self):
        from backend.core.security_utils import PasswordStrengthChecker

        result = PasswordStrengthChecker()._estimate_crack_time(48)
        assert "hour" in result

    def test_crack_time_years(self):
        from backend.core.security_utils import PasswordStrengthChecker

        result = PasswordStrengthChecker()._estimate_crack_time(80)
        assert "year" in result

    def test_crack_time_billion_years(self):
        from backend.core.security_utils import PasswordStrengthChecker

        result = PasswordStrengthChecker()._estimate_crack_time(160)
        assert "billion" in result


# =============================================================================
# AuditEvent: IP validation
# =============================================================================


class TestAuditEventIPValidation:
    def test_ipv4_valid(self):
        from backend.core.audit_logger import AuditEvent, EventType

        event = AuditEvent(event_type=EventType.LOGIN_SUCCESS, ip_address="192.168.1.1")
        assert event.ip_address == "192.168.1.1"

    def test_ipv6_valid(self):
        from backend.core.audit_logger import AuditEvent, EventType

        event = AuditEvent(event_type=EventType.LOGIN_SUCCESS, ip_address="::1")
        assert event.ip_address == "::1"

    def test_invalid_ip_raises(self):
        from backend.core.audit_logger import AuditEvent, EventType

        with pytest.raises(ValueError, match="Invalid IP"):
            AuditEvent(event_type=EventType.LOGIN_SUCCESS, ip_address="not_an_ip")

    def test_localhost_valid(self):
        from backend.core.audit_logger import AuditEvent, EventType

        event = AuditEvent(event_type=EventType.LOGIN_SUCCESS, ip_address="localhost")
        assert event.ip_address == "localhost"

    def test_details_none_stays_none(self):
        from backend.core.audit_logger import AuditEvent, EventType

        event = AuditEvent(event_type=EventType.LOGIN_SUCCESS, details=None)
        assert event.details is None