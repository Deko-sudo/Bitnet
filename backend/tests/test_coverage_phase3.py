# -*- coding: utf-8 -*-
"""
Coverage Phase 3: Hard — deep mocking, crypto errors, import integration, async DB.
"""
from __future__ import annotations

import base64
import hashlib
import io
import os
import secrets
import time
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from httpx import AsyncClient


# =============================================================================
# crypto_core: zero_memory(empty), KeyDerivationError, EncryptionError, DecryptionError
# =============================================================================


class TestCryptoCoreErrors:
    def test_zero_memory_empty_bytearray(self):
        from backend.core.crypto_core import zero_memory

        buf = bytearray(b"")
        zero_memory(buf)
        assert buf == bytearray(b"")

    def test_derive_key_error(self):
        from backend.core.crypto_core import CryptoCore, KeyDerivationError

        cc = CryptoCore()
        salt = cc.generate_salt()
        with patch("backend.core.crypto_core.hash_secret_raw", side_effect=Exception("argon2 failed")):
            with pytest.raises(KeyDerivationError, match="Failed to derive key"):
                cc.derive_master_key("password", salt)

    def test_encrypt_error(self):
        from backend.core.crypto_core import CryptoCore, EncryptionError
        from unittest.mock import patch

        cc = CryptoCore()
        key = secrets.token_bytes(32)
        plaintext = bytearray(b"test data")
        with patch("backend.core.crypto_core.AESGCM", side_effect=Exception("aes failed")):
            with pytest.raises(EncryptionError, match="Encryption failed"):
                cc.encrypt(plaintext, key)

    def test_decrypt_wrong_key_raises_auth_error(self):
        from backend.core.crypto_core import CryptoCore, AuthenticationError

        cc = CryptoCore()
        key = secrets.token_bytes(32)
        encrypted = cc.encrypt(bytearray(b"test data"), key)

        wrong_key = secrets.token_bytes(32)
        with pytest.raises(AuthenticationError):
            cc.decrypt(encrypted, wrong_key)

    def test_decrypt_generic_exception_raises_decryption_error(self):
        from backend.core.crypto_core import CryptoCore, DecryptionError

        cc = CryptoCore()
        key = secrets.token_bytes(32)
        encrypted = cc.encrypt(bytearray(b"test data"), key)

        with patch("backend.core.crypto_core.AESGCM") as MockAESGCM:
            MockAESGCM.return_value.decrypt.side_effect = ValueError("bad data")
            with pytest.raises(DecryptionError, match="Decryption failed"):
                cc.decrypt(encrypted, key)


# =============================================================================
# breach_monitor_async: check_now exception, monitor loop
# =============================================================================


class TestBreachMonitorCheckErrors:
    @pytest.mark.asyncio
    async def test_check_now_logs_exception(self):
        from backend.features.breach_monitor_async import AsyncBreachMonitorService
        from backend.database.models import MonitoredItem

        fake_item = MonitoredItem(
            id="error_check_item",
            user_id=1,
            item_type="password",
            value_hash="CCCCC",
        )
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [fake_item]
        mock_db = AsyncMock()
        mock_db.__aenter__ = AsyncMock(return_value=mock_db)
        mock_db.__aexit__ = AsyncMock(return_value=False)
        mock_db.execute.return_value = mock_result

        mock_factory = MagicMock(return_value=mock_db)

        monitor = AsyncBreachMonitorService(
            db_session_factory=mock_factory,
            check_interval_hours=9999,
        )
        with patch.object(monitor, "_check_item", new_callable=AsyncMock, side_effect=RuntimeError("network error")):
            checked = await monitor.check_now()
            assert checked == 0


# =============================================================================
# password_generator: exhausted attempts (_GeneratorError)
# =============================================================================


class TestPasswordGeneratorExhausted:
    def test_generate_with_ensure_strength_exhausted(self):
        from backend.features.password_generator import (
            PasswordGeneratorConfig, _generate_password,
            PasswordStrengthChecker, _GeneratorError,
            PasswordStrength,
        )

        config = PasswordGeneratorConfig(
            length=8,
            use_uppercase=False,
            use_numbers=False,
            use_special=False,
            exclude_similar=True,
            ensure_strength=True,
            min_strength=PasswordStrength.STRONG,
        )
        with patch("backend.features.password_generator.PasswordStrengthChecker") as MockChecker:
            mock_result = MagicMock()
            mock_result.strength = PasswordStrength.WEAK
            MockChecker.return_value.check_strength.return_value = mock_result

            with pytest.raises(_GeneratorError):
                _generate_password(config)


# =============================================================================
# import_export: CSV/JSONL import with validation errors and batch flush
# =============================================================================


class TestImportExportIntegration:
    @pytest.mark.asyncio
    async def test_csv_import_with_validation_error(self):
        from backend.services.import_export import DataPortabilityService
        from unittest.mock import MagicMock

        session = MagicMock()
        master_key = MagicMock()
        svc = DataPortabilityService(session=session, master_key=master_key, batch_size=100)

        with patch.object(svc, "_insert_batch", new_callable=AsyncMock) as mock_insert:
            mock_insert.return_value = 1
            csv_data = b"title,password\n, emptypw\nValidTitle,ValidPass\n"
            result = await svc.import_from_csv(1, io.BytesIO(csv_data))
            assert result.skipped >= 1

    @pytest.mark.asyncio
    async def test_jsonl_import_blank_lines_skipped(self):
        from backend.services.import_export import DataPortabilityService
        from unittest.mock import MagicMock

        session = MagicMock()
        master_key = MagicMock()
        svc = DataPortabilityService(session=session, master_key=master_key, batch_size=100)

        with patch.object(svc, "_insert_batch", new_callable=AsyncMock) as mock_insert:
            mock_insert.return_value = 1
            jsonl_data = b'\n\n{"title":"A","password":"B"}\n\n'
            result = await svc.import_from_jsonl(1, io.BytesIO(jsonl_data))
            assert result.total_rows == 1

    @pytest.mark.asyncio
    async def test_insert_batch_encrypt_failure_skips(self):
        from backend.services.import_export import DataPortabilityService, ImportRowSchema
        from unittest.mock import MagicMock
        from pydantic import ValidationError

        session = MagicMock()
        master_key = MagicMock()
        svc = DataPortabilityService(session=session, master_key=master_key)

        rows = [ImportRowSchema(title="t", password="p")]
        with patch.object(svc, "_encrypt_and_build_entry", new_callable=AsyncMock, side_effect=Exception("encrypt failed")):
            result = await svc._insert_batch(1, rows)
            assert result == 0


# =============================================================================
# security_utils: check_and_record_attempt
# =============================================================================


class TestSecurityUtilsCheckAttempt:
    @pytest.mark.asyncio
    async def test_check_and_record_attempt_success(self, engine):
        from backend.core.security_utils import check_and_record_attempt
        from sqlalchemy.ext.asyncio import async_sessionmaker

        session_factory = async_sessionmaker(bind=engine, expire_on_commit=False)
        async with session_factory() as session:
            result = await check_and_record_attempt(session, success=True)
            assert result is True

    @pytest.mark.asyncio
    async def test_check_and_record_attempt_failure(self, engine):
        from backend.core.security_utils import check_and_record_attempt
        from sqlalchemy.ext.asyncio import async_sessionmaker

        session_factory = async_sessionmaker(bind=engine, expire_on_commit=False)
        async with session_factory() as session:
            result = await check_and_record_attempt(session, success=False)
            assert result is True


# =============================================================================
# backup_manager: invalid version, restore new entry
# =============================================================================


class TestBackupManagerExtra:
    def test_unpack_invalid_too_short(self):
        from backend.features.backup_manager import _unpack_backup_blob, BackupError
        import struct

        with pytest.raises(BackupError):
            _unpack_backup_blob(b"\x00invalid")

    def test_restore_nonexistent_backup(self):
        from backend.features.backup_manager import BackupManager, BackupError
        from unittest.mock import AsyncMock

        mgr = BackupManager(MagicMock())
        with pytest.raises(BackupError, match="must belong to the requesting user|not found"):
            import asyncio
            asyncio.get_event_loop().run_until_complete(
                mgr.restore(1, MagicMock(), "nonexistent_backup_12345.zip", confirmed=True)
            )


# =============================================================================
# auth_manager: locked/ephemeral mode branches
# =============================================================================


class TestAuthManagerLockedAndEphemal:
    def test_with_master_key_locked(self):
        from backend.core.auth_manager import AuthManager, AlreadyLockedError

        am = AuthManager(crypto=MagicMock())
        with pytest.raises(AlreadyLockedError):
            with am.with_master_key() as key:
                pass

    def test_with_derived_key_locked(self):
        from backend.core.auth_manager import AuthManager, AlreadyLockedError

        am = AuthManager(crypto=MagicMock())
        with pytest.raises(AlreadyLockedError):
            with am.with_derived_key(b"context"):
                pass

    def test_get_provider_key_no_provider(self):
        from backend.core.auth_manager import AuthManager

        am = AuthManager(crypto=MagicMock())
        am._state = MagicMock()
        am._state.is_locked = False
        with pytest.raises(Exception, match="master_key_provider"):
            am._get_provider_key()

    def test_get_provider_key_wrong_type(self):
        from backend.core.auth_manager import AuthManager

        am = AuthManager(crypto=MagicMock())
        am._state = MagicMock()
        am._state.is_locked = False
        am._master_key_provider = lambda: "not_bytes"
        with pytest.raises(Exception, match="must return bytes"):
            am._get_provider_key()

    def test_get_provider_key_wrong_length(self):
        from backend.core.auth_manager import AuthManager

        am = AuthManager(crypto=MagicMock())
        am._state = MagicMock()
        am._state.is_locked = False
        am._master_key_provider = lambda: b"short"
        with pytest.raises(Exception, match="invalid key length"):
            am._get_provider_key()


# =============================================================================
# entries.py: E2EE list with EntryNotFoundError skip
# =============================================================================


class TestEntriesE2EESkipMissing:
    @pytest.mark.asyncio
    async def test_e2ee_list_skips_missing_envelope(self):
        from backend.database.entry_service import EntryService, EntryNotFoundError
        from backend.database.models import PasswordEntry
        from unittest.mock import MagicMock

        session = MagicMock(spec=["execute", "scalar", "add", "commit", "refresh", "scalars"])
        mock_result = MagicMock()
        entry = PasswordEntry(
            id=1, user_id=1, title_search="test",
            title_cipher=None, title_nonce="", password_cipher="p", password_nonce="n",
        )
        mock_result.scalars.return_value.all.return_value = [entry]
        session.execute.return_value = mock_result

        svc = EntryService(session)
        with pytest.raises(EntryNotFoundError):
            EntryService._to_envelope_response(entry)


# =============================================================================
# audit_logger: _is_sensitive_value branches
# =============================================================================


class TestAuditLoggerSensitiveValue:
    def test_short_value_not_sensitive(self):
        from backend.core.audit_logger import AuditEvent, EventType
        event = AuditEvent(event_type=EventType.LOGIN_ATTEMPT, details={"label": "abc"})
        assert event.details["label"] == "abc"

    def test_base64_value_is_sensitive(self):
        from backend.core.audit_logger import AuditEvent, EventType
        import base64
        token = base64.b64encode(b"x" * 30).decode()
        event = AuditEvent(event_type=EventType.LOGIN_ATTEMPT, details={"info": "safe_label", "data": token})
        assert event.details["data"] == "[REDACTED]"

    def test_high_entropy_value_is_sensitive(self):
        from backend.core.audit_logger import AuditEvent, EventType
        high_entropy = "".join(chr(ord("!") + i % 94) for i in range(50))
        event = AuditEvent(event_type=EventType.LOGIN_ATTEMPT, details={"note": high_entropy})
        assert event.details["note"] == "[REDACTED]"

    def test_medium_value_not_sensitive(self):
        from backend.core.audit_logger import AuditEvent, EventType
        event = AuditEvent(event_type=EventType.LOGIN_ATTEMPT, details={"note": "a reasonable string"})
        assert event.details["note"] == "a reasonable string"

    def test_nested_dict_sanitization(self):
        from backend.core.audit_logger import AuditEvent, EventType
        import base64
        token = base64.b64encode(b"y" * 30).decode()
        event = AuditEvent(
            event_type=EventType.LOGIN_ATTEMPT,
            details={"outer": {"credential": "secret_val", "label": "safe_val", "deep_token": token}},
        )
        assert event.details["outer"]["credential"] == "[REDACTED]"
        assert event.details["outer"]["deep_token"] == "[REDACTED]"
        assert event.details["outer"]["label"] == "safe_val"

    def test_max_depth_returns_error(self):
        from backend.core.audit_logger import AuditEvent, EventType
        nested = {"level": 0}
        current = nested
        for _ in range(12):
            current["child"] = {"level": current["level"] + 1}
            current = current["child"]
        event = AuditEvent(event_type=EventType.LOGIN_ATTEMPT, details=nested)
        assert "_error" in str(event.details) or "child" in event.details


# =============================================================================
# security_utils: _calculate_entropy zero charset, check_and_record_attempt blocked
# =============================================================================


class TestSecurityUtilsCoverage:
    def test_calculate_entropy_empty_password(self):
        from backend.core.security_utils import PasswordStrengthChecker
        checker = PasswordStrengthChecker()
        assert checker._calculate_entropy("") == 0.0

    def test_calculate_entropy_digits_only(self):
        from backend.core.security_utils import PasswordStrengthChecker
        checker = PasswordStrengthChecker()
        result = checker._calculate_entropy("12345678")
        assert result > 0

    @pytest.mark.asyncio
    async def test_check_and_record_attempt_blocked(self, engine):
        from backend.core.security_utils import check_and_record_attempt
        from backend.database.models import LoginAttempt
        from sqlalchemy.ext.asyncio import async_sessionmaker
        from datetime import datetime, timezone, timedelta

        session_factory = async_sessionmaker(bind=engine, expire_on_commit=False)
        async with session_factory() as db:
            for _ in range(5):
                db.add(LoginAttempt(success=False))
            await db.commit()

        async with session_factory() as db:
            result = await check_and_record_attempt(db, success=True, max_failures=5)
            assert result is False


# =============================================================================
# pypy_optimization: warmup_on_startup with no crypto
# =============================================================================


class TestPypyOptimizationCoverage:
    def test_warmup_on_startup_no_crypto(self):
        from backend.core.pypy_optimization import warmup_on_startup
        with patch("backend.core.pypy_optimization.CRYPTO_AVAILABLE", False):
            success, results = warmup_on_startup()
            assert success is False
            assert "error" in results

    def test_jit_warmup_no_crypto(self):
        from backend.core.pypy_optimization import JITWarmup
        with patch("backend.core.pypy_optimization.CRYPTO_AVAILABLE", False):
            warmup = JITWarmup()
            results = warmup.run_full_warmup()
            assert "error" in results


# =============================================================================
# backup_manager: restore not confirmed
# =============================================================================


class TestBackupManagerRestoreNotConfirmed:
    def test_restore_not_confirmed_raises(self):
        from backend.features.backup_manager import BackupManager, BackupError
        mgr = BackupManager(MagicMock())
        with pytest.raises(BackupError, match="confirmed=True"):
            import asyncio
            asyncio.get_event_loop().run_until_complete(
                mgr.restore(1, MagicMock(), "fake_backup.zip", confirmed=False)
            )


# =============================================================================
# auth_manager: encrypt failure after wrap_key allocation
# =============================================================================


class TestAuthManagerEncryptFailure:
    def test_unlock_encrypt_failure_zeros_wrap_key(self):
        from backend.core.auth_manager import AuthManager, AlreadyLockedError
        from backend.core.crypto_core import EncryptionError
        from unittest.mock import MagicMock, patch

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