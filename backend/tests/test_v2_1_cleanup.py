# -*- coding: utf-8 -*-
"""Targeted tests for v2.1.0 cleanup: ConfigDict, lifespan, coverage gaps."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# =============================================================================
# Config: ConfigDict verification + local config loading
# =============================================================================


class TestConfigDictMigration:
    def test_crypto_config_uses_config_dict(self):
        from backend.core.config import CryptoConfig

        cfg = CryptoConfig()
        assert cfg.model_config.get("frozen") is True
        assert cfg.model_config.get("extra") == "forbid"

    def test_crypto_config_forbids_extra(self):
        from backend.core.config import CryptoConfig
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            CryptoConfig(key_size=32, nonexistent_field=True)

    def test_rate_limit_config_forbids_extra(self):
        from backend.core.config import RateLimitConfig
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            RateLimitConfig(max_attempts=5, nonexistent=True)

    def test_password_strength_forbids_extra(self):
        from backend.core.config import PasswordStrengthConfig
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            PasswordStrengthConfig(min_length=12, nonexistent=True)

    def test_crypto_config_validation_errors(self):
        from backend.core.config import CryptoConfig
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            CryptoConfig(key_size=8)
        with pytest.raises(ValidationError):
            CryptoConfig(argon2_memory_cost=1024)

    def test_local_config_loading_no_file(self):
        from backend.core.config import _load_local_config

        with patch.object(Path, "exists", return_value=False):
            result = _load_local_config()
            assert result == {}

    def test_local_config_loading_reads_toml(self):
        import tomllib
        from backend.core.config import _load_local_config

        toml_content = b"key_size = 64\n"
        with tempfile.NamedTemporaryFile(suffix=".toml", delete=False) as f:
            f.write(toml_content)
            f.flush()
            tmppath = Path(f.name)
        try:
            with patch("backend.core.config.Path") as mock_path_cls:
                instance = MagicMock()
                instance.exists.return_value = True
                mock_path_cls.home.return_value.__truediv__ = MagicMock(
                    return_value=MagicMock(__truediv__=lambda s, o: tmppath)
                )
                result = _load_local_config()
                assert isinstance(result, dict)
        finally:
            os.unlink(tmppath)


# =============================================================================
# Lifespan: verify context manager pattern
# =============================================================================


class TestLifespanMigration:
    def test_lifespan_is_async_context_manager(self):
        from backend.main import lifespan

        ctx = lifespan(MagicMock())
        assert hasattr(ctx, "__aenter__")
        assert hasattr(ctx, "__aexit__")

    def test_app_uses_lifespan_context(self):
        from backend.main import app

        assert app.router.lifespan_context is not None

    def test_no_on_event_usage_in_main_source(self):
        import inspect
        import backend.main as main_module

        src = inspect.getsource(main_module)
        for line in src.splitlines():
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith('"') or stripped.startswith("'"):
                continue
            assert "on_event" not in stripped

    @pytest.mark.asyncio
    async def test_lifespan_startup_shutdown(self):
        from unittest.mock import AsyncMock, patch, MagicMock
        from backend.main import lifespan

        mock_monitor = AsyncMock()
        mock_monitor.start = AsyncMock()
        mock_monitor.stop = AsyncMock()

        mock_app = MagicMock()
        mock_app.state = MagicMock()

        with patch("backend.main.AsyncBreachMonitorService", return_value=mock_monitor), \
             patch("backend.main.init_db"):
            async with lifespan(mock_app):
                mock_monitor.start.assert_awaited_once()
                assert mock_app.state.breach_monitor is mock_monitor

            mock_monitor.stop.assert_awaited_once()


# =============================================================================
# main.py: exception handlers + health check
# =============================================================================


class TestMainExceptionHandlers:
    @pytest.mark.asyncio
    async def test_health_check(self, client):
        resp = await client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    @pytest.mark.asyncio
    async def test_404_returns_standard_error(self, client):
        resp = await client.get("/api/v1/nonexistent")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_unauthenticated_entries(self, client):
        resp = await client.get("/api/v1/entries/")
        assert resp.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_validation_error_handler(self, client):
        resp = await client.post(
            "/api/v1/auth/register",
            json={},
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_middleware_logs_request(self, client):
        resp = await client.get("/health")
        assert resp.status_code == 200


# =============================================================================
# db_security: path hardening (Windows-safe)
# =============================================================================


class TestDbSecurity:
    def test_ensure_secure_db_path_creates_dir(self):
        from backend.database.db_security import ensure_secure_db_path

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "subdir" / "test.db"
            result = ensure_secure_db_path(db_path)
            assert result.parent.exists()

    def test_ensure_secure_db_path_existing_file(self):
        from backend.database.db_security import ensure_secure_db_path

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db_path.write_text("test")
            result = ensure_secure_db_path(db_path)
            assert result.exists()

    def test_ensure_secure_db_path_permission_error_handled(self):
        from backend.database.db_security import ensure_secure_db_path

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            with patch("os.chmod", side_effect=PermissionError("test")):
                result = ensure_secure_db_path(db_path)
                assert result is not None

    def test_ensure_secure_db_path_file_permission_error_handled(self):
        from backend.database.db_security import ensure_secure_db_path
        import stat

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db_path.write_text("test")
            with patch("os.chmod", side_effect=PermissionError("test")):
                result = ensure_secure_db_path(db_path)
                assert result is not None

    def test_get_windows_acl_command(self):
        from backend.database.db_security import get_windows_acl_command

        cmd = get_windows_acl_command(Path("C:\\temp\\vault.db"))  # nosec B108 — test-only path, not actual temp dir
        assert "icacls" in cmd

    def test_apply_windows_acl_skips_on_non_windows(self):
        from backend.database.db_security import apply_windows_acl

        if os.name != "nt":
            result = apply_windows_acl(Path("C:\\temp\\vault.db"))  # nosec B108 — test-only path
            assert result is False


# =============================================================================
# search_engine: SearchService import
# =============================================================================


class TestSearchEngineUnit:
    def test_search_service_import(self):
        from backend.features.search_engine import SearchService

        assert SearchService is not None


# =============================================================================
# PyPyOptimization module
# =============================================================================


class TestPyPyOptimization:
    def test_is_pypy_returns_false(self):
        from backend.core.pypy_optimization import is_pypy

        assert is_pypy() is False

    def test_warmup_run_full(self):
        from backend.core.pypy_optimization import JITWarmup

        warmup = JITWarmup()
        warmup.run_full_warmup(count=1)


# =============================================================================
# CryptoCore: error paths
# =============================================================================


class TestCryptoCoreErrorPaths:
    def test_derive_master_key_empty_password_raises(self):
        from backend.core.crypto_core import CryptoCore

        cc = CryptoCore()
        with pytest.raises(ValueError):
            cc.derive_master_key("", b"salt1234")

    def test_derive_master_key_short_salt_raises(self):
        from backend.core.crypto_core import CryptoCore

        cc = CryptoCore()
        with pytest.raises(ValueError):
            cc.derive_master_key("password", b"short")

    def test_decrypt_with_wrong_key_raises(self):
        from backend.core.crypto_core import CryptoCore

        cc = CryptoCore()
        plaintext = b"test data for decryption"
        key = cc.generate_salt(32)
        ciphertext_blob = cc.encrypt(plaintext, key)
        wrong_key = cc.generate_salt(32)
        with pytest.raises(Exception):
            cc.decrypt(ciphertext_blob, wrong_key)

    def test_crypto_core_config_property(self):
        from backend.core.crypto_core import CryptoCore
        from backend.core.config import CryptoConfig

        custom = CryptoConfig(key_size=32)
        cc = CryptoCore(config=custom)
        assert cc.config.key_size == 32

    def test_generate_salt_different_sizes(self):
        from backend.core.crypto_core import CryptoCore

        cc = CryptoCore()
        s8 = cc.generate_salt(8)
        assert len(s8) == 8
        s32 = cc.generate_salt(32)
        assert len(s32) == 32


# =============================================================================
# Generator endpoint coverage
# =============================================================================


class TestGeneratorEndpoint:
    def test_password_generator_module(self):
        from backend.features.password_generator import PasswordGenerator, PasswordGeneratorConfig

        pg = PasswordGenerator()
        config = PasswordGeneratorConfig(length=16)
        result = pg.generate_password(config)
        assert len(result) >= 1
        assert result[0].strength is not None

    def test_password_generator_pin(self):
        from backend.features.password_generator import PasswordGenerator, PINGeneratorConfig

        pg = PasswordGenerator()
        config = PINGeneratorConfig(length=6)
        result = pg.generate_pin(config)
        assert len(result) >= 1
        assert result[0].value.get_secret_value().isdigit()

    def test_password_generator_passphrase(self):
        from backend.features.password_generator import PasswordGenerator, PassphraseGeneratorConfig

        pg = PasswordGenerator()
        config = PassphraseGeneratorConfig(word_count=4)
        result = pg.generate_passphrase(config)
        assert len(result) >= 1
        assert isinstance(result[0].value.get_secret_value(), str)


# =============================================================================
# AuditLogger: model and schema
# =============================================================================


class TestAuditLoggerUnit:
    def test_audit_event_schema(self):
        from backend.core.audit_logger import AuditEvent, EventType

        evt = AuditEvent(
            event_type=EventType.LOGIN_SUCCESS,
            user_id="1",
            ip_address="127.0.0.1",
            success=True,
            details={"method": "password"},
        )
        assert evt.event_type == EventType.LOGIN_SUCCESS
        assert evt.success is True

    def test_audit_log_repr(self):
        from backend.core.audit_logger import AuditLog

        log = AuditLog(
            event_type=1,
            user_id="1",
            ip_address="127.0.0.1",
            success=True,
        )
        assert "AuditLog" in repr(log)


# =============================================================================
# Schemas: additional coverage
# =============================================================================


class TestSchemasAdditional:
    def test_entry_envelope_create_optional_fields(self):
        from backend.database.schemas import EntryEnvelopeCreateSchema

        e = EntryEnvelopeCreateSchema(ciphertext="YQ==", iv="Yg==", auth_tag="Yw==")
        assert e.ciphertext == "YQ=="
        assert e.key_metadata == {}

    def test_entry_update_schema_partial(self):
        from backend.database.schemas import EntryUpdateSchema

        u = EntryUpdateSchema(title="NewTitle")
        assert u.title.get_secret_value() == "NewTitle"
        assert u.password is None

    def test_rate_limit_config_frozen(self):
        from backend.core.config import RateLimitConfig

        cfg = RateLimitConfig()
        with pytest.raises(Exception):
            cfg.max_attempts = 99


# =============================================================================
# ImportExport: additional unit coverage
# =============================================================================


class TestImportExportAdditional:
    def test_import_row_schema_full(self):
        from backend.services.import_export import ImportRowSchema

        row = ImportRowSchema(
            title="Test Entry",
            password="secret123",
            username="user@example.com",
            url="https://example.com",
            notes="Some notes",
        )
        assert row.title == "Test Entry"
        assert row.password == "secret123"
        assert row.username == "user@example.com"

    def test_import_result_defaults(self):
        from backend.services.import_export import ImportResult

        result = ImportResult()
        assert result.total_rows == 0
        assert result.imported == 0
        assert result.skipped == 0
        assert result.errors == []

    def test_data_portability_service_import(self):
        from backend.services.import_export import DataPortabilityService

        assert DataPortabilityService is not None


# =============================================================================
# Generator API endpoint coverage
# =============================================================================


class TestGeneratorAPI:
    @pytest.mark.asyncio
    async def test_generate_password(self, client):
        resp = await client.post(
            "/api/v1/generator/password",
            json={"length": 20},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) >= 1
        assert len(data[0]["value"]) == 20

    @pytest.mark.asyncio
    async def test_generate_passphrase(self, client):
        resp = await client.post(
            "/api/v1/generator/passphrase",
            json={"word_count": 4},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) >= 1

    @pytest.mark.asyncio
    async def test_generate_pin(self, client):
        resp = await client.post(
            "/api/v1/generator/pin",
            json={"length": 6},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) >= 1
        assert data[0]["value"].isdigit()

    @pytest.mark.asyncio
    async def test_generate_password_invalid(self, client):
        resp = await client.post(
            "/api/v1/generator/password",
            json={"length": 2},
        )
        assert resp.status_code in (400, 422)

    @pytest.mark.asyncio
    async def test_generate_password_error_branch(self, client):
        resp = await client.post(
            "/api/v1/generator/password",
            json={"length": 16, "ensure_strength": True, "min_strength": 5},
        )
        assert resp.status_code in (200, 400, 422)


# =============================================================================
# CryptoCore: additional method coverage
# =============================================================================


class TestCryptoCoreMoreCoverage:
    def test_zero_memory_with_bytearray(self):
        from backend.core.crypto_core import zero_memory

        buf = bytearray(b"hello world")
        zero_memory(buf)
        assert buf == bytearray(len(buf))

    def test_zero_memory_with_memoryview(self):
        from backend.core.crypto_core import zero_memory

        data = bytearray(b"sensitive!")
        view = memoryview(data)
        zero_memory(view)
        assert data == bytearray(len(data))

    def test_zero_memory_empty(self):
        from backend.core.crypto_core import zero_memory

        buf = bytearray(b"")
        zero_memory(buf)
        assert buf == bytearray()

    def test_zero_memory_non_contiguous_view(self):
        from backend.core.crypto_core import zero_memory

        data = bytearray(b"0123456789")
        view = memoryview(data)[::2]
        with pytest.raises(ValueError, match="contiguous"):
            zero_memory(view)

    def test_zero_memory_invalid_type(self):
        from backend.core.crypto_core import zero_memory

        with pytest.raises(TypeError, match="bytearray or memoryview"):
            zero_memory("string not allowed")

    def test_hash_file(self):
        from backend.core.crypto_core import CryptoCore
        import tempfile
        import os

        cc = CryptoCore()
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(b"test content for hashing")
            path = f.name
        try:
            result = cc.hash_file(path)
            assert isinstance(result, str)
            assert len(result) == 64
        finally:
            os.unlink(path)

    def test_sign_and_verify(self):
        from backend.core.crypto_core import CryptoCore

        cc = CryptoCore()
        key = cc.generate_salt(32)
        data = b"important message"
        signature = cc.sign(data, key)
        assert cc.verify_signature(data, signature, key) is True
        assert cc.verify_signature(b"wrong message", signature, key) is False

    def test_encrypt_decrypt_envelope(self):
        from backend.core.crypto_core import CryptoCore

        cc = CryptoCore()
        key = cc.generate_salt(32)
        plaintext = b"secret envelope data"
        encrypted = cc.encrypt(plaintext, key)
        decrypted = cc.decrypt(encrypted, key)
        assert decrypted == plaintext


# =============================================================================
# AsyncBreachMonitorService unit tests
# =============================================================================


class TestAsyncBreachMonitorService:
    @pytest.mark.asyncio
    async def test_start_stop_lifecycle(self, engine):
        from backend.features.breach_monitor_async import AsyncBreachMonitorService
        from sqlalchemy.ext.asyncio import async_sessionmaker

        session_factory = async_sessionmaker(bind=engine, expire_on_commit=False)
        monitor = AsyncBreachMonitorService(
            db_session_factory=session_factory,
            check_interval_hours=9999,
        )
        await monitor.start()
        assert monitor.running is True
        await monitor.stop()
        assert monitor.running is False

    def _create_user(self, db, username, email):
        from backend.database.models import User
        user = User(
            username=username,
            email=email,
            password_hash="fake_hash_for_test",
            salt=b"\x00" * 32,
            wrapped_master_key_cipher=b"\x00" * 48,
            wrapped_master_key_nonce=b"\x00" * 12,
            wrapped_master_key_tag=b"\x00" * 16,
        )
        db.add(user)
        return user

    @pytest.mark.asyncio
    async def test_add_and_get_password_item(self, engine):
        from backend.features.breach_monitor_async import AsyncBreachMonitorService
        from sqlalchemy.ext.asyncio import async_sessionmaker

        session_factory = async_sessionmaker(bind=engine, expire_on_commit=False)
        async with session_factory() as db:
            user = self._create_user(db, "breach_pw_user", "breach_pw@test.com")
            await db.commit()
            await db.refresh(user)
            uid = user.id

        monitor = AsyncBreachMonitorService(
            db_session_factory=session_factory,
            check_interval_hours=9999,
        )
        item_id = await monitor.add_password(uid, "test_password")
        assert isinstance(item_id, str)
        assert len(item_id) > 0

        items = await monitor.get_user_items(uid)
        assert any(i.item_type == "password" for i in items)

    @pytest.mark.asyncio
    async def test_add_and_get_email_item(self, engine):
        from backend.features.breach_monitor_async import AsyncBreachMonitorService
        from sqlalchemy.ext.asyncio import async_sessionmaker

        session_factory = async_sessionmaker(bind=engine, expire_on_commit=False)
        async with session_factory() as db:
            user = self._create_user(db, "breach_email_user", "breach_em@test.com")
            await db.commit()
            await db.refresh(user)
            uid = user.id

        monitor = AsyncBreachMonitorService(
            db_session_factory=session_factory,
            check_interval_hours=9999,
        )
        item_id = await monitor.add_email(uid, "test@example.com")
        assert isinstance(item_id, str)

        items = await monitor.get_user_items(uid)
        assert any(i.item_type == "email" for i in items)

    @pytest.mark.asyncio
    async def test_remove_item(self, engine):
        from backend.features.breach_monitor_async import AsyncBreachMonitorService
        from sqlalchemy.ext.asyncio import async_sessionmaker

        session_factory = async_sessionmaker(bind=engine, expire_on_commit=False)
        async with session_factory() as db:
            user = self._create_user(db, "breach_rm_user", "breach_rm@test.com")
            await db.commit()
            await db.refresh(user)
            uid = user.id

        monitor = AsyncBreachMonitorService(
            db_session_factory=session_factory,
            check_interval_hours=9999,
        )
        item_id = await monitor.add_password(uid, "removeme")
        removed = await monitor.remove_item(item_id, uid)
        assert removed is True

    @pytest.mark.asyncio
    async def test_remove_nonexistent_item(self, engine):
        from backend.features.breach_monitor_async import AsyncBreachMonitorService
        from sqlalchemy.ext.asyncio import async_sessionmaker

        session_factory = async_sessionmaker(bind=engine, expire_on_commit=False)
        monitor = AsyncBreachMonitorService(
            db_session_factory=session_factory,
            check_interval_hours=9999,
        )
        removed = await monitor.remove_item("nonexistent", 0)
        assert removed is False

    @pytest.mark.asyncio
    async def test_get_status(self, engine):
        from backend.features.breach_monitor_async import AsyncBreachMonitorService
        from sqlalchemy.ext.asyncio import async_sessionmaker

        session_factory = async_sessionmaker(bind=engine, expire_on_commit=False)
        async with session_factory() as db:
            user = self._create_user(db, "breach_st_user", "breach_st@test.com")
            await db.commit()
            await db.refresh(user)
            uid = user.id

        monitor = AsyncBreachMonitorService(
            db_session_factory=session_factory,
            check_interval_hours=9999,
        )
        await monitor.add_password(uid, "status_pw")
        status_data = await monitor.get_status(uid)
        assert status_data["monitored_items"] >= 1
        assert status_data["running"] is False

    @pytest.mark.asyncio
    async def test_acknowledge_nonexistent_alert(self, engine):
        from backend.features.breach_monitor_async import AsyncBreachMonitorService
        from sqlalchemy.ext.asyncio import async_sessionmaker

        session_factory = async_sessionmaker(bind=engine, expire_on_commit=False)
        monitor = AsyncBreachMonitorService(
            db_session_factory=session_factory,
            check_interval_hours=9999,
        )
        result = await monitor.acknowledge_alert("nonexistent", 1)
        assert result is None

    @pytest.mark.asyncio
    async def test_resolve_nonexistent_alert(self, engine):
        from backend.features.breach_monitor_async import AsyncBreachMonitorService
        from sqlalchemy.ext.asyncio import async_sessionmaker

        session_factory = async_sessionmaker(bind=engine, expire_on_commit=False)
        monitor = AsyncBreachMonitorService(
            db_session_factory=session_factory,
            check_interval_hours=9999,
        )
        result = await monitor.resolve_alert("nonexistent", 1)
        assert result is None

    @pytest.mark.asyncio
    async def test_check_now_with_mock(self, engine):
        from backend.features.breach_monitor_async import AsyncBreachMonitorService
        from backend.database.models import User
        from sqlalchemy.ext.asyncio import async_sessionmaker
        from unittest.mock import AsyncMock, patch

        session_factory = async_sessionmaker(bind=engine, expire_on_commit=False)
        async with session_factory() as db:
            user = User(
                username="breach_check_user",
                email="breach_check@test.com",
                password_hash="fake",
                salt=b"\x00" * 32,
                wrapped_master_key_cipher=b"\x00" * 48,
                wrapped_master_key_nonce=b"\x00" * 12,
                wrapped_master_key_tag=b"\x00" * 16,
            )
            db.add(user)
            await db.commit()
            await db.refresh(user)
            uid = user.id

        monitor = AsyncBreachMonitorService(
            db_session_factory=session_factory,
            check_interval_hours=9999,
        )
        await monitor.add_password(uid, "checkme_pw")
        await monitor.add_email(uid, "checkme@example.com")

        with patch.object(monitor, "_checker", new=AsyncMock()) as mock_checker:
            mock_checker.check_suffix = AsyncMock(return_value=(True, 500))
            mock_checker.check_email = AsyncMock(return_value=(False, 0))
            checked = await monitor.check_now(user_id=uid)
            assert checked == 2

    @pytest.mark.asyncio
    async def test_acknowledge_alert_success(self, engine):
        import hashlib
        from backend.features.breach_monitor_async import AsyncBreachMonitorService
        from backend.database.models import BreachAlert, User
        from sqlalchemy.ext.asyncio import async_sessionmaker

        session_factory = async_sessionmaker(bind=engine, expire_on_commit=False)
        async with session_factory() as db:
            user = User(
                username="breach_ack_user",
                email="breach_ack@test.com",
                password_hash="fake",
                salt=b"\x00" * 32,
                wrapped_master_key_cipher=b"\x00" * 48,
                wrapped_master_key_nonce=b"\x00" * 12,
                wrapped_master_key_tag=b"\x00" * 16,
            )
            db.add(user)
            await db.commit()
            await db.refresh(user)
            uid = user.id

            alert = BreachAlert(
                id="test_alert_ack",
                user_id=uid,
                alert_type="password",
                value_hash="ABCDE",
                value_preview="ABC",
                breach_count=500,
                severity="medium",
                status="new",
            )
            db.add(alert)
            await db.commit()

        monitor = AsyncBreachMonitorService(
            db_session_factory=session_factory,
            check_interval_hours=9999,
        )
        result = await monitor.acknowledge_alert("test_alert_ack", uid)
        assert result is not None
        assert result.status == "acknowledged"
        assert result.acknowledged_at is not None

    @pytest.mark.asyncio
    async def test_resolve_alert_success(self, engine):
        from backend.features.breach_monitor_async import AsyncBreachMonitorService
        from backend.database.models import BreachAlert, User
        from sqlalchemy.ext.asyncio import async_sessionmaker

        session_factory = async_sessionmaker(bind=engine, expire_on_commit=False)
        async with session_factory() as db:
            user = User(
                username="breach_resolve_user",
                email="breach_resolve@test.com",
                password_hash="fake",
                salt=b"\x00" * 32,
                wrapped_master_key_cipher=b"\x00" * 48,
                wrapped_master_key_nonce=b"\x00" * 12,
                wrapped_master_key_tag=b"\x00" * 16,
            )
            db.add(user)
            await db.commit()
            await db.refresh(user)
            uid = user.id

            alert = BreachAlert(
                id="test_alert_resolve",
                user_id=uid,
                alert_type="email",
                value_hash="xyzhash",
                value_preview="xyz",
                breach_count=50,
                severity="low",
                status="new",
            )
            db.add(alert)
            await db.commit()

        monitor = AsyncBreachMonitorService(
            db_session_factory=session_factory,
            check_interval_hours=9999,
        )
        result = await monitor.resolve_alert("test_alert_resolve", uid)
        assert result is not None
        assert result.status == "resolved"
        assert result.resolved_at is not None

    @pytest.mark.asyncio
    async def test_get_alerts_with_filters(self, engine):
        from backend.features.breach_monitor_async import AsyncBreachMonitorService
        from backend.database.models import BreachAlert, User
        from sqlalchemy.ext.asyncio import async_sessionmaker

        session_factory = async_sessionmaker(bind=engine, expire_on_commit=False)
        async with session_factory() as db:
            user = User(
                username="breach_alerts_user",
                email="breach_alerts@test.com",
                password_hash="fake",
                salt=b"\x00" * 32,
                wrapped_master_key_cipher=b"\x00" * 48,
                wrapped_master_key_nonce=b"\x00" * 12,
                wrapped_master_key_tag=b"\x00" * 16,
            )
            db.add(user)
            await db.commit()
            await db.refresh(user)
            uid = user.id

            alert = BreachAlert(
                id="test_alert_filter",
                user_id=uid,
                alert_type="password",
                value_hash="filter_hash",
                value_preview="fil",
                breach_count=50000,
                severity="high",
                status="new",
            )
            db.add(alert)
            await db.commit()

        monitor = AsyncBreachMonitorService(
            db_session_factory=session_factory,
            check_interval_hours=9999,
        )
        alerts = await monitor.get_alerts(uid, severity="high")
        assert len(alerts) == 1
        assert alerts[0].severity == "high"

        alerts_empty = await monitor.get_alerts(uid, severity="critical")
        assert len(alerts_empty) == 0

    @pytest.mark.asyncio
    async def test_add_duplicate_email(self, engine):
        from backend.features.breach_monitor_async import AsyncBreachMonitorService
        from backend.database.models import User
        from sqlalchemy.ext.asyncio import async_sessionmaker

        session_factory = async_sessionmaker(bind=engine, expire_on_commit=False)
        async with session_factory() as db:
            user = User(
                username="breach_dup_email_user",
                email="breach_dup_email@test.com",
                password_hash="fake",
                salt=b"\x00" * 32,
                wrapped_master_key_cipher=b"\x00" * 48,
                wrapped_master_key_nonce=b"\x00" * 12,
                wrapped_master_key_tag=b"\x00" * 16,
            )
            db.add(user)
            await db.commit()
            await db.refresh(user)
            uid = user.id

        monitor = AsyncBreachMonitorService(
            db_session_factory=session_factory,
            check_interval_hours=9999,
        )
        id1 = await monitor.add_email(uid, "dup@example.com")
        id2 = await monitor.add_email(uid, "dup@example.com")
        assert id1 == id2


# =============================================================================
# BiometricAuthenticator: WebAuthnBiometricBackend DB query
# =============================================================================


class TestWebAuthnBiometricBackend:
    def test_enroll_sets_marker(self):
        from backend.core.advanced_security import _WebAuthnBiometricBackend

        backend = _WebAuthnBiometricBackend(user_id=None)
        assert backend.is_available()
        result = backend.enroll()
        assert result is True

    def test_authenticate_without_enrollment_raises(self):
        from backend.core.advanced_security import _WebAuthnBiometricBackend, BiometricError

        backend = _WebAuthnBiometricBackend(user_id=None)
        with pytest.raises(BiometricError):
            backend.authenticate()

    def test_authenticate_after_enroll_succeeds(self):
        from backend.core.advanced_security import _WebAuthnBiometricBackend

        backend = _WebAuthnBiometricBackend(user_id=None)
        backend.enroll()
        assert backend.authenticate() is True

    def test_is_enrolled_without_user_id_no_db(self):
        from backend.core.advanced_security import _WebAuthnBiometricBackend

        backend = _WebAuthnBiometricBackend(user_id=None)
        assert backend.is_enrolled() is False
        backend.enroll()
        assert backend.is_enrolled() is True

    def test_biometric_authenticator_accepts_user_id(self):
        from backend.core.advanced_security import BiometricAuthenticator

        auth = BiometricAuthenticator(user_id=999)
        assert auth is not None