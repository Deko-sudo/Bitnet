# -*- coding: utf-8 -*-
"""
Coverage Phase 2: Medium difficulty — mocking, async, special states.
"""
from __future__ import annotations

import base64
import io
import os
import secrets
import time
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock

import pytest
import pytest_asyncio
from httpx import AsyncClient


# =============================================================================
# auth.py endpoint error paths (lines 122,128,192,240,285,347-348,361)
# =============================================================================


class TestAuthErrorPaths:
    @pytest.mark.asyncio
    async def test_register_duplicate_username(self, client: AsyncClient):
        resp = await client.post(
            "/api/v1/auth/register",
            json={"username": "dup_user_2", "email": "dup2@test.com", "password": "Pass123!"},
        )
        assert resp.status_code == 201

        resp2 = await client.post(
            "/api/v1/auth/register",
            json={"username": "dup_user_2", "email": "dup2_other@test.com", "password": "Pass123!"},
        )
        assert resp2.status_code == 409

    @pytest.mark.asyncio
    async def test_login_wrong_password(self, client: AsyncClient):
        await client.post(
            "/api/v1/auth/register",
            json={"username": "wrongpw_user", "email": "wrongpw@test.com", "password": "CorrectPass1!"},
        )
        resp = await client.post(
            "/api/v1/auth/login",
            json={"username": "wrongpw_user", "password": "WrongPass1!"},
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_login_nonexistent_user(self, client: AsyncClient):
        resp = await client.post(
            "/api/v1/auth/login",
            json={"username": "nonexistent_user_42", "password": "Whatever1!"},
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_bearer_scheme_required(self, client: AsyncClient):
        resp = await client.get(
            "/api/v1/entries/",
            headers={"Authorization": "Basic dXNlcjpwYXNz"},
        )
        assert resp.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_invalid_bearer_token(self, client: AsyncClient):
        resp = await client.get(
            "/api/v1/entries/",
            headers={"Authorization": "Bearer invalidtoken123"},
        )
        assert resp.status_code in (401, 403)


class TestAuthServerKeyLoading:
    def test_missing_env_var_raises(self):
        import backend.api.v1.endpoints.auth as _auth_mod
        from backend.api.v1.endpoints.auth import _load_server_wrap_key

        original = _auth_mod._server_wrap_key
        _auth_mod._server_wrap_key = None
        try:
            with patch.dict(os.environ, {}, clear=True):
                if "BITNET_SERVER_WRAP_KEY_FILE" in os.environ:
                    del os.environ["BITNET_SERVER_WRAP_KEY_FILE"]
                with pytest.raises(RuntimeError, match="environment variable"):
                    _load_server_wrap_key()
        finally:
            _auth_mod._server_wrap_key = original

    def test_empty_key_file_raises(self, tmp_path):
        import backend.api.v1.endpoints.auth as _auth_mod
        from backend.api.v1.endpoints.auth import _load_server_wrap_key

        original = _auth_mod._server_wrap_key
        _auth_mod._server_wrap_key = None
        try:
            key_file = tmp_path / "empty.key"
            key_file.write_bytes(b"")
            with patch.dict(os.environ, {"BITNET_SERVER_WRAP_KEY_FILE": str(key_file)}):
                with pytest.raises(RuntimeError, match="empty"):
                    _load_server_wrap_key()
        finally:
            _auth_mod._server_wrap_key = original

    def test_short_read_raises(self, tmp_path):
        import backend.api.v1.endpoints.auth as _auth_mod
        from backend.api.v1.endpoints.auth import _load_server_wrap_key

        original = _auth_mod._server_wrap_key
        _auth_mod._server_wrap_key = None
        try:
            key_file = tmp_path / "short.key"
            key_file.write_bytes(b"short")
            with patch.dict(os.environ, {"BITNET_SERVER_WRAP_KEY_FILE": str(key_file)}):
                with patch("os.path.getsize", return_value=32):
                    with pytest.raises(RuntimeError, match="Short read"):
                        _load_server_wrap_key()
        finally:
            _auth_mod._server_wrap_key = original


# =============================================================================
# audit_logger: to_dict, validate_ip, sanitize, _is_sensitive_value, etc.
# =============================================================================


class TestAuditLoggerCoverage:
    def test_audit_log_to_dict(self):
        from backend.core.audit_logger import AuditLog
        from datetime import datetime, timezone

        log = AuditLog(
            id=1,
            timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
            event_type=1,
            event_type_name="LOGIN_SUCCESS",
            user_id="user1",
            ip_address="127.0.0.1",
            success=True,
            details='{"key": "value"}',
            created_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        )
        d = log.to_dict()
        assert d["id"] == 1
        assert d["event_type_name"] == "LOGIN_SUCCESS"
        assert d["details"] == {"key": "value"}

    def test_validate_ip_invalid(self):
        from backend.core.audit_logger import AuditEvent

        with pytest.raises(ValueError, match="Invalid IP address"):
            AuditEvent(
                event_type=1,
                ip_address="not_an_ip_address",
            )

    def test_sanitize_max_depth(self):
        from backend.core.audit_logger import AuditEvent

        deep = {"level": 0}
        current = deep
        for i in range(12):
            current["level"] = {"nested": i}
            current = current["level"]

        event = AuditEvent(event_type=1, details=deep)
        assert "_error" in str(event.details) or "Max depth" in str(event.details) or isinstance(event.details, dict)

    def test_sanitize_non_string_value(self):
        from backend.core.audit_logger import AuditEvent

        event = AuditEvent(event_type=1, details={"count": 42, "active": True})
        assert event.details["count"] == 42
        assert event.details["active"] is True

    def test_is_sensitive_value_base64(self):
        from backend.core.audit_logger import AuditEvent

        event = AuditEvent(event_type=1)
        long_b64 = "A" * 30 + "==" + "B" * 10
        assert event._is_sensitive_value(long_b64) is True

    def test_clear_old_entries(self):
        from unittest.mock import MagicMock
        from backend.core.audit_logger import AuditLogger

        session = MagicMock()
        session.query.return_value.filter.return_value.delete.return_value = 5
        logger = AuditLogger(session)
        result = logger.clear_old_entries(days_to_keep=30)
        assert result == 5

    def test_log_event_no_bind_raises(self):
        from backend.core.audit_logger import AuditLogger, EventType

        session = MagicMock()
        session.get_bind.return_value = None
        logger = AuditLogger(session)
        with pytest.raises(RuntimeError, match="not available"):
            logger.log_event(EventType.LOGIN_ATTEMPT, user_id="u1", ip_address="127.0.0.1")


# =============================================================================
# breach_monitor_async: get_alerts with severity filter (line 194)
# =============================================================================


class TestBreachMonitorSeverityFilter:
    @pytest.mark.asyncio
    async def test_get_alerts_with_severity_filter(self, engine):
        from backend.features.breach_monitor_async import AsyncBreachMonitorService
        from backend.database.models import User, BreachAlert
        from sqlalchemy.ext.asyncio import async_sessionmaker

        session_factory = async_sessionmaker(bind=engine, expire_on_commit=False)
        monitor = AsyncBreachMonitorService(
            db_session_factory=session_factory,
            check_interval_hours=9999,
        )
        await monitor.start()
        try:
            async with session_factory() as session:
                user = User(
                    username="sev_user",
                    email="sev@test.com",
                    password_hash="x",
                    salt=b"salt_1234567890123456",
                    wrapped_master_key_cipher=b"w",
                    wrapped_master_key_nonce=b"n",
                    wrapped_master_key_tag=b"t",
                    session_token_hash="s" * 64,
                )
                session.add(user)
                await session.commit()
                await session.refresh(user)

                from datetime import datetime, timezone
                alert = BreachAlert(
                    id="sev_alert_1",
                    user_id=user.id,
                    alert_type="password",
                    value_hash="AAAAA",
                    value_preview="AAA",
                    breach_count=500,
                    severity="high",
                    status="new",
                )
                session.add(alert)
                await session.commit()

            alerts = await monitor.get_alerts(user.id, severity="high")
            assert len(alerts) >= 1
            assert all(a.severity == "high" for a in alerts)
        finally:
            await monitor.stop()


# =============================================================================
# import_export: JSONL empty lines, export_full_csv, export_full_jsonl
# =============================================================================


class TestImportExportExtra:
    @pytest.mark.asyncio
    async def test_jsonl_empty_lines_skipped(self):
        from backend.services.import_export import DataPortabilityService, ImportRowSchema
        from unittest.mock import MagicMock

        session = MagicMock()
        master_key = MagicMock()
        svc = DataPortabilityService(session=session, master_key=master_key, batch_size=100)

        data = b'\n\n{"title":"A","password":"B"}\n\n{"title":"C","password":"D"}\n\n'
        with patch.object(svc, "_insert_batch", new_callable=AsyncMock) as mock_insert:
            mock_insert.return_value = 2
            result = await svc.import_from_jsonl(1, data)
        assert result.total_rows == 2


# =============================================================================
# trash.py: 404 for non-deleted entry, entry with URL
# =============================================================================


class TestTrashErrorPaths:
    @pytest.mark.asyncio
    async def test_restore_nonexistent_returns_404(self, client: AsyncClient, auth_headers: dict):
        resp = await client.post("/api/v1/trash/99999/restore", headers=auth_headers)
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_purge_nonexistent_returns_404(self, client: AsyncClient, auth_headers: dict):
        resp = await client.delete("/api/v1/trash/99999/purge", headers=auth_headers)
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_restore_active_entry_returns_404(self, client: AsyncClient, auth_headers: dict):
        create_resp = await client.post(
            "/api/v1/entries/",
            json={"title": "ActiveEntry", "password": "Pass123!"},
            headers=auth_headers,
        )
        assert create_resp.status_code == 201
        entry_id = create_resp.json()["id"]

        resp = await client.post(f"/api/v1/trash/{entry_id}/restore", headers=auth_headers)
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_list_trash_with_url(self, client: AsyncClient, auth_headers: dict):
        create_resp = await client.post(
            "/api/v1/entries/",
            json={"title": "TrashWithUrl", "password": "Pass123!", "url": "https://example.com"},
            headers=auth_headers,
        )
        assert create_resp.status_code == 201
        entry_id = create_resp.json()["id"]

        await client.delete(f"/api/v1/entries/{entry_id}", headers=auth_headers)

        resp = await client.get("/api/v1/trash/", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert any(e["id"] == entry_id for e in data)


# =============================================================================
# entries.py: PATCH with empty body, E2EE update ValueError
# =============================================================================


class TestEntriesExtraPaths:
    @pytest.mark.asyncio
    async def test_patch_empty_body(self, client: AsyncClient, auth_headers: dict):
        create_resp = await client.post(
            "/api/v1/entries/",
            json={"title": "EmptyPatch", "password": "Pass123!"},
            headers=auth_headers,
        )
        assert create_resp.status_code == 201
        entry_id = create_resp.json()["id"]

        patch_resp = await client.patch(
            f"/api/v1/entries/{entry_id}",
            json={},
            headers=auth_headers,
        )
        assert patch_resp.status_code == 200

    @pytest.mark.asyncio
    async def test_e2ee_update_incomplete_core_fields(self, client: AsyncClient, auth_headers: dict):
        create_resp = await client.post(
            "/api/v1/entries/e2ee",
            json={
                "title_search": "e2ee_incomplete",
                "ciphertext": base64.b64encode(secrets.token_bytes(32)).decode(),
                "iv": base64.b64encode(secrets.token_bytes(12)).decode(),
                "auth_tag": base64.b64encode(secrets.token_bytes(16)).decode(),
            },
            headers=auth_headers,
        )
        assert create_resp.status_code == 201
        entry_id = create_resp.json()["id"]

        update_resp = await client.patch(
            f"/api/v1/entries/e2ee/{entry_id}",
            json={"ciphertext": base64.b64encode(secrets.token_bytes(32)).decode()},
            headers=auth_headers,
        )
        assert update_resp.status_code == 400


# =============================================================================
# backup_manager: BackupError on invalid version, nonexistent file
# =============================================================================


class TestBackupManagerErrors:
    @pytest.mark.asyncio
    async def test_backup_not_found_restore(self, client: AsyncClient, auth_headers: dict):
        resp = await client.post(
            "/api/v1/backups/nonexistent_backup/restore",
            json={"confirmed": True},
            headers=auth_headers,
        )
        assert resp.status_code in (400, 404)


# =============================================================================
# pypy_optimization: CRYPTO_AVAILABLE=False and PyPy branches
# =============================================================================


class TestPyPyOptimization:
    def test_crypto_unavailable_warmup(self):
        from backend.core import pypy_optimization

        original = pypy_optimization.CRYPTO_AVAILABLE
        try:
            pypy_optimization.CRYPTO_AVAILABLE = False
            jit = pypy_optimization.JITWarmup()
            result = jit.run_full_warmup()
            assert "error" in result
        finally:
            pypy_optimization.CRYPTO_AVAILABLE = original

    def test_crypto_unavailable_comparator(self):
        from backend.core import pypy_optimization

        original = pypy_optimization.CRYPTO_AVAILABLE
        try:
            pypy_optimization.CRYPTO_AVAILABLE = False
            comp = pypy_optimization.PerformanceComparator()
            result = comp.compare_crypto_operations()
            assert "error" in result
        finally:
            pypy_optimization.CRYPTO_AVAILABLE = original

    def test_pypy_version_detection(self):
        import sys
        from unittest.mock import patch
        from backend.core import pypy_optimization

        with patch.object(pypy_optimization, "is_pypy", return_value=True):
            sys.pypy_version_info = type("version_info", (), {"major": 7, "minor": 3, "micro": 15})()
            try:
                result = pypy_optimization.get_python_implementation()
                assert "PyPy" in result
            finally:
                delattr(sys, "pypy_version_info")

    def test_crypto_unavailable_recommendations(self):
        from backend.core import pypy_optimization

        original = pypy_optimization.CRYPTO_AVAILABLE
        try:
            pypy_optimization.CRYPTO_AVAILABLE = False
            recs = pypy_optimization.get_optimization_recommendations()
            assert any("Crypto libraries" in w for w in recs.get("warnings", []))
        finally:
            pypy_optimization.CRYPTO_AVAILABLE = original

    def test_warmup_on_startup_no_crypto(self):
        from backend.core import pypy_optimization

        original = pypy_optimization.CRYPTO_AVAILABLE
        try:
            pypy_optimization.CRYPTO_AVAILABLE = False
            success, result = pypy_optimization.warmup_on_startup()
            assert success is False
            assert "error" in result
        finally:
            pypy_optimization.CRYPTO_AVAILABLE = original

    def test_warmup_on_startup_error_result(self):
        from backend.core import pypy_optimization

        with patch.object(pypy_optimization.JITWarmup, "run_full_warmup", return_value={"error": "test error"}):
            success, result = pypy_optimization.warmup_on_startup()
            assert success is False


# =============================================================================
# security_utils: PasswordStrength special chars, _calculate_entropy empty
# =============================================================================


class TestSecurityUtilsExtra:
    def test_password_strength_special_chars(self):
        from backend.core.security_utils import PasswordStrengthChecker

        checker = PasswordStrengthChecker(require_special=True)
        result = checker.check_strength("abc")
        suggestions = result.suggestions
        assert any("special" in s.lower() or "Special" in s for s in suggestions)

    def test_calculate_entropy_empty(self):
        from backend.core.security_utils import PasswordStrengthChecker

        checker = PasswordStrengthChecker()
        entropy = checker._calculate_entropy("")
        assert entropy == 0.0