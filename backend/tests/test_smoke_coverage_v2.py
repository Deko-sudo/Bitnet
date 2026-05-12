# -*- coding: utf-8 -*-
"""
Quick smoke tests to exercise import-time code and trivial helpers across
modules with coverage gaps.  Avoids crash-prone paths (SecureMemoryBuffer).
"""
from __future__ import annotations

import pytest


class TestBreachMonitorSmoke:
    def test_async_service_import(self):
        from backend.features.breach_monitor_async import AsyncBreachMonitorService
        assert AsyncBreachMonitorService is not None

    def test_severity_function(self):
        from backend.features.breach_monitor_async import _severity
        assert _severity(5) == "low"
        assert _severity(500) == "medium"
        assert _severity(50000) == "high"
        assert _severity(5000000) == "critical"

    def test_quick_check_functions_import(self):
        from backend.features.breach_monitor_async import quick_check_password, quick_check_email
        assert callable(quick_check_password)
        assert callable(quick_check_email)

    def test_async_service_import(self):
        from backend.features.breach_monitor_async import AsyncBreachMonitorService
        assert AsyncBreachMonitorService is not None

    def test_severity_function(self):
        from backend.features.breach_monitor_async import _severity
        assert _severity(5) == "low"
        assert _severity(500) == "medium"
        assert _severity(50000) == "high"
        assert _severity(5000000) == "critical"

    @pytest.mark.asyncio
    async def test_async_service_lifecycle(self, engine):
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


class TestAdvancedSecuritySmoke:
    def test_totp(self):
        from backend.core.advanced_security import (
            TOTPAuthenticator,
            RecoveryCodeManager,
            HaveIBeenPwnedChecker,
        )
        assert TOTPAuthenticator is not None
        assert RecoveryCodeManager is not None
        assert HaveIBeenPwnedChecker is not None

    def test_pwned_checker(self):
        from backend.core.advanced_security import HaveIBeenPwnedChecker
        checker = HaveIBeenPwnedChecker()
        assert checker is not None


class TestAuthManagerSmoke:
    def test_exceptions(self):
        from backend.core.auth_manager import (
            AuthError,
            NotLockedError,
            AlreadyLockedError,
            SessionExpiredError,
        )
        assert isinstance(NotLockedError(), AuthError)
        assert isinstance(AlreadyLockedError(), AuthError)
        assert isinstance(SessionExpiredError(), AuthError)

    def test_session_state(self):
        from backend.core.auth_manager import SessionState
        st = SessionState()
        assert st.is_locked is True

class TestSecureDeleteSmoke:
    def test_class_exists(self):
        from backend.core.secure_delete import SecureFileDeleter
        assert SecureFileDeleter is not None
        deleter = SecureFileDeleter(passes=1)
        assert deleter is not None


class TestEntryServiceSmoke:
    @pytest.mark.asyncio
    async def test_empty_search(self, db_session):
        from backend.database.entry_service import EntryService
        service = EntryService(db_session)
        assert await service.search_entries_async(1, "none") == []


class TestBackupManagerSmoke:
    def test_exceptions(self):
        from backend.features.backup_manager import BackupError, _InvalidHMAC
        assert str(BackupError("b")) == "b"
        assert isinstance(_InvalidHMAC(), BackupError)


class TestPasswordHistorySmoke:
    @pytest.mark.asyncio
    async def test_empty(self, db_session):
        from backend.features.password_history_manager import PasswordHistoryManager
        from unittest.mock import MagicMock
        mgr = PasswordHistoryManager(db_session)
        assert await mgr.get_history_async(1, MagicMock()) == []


class TestAuditLoggerSmoke:
    def test_enums_and_classes(self):
        from backend.core.audit_logger import EventType, AuditLog, AuditEvent, AuditLogger
        assert EventType.LOGIN_ATTEMPT.value == 1
        assert AuditLog is not None
        assert AuditEvent is not None
        assert AuditLogger is not None

    def test_audit_event_ip(self):
        from backend.core.audit_logger import AuditEvent, EventType
        ev = AuditEvent(event_type=EventType.LOGIN_ATTEMPT, ip_address="192.168.1.1")
        assert ev.ip_address == "192.168.1.1"
