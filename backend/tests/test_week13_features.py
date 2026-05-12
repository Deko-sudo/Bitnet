# -*- coding: utf-8 -*-
"""
Tests for Week 13+ Advanced Security Features

Tests for:
- FIDO2/WebAuthn authentication
- QR Code generation
- Breach monitoring service

Author: Nikita (BE1)
Version: 1.0.0
"""

import pytest
import time
import hashlib
import os
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime


# =============================================================================
# QR Generator Tests
# =============================================================================

# Проверка доступности QR перед тестами
try:
    from backend.features.qr_generator import QRCodeGenerator, QR_AVAILABLE
    QR_TESTS_AVAILABLE = QR_AVAILABLE
except ImportError:
    QR_TESTS_AVAILABLE = False


@pytest.mark.skipif(not QR_TESTS_AVAILABLE, reason="qrcode not installed")
class TestQRCodeGenerator:
    """Tests for QR code generator."""

    @pytest.fixture
    def qr_generator(self):
        """Create QR code generator."""
        return QRCodeGenerator()
    
    def test_initialization(self, qr_generator):
        """Test QR generator initialization."""
        assert qr_generator._box_size == 10
        assert qr_generator._border == 4
    
    def test_generate_png(self, qr_generator):
        """Test PNG generation."""
        data = "https://example.com"
        result = qr_generator.generate(data, output_format="png")
        
        assert isinstance(result, bytes)
        assert len(result) > 0
        # PNG magic bytes
        assert result[:4] == b'\x89PNG'
    
    def test_generate_base64(self, qr_generator):
        """Test Base64 generation."""
        data = "https://example.com"
        result = qr_generator.generate(data, output_format="base64")
        
        assert isinstance(result, str)
        assert len(result) > 0
        # Base64 should only contain valid characters
        import re
        assert re.match(r'^[A-Za-z0-9+/=]+$', result)
    
    def test_generate_svg(self, qr_generator):
        """Test SVG generation."""
        data = "https://example.com"
        result = qr_generator.generate(data, output_format="svg")
        
        assert isinstance(result, str)
        assert '<svg' in result
        assert '</svg>' in result
    
    def test_generate_ascii(self, qr_generator):
        """Test ASCII art generation."""
        data = "https://example.com"
        result = qr_generator.generate(data, output_format="ascii")
        
        assert isinstance(result, str)
        assert '██' in result  # Should contain block characters
    
    def test_generate_totp_qr(self, qr_generator):
        """Test TOTP QR code generation."""
        result = qr_generator.generate_totp_qr(
            username="user@example.com",
            secret="ABC123DEF456",
            issuer="TestApp",
            output_format="base64"
        )
        
        assert isinstance(result, str)
        assert len(result) > 0
    
    def test_generate_with_cache(self, qr_generator):
        """Test caching functionality."""
        data = "https://example.com"
        
        # First generation
        result1 = qr_generator.generate(data, use_cache=True)
        
        # Second generation (should use cache)
        result2 = qr_generator.generate(data, use_cache=True)
        
        assert result1 == result2
        assert len(qr_generator._cache) == 1
    
    def test_clear_cache(self, qr_generator):
        """Test cache clearing."""
        data = "https://example.com"
        qr_generator.generate(data, use_cache=True)
        
        qr_generator.clear_cache()
        
        assert len(qr_generator._cache) == 0
    
    def test_get_stats(self, qr_generator):
        """Test statistics retrieval."""
        stats = qr_generator.get_stats()
        
        assert 'cached_items' in stats
        assert 'qr_available' in stats
    
    def test_generate_invalid_format(self, qr_generator):
        """Test error handling for invalid format."""
        from backend.features.qr_generator import QRCodeGenerationError
        
        with pytest.raises(QRCodeGenerationError):
            qr_generator.generate("data", output_format="invalid")


class TestQRCodeConvenienceFunctions:
    """Tests for QR convenience functions."""
    
    def test_generate_totp_qr_function(self):
        """Test convenience function for TOTP QR."""
        try:
            from backend.features.qr_generator import generate_totp_qr
        except ImportError:
            pytest.skip("qrcode not installed")
        
        result = generate_totp_qr(
            username="user@example.com",
            secret="ABC123",
            issuer="TestApp"
        )
        
        assert isinstance(result, str)
        assert len(result) > 0
    
    def test_generate_qr_file_function(self, tmp_path):
        """Test convenience function for file generation."""
        try:
            from backend.features.qr_generator import generate_qr_file
        except ImportError:
            pytest.skip("qrcode not installed")
        
        filepath = tmp_path / "test_qr.png"
        result_path = generate_qr_file("https://example.com", filepath)
        
        assert result_path.exists()
        assert result_path.stat().st_size > 0


# =============================================================================
# Breach Monitor Tests (async)
# =============================================================================


@pytest.mark.asyncio
class TestBreachMonitorAsync:
    async def test_service_lifecycle(self, engine):
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

    async def test_double_start_is_noop(self, engine):
        from backend.features.breach_monitor_async import AsyncBreachMonitorService
        from sqlalchemy.ext.asyncio import async_sessionmaker

        session_factory = async_sessionmaker(bind=engine, expire_on_commit=False)
        monitor = AsyncBreachMonitorService(
            db_session_factory=session_factory,
            check_interval_hours=9999,
        )
        await monitor.start()
        await monitor.start()
        assert monitor.running is True
        await monitor.stop()

    async def test_dedup_password(self, engine):
        from backend.features.breach_monitor_async import AsyncBreachMonitorService
        from sqlalchemy.ext.asyncio import async_sessionmaker
        from backend.database.models import User

        session_factory = async_sessionmaker(bind=engine, expire_on_commit=False)
        monitor = AsyncBreachMonitorService(
            db_session_factory=session_factory,
            check_interval_hours=9999,
        )
        await monitor.start()
        try:
            async with session_factory() as session:
                user = User(
                    username="breach_dedup_user",
                    email="dedup@test.com",
                    password_hash="x",
                    salt=b"salt_1234567890123456",
                    wrapped_master_key_cipher=b"w",
                    wrapped_master_key_nonce=b"n",
                    wrapped_master_key_tag=b"t",
                    session_token_hash="a" * 64,
                )
                session.add(user)
                await session.commit()
                await session.refresh(user)
                uid = user.id

            id1 = await monitor.add_password(uid, "DedupPassword1")
            id2 = await monitor.add_password(uid, "DedupPassword1")
            assert id1 == id2
        finally:
            await monitor.stop()

    async def test_check_item_email_no_runtime_email(self, engine):
        from backend.features.breach_monitor_async import AsyncBreachMonitorService
        from backend.database.models import MonitoredItem
        from sqlalchemy.ext.asyncio import async_sessionmaker

        session_factory = async_sessionmaker(bind=engine, expire_on_commit=False)
        monitor = AsyncBreachMonitorService(
            db_session_factory=session_factory,
            check_interval_hours=9999,
        )
        await monitor.start()
        try:
            item = MonitoredItem(
                id="no_runtime_email_item",
                user_id=99999,
                item_type="email",
                value_hash="abc123",
            )
            await monitor._check_item(item)
        finally:
            await monitor.stop()

    async def test_check_item_unknown_type(self, engine):
        from backend.features.breach_monitor_async import AsyncBreachMonitorService
        from backend.database.models import MonitoredItem
        from sqlalchemy.ext.asyncio import async_sessionmaker

        session_factory = async_sessionmaker(bind=engine, expire_on_commit=False)
        monitor = AsyncBreachMonitorService(
            db_session_factory=session_factory,
            check_interval_hours=9999,
        )
        await monitor.start()
        try:
            item = MonitoredItem(
                id="unknown_type_item",
                user_id=99999,
                item_type="domain",
                value_hash="def456",
            )
            await monitor._check_item(item)
        finally:
            await monitor.stop()

    async def test_duplicate_alert_suppression(self, engine):
        from backend.features.breach_monitor_async import AsyncBreachMonitorService
        from backend.database.models import User, MonitoredItem, BreachAlert
        from sqlalchemy.ext.asyncio import async_sessionmaker
        from sqlalchemy import select, func as sa_func

        session_factory = async_sessionmaker(bind=engine, expire_on_commit=False)
        monitor = AsyncBreachMonitorService(
            db_session_factory=session_factory,
            check_interval_hours=9999,
        )
        await monitor.start()
        try:
            async with session_factory() as session:
                user = User(
                    username="alert_dedup_user",
                    email="alert_dedup@test.com",
                    password_hash="x",
                    salt=b"salt_1234567890123456",
                    wrapped_master_key_cipher=b"w",
                    wrapped_master_key_nonce=b"n",
                    wrapped_master_key_tag=b"t",
                    session_token_hash="b" * 64,
                )
                session.add(user)
                await session.commit()
                await session.refresh(user)
                uid = user.id

            await monitor._create_alert(
                MonitoredItem(
                    id="alert_dedup_item",
                    user_id=uid,
                    item_type="password",
                    value_hash="AAAAA",
                ),
                500,
            )
            await monitor._create_alert(
                MonitoredItem(
                    id="alert_dedup_item2",
                    user_id=uid,
                    item_type="password",
                    value_hash="AAAAA",
                ),
                500,
            )

            async with session_factory() as session:
                count = await session.scalar(
                    select(sa_func.count()).where(
                        BreachAlert.user_id == uid,
                        BreachAlert.value_hash == "AAAAA",
                        BreachAlert.status == "new",
                    )
                )
                assert count == 1
        finally:
            await monitor.stop()

    async def test_check_item_no_checker(self, engine):
        from backend.features.breach_monitor_async import AsyncBreachMonitorService
        from backend.database.models import MonitoredItem
        from sqlalchemy.ext.asyncio import async_sessionmaker

        session_factory = async_sessionmaker(bind=engine, expire_on_commit=False)
        monitor = AsyncBreachMonitorService(
            db_session_factory=session_factory,
            check_interval_hours=9999,
        )
        monitor._checker = None
        item = MonitoredItem(
            id="no_checker_item",
            user_id=99999,
            item_type="password",
            value_hash="BBBBB",
        )
        await monitor._check_item(item)

    async def test_monitor_loop_iteration(self, engine):
        from backend.features.breach_monitor_async import AsyncBreachMonitorService
        from sqlalchemy.ext.asyncio import async_sessionmaker

        session_factory = async_sessionmaker(bind=engine, expire_on_commit=False)
        monitor = AsyncBreachMonitorService(
            db_session_factory=session_factory,
            check_interval_hours=0,
        )
        await monitor.start()
        try:
            import asyncio
            await asyncio.sleep(0.3)
        finally:
            await monitor.stop()


class TestQuickCheckFunctions:
    def test_quick_check_password_returns_tuple(self):
        from backend.features.breach_monitor_async import quick_check_password
        from unittest.mock import patch

        with patch("backend.features.breach_monitor_async.HaveIBeenPwnedChecker._fetch_hashes", return_value=""):
            result = quick_check_password("test_password_123")
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_quick_check_password_connection_error(self):
        from backend.features.breach_monitor_async import quick_check_password
        from unittest.mock import patch

        with patch("backend.features.breach_monitor_async.HaveIBeenPwnedChecker._fetch_hashes", side_effect=ConnectionError):
            result = quick_check_password("test_password_123")
        assert result == (False, 0)

    def test_quick_check_password_match(self):
        from backend.features.breach_monitor_async import quick_check_password
        from unittest.mock import patch
        import hashlib

        sha1 = hashlib.sha1(b"test_password_123", usedforsecurity=False).hexdigest().upper()
        suffix = sha1[5:]
        fake_response = f"{suffix}:42\nOTHERSUFFIX:1"
        with patch("backend.features.breach_monitor_async.HaveIBeenPwnedChecker._fetch_hashes", return_value=fake_response):
            result = quick_check_password("test_password_123")
        assert result[0] is True
        assert result[1] == 42

    def test_quick_check_email_returns_tuple(self):
        from backend.features.breach_monitor_async import quick_check_email

        with patch("backend.core.advanced_security.HaveIBeenPwnedChecker.check_email_sync") as mocked_check:
            mocked_check.return_value = (True, 42)
            result = quick_check_email("test@example.com")

        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_quick_check_email_connection_error(self):
        from backend.features.breach_monitor_async import quick_check_email

        with patch("backend.core.advanced_security.HaveIBeenPwnedChecker.check_email_sync", side_effect=ConnectionError):
            result = quick_check_email("test@example.com")
        assert result == (False, 0)

    def test_quick_check_email_permission_error(self):
        from backend.features.breach_monitor_async import quick_check_email

        with patch("backend.core.advanced_security.HaveIBeenPwnedChecker.check_email_sync", side_effect=PermissionError):
            result = quick_check_email("test@example.com")
        assert result == (False, 0)


# =============================================================================
# Integration Tests
# =============================================================================

class TestWeek13Integration:
    """Integration tests for Week 13+ features."""

    @pytest.mark.skipif(not QR_TESTS_AVAILABLE, reason="qrcode not installed")
    def test_totp_with_qr_code(self):
        """Test complete TOTP setup with QR code."""
        from backend.core.advanced_security import TOTPAuthenticator
        
        # Setup TOTP
        totp = TOTPAuthenticator()
        secret, uri = totp.setup("user@example.com", "TestApp")
        
        # Generate QR code
        qr = QRCodeGenerator()
        qr_base64 = qr.generate(uri, output_format="base64")
        
        assert isinstance(secret, str)
        assert uri.startswith("otpauth://")
        assert isinstance(qr_base64, str)
        assert len(qr_base64) > 0
    

    @pytest.mark.skipif(not QR_TESTS_AVAILABLE, reason="qrcode not installed")
    def test_qr_feature_flag(self):
        """Test QR feature availability check."""
        
        assert isinstance(QR_AVAILABLE, bool)
