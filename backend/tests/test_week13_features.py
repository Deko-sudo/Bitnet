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
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime


# =============================================================================
# FIDO2 Tests
# =============================================================================

# Проверка доступности FIDO2 перед тестами
try:
    from backend.core.fido2_auth import FIDO2Authenticator, FIDO2Key, FIDO2_AVAILABLE
    FIDO2_TESTS_AVAILABLE = FIDO2_AVAILABLE
except (ImportError, NameError):
    FIDO2_TESTS_AVAILABLE = False


@pytest.mark.skipif(not FIDO2_TESTS_AVAILABLE, reason="python-fido2 not installed")
class TestFIDO2Authenticator:
    """Tests for FIDO2 authenticator."""

    @pytest.fixture
    def fido(self):
        """Create FIDO2 authenticator."""
        return FIDO2Authenticator(
            rp_id="example.com",
            rp_name="Test Password Manager"
        )
    
    def test_initialization(self, fido):
        """Test FIDO2 authenticator initialization."""
        assert fido._rp_id == "example.com"
        assert fido._rp.name == "Test Password Manager"
    
    def test_no_keys_initially(self, fido):
        """Test that user has no keys initially."""
        assert fido.has_user_keys("user123") is False
        assert fido.get_user_keys("user123") == []
    
    def test_get_stats(self, fido):
        """Test statistics retrieval."""
        stats = fido.get_stats()
        assert 'total_users' in stats
        assert 'total_keys' in stats
        assert 'fido2_available' in stats
    
    def test_start_registration(self, fido):
        """Test starting registration process."""
        options, state_id = fido.start_registration(
            user_id="user123",
            username="user@example.com"
        )
        
        assert isinstance(options, dict)
        assert 'publicKey' in options
        assert 'challenge' in options
        assert isinstance(state_id, str)
        assert len(state_id) > 0
    
    def test_registration_state_cleanup(self, fido):
        """Test that old registration states are cleaned up."""
        # Start registration
        _, state_id = fido.start_registration("user123", "user@example.com")
        
        # Manually expire the state
        fido._registration_state[state_id]['created_at'] = time.time() - 600
        
        # Trigger cleanup
        fido._cleanup_old_states(fido._registration_state, 300)
        
        # State should be removed
        assert state_id not in fido._registration_state
    
    def test_delete_nonexistent_key(self, fido):
        """Test deleting a key that doesn't exist."""
        result = fido.delete_key("user123", "nonexistent_key")
        assert result is False
    
    def test_delete_all_user_keys_empty(self, fido):
        """Test deleting all keys for user with no keys."""
        count = fido.delete_all_user_keys("user123")
        assert count == 0


class TestFIDO2KeyDataClass:
    """Tests for FIDO2Key data class."""

    @pytest.mark.skipif(not FIDO2_TESTS_AVAILABLE, reason="python-fido2 not installed")
    def test_to_dict(self):
        """Test FIDO2Key serialization."""
        key = FIDO2Key(
            key_id="test_key",
            user_id="user123",
            credential_id=b"credential_bytes",
            public_key=b"public_key_bytes",
            created_at=1000000000.0,
            device_name="YubiKey 5",
            transports=["usb", "nfc"]
        )
        
        data = key.to_dict()
        
        assert data['key_id'] == "test_key"
        assert data['user_id'] == "user123"
        assert isinstance(data['credential_id'], str)  # base64
        assert data['device_name'] == "YubiKey 5"
        assert data['transports'] == ["usb", "nfc"]
    
    @pytest.mark.skipif(not FIDO2_TESTS_AVAILABLE, reason="python-fido2 not installed")
    def test_from_dict(self):
        """Test FIDO2Key deserialization."""
        data = {
            'key_id': 'test_key',
            'user_id': 'user123',
            'credential_id': 'Y3JlZGVudGlhbF9ieXRlcw==',  # base64
            'public_key': 'cHVibGljX2tleV9ieXRlcw==',  # base64
            'created_at': 1000000000.0,
            'device_name': 'YubiKey 5 NFC',
            'transports': ['usb', 'nfc']
        }
        
        key = FIDO2Key.from_dict(data)
        
        assert key.key_id == "test_key"
        assert key.user_id == "user123"
        assert key.device_name == "YubiKey 5 NFC"
        assert key.transports == ["usb", "nfc"]


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
# Breach Monitor Tests
# =============================================================================

# Проверка доступности Breach Monitor перед тестами
try:
    from backend.features.breach_monitor import BreachMonitorService
    BREACH_MONITOR_TESTS_AVAILABLE = True
except ImportError:
    BREACH_MONITOR_TESTS_AVAILABLE = False


@pytest.mark.skipif(not BREACH_MONITOR_TESTS_AVAILABLE, reason="breach monitor dependencies not installed")
class TestBreachMonitorService:
    """Tests for breach monitoring service."""

    @pytest.fixture
    def monitor(self, tmp_path):
        """Create breach monitor."""
        from backend.features.breach_monitor import BreachMonitorService
        storage_path = tmp_path / "breach_monitor.json"
        return BreachMonitorService(
            check_interval_hours=1,
            storage_path=storage_path
        )
    
    def test_initialization(self, monitor):
        """Test monitor initialization."""
        stats = monitor.get_stats()
        assert stats['running'] is False
        assert stats['monitored_items_count'] == 0
    
    def test_add_password(self, monitor):
        """Test adding password for monitoring."""
        item_id = monitor.add_password("user123", "test_password")
        
        assert isinstance(item_id, str)
        assert len(item_id) > 0
        
        items = monitor.get_user_items("user123")
        assert len(items) == 1
        assert items[0].item_type == 'password'
    
    def test_add_email(self, monitor):
        """Test adding email for monitoring."""
        item_id = monitor.add_email("user123", "test@example.com")
        
        assert isinstance(item_id, str)
        
        items = monitor.get_user_items("user123")
        assert len(items) == 1
        assert items[0].item_type == 'email'
    
    def test_add_duplicate_password(self, monitor):
        """Test that duplicate passwords are not added."""
        item_id1 = monitor.add_password("user123", "test_password")
        item_id2 = monitor.add_password("user123", "test_password")
        
        assert item_id1 == item_id2
        
        items = monitor.get_user_items("user123")
        assert len(items) == 1
    
    def test_remove_item(self, monitor):
        """Test removing monitored item."""
        item_id = monitor.add_password("user123", "test_password")
        
        result = monitor.remove_item(item_id)
        assert result is True
        
        items = monitor.get_user_items("user123")
        assert len(items) == 0
    
    def test_remove_nonexistent_item(self, monitor):
        """Test removing item that doesn't exist."""
        result = monitor.remove_item("nonexistent")
        assert result is False
    
    def test_remove_user_items(self, monitor):
        """Test removing all user items."""
        monitor.add_password("user123", "password1")
        monitor.add_password("user123", "password2")
        monitor.add_email("user123", "test@example.com")
        
        count = monitor.remove_user_items("user123")
        assert count == 3
        
        items = monitor.get_user_items("user123")
        assert len(items) == 0
    
    def test_set_alert_callback(self, monitor):
        """Test setting alert callback."""
        callback_called = []
        
        def callback(alert):
            callback_called.append(alert)
        
        monitor.set_alert_callback(callback)
        
        assert len(monitor._alert_callbacks) == 1
    
    def test_get_unacknowledged_alerts(self, monitor):
        """Test getting unacknowledged alerts."""
        alerts = monitor.get_unacknowledged_alerts("user123")
        assert len(alerts) == 0
    
    def test_start_stop(self, monitor):
        """Test starting and stopping monitor."""
        monitor.start()
        
        stats = monitor.get_stats()
        assert stats['running'] is True
        
        monitor.stop()
        
        stats = monitor.get_stats()
        assert stats['running'] is False
    
    def test_check_now(self, monitor):
        """Test immediate check."""
        monitor.add_password("user123", "test_password")
        monitor.add_email("user123", "test@example.com")

        with patch.object(monitor._checker, "_fetch_hashes", return_value=""):
            with patch.object(monitor._checker, "check_email", return_value=(False, 0)):
                count = monitor.check_now("user123")
        assert count == 2

    def test_check_now_raises_on_partial_failure(self, monitor):
        """Test immediate check fails loudly when one of items cannot be checked."""
        from backend.features.breach_monitor import BreachMonitorError

        monitor.add_password("user123", "test_password")
        monitor.add_email("user123", "test@example.com")

        original_check = monitor._check_item

        def flaky_check(item):
            if item.item_type == "email":
                raise RuntimeError("forced email failure")
            return original_check(item)

        with patch.object(monitor._checker, "_fetch_hashes", return_value=""):
            with patch.object(monitor, "_check_item", side_effect=flaky_check):
                with pytest.raises(BreachMonitorError):
                    monitor.check_now("user123")

        stats = monitor.get_stats()
        assert stats["total_check_failures"] >= 1

    def test_restart_requires_email_resolver_for_persisted_email(self, monitor, tmp_path):
        """Test persisted email checks require resolver after process restart."""
        from backend.features.breach_monitor import (
            BreachMonitorNotAvailableError,
            BreachMonitorService,
        )

        monitor.add_email("user123", "test@example.com")
        monitor.save_state()

        restored = BreachMonitorService(
            check_interval_hours=1,
            storage_path=tmp_path / "breach_monitor.json",
        )

        with pytest.raises(BreachMonitorNotAvailableError):
            restored.check_now("user123")

    def test_restart_with_email_resolver_allows_checks(self, monitor, tmp_path):
        """Test resolver restores email check capability for persisted items."""
        from backend.features.breach_monitor import BreachMonitorService

        monitor.add_email("user123", "test@example.com")
        monitor.save_state()

        def resolver(_item):
            return "test@example.com"

        restored = BreachMonitorService(
            check_interval_hours=1,
            storage_path=tmp_path / "breach_monitor.json",
            email_resolver=resolver,
        )

        with patch.object(restored._checker, "check_email", return_value=(False, 0)):
            checked = restored.check_now("user123")

        assert checked == 1
    
    def test_save_load_state(self, monitor, tmp_path):
        """Test saving and loading state."""
        # Add items
        monitor.add_password("user123", "password1")
        monitor.add_email("user123", "test@example.com")
        
        # Save state
        monitor.save_state()
        
        # Verify file exists
        storage_path = tmp_path / "breach_monitor.json"
        assert storage_path.exists()
    
    def test_get_user_stats(self, monitor):
        """Test user statistics."""
        monitor.add_password("user123", "test_password")
        
        stats = monitor.get_user_stats("user123")
        
        assert 'monitored_items' in stats
        assert stats['monitored_items'] == 1
        assert 'unacknowledged_alerts' in stats
    
    def test_alert_severity_calculation(self, monitor):
        """Test alert severity calculation."""
        from backend.features.breach_monitor import AlertSeverity
        
        assert monitor._calculate_severity(50) == AlertSeverity.LOW
        assert monitor._calculate_severity(500) == AlertSeverity.MEDIUM
        assert monitor._calculate_severity(50000) == AlertSeverity.HIGH
        assert monitor._calculate_severity(5000000) == AlertSeverity.CRITICAL


class TestBreachAlertDataClass:
    """Tests for BreachAlert data class."""

    @pytest.mark.skipif(not BREACH_MONITOR_TESTS_AVAILABLE, reason="breach monitor dependencies not installed")
    def test_to_dict(self):
        """Test BreachAlert serialization."""
        from backend.features.breach_monitor import BreachAlert, AlertSeverity, AlertStatus
        
        alert = BreachAlert(
            alert_id="alert123",
            user_id="user123",
            alert_type="password",
            value_hash="abc123",
            value_preview="abc",
            breach_count=100,
            severity=AlertSeverity.MEDIUM,
            status=AlertStatus.NEW,
            detected_at=1000000000.0
        )
        
        data = alert.to_dict()
        
        assert data['alert_id'] == "alert123"
        assert data['severity'] == "medium"
        assert data['status'] == "new"
    
    @pytest.mark.skipif(not BREACH_MONITOR_TESTS_AVAILABLE, reason="breach monitor dependencies not installed")
    def test_from_dict(self):
        """Test BreachAlert deserialization."""
        from backend.features.breach_monitor import BreachAlert, AlertSeverity, AlertStatus
        
        data = {
            'alert_id': 'alert123',
            'user_id': 'user123',
            'alert_type': 'email',
            'value_hash': 'def456',
            'value_preview': 'def',
            'breach_count': 500,
            'severity': 'high',
            'status': 'acknowledged',
            'detected_at': 1000000000.0,
            'acknowledged_at': 1000000100.0
        }
        
        alert = BreachAlert.from_dict(data)
        
        assert alert.alert_id == "alert123"
        assert alert.severity == AlertSeverity.HIGH
        assert alert.status == AlertStatus.ACKNOWLEDGED
    
    @pytest.mark.skipif(not BREACH_MONITOR_TESTS_AVAILABLE, reason="breach monitor dependencies not installed")
    def test_age_days(self):
        """Test alert age calculation."""
        from backend.features.breach_monitor import BreachAlert, AlertSeverity, AlertStatus
        
        # Create alert from 10 days ago
        old_time = time.time() - (10 * 24 * 3600)
        
        alert = BreachAlert(
            alert_id="old_alert",
            user_id="user123",
            alert_type="password",
            value_hash="abc",
            value_preview="a",
            breach_count=10,
            severity=AlertSeverity.LOW,
            detected_at=old_time
        )
        
        assert alert.age_days >= 9  # Allow some margin


class TestQuickCheckFunctions:
    """Tests for quick check convenience functions."""

    @pytest.mark.skipif(not BREACH_MONITOR_TESTS_AVAILABLE, reason="breach monitor dependencies not installed")
    def test_quick_check_password_format(self):
        """Test quick password check returns correct format."""
        from backend.features.breach_monitor import quick_check_password
        
        is_pwned, count = quick_check_password("test_password_123")
        
        assert isinstance(is_pwned, bool)
        assert isinstance(count, int)
        assert count >= 0
    
    @pytest.mark.skipif(not BREACH_MONITOR_TESTS_AVAILABLE, reason="breach monitor dependencies not installed")
    def test_quick_check_email_format(self):
        """Test quick email check returns correct format."""
        from backend.features.breach_monitor import quick_check_email

        with patch("backend.core.advanced_security.HaveIBeenPwnedChecker.check_email") as mocked_check:
            mocked_check.return_value = (True, 42)
            is_pwned, count = quick_check_email("test@example.com")
        
        assert isinstance(is_pwned, bool)
        assert isinstance(count, int)
        assert count >= 0


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
    
    @pytest.mark.skipif(not FIDO2_TESTS_AVAILABLE, reason="python-fido2 not installed")
    def test_fido2_feature_flag(self):
        """Test FIDO2 feature availability check."""
        
        # Just check the flag exists and is boolean
        assert isinstance(FIDO2_AVAILABLE, bool)
    
    @pytest.mark.skipif(not QR_TESTS_AVAILABLE, reason="qrcode not installed")
    def test_qr_feature_flag(self):
        """Test QR feature availability check."""
        
        assert isinstance(QR_AVAILABLE, bool)
    
    @pytest.mark.skipif(not BREACH_MONITOR_TESTS_AVAILABLE, reason="breach monitor dependencies not installed")
    def test_breach_monitor_feature_flag(self):
        """Test breach monitor availability."""
        
        # Should be able to instantiate
        monitor = BreachMonitorService()
        assert monitor is not None
