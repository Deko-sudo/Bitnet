# -*- coding: utf-8 -*-
"""
Coverage Phase 1: Easy wins — direct unit tests for simple branches.
"""
from __future__ import annotations

import os
import time
from unittest.mock import MagicMock, patch

import pytest


# =============================================================================
# crypto_bridge: _as_readable_buffer branches (lines 41, 45)
# =============================================================================


class TestCryptoBridgeReadableBuffer:
    def test_readable_buffer_locked_buffer(self):
        from backend.core.crypto_bridge import _as_readable_buffer, bridge

        key = bridge.generate_random_locked(32)
        try:
            result = _as_readable_buffer(key, field_name="test")
            assert result is key
        finally:
            key.close()

    def test_readable_buffer_bytearray(self):
        from backend.core.crypto_bridge import _as_readable_buffer

        buf = bytearray(b"hello")
        result = _as_readable_buffer(buf, field_name="test")
        assert isinstance(result, memoryview)
        assert bytes(result) == b"hello"


# =============================================================================
# encryption_helper: LockedBufferSet (lines 138, 144, 147)
# =============================================================================


class TestLockedBufferSet:
    def test_close_with_locked_buffer(self):
        from backend.core.encryption_helper import LockedBufferSet
        from backend.core.crypto_bridge import bridge

        key = bridge.generate_random_locked(32)
        lbs = LockedBufferSet()
        lbs.add(key)
        lbs.close()
        assert key.is_closed

    def test_context_manager_enter_exit(self):
        from backend.core.encryption_helper import LockedBufferSet
        from backend.core.crypto_bridge import bridge

        key = bridge.generate_random_locked(32)
        with LockedBufferSet() as lbs:
            lbs.add(key)
            assert not key.is_closed
        assert key.is_closed


# =============================================================================
# schemas: EntryResponseRaw.wipe() (lines 118-120)
# =============================================================================


class TestEntryResponseRawWipe:
    def test_wipe_clears_bytearrays(self):
        from backend.database.schemas import EntryResponseRaw
        from datetime import datetime, timezone

        title = bytearray(b"my_title")
        password = bytearray(b"my_pass")
        username = bytearray(b"user1")
        raw = EntryResponseRaw(
            id=1,
            user_id=1,
            title=title,
            password=password,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            username=username,
            url=None,
            notes=None,
        )
        raw.wipe()
        assert title == bytearray(len(title))
        assert password == bytearray(len(password))
        assert username == bytearray(len(username))


# =============================================================================
# security_utils: RateLimiter edge cases (lines 219, 225, 264)
# =============================================================================


class TestRateLimiterEdgeCases:
    def test_get_delay_unknown_id(self):
        from backend.core.security_utils import RateLimiter

        rl = RateLimiter()
        assert rl.get_delay("unknown_id") == 0.0

    def test_get_delay_after_success(self):
        from backend.core.security_utils import RateLimiter

        rl = RateLimiter()
        rl.register_failed("user1")
        rl.register_failed("user1")
        assert rl.get_delay("user1") > 0
        rl.register_success("user1")
        assert rl.get_delay("user1") == 0.0

    def test_is_blocked_unknown_id(self):
        from backend.core.security_utils import RateLimiter

        rl = RateLimiter()
        assert rl.is_blocked("unknown_id") is False


# =============================================================================
# session: _configured_database_url and _sqlite_connect_args (lines 32, 54)
# =============================================================================


class TestSessionHelpers:
    def test_sqlite_connect_args_non_sqlite(self):
        from backend.database.session import _sqlite_connect_args

        result = _sqlite_connect_args("postgresql://user:pass@localhost/db")
        assert result == {}

    def test_sqlite_connect_args_sqlite(self):
        from backend.database.session import _sqlite_connect_args

        result = _sqlite_connect_args("sqlite+aiosqlite:///./vault.db")
        assert result == {"check_same_thread": False}

    def test_configured_database_url_sqlite_driver_upgrade(self):
        from sqlalchemy import make_url
        from backend.database.session import _configured_database_url

        with patch.dict(os.environ, {"DATABASE_URL": "sqlite:///./test_vault.db"}, clear=False):
            url = _configured_database_url()
            assert url.drivername == "sqlite+aiosqlite"


# =============================================================================
# password_generator: _parse_password_strength (line 28)
# =============================================================================


class TestPasswordGeneratorParseStrength:
    def test_invalid_strength_raises_value_error(self):
        from backend.features.password_generator import _parse_password_strength

        with pytest.raises(ValueError):
            _parse_password_strength(99)

    def test_parse_from_int(self):
        from backend.features.password_generator import _parse_password_strength
        from backend.core.security_utils import PasswordStrength

        assert _parse_password_strength(2) == PasswordStrength.FAIR

    def test_parse_from_string(self):
        from backend.features.password_generator import _parse_password_strength
        from backend.core.security_utils import PasswordStrength

        assert _parse_password_strength("weak") == PasswordStrength.WEAK


# =============================================================================
# auth_manager: SessionManager methods (lines 671, 689, 703)
# =============================================================================


class TestAuthManagerSessionState:
    def test_time_since_unlock_none(self):
        from backend.core.auth_manager import SessionState

        state = SessionState()
        assert state.time_since_unlock is None

    def test_time_since_unlock_not_none(self):
        from backend.core.auth_manager import SessionState

        state = SessionState()
        state.unlocked_at = time.time()
        result = state.time_since_unlock
        assert result >= 0


class TestSessionManagerExtra:
    def test_destroy_session_returns_true(self):
        from backend.core.auth_manager import SessionManager

        sm = SessionManager()
        sid = sm.create_session("user1")
        assert sm.destroy_session(sid) is True

    def test_destroy_nonexistent_returns_false(self):
        from backend.core.auth_manager import SessionManager

        sm = SessionManager()
        assert sm.destroy_session("nonexistent") is False

    def test_touch_session_returns_true(self):
        from backend.core.auth_manager import SessionManager

        sm = SessionManager()
        sid = sm.create_session("user1")
        assert sm.touch_session(sid) is True

    def test_is_session_valid_nonexistent(self):
        from backend.core.auth_manager import SessionManager

        sm = SessionManager()
        assert sm.is_session_valid("nonexistent") is False


# =============================================================================
# entry_service: change_master_password errors (lines 229, 233)
# =============================================================================


class TestEntryServiceExtraErrors:
    @pytest.mark.asyncio
    async def test_change_master_password_user_not_found(self):
        from backend.database.entry_service import EntryService
        from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

        engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
        from backend.core.audit_logger import Base
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        session_factory = async_sessionmaker(bind=engine, expire_on_commit=False)
        async with session_factory() as session:
            svc = EntryService(session)
            with pytest.raises(ValueError, match="User not found"):
                await svc.change_master_password_async(99999, "old", "new")
        await engine.dispose()

    @pytest.mark.asyncio
    async def test_change_master_password_wrong_old(self):
        from backend.database.entry_service import EntryService
        from backend.database.models import User
        from backend.core.crypto_bridge import bridge
        from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

        engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
        from backend.core.audit_logger import Base
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        session_factory = async_sessionmaker(bind=engine, expire_on_commit=False)
        async with session_factory() as session:
            salt = os.urandom(16)
            pw_buf = bytearray(b"CorrectPass1!")
            key = bridge.argon2_derive_key(pw_buf, salt, wipe_password=True)
            import hashlib
            derived_bytes = bridge.locked_buffer_to_bytearray(key)
            pw_hash = hashlib.sha256(derived_bytes).hexdigest()
            from backend.core.crypto_bridge import zeroize_mutable_buffer
            zeroize_mutable_buffer(derived_bytes)
            key.close()

            user = User(
                username="cmp_user",
                email="cmp@test.com",
                password_hash=pw_hash,
                salt=salt,
                wrapped_master_key_cipher=b"w" * 32,
                wrapped_master_key_nonce=b"n" * 12,
                wrapped_master_key_tag=b"t" * 16,
                session_token_hash="x" * 64,
            )
            session.add(user)
            await session.commit()
            await session.refresh(user)

            svc = EntryService(session)
            with pytest.raises(ValueError, match="Old password is incorrect"):
                await svc.change_master_password_async(user.id, "WrongPass!", "NewPass1!")
        await engine.dispose()


# =============================================================================
# entry_service: _to_envelope_response with None ciphertext (line 255)
# =============================================================================


class TestEntryServiceEnvelopeNullCiphertext:
    def test_to_envelope_response_none_ciphertext_raises(self):
        from backend.database.entry_service import EntryService, EntryNotFoundError
        from backend.database.models import PasswordEntry

        entry = PasswordEntry(
            id=1,
            user_id=1,
            title_search="test",
            title_cipher=None,
            title_nonce="",
            password_cipher="p",
            password_nonce="n",
        )
        with pytest.raises(EntryNotFoundError, match="not available"):
            EntryService._to_envelope_response(entry)


# =============================================================================
# entry_service: update with key_metadata (line 176)
# =============================================================================


class TestEntryServiceKeyMetadata:
    @pytest.mark.asyncio
    async def test_update_with_key_metadata(self):
        from backend.database.entry_service import EntryService
        from backend.database.models import User
        from backend.database.schemas import EntryEnvelopeCreateSchema, EntryEnvelopeUpdateSchema
        from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
        import base64, secrets

        engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
        from backend.core.audit_logger import Base
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        session_factory = async_sessionmaker(bind=engine, expire_on_commit=False)
        async with session_factory() as session:
            user = User(
                username=f"km_test_{secrets.token_hex(4)}",
                email=f"km_{secrets.token_hex(4)}@test.com",
                password_hash="x",
                salt=b"salt_1234567890123456",
                wrapped_master_key_cipher=b"w",
                wrapped_master_key_nonce=b"n",
                wrapped_master_key_tag=b"t",
                session_token_hash="k" * 64,
            )
            session.add(user)
            await session.commit()
            await session.refresh(user)

            svc = EntryService(session)
            ct = base64.b64encode(secrets.token_bytes(32)).decode()
            iv = base64.b64encode(secrets.token_bytes(12)).decode()
            tag = base64.b64encode(secrets.token_bytes(16)).decode()
            schema = EntryEnvelopeCreateSchema(
                title_search="km_test",
                ciphertext=ct, iv=iv, auth_tag=tag,
            )
            created = await svc.create_entry_async(user.id, schema)

            update = EntryEnvelopeUpdateSchema(
                key_metadata={"alg": "AES-256-GCM", "version": 2}
            )
            updated = await svc.update_entry_async(user.id, created.id, update)
            assert updated.key_metadata is not None
            assert "version" in updated.key_metadata
        await engine.dispose()