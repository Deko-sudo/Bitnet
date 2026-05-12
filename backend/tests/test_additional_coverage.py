# -*- coding: utf-8 -*-
"""Targeted tests for coverage gaps — deterministic, no external deps."""
from __future__ import annotations

import io
import time
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException
from pydantic import ValidationError


# =============================================================================
# Config coverage
# =============================================================================


class TestConfigExtra:
    def test_crypto_config_defaults(self):
        from backend.core.config import CryptoConfig

        cfg = CryptoConfig()
        assert cfg.key_size == 32
        assert cfg.nonce_size == 12
        assert cfg.tag_size == 16
        assert cfg.key_size_bits == 256
        assert cfg.memory_cost_mb == 64
        assert cfg.auto_lock_timeout == 300
        assert cfg.max_login_attempts == 5
        assert cfg.rate_limit_window == 60
        assert cfg.hmac_algorithm == "sha256"
        assert cfg.argon2_type == "id"
        assert cfg.argon2_time_cost == 3
        assert cfg.argon2_memory_cost == 65536
        assert cfg.argon2_parallelism == 4
        assert cfg.argon2_hash_len == 32
        assert cfg.argon2_salt_len == 16

    def test_crypto_config_custom(self):
        from backend.core.config import CryptoConfig

        cfg = CryptoConfig(key_size=64, nonce_size=16, tag_size=16, argon2_memory_cost=262144)
        assert cfg.key_size == 64
        assert cfg.key_size_bits == 512
        assert cfg.memory_cost_mb == 256

    def test_rate_limit_config(self):
        from backend.core.config import RateLimitConfig

        cfg = RateLimitConfig()
        assert cfg.max_attempts == 5
        assert cfg.window_seconds == 60
        assert cfg.block_duration_seconds == 1800

    def test_password_strength_config(self):
        from backend.core.config import PasswordStrengthConfig

        cfg = PasswordStrengthConfig()
        assert cfg.min_length == 12
        assert cfg.min_entropy_bits == 60.0
        assert cfg.require_uppercase is True
        assert cfg.require_lowercase is True
        assert cfg.require_digits is True

    def test_get_functions(self):
        from backend.core.config import get_crypto_config, get_rate_limit_config, get_password_strength_config

        assert get_crypto_config() is not None
        assert get_rate_limit_config() is not None
        assert get_password_strength_config() is not None

    def test_config_dict_used_not_class_config(self):
        from backend.core.config import CryptoConfig, RateLimitConfig, PasswordStrengthConfig

        assert hasattr(CryptoConfig, "model_config")
        assert CryptoConfig.model_config.get("frozen") is True
        assert CryptoConfig.model_config.get("extra") == "forbid"
        assert hasattr(RateLimitConfig, "model_config")
        assert RateLimitConfig.model_config.get("frozen") is True
        assert hasattr(PasswordStrengthConfig, "model_config")
        assert PasswordStrengthConfig.model_config.get("frozen") is True

    def test_crypto_config_validation(self):
        from backend.core.config import CryptoConfig
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            CryptoConfig(key_size=8)
        with pytest.raises(ValidationError):
            CryptoConfig(argon2_memory_cost=1024)


# =============================================================================
# main.py coverage
# =============================================================================


class TestMainExtra:
    def test_lifespan_import(self):
        from backend.main import app, lifespan

        assert app is not None
        assert lifespan is not None

    def test_lifespan_callable_and_async(self):
        import asyncio
        from unittest.mock import MagicMock
        from backend.main import lifespan
        from contextlib import asynccontextmanager

        assert callable(lifespan)
        assert hasattr(lifespan, "__call__")
        ctx = lifespan(MagicMock())
        assert hasattr(ctx, "__aenter__")
        assert hasattr(ctx, "__aexit__")

    def test_app_uses_lifespan(self):
        from backend.main import app

        assert app.router.lifespan_context is not None


# =============================================================================
# entry_service.py coverage
# =============================================================================


class TestEntryServiceHelpers:
    def test_metadata_helpers(self):
        from backend.database.entry_service import _metadata_to_json, _metadata_from_json

        assert _metadata_to_json({"a": 1}) == '{"a":1}'
        assert _metadata_to_json(None) == '{}'
        assert _metadata_from_json('{"a":1}') == {"a": 1}
        assert _metadata_from_json(None) == {}
        assert _metadata_from_json("") == {}
        assert _metadata_from_json('[1,2,3]') == {}  # non-dict falls back

    def test_decode_blob(self):
        from backend.database.entry_service import _decode_blob, _encode_blob
        import base64

        raw = b"hello"
        encoded = _encode_blob(raw)
        assert _decode_blob(encoded, "test") == raw

    def test_decode_blob_invalid(self):
        from backend.database.entry_service import _decode_blob

        with pytest.raises(ValueError, match="must be valid base64"):
            _decode_blob("not-base64!!!", "test")
        with pytest.raises(ValueError, match="must not be empty"):
            _decode_blob("", "test")

    def test_derive_login_hash(self):
        from backend.database.entry_service import _derive_login_hash

        h = _derive_login_hash("password", b"salt" * 4)
        assert isinstance(h, str)
        assert len(h) == 64  # sha256 hex


# =============================================================================
# auth.py coverage
# =============================================================================


class TestAuthHelpers:
    def test_auth_password_derivation(self):
        from backend.core.crypto_core import CryptoCore

        cc = CryptoCore()
        salt = cc.generate_salt()
        key1 = cc.derive_master_key("password", salt)
        key2 = cc.derive_master_key("password", salt)
        key3 = cc.derive_master_key("wrong", salt)
        assert key1 == key2
        assert key1 != key3

    @pytest.mark.asyncio
    async def test_get_current_user_missing_token(self, client):
        resp = await client.get("/api/v1/entries/")
        assert resp.status_code in (401, 403)


# =============================================================================
# crypto_core / crypto_bridge coverage
# =============================================================================


class TestCryptoHelpers:
    def test_crypto_core_repr(self):
        from backend.core.crypto_core import CryptoCore

        cc = CryptoCore()
        assert "CryptoCore" in repr(cc)

    def test_derive_key_comparison(self):
        from backend.core.crypto_core import CryptoCore

        cc = CryptoCore()
        salt = cc.generate_salt()
        key1 = cc.derive_master_key("password", salt)
        key2 = cc.derive_master_key("password", salt)
        assert len(key1) == 32
        assert key1 == key2
        key3 = cc.derive_master_key("wrong", salt)
        assert key1 != key3

    def test_bridge_zeroize_mutable_buffer(self):
        from backend.core.crypto_bridge import zeroize_mutable_buffer

        buf = bytearray(b"secret")
        zeroize_mutable_buffer(buf)
        assert buf == bytearray(b"\x00" * 6)

    def test_as_writable_view_readonly_memoryview(self):
        from backend.core.crypto_bridge import _as_writable_view
        buf = bytearray(b"data")
        ro = memoryview(buf).toreadonly()
        with pytest.raises(TypeError, match="writable"):
            _as_writable_view(ro, field_name="test")

    def test_as_writable_view_noncontiguous_memoryview(self):
        import array
        from backend.core.crypto_bridge import _as_writable_view
        arr = array.array("b", [1, 2, 3, 4])
        nc = memoryview(arr)[::2]
        with pytest.raises(ValueError, match="contiguous"):
            _as_writable_view(nc, field_name="test")

    def test_as_writable_view_bad_type(self):
        from backend.core.crypto_bridge import _as_writable_view
        with pytest.raises(TypeError, match="bytearray or writable memoryview"):
            _as_writable_view("not a buffer", field_name="test")

    def test_as_readable_buffer_noncontiguous_memoryview(self):
        import array
        from backend.core.crypto_bridge import _as_readable_buffer
        arr = array.array("b", [1, 2, 3, 4])
        nc = memoryview(arr)[::2]
        with pytest.raises(ValueError, match="contiguous"):
            _as_readable_buffer(nc, field_name="test")

    def test_as_readable_buffer_bad_type(self):
        from backend.core.crypto_bridge import _as_readable_buffer
        with pytest.raises(TypeError, match="bytes-like or LockedBuffer"):
            _as_readable_buffer(42, field_name="test")

    def test_decrypt_from_storage_short_tag(self):
        from backend.core.crypto_bridge import bridge, bridge as b2
        key = bridge.generate_random_locked(32)
        try:
            with pytest.raises(ValueError, match="does not contain"):
                bridge.decrypt_from_storage(key, "0011", "aabbccdd")
        finally:
            key.close()


# =============================================================================
# database schemas coverage
# =============================================================================


class TestSchemasExtra:
    def test_entry_create(self):
        from backend.database.schemas import EntryCreateSchema

        e = EntryCreateSchema(title="T", password="P")
        assert e.title.get_secret_value() == "T"
        assert e.password.get_secret_value() == "P"

    def test_entry_update_empty(self):
        from backend.database.schemas import EntryUpdateSchema

        u = EntryUpdateSchema()
        assert u.title is None

    def test_entry_envelope_create(self):
        from backend.database.schemas import EntryEnvelopeCreateSchema

        e = EntryEnvelopeCreateSchema(ciphertext="YQ==", iv="Yg==", auth_tag="Yw==")
        assert e.ciphertext == "YQ=="


# =============================================================================
# import_export service (simple paths)
# =============================================================================


class TestImportExportUnit:
    def test_import_row_schema(self):
        from backend.services.import_export import ImportRowSchema, ImportResult

        row = ImportRowSchema(title="t", password="p")
        assert row.username is None
        result = ImportResult()
        assert result.total_rows == 0

    def test_enforce_row_size(self):
        from backend.services.import_export import DataPortabilityService, ImportValidationError, MAX_ROW_SIZE_BYTES

        DataPortabilityService._enforce_row_size(["x"], 1)
        with pytest.raises(ImportValidationError):
            DataPortabilityService._enforce_row_size(["x" * (MAX_ROW_SIZE_BYTES + 10)], 1)

    def test_coerce_binary_stream(self):
        from backend.services.import_export import DataPortabilityService

        bio = io.BytesIO(b"data")
        assert DataPortabilityService._coerce_binary_stream(bio) is bio
        assert DataPortabilityService._coerce_binary_stream(b"data").read() == b"data"

    def test_buf_to_str_none(self):
        from backend.services.import_export import DataPortabilityService

        assert DataPortabilityService._buf_to_str(None) == ""

    def test_buf_to_str_value(self):
        from backend.services.import_export import DataPortabilityService

        assert DataPortabilityService._buf_to_str(bytearray(b"hello")) == "hello"

    @pytest.mark.asyncio
    async def test_iter_text_lines_row_size_exceeds(self):
        from backend.services.import_export import (
            DataPortabilityService,
            ImportValidationError,
            MAX_ROW_SIZE_BYTES,
        )
        from unittest.mock import AsyncMock, MagicMock

        session = MagicMock()
        master_key = MagicMock()
        svc = DataPortabilityService(session=session, master_key=master_key)
        big_line = b"x" * (MAX_ROW_SIZE_BYTES + 10) + b"\n"
        bio = io.BytesIO(big_line)
        with pytest.raises(ImportValidationError, match="exceeds row size"):
            async for _ in svc._iter_text_lines(bio):
                pass

    @pytest.mark.asyncio
    async def test_insert_batch_sqlalchemy_error(self):
        from backend.services.import_export import (
            DataPortabilityService,
            ImportDatabaseError,
            ImportRowSchema,
        )
        from backend.database.models import PasswordEntry
        from unittest.mock import AsyncMock, MagicMock, patch
        from sqlalchemy.exc import OperationalError

        session = MagicMock()
        session.add_all = MagicMock()
        session.commit = AsyncMock(side_effect=OperationalError("", {}, Exception("db error")))
        session.rollback = AsyncMock()
        master_key = MagicMock()
        svc = DataPortabilityService(session=session, master_key=master_key)

        rows = [ImportRowSchema(title="t", password="p")]
        with patch.object(svc, "_encrypt_and_build_entry", new_callable=AsyncMock) as mock_enc:
            mock_enc.return_value = PasswordEntry(
                user_id=1,
                title_search="x",
                title_cipher="c",
                title_nonce="n",
                password_cipher="p",
                password_nonce="q",
            )
            with pytest.raises(ImportDatabaseError):
                await svc._insert_batch(1, rows)
