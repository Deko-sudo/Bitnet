# -*- coding: utf-8 -*-
"""Targeted tests to push coverage past 91%."""
from __future__ import annotations

import base64
import io
import secrets
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException
from httpx import AsyncClient
from sqlalchemy.orm.exc import StaleDataError
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database.entry_service import EntryService
from backend.database.schemas import EntryEnvelopeCreateSchema


class TestEntriesStaleDataError:
    @pytest.mark.asyncio
    async def test_update_entry_stale_data(self, client: AsyncClient, auth_headers: dict):
        # Create entry
        create_resp = await client.post(
            "/api/v1/entries/",
            json={"title": "Stale", "password": "x"},
            headers=auth_headers,
        )
        assert create_resp.status_code == 201
        entry_id = create_resp.json()["id"]

        # Patch flush to raise StaleDataError on first call
        call_count = 0
        original_flush = AsyncSession.flush

        async def fake_flush(self):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise StaleDataError("stale")
            await original_flush(self)

        with patch.object(AsyncSession, "flush", fake_flush):
            patch_resp = await client.patch(
                f"/api/v1/entries/{entry_id}",
                json={"title": "Updated"},
                headers=auth_headers,
            )
            assert patch_resp.status_code == 409


class TestPasswordHistoryEndpoint:
    @pytest.mark.asyncio
    async def test_password_history(self, client: AsyncClient, auth_headers: dict):
        # create entry
        r1 = await client.post(
            "/api/v1/entries/",
            json={"title": "Hist", "password": "oldpass"},
            headers=auth_headers,
        )
        assert r1.status_code == 201
        entry_id = r1.json()["id"]

        # update password -> history
        r2 = await client.patch(
            f"/api/v1/entries/{entry_id}",
            json={"password": "newpass"},
            headers=auth_headers,
        )
        assert r2.status_code == 200

        # fetch history
        r3 = await client.get(f"/api/v1/entries/{entry_id}/history", headers=auth_headers)
        assert r3.status_code == 200
        data = r3.json()
        assert isinstance(data, list)


class TestImportExportErrors:
    @pytest.mark.asyncio
    async def test_import_csv_bad_row(self, client: AsyncClient, auth_headers: dict):
        csv_data = b"title,username,password\nEntry1,user,\n"  # empty password
        files = {"file": ("bad.csv", io.BytesIO(csv_data), "text/csv")}
        resp = await client.post(
            "/api/v1/portability/import/csv",
            files=files,
            headers={k: v for k, v in auth_headers.items() if k.lower() != "content-type"},
        )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_import_jsonl_bad_json(self, client: AsyncClient, auth_headers: dict):
        jsonl_data = b"not json\n"
        files = {"file": ("bad.jsonl", io.BytesIO(jsonl_data), "application/x-ndjson")}
        resp = await client.post(
            "/api/v1/portability/import/jsonl",
            files=files,
            headers={k: v for k, v in auth_headers.items() if k.lower() != "content-type"},
        )
        assert resp.status_code == 200
        assert resp.json()["skipped"] >= 1

    @pytest.mark.asyncio
    async def test_import_csv_not_a_csv(self, client: AsyncClient, auth_headers: dict):
        data = b"foo,bar\n1,2\n"
        files = {"file": ("foo.txt", io.BytesIO(data), "text/plain")}
        resp = await client.post(
            "/api/v1/portability/import/csv",
            files=files,
            headers={k: v for k, v in auth_headers.items() if k.lower() != "content-type"},
        )
        assert resp.status_code == 400


class TestAuthManagerExtra:
    def test_properties_and_callbacks(self):
        from backend.core.auth_manager import AuthManager, SessionState
        mock_crypto = MagicMock()
        mock_crypto.config.key_size = 32
        am = AuthManager(crypto=mock_crypto)
        assert am.auto_lock_timeout == 300
        assert am.time_since_activity is None
        assert am.time_until_auto_lock is None
        assert "locked" in repr(am)

        am._state = SessionState()
        am._state.is_locked = False
        am._state.last_activity = time.time()
        assert am.time_since_activity >= 0
        assert am.time_until_auto_lock == pytest.approx(300, abs=1)

        am._state.is_locked = True
        assert am.time_until_auto_lock is None
        assert "locked" in repr(am)

        am._state = SessionState()
        am._state.is_locked = False
        am._state.last_activity = time.time()
        assert am.time_since_activity >= 0
        assert 0 <= am.time_until_auto_lock <= 300

        am._state.is_locked = True
        assert am.time_until_auto_lock is None

    def test_lock_unlock(self):
        from backend.core.auth_manager import AuthManager, AlreadyLockedError, NotLockedError
        mock_crypto = MagicMock()
        mock_crypto.derive_master_key.return_value = b"k" * 32
        mock_crypto.generate_random_bytes.return_value = b"w" * 32
        mock_crypto.encrypt.return_value = b"wrapped"

        am = AuthManager(crypto=mock_crypto)
        # lock() when already locked -> NotLockedError
        with pytest.raises(NotLockedError):
            am.lock()
        am.unlock("password", b"salt" * 4)
        assert am.is_unlocked is True
        # lock() when unlocked -> succeeds
        am.lock()
        assert am.is_locked is True
        # unlock() when locked -> succeeds
        am.unlock("password", b"salt" * 4)
        assert am.is_unlocked is True
        # unlock() when already unlocked -> AlreadyLockedError
        with pytest.raises(AlreadyLockedError):
            am.unlock("password", b"salt" * 4)

    def test_with_master_key(self):
        from backend.core.auth_manager import AuthManager
        mock_crypto = MagicMock()
        mock_crypto.config.key_size = 32
        mock_crypto.derive_master_key.return_value = b"key" * 8
        am = AuthManager(crypto=mock_crypto)
        am.unlock("password", b"salt" * 4)
        with am.with_master_key() as key:
            assert isinstance(key, bytearray)

    def test_with_derived_key(self):
        from backend.core.auth_manager import AuthManager
        mock_crypto = MagicMock()
        mock_crypto.config.key_size = 32
        mock_crypto.derive_master_key.return_value = b"key" * 8
        mock_crypto.derive_subkey.return_value = b"sub" * 8
        am = AuthManager(crypto=mock_crypto)
        am.unlock("password", b"salt" * 4)
        with am.with_derived_key(b"ctx") as key:
            assert isinstance(key, bytearray)

    def test_context_manager(self):
        from backend.core.auth_manager import AuthManager
        am = AuthManager(crypto=MagicMock())
        with am as a:
            assert a is am

    def test_session_manager(self):
        from backend.core.auth_manager import SessionManager, SessionInfo
        sm = SessionManager()
        sid = sm.create_session("user1")
        assert sm.is_session_valid(sid)
        assert sm.touch_session(sid) is True
        info = sm.get_active_sessions()
        assert len(info) == 1
        assert isinstance(info[0], SessionInfo)
        sm.destroy_session(sid)
        assert not sm.is_session_valid(sid)


class TestEntriesE2EEErrorPaths:
    @pytest.mark.asyncio
    async def test_e2ee_create_with_invalid_b64(self, client: AsyncClient, auth_headers: dict):
        resp = await client.post(
            "/api/v1/entries/e2ee",
            json={
                "title_search": "test",
                "ciphertext": "not-valid-base64!!!",
                "iv": "Yg==",
                "auth_tag": "Yw==",
            },
            headers=auth_headers,
        )
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_e2ee_read_nonexistent(self, client: AsyncClient, auth_headers: dict):
        resp = await client.get("/api/v1/entries/e2ee/99999", headers=auth_headers)
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_e2ee_update_nonexistent(self, client: AsyncClient, auth_headers: dict):
        resp = await client.patch(
            "/api/v1/entries/e2ee/99999",
            json={"title_search": "x"},
            headers=auth_headers,
        )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_e2ee_delete_nonexistent(self, client: AsyncClient, auth_headers: dict):
        resp = await client.delete("/api/v1/entries/e2ee/99999", headers=auth_headers)
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_read_nonexistent_entry(self, client: AsyncClient, auth_headers: dict):
        resp = await client.get("/api/v1/entries/99999", headers=auth_headers)
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_delete_nonexistent_entry(self, client: AsyncClient, auth_headers: dict):
        resp = await client.delete("/api/v1/entries/99999", headers=auth_headers)
        assert resp.status_code == 404
