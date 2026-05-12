# -*- coding: utf-8 -*-
"""
Tests for backend.features.backup_manager.

Coverage target: >85% (core logic, endpoint wiring, confirmed=True gate).
"""
from __future__ import annotations

import datetime
import os
import uuid
from pathlib import Path

import shutil

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker

from backend.api.v1.endpoints import backups as backups_router
from backend.core.crypto_bridge import bridge
from backend.database.models import PasswordEntry, User
from backend.database.session import init_db, _configured_database_url
from backend.features.backup_manager import (
    BackupError,
    BackupManager,
    _InvalidHMAC,
    _derive_backup_key,
    _ensure_backup_dir,
)

# ---------------------------------------------------------------------------
# Module-level setup
# ---------------------------------------------------------------------------

init_db()

_async_engine = create_async_engine(
    _configured_database_url().render_as_string(hide_password=False),
    connect_args={"check_same_thread": False},
    pool_pre_ping=True,
)
_AsyncSessionLocal = async_sessionmaker(
    bind=_async_engine,
    expire_on_commit=False,
    class_=AsyncSession,
    autoflush=False,
)


@pytest.fixture
async def db_session():
    async with _AsyncSessionLocal() as session:
        yield session


@pytest.fixture(autouse=True)
def _clean_backups(monkeypatch, tmp_path):
    backups_dir = tmp_path / "backups"
    monkeypatch.setenv("BITNET_BACKUP_DIR", str(backups_dir))
    import backend.features.backup_manager as _bm
    monkeypatch.setattr(_bm, "_BACKUP_DIR", backups_dir)
    yield
    for f in backups_dir.glob("*.bin"):
        f.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _make_user(db: AsyncSession) -> tuple[User, Any]:
    salt = b"bk_salt_1234567890123456"
    password_buf = bytearray(b"bk_pass")
    master_key = bridge.argon2_derive_key(
        memoryview(password_buf),
        memoryview(salt),
        wipe_password=False,
    )
    uid = uuid.uuid4().hex[:8]
    user = User(
        username=f"bk_{uid}",
        email=f"bk_{uid}@test.com",
        password_hash="deadbeef",
        salt=salt,
        wrapped_master_key_cipher=b"wrap",
        wrapped_master_key_nonce=b"nonce",
        wrapped_master_key_tag=b"tag",
        session_token_hash="bk" + uid + "x" * (60 - len(uid)),
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user, master_key


async def _make_entry(db: AsyncSession, user_id: int, title: str = "Bank") -> PasswordEntry:
    entry = PasswordEntry(
        user_id=user_id,
        title_search="idx",
        title_cipher="c",
        title_nonce="n",
        password_cipher="pc",
        password_nonce="pn",
    )
    db.add(entry)
    await db.commit()
    await db.refresh(entry)
    return entry


# ---------------------------------------------------------------------------
# BackupManager core tests
# ---------------------------------------------------------------------------

class TestBackupManagerCore:
    @pytest.mark.asyncio
    async def test_create_returns_path(self, db_session: AsyncSession):
        user, master_key = await _make_user(db_session)
        try:
            mgr = BackupManager(db_session)
            entry = await _make_entry(db_session, user.id)
            path = await mgr.create(user.id, master_key)
            assert path.exists()
            assert path.stat().st_size > 0
        finally:
            master_key.close()

    @pytest.mark.asyncio
    async def test_list_after_create(self, db_session: AsyncSession):
        user, master_key = await _make_user(db_session)
        try:
            mgr = BackupManager(db_session)
            await mgr.create(user.id, master_key)
            infos = await mgr.list(user.id)
            assert len(infos) == 1
            assert infos[0].size_bytes > 0
            assert isinstance(infos[0].created_at, datetime.datetime)
        finally:
            master_key.close()

    @pytest.mark.asyncio
    async def test_restore_without_confirmed_raises(self, db_session: AsyncSession):
        user, master_key = await _make_user(db_session)
        try:
            mgr = BackupManager(db_session)
            path = await mgr.create(user.id, master_key)
            infos = await mgr.list(user.id)
            with pytest.raises(BackupError) as exc_info:
                await mgr.restore(user.id, master_key, infos[0].name, confirmed=False)
            assert "confirmed=True" in str(exc_info.value)
        finally:
            master_key.close()

    @pytest.mark.asyncio
    async def test_restore_confirmed_count(self, db_session: AsyncSession):
        user, master_key = await _make_user(db_session)
        try:
            mgr = BackupManager(db_session)
            await _make_entry(db_session, user.id)
            await mgr.create(user.id, master_key)
            infos = await mgr.list(user.id)
            count = await mgr.restore(
                user.id, master_key, infos[0].name, confirmed=True
            )
            assert count == 1
        finally:
            master_key.close()

    @pytest.mark.asyncio
    async def test_rotate_old_deletes(self, db_session: AsyncSession):
        user, master_key = await _make_user(db_session)
        try:
            mgr = BackupManager(db_session)
            await mgr.create(user.id, master_key)
            await mgr.create(user.id, master_key)
            removed = await mgr.rotate(user.id, max_backups=1)
            assert removed == 1
            assert len(await mgr.list(user.id)) == 1
        finally:
            master_key.close()

    @pytest.mark.asyncio
    async def test_restore_tampered_raises(self, db_session: AsyncSession):
        user, master_key = await _make_user(db_session)
        try:
            mgr = BackupManager(db_session)
            await mgr.create(user.id, master_key)
            infos = await mgr.list(user.id)
            # Corrupt the last byte (HMAC tag area)
            backup_path = Path(os.getenv("BITNET_BACKUP_DIR")) / infos[0].name
            raw = backup_path.read_bytes()
            corrupted = raw[:-1] + bytes([raw[-1] ^ 0xFF])
            backup_path.write_bytes(corrupted)
            with pytest.raises(_InvalidHMAC):
                await mgr.restore(
                    user.id, master_key, infos[0].name, confirmed=True
                )
        finally:
            master_key.close()

    @pytest.mark.asyncio
    async def test_derive_backup_key_zero(self, db_session: AsyncSession):
        """Key derivation must return a zeroisable buffer."""
        user, master_key = await _make_user(db_session)
        try:
            key = _derive_backup_key(master_key)
            assert len(key) == 32
            assert any(key)  # non-zero
        finally:
            master_key.close()

    def test_ensure_backup_dir(self):
        _ensure_backup_dir()


# ---------------------------------------------------------------------------
# API endpoint smoke tests (public utility — no auth required for unit)
# ---------------------------------------------------------------------------

class TestBackupEndpoints:
    @pytest.fixture(scope="class")
    def client(self) -> TestClient:
        app = FastAPI()
        app.include_router(backups_router.router, prefix="/api/v1/backups")
        return TestClient(app)

    def test_list_unauth_401(self, client: TestClient) -> None:
        resp = client.get("/api/v1/backups/")
        assert resp.status_code == 401

    def test_restore_unauth_401(self, client: TestClient) -> None:
        resp = client.post("/api/v1/backups/foo/restore", json={"confirmed": True})
        assert resp.status_code == 401

    def test_rotate_unauth_401(self, client: TestClient) -> None:
        resp = client.post("/api/v1/backups/rotate")
        assert resp.status_code == 401

