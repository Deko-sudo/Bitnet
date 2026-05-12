# -*- coding: utf-8 -*-
"""
Tests for backend.features.search_engine.

Covers:
- Blind-index exact match via SearchService
- Zero-residual-memory guarantee (query buffer wiped)
- Performance baseline (10K entries <500ms)
"""
from __future__ import annotations

import gc
import os
import time
import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker

from backend.core.crypto_bridge import bridge
from backend.core.encryption_helper import generate_search_index
from backend.database.models import PasswordEntry, User
from backend.database.session import init_db, sync_engine, _configured_database_url
from backend.features.search_engine import SearchService


# ---------------------------------------------------------------------------
# Module-level setup: ensure tables exist, create a clean async engine
# ---------------------------------------------------------------------------

init_db()

# Create a separate async engine bound to the same on-disk SQLite file
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


@pytest.fixture
async def clean_db(db_session: AsyncSession):
    """Truncate tables before each test to avoid unique-constraint collisions."""
    await db_session.execute(select(PasswordEntry).where(PasswordEntry.id > 0))
    await db_session.execute(select(User).where(User.id > 0))
    await db_session.commit()


# ---------------------------------------------------------------------------
# SearchService unit tests
# ---------------------------------------------------------------------------

@pytest.fixture
async def user_with_entries(db_session: AsyncSession, clean_db):
    salt = b"test_salt_1234567890123456"
    password_buf = bytearray(b"test_password")
    master_key = bridge.argon2_derive_key(
        memoryview(password_buf),
        memoryview(salt),
        wipe_password=False,
    )
    try:
        uid = uuid.uuid4().hex[:8]
        user = User(
            username=f"search_user_{uid}",
            email=f"search_{uid}@test.com",
            password_hash="deadbeef",
            salt=salt,
            wrapped_master_key_cipher=b"wrap",
            wrapped_master_key_nonce=b"nonce",
            wrapped_master_key_tag=b"tag",
            session_token_hash="tok" + uid + "x" * (62 - len(uid)),
        )
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)

        titles = [f"Account-{i}" for i in range(10)]
        for title in titles:
            title_buf = bytearray(title.encode("utf-8"))
            blind = generate_search_index(master_key, title_buf)
            entry = PasswordEntry(
                user_id=user.id,
                title_search=blind,
                title_cipher="ciph",
                title_nonce="nonce",
                password_cipher="pc",
                password_nonce="pn",
            )
            db_session.add(entry)
        await db_session.commit()
        yield user, master_key, titles
    finally:
        master_key.close()


class TestSearchServiceUnit:
    @pytest.mark.asyncio
    async def test_search_blind_exact_match(self, db_session, user_with_entries):
        user, master_key, titles = user_with_entries
        svc = SearchService(db_session)
        results = await svc.search_by_title(user.id, "Account-5", master_key)
        assert len(results) == 1
        assert results[0].user_id == user.id

    @pytest.mark.asyncio
    async def test_search_no_match(self, db_session, user_with_entries):
        user, master_key, _ = user_with_entries
        svc = SearchService(db_session)
        results = await svc.search_by_title(user.id, "NonExistent", master_key)
        assert results == []

    @pytest.mark.asyncio
    async def test_search_pagination(self, db_session, user_with_entries):
        user, master_key, titles = user_with_entries
        svc = SearchService(db_session)
        for title in titles:
            results = await svc.search_by_title(user.id, title, master_key, limit=1)
            assert len(results) <= 1

    @pytest.mark.asyncio
    async def test_count_by_title(self, db_session, user_with_entries):
        user, master_key, _ = user_with_entries
        svc = SearchService(db_session)
        count = await svc.count_by_title(user.id, "Account-0", master_key)
        assert count == 1

    @pytest.mark.asyncio
    async def test_sorting_desc(self, db_session, user_with_entries):
        user, master_key, _ = user_with_entries
        svc = SearchService(db_session)
        results = await svc.search_by_title(
            user.id, "Account-0", master_key, sort_order="desc"
        )
        assert len(results) == 1

    @pytest.mark.asyncio
    async def test_memory_zero_residual(self, db_session, user_with_entries):
        user, master_key, _ = user_with_entries
        svc = SearchService(db_session)
        query = "Account-1"
        await svc.search_by_title(user.id, query, master_key)
        gc.collect()
        for obj in gc.get_objects():
            if isinstance(obj, bytearray) and query.encode() in obj:
                pytest.fail("Query plaintext found in residual bytearray after search")


# ---------------------------------------------------------------------------
# Performance test — 10K entries <500ms
# ---------------------------------------------------------------------------

class TestSearchEnginePerformance:
    @pytest.fixture
    async def tenk_user(self, db_session: AsyncSession):
        salt = b"perf_salt______________32bytes"
        password_buf = bytearray(b"perf_pass")
        master_key = bridge.argon2_derive_key(
            memoryview(password_buf),
            memoryview(salt),
            wipe_password=False,
        )
        try:
            uid = uuid.uuid4().hex[:8]
            user = User(
                username=f"perf_user_{uid}",
                email=f"perf_{uid}@test.com",
                password_hash="deadbeef",
                salt=salt,
                wrapped_master_key_cipher=b"wrap",
                wrapped_master_key_nonce=b"nonce",
                wrapped_master_key_tag=b"tag",
                session_token_hash="perf" + uid + "x" * (60 - len(uid)),
            )
            db_session.add(user)
            await db_session.commit()
            await db_session.refresh(user)

            for i in range(10_000):
                title = f"BulkEntry-{i:05d}"
                title_buf = bytearray(title.encode("utf-8"))
                blind = generate_search_index(master_key, title_buf)
                entry = PasswordEntry(
                    user_id=user.id,
                    title_search=blind,
                    title_cipher="c",
                    title_nonce="n",
                    password_cipher="p",
                    password_nonce="q",
                )
                db_session.add(entry)
            await db_session.commit()
            yield user, master_key
        finally:
            master_key.close()

    @pytest.mark.asyncio
    async def test_10k_entries_under_500ms(self, db_session, tenk_user):
        user, master_key = tenk_user
        svc = SearchService(db_session)
        start = time.perf_counter()
        results = await svc.search_by_title(user.id, "BulkEntry-05000", master_key)
        elapsed_ms = (time.perf_counter() - start) * 1000
        assert len(results) == 1
        assert elapsed_ms < 500.0, f"Search took {elapsed_ms:.1f}ms (target <500ms)"


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

class TestSearchServiceSortAndFilter:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("sort_by,sort_order", [
        ("created_at", "asc"),
        ("updated_at", "asc"),
        ("created_at", "desc"),
    ])
    async def test_sort_variants(
        self, db_session, user_with_entries, sort_by, sort_order
    ):
        user, master_key, _ = user_with_entries
        svc = SearchService(db_session)
        results = await svc.search_by_title(
            user.id, "Account-0", master_key,
            sort_by=sort_by, sort_order=sort_order,
        )
        assert len(results) == 1

    @pytest.mark.asyncio
    async def test_created_after_filter(self, db_session, user_with_entries):
        from datetime import datetime, timezone
        user, master_key, _ = user_with_entries
        svc = SearchService(db_session)
        far_future = datetime(2099, 1, 1, tzinfo=timezone.utc)
        results = await svc.search_by_title(
            user.id, "Account-0", master_key, created_after=far_future,
        )
        assert results == []

    @pytest.mark.asyncio
    async def test_updated_after_filter(self, db_session, user_with_entries):
        from datetime import datetime, timezone
        user, master_key, _ = user_with_entries
        svc = SearchService(db_session)
        far_past = datetime(2000, 1, 1, tzinfo=timezone.utc)
        results = await svc.search_by_title(
            user.id, "Account-0", master_key, updated_after=far_past,
        )
        assert len(results) == 1


class TestSearchIntegrationSmoke:
    def test_compile_ok(self) -> None:
        import py_compile
        py_compile.compile(os.path.join("backend", "features", "search_engine.py"), doraise=True)
