# -*- coding: utf-8 -*-
import os
import secrets
import sys
import tempfile
from typing import AsyncGenerator, Generator
from unittest.mock import patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

# ---------------------------------------------------------------------------
# Ensure project root is on sys.path
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from backend.core.audit_logger import Base
from backend.database import models as _models
from backend.database.session import get_db
from backend.main import app

# =============================================================================
# Server Wrap Key (Shared across test session)
# =============================================================================


@pytest.fixture(scope="session")
def server_wrap_key_file() -> Generator[str, None, None]:
    key_bytes = secrets.token_bytes(32)
    with tempfile.NamedTemporaryFile(delete=False, suffix=".key") as fh:
        fh.write(key_bytes)
        path = fh.name

    original = os.environ.get("BITNET_SERVER_WRAP_KEY_FILE")
    os.environ["BITNET_SERVER_WRAP_KEY_FILE"] = path
    yield path
    if original:
        os.environ["BITNET_SERVER_WRAP_KEY_FILE"] = original
    else:
        os.environ.pop("BITNET_SERVER_WRAP_KEY_FILE", None)
    os.unlink(path)


# =============================================================================
# In-Memory SQLite Async Engine
# =============================================================================


@pytest_asyncio.fixture(scope="session")
async def engine(server_wrap_key_file):
    from sqlalchemy.pool import StaticPool

    eng = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )

    @event.listens_for(eng.sync_engine, "connect")
    def _set_pragmas(dbapi_conn, _connection_record):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("PRAGMA synchronous=NORMAL;")
        cursor.execute("PRAGMA foreign_keys=ON;")
        cursor.close()

    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield eng
    await eng.dispose()


# =============================================================================
# Async DB Session (per-test, auto-rollback)
# =============================================================================


@pytest_asyncio.fixture()
async def db_session(engine) -> AsyncGenerator[AsyncSession, None]:
    connection = await engine.connect()
    transaction = await connection.begin()
    session_factory = async_sessionmaker(bind=connection, expire_on_commit=False)
    session = session_factory()

    yield session

    await session.close()
    await transaction.rollback()
    await connection.close()


# =============================================================================
# Async FastAPI Client
# =============================================================================


@pytest_asyncio.fixture()
async def client(engine) -> AsyncGenerator[AsyncClient, None]:
    connection = await engine.connect()
    transaction = await connection.begin()

    AsyncSessionLocal = async_sessionmaker(bind=connection, expire_on_commit=False)

    async def _override_get_db():
        async with AsyncSessionLocal() as sess:
            yield sess

    app.dependency_overrides[get_db] = _override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    app.dependency_overrides.clear()
    await transaction.rollback()
    await connection.close()


# =============================================================================
# Registered User + Auth Headers (for API integration tests)
# =============================================================================

_TEST_PASSWORD = "SecureP@ssw0rd2024!"


@pytest_asyncio.fixture()
async def registered_user(db_session) -> dict:
    """
    Registers a user via the API and returns their data.
    """
    from httpx import ASGITransport, AsyncClient

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.post(
            "/api/v1/auth/register",
            json={
                "username": "portability_test_user",
                "email": "portability@test.com",
                "password": _TEST_PASSWORD,
            },
        )
    assert resp.status_code == 201, f"Registration failed: {resp.text}"
    user_data = resp.json()
    return {
        "user_id": user_data["id"],
        "username": user_data["username"],
        "email": user_data["email"],
        "password": _TEST_PASSWORD,
    }


@pytest_asyncio.fixture()
async def auth_headers(client, registered_user) -> dict:
    """
    Logs in via API and returns Authorization headers.
    """
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={
            "username": registered_user["username"],
            "password": registered_user["password"],
        },
    )
    assert login_resp.status_code == 200, f"Login failed: {login_resp.text}"
    token_data = login_resp.json()
    return {"Authorization": f"Bearer {token_data['access_token']}"}


# =============================================================================
# Breach Monitor fixture (for API integration tests)
# =============================================================================


@pytest_asyncio.fixture()
async def breach_monitor(engine):
    """Create an AsyncBreachMonitorService wired to the test DB."""
    from backend.features.breach_monitor_async import AsyncBreachMonitorService

    session_factory = async_sessionmaker(bind=engine, expire_on_commit=False)
    monitor = AsyncBreachMonitorService(
        db_session_factory=session_factory,
        hibp_api_key=None,
        check_interval_hours=9999,
    )
    await monitor.start()
    yield monitor
    await monitor.stop()