# -*- coding: utf-8 -*-
"""
Database Session Management — hardened for high-concurrency SQLite.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import AsyncGenerator

from sqlalchemy import create_engine, event
from sqlalchemy.engine import URL, make_url
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from backend.core.audit_logger import Base
from backend.database.db_security import apply_windows_acl, ensure_secure_db_path

DEFAULT_DATABASE_URL = "sqlite+aiosqlite:///./vault.db"


def _configured_database_url() -> URL:
    """Return the async database URL, honoring env config and local hardening."""
    raw_url = (
        os.getenv("DATABASE_URL") or os.getenv("SQLALCHEMY_DATABASE_URL") or DEFAULT_DATABASE_URL
    )
    url = make_url(raw_url)

    if url.drivername == "sqlite":
        url = url.set(drivername="sqlite+aiosqlite")

    if url.drivername == "sqlite+aiosqlite" and url.database not in (None, ":memory:"):
        secure_path = ensure_secure_db_path(Path(url.database))
        if os.name == "nt":
            apply_windows_acl(secure_path)
        url = url.set(database=str(secure_path))

    return url


def _sync_database_url(async_url: URL) -> str:
    """Convert an async SQLAlchemy URL to the equivalent sync engine URL."""
    sync_url = async_url
    if sync_url.drivername == "sqlite+aiosqlite":
        sync_url = sync_url.set(drivername="sqlite")
    return sync_url.render_as_string(hide_password=False)


def _sqlite_connect_args(database_url: str) -> dict[str, bool]:
    if database_url.startswith("sqlite"):
        return {"check_same_thread": False}
    return {}


def _apply_sqlite_pragmas(dbapi_connection) -> None:
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("PRAGMA synchronous=NORMAL;")
        cursor.execute("PRAGMA foreign_keys=ON;")
    finally:
        cursor.close()


_database_url = _configured_database_url()
SQLALCHEMY_DATABASE_URL = _database_url.render_as_string(hide_password=False)
SYNC_DATABASE_URL = _sync_database_url(_database_url)


# Async engine for application
async_engine = create_async_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args=_sqlite_connect_args(SQLALCHEMY_DATABASE_URL),
    pool_pre_ping=True,
)

AsyncSessionLocal = async_sessionmaker(
    bind=async_engine,
    expire_on_commit=False,
    class_=AsyncSession,
    autoflush=False,
)

# Sync engine for init_db
sync_engine = create_engine(
    SYNC_DATABASE_URL,
    connect_args=_sqlite_connect_args(SYNC_DATABASE_URL),
    future=True,
)


# SQLite hardening
@event.listens_for(sync_engine, "connect")
def _sqlite_set_pragmas(dbapi_connection, _connection_record) -> None:
    _apply_sqlite_pragmas(dbapi_connection)


@event.listens_for(async_engine.sync_engine, "connect")
def _async_sqlite_set_pragmas(dbapi_connection, _connection_record) -> None:
    _apply_sqlite_pragmas(dbapi_connection)


def init_db() -> None:
    Base.metadata.create_all(bind=sync_engine)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        yield session
