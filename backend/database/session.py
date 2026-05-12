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
import backend.database.models  # noqa: F401 (register ORM models with Base.metadata)
from backend.database.db_optimization import optimize_sqlite_pragma
from backend.database.db_security import apply_windows_acl, ensure_secure_db_path

DEFAULT_DATABASE_URL = "sqlite+aiosqlite:///./vault.db"


def _configured_database_url() -> URL:
    """Return the async database URL, honoring env config and local hardening."""  # pragma: no cover — covered by integration tests
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
    optimize_sqlite_pragma(dbapi_connection)


@event.listens_for(async_engine.sync_engine, "connect")
def _async_sqlite_set_pragmas(dbapi_connection, _connection_record) -> None:
    optimize_sqlite_pragma(dbapi_connection)


def init_db() -> None:
    Base.metadata.create_all(bind=sync_engine)
    _ensure_sqlite_schema_compatibility()


def _ensure_sqlite_schema_compatibility() -> None:  # pragma: no cover — only runs on existing physical DB files
    """Add newly introduced nullable columns for existing local SQLite DBs."""
    if not SYNC_DATABASE_URL.startswith("sqlite"):
        return

    required_columns = {
        "ciphertext": "BLOB",
        "iv": "BLOB",
        "auth_tag": "BLOB",
        "key_metadata": "TEXT",
    }

    user_required_columns = {
        "session_expires_at": "DATETIME",
    }

    login_attempt_required_columns = {
        "ip_address": "VARCHAR(45)",
        "username": "VARCHAR(255)",
    }

    with sync_engine.begin() as conn:
        rows = conn.exec_driver_sql("PRAGMA table_info(password_entries)").fetchall()
        existing_columns = {row[1] for row in rows}
        for column_name, column_type in required_columns.items():
            if column_name not in existing_columns:
                conn.exec_driver_sql(
                    f"ALTER TABLE password_entries ADD COLUMN {column_name} {column_type}"
                )

        user_rows = conn.exec_driver_sql("PRAGMA table_info(users)").fetchall()
        user_existing = {row[1] for row in user_rows}
        for column_name, column_type in user_required_columns.items():
            if column_name not in user_existing:
                conn.exec_driver_sql(
                    f"ALTER TABLE users ADD COLUMN {column_name} {column_type}"
                )

        la_rows = conn.exec_driver_sql("PRAGMA table_info(login_attempts)").fetchall()
        la_existing = {row[1] for row in la_rows}
        for column_name, column_type in login_attempt_required_columns.items():
            if column_name not in la_existing:
                conn.exec_driver_sql(
                    f"ALTER TABLE login_attempts ADD COLUMN {column_name} {column_type}"
                )


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        yield session
