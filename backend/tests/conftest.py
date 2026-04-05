# -*- coding: utf-8 -*-
"""
Pytest configuration — shared fixtures for Nikita (BE1) and Alex (BE2).

Provides:
- In-memory SQLite engine for isolated test databases
- Session-scoped SQLAlchemy Base metadata
- Function-scoped Session fixture with automatic rollback
"""

import sys
import os

# Ensure project root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from typing import Generator

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from backend.database.models import Base


# =============================================================================
# In-Memory SQLite Engine
# =============================================================================


@pytest.fixture(scope="session")
def engine():
    """
    Create an in-memory SQLite engine shared across the test session.

    Uses StaticPool so the :memory: database persists across multiple
    connections within the same session.
    """
    eng = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(eng)
    yield eng
    Base.metadata.drop_all(eng)
    eng.dispose()


# =============================================================================
# SQLAlchemy Session
# =============================================================================


@pytest.fixture()
def db_session(engine) -> Generator[Session, None, None]:
    """
    Provide a transactional database session for each test.

    The session is rolled back after the test completes, ensuring
    complete isolation between tests.

    Yields:
        SQLAlchemy Session bound to in-memory SQLite.
    """
    connection = engine.connect()
    transaction = connection.begin()
    session_factory = sessionmaker(
        bind=connection,
        expire_on_commit=False,
    )
    session = session_factory()

    yield session

    session.close()
    transaction.rollback()
    connection.close()


# =============================================================================
# Crypto Test Helpers
# =============================================================================


@pytest.fixture()
def sample_master_key() -> bytearray:
    """
    Provide a deterministic 32-byte master key for tests.

    WARNING: This is NOT a real key — only for unit tests.
    """
    return bytearray(b"\x00" * 32)


@pytest.fixture()
def sample_salt() -> bytes:
    """Provide a deterministic 16-byte salt for tests."""
    return b"test_salt_16b!!"
