# -*- coding: utf-8 -*-
"""Shared API dependencies (database lifecycle, sessions)."""

import os
from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from backend.core.audit_logger import Base
from backend.database import models as _models  # noqa: F401 (register ORM models)


DATABASE_URL = os.getenv("BEZ_DATABASE_URL", "sqlite:///./bez.db")
CONNECT_ARGS = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(
    DATABASE_URL,
    connect_args=CONNECT_ARGS,
    future=True,
)
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    future=True,
)


def init_db() -> None:
    """Create tables for API runtime when they do not exist yet."""
    Base.metadata.create_all(bind=engine)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency that yields SQLAlchemy session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
