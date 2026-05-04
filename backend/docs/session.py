# -*- coding: utf-8 -*-
"""
Database Session Management.

Предоставляет зависимость `get_db` для FastAPI. 
Соблюдает строгий подход управления сессиями: сессия открывается на время обработки
запроса HTTP и гарантированно закрывается в finally блоке.
"""

import os
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from backend.core.audit_logger import Base
from backend.database import models as _models  # noqa: F401

# По умолчанию SQLite, но теперь с возможностью переопределения через Docker ENV
SQLALCHEMY_DATABASE_URL = os.getenv("SQLALCHEMY_DATABASE_URL", "sqlite:///./bitnet.db")

# check_same_thread=False специфично для SQLite (FastAPI работает асинхронно/в потоках пула)
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False, "timeout": 30},
    future=True,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine, future=True)


if SQLALCHEMY_DATABASE_URL.startswith("sqlite"):

    @event.listens_for(engine, "connect")
    def _sqlite_hardening(dbapi_connection, _connection_record) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("PRAGMA synchronous=NORMAL;")
        cursor.execute("PRAGMA busy_timeout=5000;")
        cursor.execute("PRAGMA foreign_keys=ON;")
        cursor.close()


def init_db() -> None:
    """Create runtime tables and apply SQLite durability settings."""
    Base.metadata.create_all(bind=engine)

def get_db():
    """Dependency-injection генератор сессии для роутеров FastAPI."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
