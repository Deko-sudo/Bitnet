# -*- coding: utf-8 -*-
"""
Database Session Management.

Предоставляет зависимость `get_db` для FastAPI. 
Соблюдает строгий подход управления сессиями: сессия открывается на время обработки
запроса HTTP и гарантированно закрывается в finally блоке.
"""

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# По умолчанию SQLite, но теперь с возможностью переопределения через Docker ENV
SQLALCHEMY_DATABASE_URL = os.getenv("SQLALCHEMY_DATABASE_URL", "sqlite:///./bitnet.db")

# check_same_thread=False специфично для SQLite (FastAPI работает асинхронно/в потоках пула)
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    """Dependency-injection генератор сессии для роутеров FastAPI."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
