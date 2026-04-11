# -*- coding: utf-8 -*-
"""
Тесты CRUD Сервиса (Week 4 Validation).
Проверяют работоспособность и безопасность EntryService во внутренней SQLite базе.
"""

import pytest
from pydantic import SecretStr

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from backend.core.audit_logger import Base
from backend.database.models import User, PasswordEntry, PasswordHistory
from backend.database.schemas import EntryCreateSchema
from backend.database.entry_service import EntryService, EntryNotFoundError
from backend.core.encryption_helper import EncryptionHelper
from backend.core.crypto_core import CryptoCore, CryptoConfig

@pytest.fixture(scope="module")
def engine():
    """Инициализация in-memory базы с SQLAlchemy 2.0."""
    engine = create_engine("sqlite:///:memory:")
    # Base.metadata аккумулировала все модели из импортов backend.database.models
    Base.metadata.create_all(engine)
    return engine

@pytest.fixture
def session(engine) -> Session:
    """Предоставление транзакционной сессии на тест."""
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()
    yield session
    session.rollback()
    session.close()

@pytest.fixture
def crypto():
    """Инициализируем класс криптографии без сторонних сервисов."""
    return CryptoCore(CryptoConfig())

@pytest.fixture
def helper(crypto):
    """
    Мок EncryptionHelper, который эмулирует авторизованную сессию
    с dummy-ключом длиной 32 байта.
    """
    dummy_key = bytearray(b"0" * 32)
    def key_provider() -> bytearray:
        return bytearray(dummy_key)
    
    # Временный патч генерации слепого индекса для старых версий crypto_core.py
    if not hasattr(crypto, "generate_blind_index"):
        def mock_generate_blind_index(text: bytes, k: bytes) -> bytes:
            import hmac, hashlib
            return hmac.new(k, text, hashlib.sha256).digest()
        crypto.generate_blind_index = mock_generate_blind_index

    h = EncryptionHelper(key_provider=key_provider)
    h._crypto = crypto
    return h

@pytest.fixture
def user_id(session):
    """Вспомогательный пользователь для привязки ForeignKey."""
    u = User(
        username="test_user", 
        email="test@test.com", 
        password_hash="test", 
        salt=b"12345678"
    )
    session.add(u)
    session.commit()
    return u.id

def test_create_entry_blind_index(session, helper, user_id):
    """
    Test Case 1: Создание записи и верификация логики Слепого Индекса.
    Убеждаемся, что title_search не открытый текст, но существует как хеш.
    """
    service = EntryService(session, helper)
    schema = EntryCreateSchema(
        title=SecretStr("My Bank"),
        username=SecretStr("user1"),
        password=SecretStr("sup3rs3cr3t")
    )
    
    entry = service.create_entry(user_id, schema)
    assert entry.id is not None
    assert entry.title_cipher is not None
    assert entry.title_search is not None
    
    # Проверка, что индекс не сливает открытый текст заголовка
    assert entry.title_search != "My Bank"

def test_get_entry_integrity(session, helper, user_id):
    """
    Test Case 2: Интеграция `get_entry`.
    Проверка возврата правильных SecretStr и корректного обнуления ОЗУ 
    без возникновения Runtime Exception (блок try...finally отрабатывает).
    """
    service = EntryService(session, helper)
    schema = EntryCreateSchema(
        title=SecretStr("Gmail"),
        password=SecretStr("emailpass")
    )
    created = service.create_entry(user_id, schema)
    
    retrieved = service.get_entry(user_id, created.id)
    assert isinstance(retrieved.title, SecretStr)
    assert retrieved.title.get_secret_value() == "Gmail"
    assert retrieved.password.get_secret_value() == "emailpass"

def test_soft_delete(session, helper, user_id):
    """
    Test Case 3: Мягкое удаление (Soft Delete).
    Убеждаемся, что запись "исчезает" из методов сервиса, но остается в БД (is_deleted=True).
    """
    service = EntryService(session, helper)
    schema = EntryCreateSchema(
        title=SecretStr("To Delete"),
        password=SecretStr("delpass")
    )
    created = service.create_entry(user_id, schema)
    
    assert service.soft_delete_entry(user_id, created.id) is True
    
    # Запись не должна находиться через CRUD Service (имитация 404/Trash)
    with pytest.raises(EntryNotFoundError):
        service.get_entry(user_id, created.id)
    
    # Прямой запрос к БД показывает, что запись существует
    db_entry = session.query(PasswordEntry).filter(PasswordEntry.id == created.id).first()
    assert db_entry is not None
    assert db_entry.is_deleted is True
