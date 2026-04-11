# -*- coding: utf-8 -*-
"""
Search Engine - Реализует паттерн Blind Index (Слепой Индекс).

Архитектурный выбор:
Вместо небезопасной расшифровки всех записей пользователя в ОЗУ для фильтрации,
сервис использует детерминированное хеширование пользовательского запроса 
и производит быстрый поиск exact-match по базе данных. HMAC-ключом выступает
Master Key пользователя, что исключает возможность подбора по Rainbow таблицам.
"""

from typing import List
from sqlalchemy.orm import Session
from backend.database.models import PasswordEntry
from backend.core.encryption_helper import EncryptionHelper
from backend.core.crypto_core import zero_memory

class SearchService:
    """Сервис поиска по зашифрованным данным."""

    def __init__(self, session: Session, encryption_helper: EncryptionHelper):
        self.session = session
        self.encryption_helper = encryption_helper

    def search_by_title(self, user_id: int, query: str) -> List[PasswordEntry]:
        """Ищет записи по Слепому Индексу заголовка."""
        blind_index_hex = None
        
        # Запрашиваем временный контекст ключа
        with self.encryption_helper._operation_key() as key:
            query_bytes = bytearray(query.encode("utf-8"))
            try:
                # Генерируем HMAC хэш от поискового запроса
                if hasattr(self.encryption_helper._crypto, "generate_blind_index"):
                    blind_index_bytes = self.encryption_helper._crypto.generate_blind_index(
                        bytes(query_bytes), bytes(key)
                    )
                    if blind_index_bytes:
                        blind_index_hex = blind_index_bytes.hex()
            finally:
                # Обязательное автозатирание поискового запроса
                zero_memory(query_bytes)
        
        # Fallback, если Blind Index еще не задеплоен BE1
        if not blind_index_hex:
            return []

        # Быстрый и безопасный SQL-запрос
        entries = self.session.query(PasswordEntry).filter(
            PasswordEntry.user_id == user_id,
            PasswordEntry.is_deleted == False,
            PasswordEntry.title_search == blind_index_hex
        ).all()

        return entries
