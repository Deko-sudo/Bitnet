# -*- coding: utf-8 -*-
"""
Pydantic schemas for Database and API data validation (Zero-Trust adherence).

Архитектурный выбор (Pydantic v2):
- Использование `SecretStr` обязательно для всех чувствительных строковых полей (даже опциональных). 
  Pydantic перехватит `repr` и `str` преобразования, маскируя значения как '**********'. Это 
  фундаментально для предотвращения утечек паролей и заголовков в системных логах сервера.
- `ConfigDict(from_attributes=True)` – стандарт Pydantic v2 для маппинга SQLAlchemy 2.0 
  моделей directamente в Pydantic схемы ответов.
"""

from typing import Optional
from datetime import datetime
from pydantic import BaseModel, SecretStr, ConfigDict

class EntryCreateSchema(BaseModel):
    """Схема создания новой записи с паролем."""
    title: SecretStr
    username: Optional[SecretStr] = None
    password: SecretStr
    url: Optional[SecretStr] = None
    notes: Optional[SecretStr] = None

class EntryUpdateSchema(BaseModel):
    """Схема обновления записи (все поля необязательны)."""
    title: Optional[SecretStr] = None
    username: Optional[SecretStr] = None
    password: Optional[SecretStr] = None
    url: Optional[SecretStr] = None
    notes: Optional[SecretStr] = None

class EntryResponseSchema(BaseModel):
    """Схема ответа для клиента (содержит расшифрованные поля в виде SecretStr)."""
    id: int
    user_id: int
    title: SecretStr
    username: Optional[SecretStr] = None
    password: SecretStr
    url: Optional[SecretStr] = None
    notes: Optional[SecretStr] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

class EntryListItemSchema(BaseModel):
    """Схема списка записей (содержит только метаданные)."""
    id: int
    title: SecretStr
    url: Optional[SecretStr] = None

    model_config = ConfigDict(from_attributes=True)
