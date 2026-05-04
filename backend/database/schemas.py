# -*- coding: utf-8 -*-
"""
Pydantic schemas for Database and API data validation (Zero-Trust adherence).

Architecture choice (Pydantic v2):
- ``SecretStr`` is used for all sensitive fields to prevent accidental logging
  and repr leakage.
- ``@field_serializer`` overrides ensure the **real** secret value is sent in
  the JSON response body (the client needs the decrypted plaintext).
- Masking (``**********``) applies only to ``repr`` / ``str`` / log output,
  not to the serialized API payload.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, SecretStr, field_serializer
from backend.core.crypto_core import zero_memory


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

    @field_serializer("title", "username", "password", "url", "notes")
    def _serialize_secrets(self, value: SecretStr | None, _info) -> str | None:
        if value is None:
            return None
        return value.get_secret_value()


@dataclass
class EntryResponseRaw:
    """Внутреннее представление для Desktop приложения — содержит только zeroable структуры bytearray"""

    id: int
    user_id: int
    title: bytearray
    password: bytearray
    created_at: datetime
    updated_at: datetime
    username: Optional[bytearray] = None
    url: Optional[bytearray] = None
    notes: Optional[bytearray] = None

    def wipe(self) -> None:
        """Обнулить все конфиденциальные поля после использования."""
        for field in [self.title, self.password, self.username, self.url, self.notes]:
            if field is not None:
                zero_memory(field)




class EntryListItemSchema(BaseModel):
    """Схема списка записей (содержит только метаданные)."""

    id: int
    title: SecretStr
    url: Optional[SecretStr] = None

    model_config = ConfigDict(from_attributes=True)

    @field_serializer("title", "url")
    def _serialize_list_secrets(self, value: SecretStr | None, _info) -> str | None:
        if value is None:
            return None
        return value.get_secret_value()
