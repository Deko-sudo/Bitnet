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
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_serializer
from backend.core.crypto_core import zero_memory


_MAX_FIELD_LENGTH = 10000


class EntryCreateSchema(BaseModel):
    """Схема создания новой записи с паролем."""

    title: SecretStr = Field(..., max_length=_MAX_FIELD_LENGTH)
    username: Optional[SecretStr] = Field(None, max_length=_MAX_FIELD_LENGTH)
    password: SecretStr = Field(..., max_length=_MAX_FIELD_LENGTH)
    url: Optional[SecretStr] = Field(None, max_length=_MAX_FIELD_LENGTH)
    notes: Optional[SecretStr] = Field(None, max_length=_MAX_FIELD_LENGTH)


class EntryUpdateSchema(BaseModel):
    """Схема обновления записи (все поля необязательны)."""

    title: Optional[SecretStr] = Field(None, max_length=_MAX_FIELD_LENGTH)
    username: Optional[SecretStr] = Field(None, max_length=_MAX_FIELD_LENGTH)
    password: Optional[SecretStr] = Field(None, max_length=_MAX_FIELD_LENGTH)
    url: Optional[SecretStr] = Field(None, max_length=_MAX_FIELD_LENGTH)
    notes: Optional[SecretStr] = Field(None, max_length=_MAX_FIELD_LENGTH)


class EntryEnvelopeCreateSchema(BaseModel):
    """E2EE create schema: opaque client-encrypted payload."""

    ciphertext: str = Field(..., min_length=1)
    iv: str = Field(..., min_length=1)
    auth_tag: str = Field(..., min_length=1)
    key_metadata: dict[str, Any] = Field(default_factory=dict)
    title_search: Optional[str] = None


class EntryEnvelopeUpdateSchema(BaseModel):
    """E2EE update schema: optional opaque encrypted payload replacement."""

    ciphertext: Optional[str] = Field(default=None, min_length=1)
    iv: Optional[str] = Field(default=None, min_length=1)
    auth_tag: Optional[str] = Field(default=None, min_length=1)
    key_metadata: Optional[dict[str, Any]] = None
    title_search: Optional[str] = None


class EntryEnvelopeResponseSchema(BaseModel):
    """E2EE response schema: encrypted blobs only, no plaintext."""

    id: int
    user_id: int
    ciphertext: str
    iv: str
    auth_tag: str
    key_metadata: dict[str, Any] = Field(default_factory=dict)
    title_search: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


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
