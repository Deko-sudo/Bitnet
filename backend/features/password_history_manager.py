# -*- coding: utf-8 -*-
"""
Password History Manager — Fully asynchronous, Zero-Trust compliant.

Decrypts archived password ciphertexts using the real crypto pipeline:
    PasswordHistory.password_cipher + password_nonce
    → decrypt_entry_data(key) → LockedBuffer → bytearray → SecretStr
    → zero_memory(bytearray) + LockedBuffer.close()
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, SecretStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.core.crypto_bridge import LockedBuffer
from backend.core.crypto_core import zero_memory
from backend.core.encryption_helper import (
    decrypt_entry_data,
)
from backend.database.models import PasswordHistory

# ===========================================================================
# Schemas
# ===========================================================================


class HistoryResponseSchema(BaseModel):
    """Один архивный пароль из истории."""

    id: int
    entry_id: int
    password: SecretStr
    reason: Optional[str] = None
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


# ===========================================================================
# Service
# ===========================================================================


class PasswordHistoryManager:
    """Async-сервис для чтения архива старых паролей записи."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def get_history_async(
        self, entry_id: int, master_key: LockedBuffer
    ) -> list[HistoryResponseSchema]:
        """
        Возвращает историю старых паролей записи в хронологическом убывании.

        Каждая запись расшифровывается через реальный крипто-пайплайн,
        а plaintext немедленно обнуляется.
        """
        stmt = (
            select(PasswordHistory)
            .where(PasswordHistory.entry_id == entry_id)
            .order_by(PasswordHistory.created_at.desc())
        )
        result = await self.session.execute(stmt)
        records = result.scalars().all()

        history_responses: list[HistoryResponseSchema] = []
        for record in records:
            locked: LockedBuffer | None = None
            try:
                locked = decrypt_entry_data(
                    master_key,
                    record.password_cipher,
                    record.password_nonce,
                )
                pw_bytes = bytearray(len(locked))
                locked.copy_into(pw_bytes)
                try:
                    pw_str = pw_bytes.decode("utf-8")
                finally:
                    zero_memory(pw_bytes)

                history_responses.append(
                    HistoryResponseSchema(
                        id=record.id,
                        entry_id=record.entry_id,
                        password=SecretStr(pw_str),
                        reason=record.reason,
                        created_at=record.created_at,
                    )
                )
            finally:
                if locked is not None:
                    locked.close()

        return history_responses
