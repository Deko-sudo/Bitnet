# -*- coding: utf-8 -*-
"""
Data Portability Service - Модуль Импорта и Экспорта (Полностью асинхронный).
"""

import csv
import io

from pydantic import SecretStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.core.crypto_core import zero_memory
from backend.core.encryption_helper import EncryptionHelper
from backend.database.entry_service import EntryService
from backend.database.models import PasswordEntry
from backend.database.schemas import EntryCreateSchema


class DataPortabilityService:
    def __init__(self, session: AsyncSession, encryption_helper: EncryptionHelper):
        self.session = session
        self.encryption_helper = encryption_helper
        self.entry_service = EntryService(session, encryption_helper)

    async def import_from_csv(self, user_id: int, file_content: bytes) -> int:
        csv_file = io.StringIO(file_content.decode("utf-8"))
        reader = csv.DictReader(csv_file)
        imported_count = 0
        for row in reader:
            raw_password = row.get("password", "")
            raw_password_bytes = bytearray(raw_password.encode("utf-8"))
            try:
                schema = EntryCreateSchema(
                    title=SecretStr(row.get("title", "Untitled")),
                    username=SecretStr(row.get("username"))
                    if row.get("username")
                    else None,
                    password=SecretStr(raw_password),
                    url=SecretStr(row.get("url")) if row.get("url") else None,
                    notes=SecretStr(row.get("notes")) if row.get("notes") else None,
                )
                await self.entry_service.create_entry_async(user_id, schema)
                imported_count += 1
            finally:
                zero_memory(raw_password_bytes)
                row.clear()

        bytearray_content = bytearray(file_content)
        zero_memory(bytearray_content)
        return imported_count

    async def export_to_encrypted_json(self, user_id: int) -> str:
        stmt = select(PasswordEntry).filter(
            PasswordEntry.user_id == user_id, PasswordEntry.is_deleted == False
        )
        result = await self.session.execute(stmt)
        entries = result.scalars().all()

        export_data = []
        for e in entries:
            decrypted = await self.entry_service.get_entry_async(user_id, e.id)
            export_data.append(
                {
                    "title": decrypted.title.get_secret_value(),
                    "username": decrypted.username.get_secret_value()
                    if decrypted.username
                    else None,
                    "password": decrypted.password.get_secret_value(),
                    "url": decrypted.url.get_secret_value() if decrypted.url else None,
                    "notes": decrypted.notes.get_secret_value()
                    if decrypted.notes
                    else None,
                }
            )

        try:
            return self.encryption_helper.encrypt_custom_fields(
                {"entries": export_data}
            )
        finally:
            for record in export_data:
                record.clear()
            export_data.clear()
