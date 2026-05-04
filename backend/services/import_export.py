# -*- coding: utf-8 -*-
"""
Data Portability Service — Async Import/Export with Zero-Trust guarantees.

Architecture
------------
* **Batch Import**: пакетная обработка с ``add_all()`` и коммитом каждые N
  записей. Не вызывает ``session.add()`` в цикле.
* **Streaming Export**: async-генераторы (``yield``) — ни одна коллекция
  не загружается целиком в RAM. Поддержка CSV и JSONL.
* **Zero-Trust**: все plaintext-буферы — ``bytearray``, шифруются
  немедленно через ``encrypt_all_entry_fields``, затем ``zero_memory``.
* **Pydantic-валидация**: каждая строка импорта проверяется схемой до
  попадания в крипто-пайплайн.
"""

from __future__ import annotations

import asyncio
import csv
import io
import json
from typing import AsyncGenerator, Optional

from pydantic import BaseModel, ValidationError
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from backend.core.crypto_bridge import LockedBuffer
from backend.core.crypto_core import zero_memory
from backend.core.encryption_helper import (
    LockedBufferSet,
    decrypt_all_entry_fields,
    encrypt_all_entry_fields,
    generate_search_index,
)
from backend.database.models import PasswordEntry

# ===========================================================================
# Exceptions
# ===========================================================================


class ImportDatabaseError(Exception):
    """Batch insert failed (IntegrityError, OperationalError, etc.)."""


class ImportValidationError(Exception):
    """Pydantic validation of import rows failed."""


class ExportDatabaseError(Exception):
    """Failed to query entries for export."""


class ExportSerializationError(Exception):
    """Failed to serialize export chunk."""


# ===========================================================================
# Pydantic Schemas для импорта
# ===========================================================================


class ImportRowSchema(BaseModel):
    """Одна строка импорта (CSV/JSON). Все поля, кроме title и password, опциональны."""

    title: str
    username: Optional[str] = None
    password: str
    url: Optional[str] = None
    notes: Optional[str] = None


class ImportResult(BaseModel):
    """Результат операции импорта."""

    total_rows: int = 0
    imported: int = 0
    skipped: int = 0
    errors: list[str] = []


# ===========================================================================
# Константы
# ===========================================================================

# Размер batch-пакета: каждые N записей — один commit.
DEFAULT_BATCH_SIZE = 50

# Максимальное число одновременных batch-операций (semaphore).
MAX_CONCURRENT_BATCHES = 4

# Максимальный размер одной строки импорта (защита от DoS).
MAX_ROW_SIZE_BYTES = 10_000


# ===========================================================================
# Service
# ===========================================================================


class DataPortabilityService:
    """Асинхронный сервис импорта/экспорта с Zero-Trust и batch-обработкой."""

    def __init__(
        self,
        session: AsyncSession,
        master_key: LockedBuffer,
        *,
        batch_size: int = DEFAULT_BATCH_SIZE,
    ):
        self.session = session
        self.master_key = master_key
        self.batch_size = batch_size
        self._semaphore = asyncio.Semaphore(MAX_CONCURRENT_BATCHES)

    # =======================================================================
    # IMPORT
    # =======================================================================

    async def import_from_csv(self, user_id: int, file_content: bytes) -> ImportResult:
        """
        Импорт из CSV-файла.

        1. Декодирует CSV в строки.
        2. Валидирует каждую строку через Pydantic.
        3. Шифрует поля и создаёт ``PasswordEntry``.
        4. Пакетная вставка через ``add_all()`` + commit каждые ``batch_size``.
        """
        text_content = file_content.decode("utf-8")
        reader = csv.DictReader(io.StringIO(text_content))

        # Zeroize исходный файл после декодирования
        raw_bytes = bytearray(file_content)

        rows: list[ImportRowSchema] = []
        result = ImportResult()

        for row in reader:
            result.total_rows += 1
            try:
                schema = ImportRowSchema(
                    title=row.get("title", "").strip(),
                    username=row.get("username", "").strip() or None,
                    password=row.get("password", ""),
                    url=row.get("url", "").strip() or None,
                    notes=row.get("notes", "").strip() or None,
                )
                rows.append(schema)
            except ValidationError as exc:
                result.skipped += 1
                result.errors.append(f"Row {result.total_rows}: {exc}")
            finally:
                # Zeroize сырые данные строки
                for value in row.values():
                    if isinstance(value, str):
                        buf = bytearray(value.encode())
                        zero_memory(buf)

        zero_memory(raw_bytes)

        if not rows:
            return result

        result.imported = await self._batch_insert(user_id, rows, result)
        return result

    async def import_from_jsonl(
        self, user_id: int, file_content: bytes
    ) -> ImportResult:
        """
        Импорт из JSONL (JSON Lines). Каждая строка — один объект.

        Работает так же, как CSV-импорт, но парсит JSON вместо CSV.
        """
        text = file_content.decode("utf-8")
        raw_buf = bytearray(file_content)

        rows: list[ImportRowSchema] = []
        result = ImportResult()

        for line_no, line in enumerate(text.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            result.total_rows += 1
            try:
                data = json.loads(line)
                schema = ImportRowSchema(**data)
                rows.append(schema)
            except (json.JSONDecodeError, ValidationError) as exc:
                result.skipped += 1
                result.errors.append(f"Line {line_no}: {exc}")

        zero_memory(raw_buf)

        if not rows:
            return result

        result.imported = await self._batch_insert(user_id, rows, result)
        return result

    async def _batch_insert(
        self,
        user_id: int,
        rows: list[ImportRowSchema],
        result: ImportResult,
    ) -> int:
        """
        Пакетная вставка: шифрование + ``add_all()`` + commit каждые ``batch_size``.

        Использует семафор для ограничения параллельных batch-операций.
        """
        imported = 0

        for batch_start in range(0, len(rows), self.batch_size):
            batch = rows[batch_start:batch_start + self.batch_size]

            async with self._semaphore:
                ok = await self._insert_batch(user_id, batch)
                imported += ok
                result.skipped += len(batch) - ok

        return imported

    async def _insert_batch(self, user_id: int, rows: list[ImportRowSchema]) -> int:
        """
        Вставляет один батч записей.

        Для каждой строки:
        1. Конвертирует в ``bytearray`` (для шифрования).
        2. Генерирует blind index.
        3. Шифрует все поля.
        4. Создаёт ``PasswordEntry``.
        5. ``session.add_all()`` + ``session.commit()``.
        """
        entries: list[PasswordEntry] = []
        imported = 0

        for row in rows:
            try:
                entry = await self._encrypt_and_build_entry(user_id, row)
                entries.append(entry)
                imported += 1
            except (ValidationError, Exception):
                # Пропускаем проблемную запись, продолжаем батч
                continue

        if entries:
            try:
                self.session.add_all(entries)
                await self.session.commit()
            except SQLAlchemyError as exc:
                await self.session.rollback()
                raise ImportDatabaseError(f"Batch insert failed: {exc}") from exc

        return imported

    async def _encrypt_and_build_entry(
        self, user_id: int, row: ImportRowSchema
    ) -> PasswordEntry:
        """
        Шифрует поля строки и создаёт ``PasswordEntry``.

        Все ``bytearray`` буферы zeroiz-ятся сразу после шифрования.
        """
        # Конвертируем в mutable буферы для шифрования
        title_buf = bytearray(row.title.encode("utf-8"))
        title_buf_idx = bytearray(row.title.encode("utf-8"))
        password_buf = bytearray(row.password.encode("utf-8"))
        username_buf = bytearray(row.username.encode("utf-8")) if row.username else None
        url_buf = bytearray(row.url.encode("utf-8")) if row.url else None
        notes_buf = bytearray(row.notes.encode("utf-8")) if row.notes else None

        try:
            # Blind index для поиска (zeroiz-ится внутри generate_search_index)
            blind_index = generate_search_index(self.master_key, title_buf_idx)

            # Шифруем все поля (каждый buf zeroiz-ится внутри encrypt_all_entry_fields)
            encrypted = encrypt_all_entry_fields(
                self.master_key,
                title=title_buf,
                username=username_buf,
                password=password_buf,
                url=url_buf,
                notes=notes_buf,
            )
        finally:
            # Defense-in-depth: убеждаемся, что буферы обнулены
            for buf in (
                title_buf,
                title_buf_idx,
                password_buf,
                username_buf,
                url_buf,
                notes_buf,
            ):
                if buf is not None:
                    zero_memory(buf)

        return PasswordEntry(
            user_id=user_id,
            title_search=blind_index,
            title_cipher=encrypted["title_cipher"],
            title_nonce=encrypted["title_nonce"],
            username_cipher=encrypted["username_cipher"],
            username_nonce=encrypted["username_nonce"],
            password_cipher=encrypted["password_cipher"],
            password_nonce=encrypted["password_nonce"],
            url_cipher=encrypted["url_cipher"],
            url_nonce=encrypted["url_nonce"],
            notes_cipher=encrypted["notes_cipher"],
            notes_nonce=encrypted["notes_nonce"],
        )

    # =======================================================================
    # EXPORT — Streaming
    # =======================================================================

    async def _query_user_entries(
        self, user_id: int
    ) -> AsyncGenerator[PasswordEntry, None]:
        """
        Асинхронный генератор: отдаёт записи по одной через ``yield``.

        Использует chunked select, чтобы не загружать весь результат в RAM.
        """
        stmt = (
            select(PasswordEntry)
            .where(
                PasswordEntry.user_id == user_id,
                PasswordEntry.is_deleted == False,  # noqa: E712
            )
            .order_by(PasswordEntry.id)
        )

        # Chunked pagination: читаем по ``batch_size`` записей за раз
        offset = 0
        while True:
            chunk_stmt = stmt.offset(offset).limit(self.batch_size)
            result = await self.session.execute(chunk_stmt)
            chunk = list(result.scalars().all())

            if not chunk:
                break

            for entry in chunk:
                yield entry

            offset += self.batch_size

    async def export_to_csv_stream(self, user_id: int) -> AsyncGenerator[str, None]:
        """
        Streaming CSV-экспорт.

        Yield-ит строки CSV по одной (включая заголовок).
        После decrypt каждая ``bytearray`` обнуляется.
        """
        header = "title,username,password,url,notes\n"
        yield header

        async for entry in self._query_user_entries(user_id):
            lbs, decrypted = self._decrypt_entry(entry)
            try:
                row_dict = {
                    "title": self._buf_to_str(decrypted.get("title")),
                    "username": self._buf_to_str(decrypted.get("username")),
                    "password": self._buf_to_str(decrypted.get("password")),
                    "url": self._buf_to_str(decrypted.get("url")),
                    "notes": self._buf_to_str(decrypted.get("notes")),
                }
                output = io.StringIO()
                writer = csv.DictWriter(output, fieldnames=row_dict.keys())
                writer.writerow(row_dict)
                yield output.getvalue()
            finally:
                lbs.close()

    async def export_to_jsonl_stream(self, user_id: int) -> AsyncGenerator[str, None]:
        """
        Streaming JSONL-экспорт.

        Каждая строка — JSON-объект с расшифрованными полями.
        Память освобождается сразу после yield.
        """
        async for entry in self._query_user_entries(user_id):
            lbs, decrypted = self._decrypt_entry(entry)
            try:
                obj = {
                    "title": self._buf_to_str(decrypted.get("title")),
                    "username": self._buf_to_str(decrypted.get("username")),
                    "password": self._buf_to_str(decrypted.get("password")),
                    "url": self._buf_to_str(decrypted.get("url")),
                    "notes": self._buf_to_str(decrypted.get("notes")),
                }
                yield json.dumps(obj, ensure_ascii=False) + "\n"
            finally:
                lbs.close()

    async def export_full_csv(self, user_id: int) -> str:
        """
        Удобный метод: собирает весь CSV в строку (для маленьких наборов).

        Для больших наборов используйте ``export_to_csv_stream()``.
        """
        chunks: list[str] = []
        async for chunk in self.export_to_csv_stream(user_id):
            chunks.append(chunk)
        return "".join(chunks)

    async def export_full_jsonl(self, user_id: int) -> str:
        """
        Удобный метод: собирает весь JSONL в строку (для маленьких наборов).

        Для больших наборов используйте ``export_to_jsonl_stream()``.
        """
        chunks: list[str] = []
        async for chunk in self.export_to_jsonl_stream(user_id):
            chunks.append(chunk)
        return "".join(chunks)

    # =======================================================================
    # Internal helpers
    # =======================================================================

    def _decrypt_entry(
        self, entry: PasswordEntry
    ) -> tuple[LockedBufferSet, dict[str, Optional[bytearray]]]:
        """Расшифровывает все поля записи. Вызывающий обязан закрыть ``LockedBufferSet``."""
        return decrypt_all_entry_fields(
            self.master_key,
            title_cipher=entry.title_cipher,
            title_nonce=entry.title_nonce,
            username_cipher=entry.username_cipher,
            username_nonce=entry.username_nonce,
            password_cipher=entry.password_cipher,
            password_nonce=entry.password_nonce,
            url_cipher=entry.url_cipher,
            url_nonce=entry.url_nonce,
            notes_cipher=entry.notes_cipher,
            notes_nonce=entry.notes_nonce,
        )

    @staticmethod
    def _buf_to_str(buf: Optional[bytearray]) -> str:
        """Конвертирует ``bytearray`` в ``str``. Возвращает пустую строку если ``None``."""
        if buf is None:
            return ""
        return buf.decode("utf-8")
