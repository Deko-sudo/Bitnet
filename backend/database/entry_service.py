# -*- coding: utf-8 -*-
"""
Entry Service - CRUD operations for Password Entries.

Архитектурный выбор (SQLAlchemy 2.0 + Zero-Trust):
- Экземпляр Session не кэшируется глобально, так как он не thread-safe. Ожидается, что
  сессия будет создаваться через Context Manager на уровне API request (Dependency Injection в FastAPI).
- Вся работа с памятью и преобразования строгих `SecretStr` в raw-байты сопровождается
  блоками `finally: zero_memory()`, предотвращая засорение кучи CPython открытыми текстами.
- Реализована связка split-схемы моделей SQLAlchemy (`_cipher` и `_nonce`) без ORM-магии,
  явно инициализируя колонки БД.
"""

from datetime import datetime, timezone

from pydantic import SecretStr
from sqlalchemy.orm import Session
from sqlalchemy.orm.exc import StaleDataError

from backend.core.crypto_core import zero_memory
from backend.core.encryption_helper import (
    EncryptionHelper,
    EntryFieldsEncrypted,
    EntryFieldsRaw,
)
from backend.database.models import PasswordEntry
from backend.database.schemas import (
    EntryCreateSchema,
    EntryResponseSchema,
    EntryUpdateSchema,
)


class EntryNotFoundError(Exception):
    """Исключение, если запись не найдена или уделена (Trash)."""

    pass


class EntryConflictError(Exception):
    """Raised when optimistic concurrency detects a stale update."""

    pass


class EntryService:
    """Интерфейс для работы с зашифрованными записями в БД."""

    def __init__(self, session: Session, encryption_helper: EncryptionHelper):
        self.session = session
        self.encryption_helper = encryption_helper

    def create_entry(self, user_id: int, data: EntryCreateSchema) -> PasswordEntry:
        """
        Создает новую зашифрованную запись. Строгий Zero-Trust процесс.
        """
        raw_fields = EntryFieldsRaw(
            title=data.title,
            username=data.username,
            password=data.password,
            url=data.url,
            notes=data.notes,
        )

        encrypted_fields = self.encryption_helper.encrypt_entry_fields(raw_fields)

        blind_index_hex = None

        with self.encryption_helper._operation_key() as key:
            blind_index_hex = self.encryption_helper.generate_blind_index(
                data.title, key
            )

        new_entry = PasswordEntry(
            user_id=user_id,
            title_search=blind_index_hex,
            title_cipher=encrypted_fields.title_cipher,
            title_nonce=encrypted_fields.title_nonce,
            username_cipher=encrypted_fields.username_cipher,
            username_nonce=encrypted_fields.username_nonce,
            password_cipher=encrypted_fields.password_cipher,
            password_nonce=encrypted_fields.password_nonce,
            url_cipher=encrypted_fields.url_cipher,
            url_nonce=encrypted_fields.url_nonce,
            notes_cipher=encrypted_fields.notes_cipher,
            notes_nonce=encrypted_fields.notes_nonce,
        )

        self.session.add(new_entry)
        self.session.commit()
        self.session.refresh(new_entry)

        return new_entry

    # Внимание: параметр `entry_id` типизирован как `int` в соответствии с вашей SQLAlchemy моделью `PasswordEntry`
    # (id = mapped_column(Integer)). При необходимости использования UUID потребуется миграция БД.
    def get_entry(self, user_id: int, entry_id: int) -> EntryResponseSchema:
        """
        Чтение записи (Read).
        Извлекает запись и расшифровывает её, строго затирая мутабельные
        буферы (bytearray) после упаковки в Pydantic `SecretStr`.
        """
        entry = (
            self.session.query(PasswordEntry)
            .filter(
                PasswordEntry.id == entry_id,
                PasswordEntry.user_id == user_id,
                PasswordEntry.is_deleted == False,
            )
            .first()
        )

        if not entry:
            raise EntryNotFoundError(f"Entry {entry_id} not found or sent to trash.")

        encrypted_fields = EntryFieldsEncrypted(
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

        # helper вернет словарь, где все значения - это bytearray
        decrypted_dict = self.encryption_helper.decrypt_entry_fields(encrypted_fields)

        try:
            # Конвертируем bytearray в SecretStr для ResponseSchema
            title_sec = SecretStr(decrypted_dict["title"].decode("utf-8"))
            password_sec = SecretStr(decrypted_dict["password"].decode("utf-8"))

            username_sec = (
                SecretStr(decrypted_dict["username"].decode("utf-8"))
                if decrypted_dict["username"]
                else None
            )
            url_sec = (
                SecretStr(decrypted_dict["url"].decode("utf-8"))
                if decrypted_dict["url"]
                else None
            )
            notes_sec = (
                SecretStr(decrypted_dict["notes"].decode("utf-8"))
                if decrypted_dict["notes"]
                else None
            )

            return EntryResponseSchema(
                id=entry.id,
                user_id=entry.user_id,
                title=title_sec,
                username=username_sec,
                password=password_sec,
                url=url_sec,
                notes=notes_sec,
                created_at=entry.created_at,
                updated_at=entry.updated_at,
            )
        finally:
            # CRITICAL ZERO-TRUST RAM CLEARING RULE:
            # Итерируемся по словарю bytearray и принудительно обнуляем C-буферы (ctypes.memset).
            # Мы обязаны сделать это в блоке finally, чтобы предотвратить оседание
            # открытых текстов (паролей) в куче памяти в случае исключений Pydantic.
            for field_name, byte_arr in decrypted_dict.items():
                if byte_arr is not None:
                    zero_memory(byte_arr)

    def update_entry(
        self, user_id: int, entry_id: int, update_data: EntryUpdateSchema
    ) -> PasswordEntry:
        """
        Частичное обновление полей (Update). Пересчитывает слепой индекс при обновлении заголовка
        и перешифровывает только измененные поля по отдельности (Partial updates / PATCH).
        """
        entry = (
            self.session.query(PasswordEntry)
            .filter(
                PasswordEntry.id == entry_id,
                PasswordEntry.user_id == user_id,
                PasswordEntry.is_deleted == False,
            )
            .first()
        )

        if not entry:
            raise EntryNotFoundError(f"Entry {entry_id} not found or sent to trash.")

        # exclude_unset гарантирует, что мы обновляем только те объекты, которые явно передал клиент
        update_dict = update_data.model_dump(exclude_unset=True)
        if not update_dict:
            return entry

        # Пересчитываем Blind Index, если изменили заголовок
        if "title" in update_dict:
            with self.encryption_helper._operation_key() as key:
                blind_index_hex = self.encryption_helper.generate_blind_index(
                    update_data.title,
                    key,
                )
            entry.title_search = blind_index_hex

        # Сохранение старого пароля ПЕРЕД его заменой (Интеграция с PasswordHistoryManager)
        # Архитектурное решение безопасности: мы не расшифровываем старый пароль,
        # а просто копируем пару cipher/nonce. Ключ у юзера один и тот же!
        if "password" in update_dict and getattr(update_data, "password") is not None:
            from backend.database.models import PasswordHistory

            history_record = PasswordHistory(
                entry_id=entry.id,
                password_cipher=entry.password_cipher,
                password_nonce=entry.password_nonce,
                reason="Обновление пароля",
            )
            self.session.add(history_record)

        # Итерируемся по полям БД и перешифровываем порции (только те, которые затронуты в update_dict)
        target_fields = ["title", "username", "password", "url", "notes"]
        with self.encryption_helper._operation_key() as key:
            for field in target_fields:
                if field in update_dict:
                    new_val_sec = getattr(update_data, field)
                    if new_val_sec is not None:
                        cipher_hex, nonce_hex = (
                            self.encryption_helper._encrypt_text_field(new_val_sec, key)
                        )
                        setattr(entry, f"{field}_cipher", cipher_hex)
                        setattr(entry, f"{field}_nonce", nonce_hex)
                    else:
                        # Обработка обнуления опционального поля
                        if field not in ["title", "password"]:
                            setattr(entry, f"{field}_cipher", None)
                            setattr(entry, f"{field}_nonce", None)

        try:
            self.session.flush()
            self.session.commit()
        except StaleDataError as exc:
            self.session.rollback()
            raise EntryConflictError(
                f"Entry {entry_id} was modified by another transaction."
            ) from exc

        self.session.refresh(entry)
        return entry

    def soft_delete_entry(self, user_id: int, entry_id: int) -> bool:
        """
        Мягкое удаление (Soft Delete).
        Не стирает строку таблицы, а устанавливает флаг для механизма корзины.
        """
        entry = (
            self.session.query(PasswordEntry)
            .filter(
                PasswordEntry.id == entry_id,
                PasswordEntry.user_id == user_id,
                PasswordEntry.is_deleted == False,
            )
            .first()
        )

        if not entry:
            raise EntryNotFoundError(f"Entry {entry_id} not found or already in trash.")

        entry.is_deleted = True
        entry.deleted_at = datetime.now(timezone.utc)

        self.session.commit()
        return True
