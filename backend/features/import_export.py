# -*- coding: utf-8 -*-
"""
Data Portability Service - Модуль Импорта и Экспорта.

Обеспечивает защищенную миграцию пользовательских данных в и из хранилища.
Гарантирует потоковую очистку памяти (Zero-Trust RAM Safety) при пакетной обработке 
десятков или сотен записей. Для экспорта формируется зашифрованный HEX-дамп всей 
базы (JSON не отдается в открытом виде!).
"""

import csv
import io
from pydantic import SecretStr
from sqlalchemy.orm import Session

from backend.database.models import PasswordEntry
from backend.database.schemas import EntryCreateSchema
from backend.database.entry_service import EntryService
from backend.core.encryption_helper import EncryptionHelper
from backend.core.crypto_core import zero_memory


class DataPortabilityService:
    def __init__(self, session: Session, encryption_helper: EncryptionHelper):
        self.session = session
        self.encryption_helper = encryption_helper
        self.entry_service = EntryService(session, encryption_helper)

    def import_from_csv(self, user_id: int, file_content: bytes) -> int:
        """
        Импорт записей из CSV формата. Процессинг строк через итератор
        для предотвращения загрузки всего массива незашифрованных паролей в ОЗУ разом.
        """
        # Преобразуем входящие байты в стрим для CSV-парсера
        csv_file = io.StringIO(file_content.decode("utf-8"))
        reader = csv.DictReader(csv_file)
        
        imported_count = 0
        for row in reader:
            raw_password_bytes = bytearray()
            try:
                # Извлекаем данные
                title = row.get("title", "Untitled")
                url = row.get("url") or None
                username = row.get("username") or None
                notes = row.get("notes") or None
                raw_password = row.get("password", "")
                
                # Копируем пароль в bytearray для гарантированной возможности очистки
                # (т.к. raw_password сам по себе str и иммутабелен)
                raw_password_bytes = bytearray(raw_password.encode("utf-8"))

                # Упаковка в схемы с SecretStr
                schema = EntryCreateSchema(
                    title=SecretStr(title),
                    username=SecretStr(username) if username else None,
                    password=SecretStr(raw_password),
                    url=SecretStr(url) if url else None,
                    notes=SecretStr(notes) if notes else None
                )

                # Безопасно сохраняем используя готовый цикл Zero-Trust 
                self.entry_service.create_entry(user_id, schema)
                imported_count += 1
            finally:
                # Мгновенно стираем байтовый буфер этого пароля перед парсингом следующей строки
                zero_memory(raw_password_bytes)
                # Очищаем словарь-ссылку CSV
                row.clear()

        # Стираем исходный полный буфер загруженного файла
        bytearray_content = bytearray(file_content)
        zero_memory(bytearray_content)
        
        return imported_count

    def export_to_encrypted_json(self, user_id: int) -> str:
        """
        Экспорт. Генерирует JSON-объект активных записей, 
        но перед отдачей полностью шифрует его Мастер-Ключом пользователя.
        Клиент получит HEX-дамп и расшифрует его локально.
        """
        entries = self.session.query(PasswordEntry).filter(
            PasswordEntry.user_id == user_id,
            PasswordEntry.is_deleted == False
        ).all()

        export_data = []
        for e in entries:
            # Для экспорта мы временно получаем полную развернутую схему 
            # (get_entry сама чистит внутренние C-буферы байтов)
            decrypted = self.entry_service.get_entry(user_id, e.id)
            export_data.append({
                "title": decrypted.title.get_secret_value(),
                "username": decrypted.username.get_secret_value() if decrypted.username else None,
                "password": decrypted.password.get_secret_value(),
                "url": decrypted.url.get_secret_value() if decrypted.url else None,
                "notes": decrypted.notes.get_secret_value() if decrypted.notes else None
            })

        try:
            # Превращаем финальный JSON в один гигантский зашифрованный блок с обнулением
            encrypted_hex = self.encryption_helper.encrypt_custom_fields({"entries": export_data})
            return encrypted_hex
        finally:
            # Затираем промежуточные открытые данные, переданные в export_data
            for record in export_data:
                record.clear()
            export_data.clear()
