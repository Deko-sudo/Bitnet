# -*- coding: utf-8 -*-
"""
Password History Manager - Отслеживание истории паролей.

Архитектурный выбор (Zero-Trust):
Хранение истории паролей не должно ослаблять общую защиту пользователя. В данном
сервисе исторические пароли возвращаются клиенту исключительно через Pydantic `SecretStr`.
Реализовано обязательное аппаратное затирание буферов (bytearray) в `finally`.
"""

from datetime import datetime
from sqlalchemy.orm import Session
from pydantic import BaseModel, SecretStr, ConfigDict
from backend.database.models import PasswordHistory
from backend.core.encryption_helper import EncryptionHelper
from backend.core.crypto_core import zero_memory

class HistoryResponseSchema(BaseModel):
    """Схема ответа для отдельной записи исторического пароля."""
    id: int
    entry_id: int
    password: SecretStr
    reason: str | None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class PasswordHistoryManager:
    """Сервис для доступа к архиву старых паролей записи."""
    
    def __init__(self, session: Session, encryption_helper: EncryptionHelper):
        self.session = session
        self.encryption_helper = encryption_helper

    def add_old_password(self, entry_id: int, old_password: str | SecretStr, reason: str = "Пароль изменен") -> PasswordHistory:
        """
        [Устаревший метод] 
        Резервный метод для явного шифрования сырого сохраненного текста.
        Обычно используется прямой копипаст cipher/nonce из БД внутри entry_service 
        (см. update_entry), чтобы не нагружать процессор и не открывать текст.
        """
        with self.encryption_helper._operation_key() as key:
            cipher_hex, nonce_hex = self.encryption_helper._encrypt_text_field(old_password, key)
            
            history_record = PasswordHistory(
                entry_id=entry_id,
                password_cipher=cipher_hex,
                password_nonce=nonce_hex,
                reason=reason
            )
            self.session.add(history_record)
            self.session.commit()
            return history_record

    def get_history(self, entry_id: int) -> list[HistoryResponseSchema]:
        """
        Возвращает историю старых паролей записи в хронологическом убывании.
        Строго соблюден паттерн Memory Safety при расшифровке.
        """
        records = self.session.query(PasswordHistory).filter(
            PasswordHistory.entry_id == entry_id
        ).order_by(PasswordHistory.created_at.desc()).all()

        history_responses = []
        with self.encryption_helper._operation_key() as key:
            for record in records:
                try:
                    # Расшифровываем в мутабельный буфер
                    pass_bytes = self.encryption_helper._decrypt_text_field(
                        record.password_cipher, record.password_nonce, key
                    )
                    # Упаковываем в безопасную модель
                    pass_sec = SecretStr(pass_bytes.decode('utf-8'))
                    history_responses.append(
                        HistoryResponseSchema(
                            id=record.id,
                            entry_id=record.entry_id,
                            password=pass_sec,
                            reason=record.reason,
                            created_at=record.created_at
                        )
                    )
                finally:
                    # ZERO-TRUST: строго стираем восстановленный старый пароль из ОЗУ на каждой итерации
                    zero_memory(pass_bytes)
                    
        return history_responses
