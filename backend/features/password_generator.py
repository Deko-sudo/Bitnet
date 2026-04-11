# -*- coding: utf-8 -*-
"""
Password Generator - Криптостойкий генератор паролей (Zero-Trust).
"""

import secrets
from pydantic import BaseModel, SecretStr, Field
from backend.core.crypto_core import zero_memory

class GeneratorConfig(BaseModel):
    """Схема конфигурации генерации пароля."""
    length: int = Field(default=16, ge=12, le=128)
    use_uppercase: bool = True
    use_numbers: bool = True
    use_special: bool = True
    exclude_similar: bool = False

class PasswordGenerator:
    """Генератор криптостойких паролей с настройкой энтропии."""
    
    def generate(self, config: GeneratorConfig) -> SecretStr:
        """
        Создает случайный пароль и оборачивает в Pydantic SecretStr.
        Zero-Trust: Генерация происходит напрямую в массив байтов,
        после оборачивания буфер обнуляется аппаратно (memory wiped).
        """
        # Формируем алфавитный набор строго в виде байтов, чтобы не плодить string caching
        charset = bytearray(b'abcdefghijklmnopqrstuvwxyz')
        if config.use_uppercase: 
            charset.extend(b'ABCDEFGHIJKLMNOPQRSTUVWXYZ')
        if config.use_numbers: 
            charset.extend(b'0123456789')
        if config.use_special: 
            charset.extend(b'!@#$%^&*()_+-=[]{}|;:,.<>?')

        if config.exclude_similar:
            # Исключаем i, l, 1, L, o, 0, O
            similar = b'il1Lo0O'
            charset = bytearray([c for c in charset if c not in similar])

        if not charset:
            raise ValueError("Набор символов для генератора пуст")

        # Буфер для сборки "чистого" пароля (mutable memory)
        pass_buf = bytearray(config.length)
        
        for i in range(config.length):
            pass_buf[i] = secrets.choice(charset)

        # Конвертация в строку и оборачивание в SecretStr
        secret = SecretStr(pass_buf.decode('utf-8'))
        
        # Строго и принудительно затираем случайный результат в ОЗУ
        zero_memory(pass_buf)
        zero_memory(charset)
        
        return secret
