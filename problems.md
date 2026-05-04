# problems.md

- [001]: [CRITICAL] [SOURCE]: backend/core/encryption_helper.py
  [VIOLATION]: Недостаточная автоматизация очистки памяти для возвращаемых полей.
  [REMEDY]: Изменить `decrypt_all_entry_fields` так, чтобы возвращались не просто `bytearray`, а обёртки `MemoryGuard` или реализовать явный `ContextManager` для пачки полей, чтобы Алексей гарантированно обнулял их после использования.

- [002]: [WARNING] [SOURCE]: backend/core/crypto_core.py, метод derive_master_key
  [VIOLATION]: Риск утечки копий пароля в RAM через создание `bytes(...)` из `bytearray`.
  [REMEDY]: Пересмотреть использование `bytes` при передаче в `argon2.low_level.hash_secret_raw`. Возможно, использовать `memoryview` для чтения данных без копирования.

- [003]: [INFO] [SOURCE]: backend/database/entry_service.py
  [VIOLATION]: Риск накопления расшифрованных данных в памяти при обработке списков (список записей = много объектов `bytearray` в RAM).
  [REMEDY]: Внедрить жесткое правило: при листинге (`list_entries`) данные НЕ расшифровываются. Расшифровка только при получении конкретной записи (`get_entry`) по запросу пользователя.
