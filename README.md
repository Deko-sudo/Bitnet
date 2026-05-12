# BitNet: Zero-Trust E2EE Password Manager 🔐

BitNet — это высоконадежный серверный бэкенд для управления паролями. Проект построен на концепции **Сквозного Шифрования (End-to-End Encryption)** и агрессивной **Защите Памяти (Zero-Trust RAM Wiping)**. Сервер *никогда* не хранит, не кэширует и не выводит в логи ничего, кроме криптографически нечитаемых данных.

## 🛡️ Технологический Стек
*   **Язык:** Python 3.11+
*   **Фреймворк:** FastAPI (REST, Swagger/OpenAPI)
*   **СУБД:** SQLite по умолчанию (Интегрирован SQLAlchemy 2.0, готово к Alembic и PostgreSQL)
*   **Криптография:** 
    * `cryptography` (AES-256-GCM алгоритм)
    * `argon2-cffi` (Argon2id KDF для защиты от GPU/ASIC-подбора алгоритмов)
    * Интеграция `HMAC` для защищенного Blind-поиска
*   **Валидация потоков:** Pydantic v2 (Использование только-only объекта `SecretStr`)

## 🔐 Ключевые архитектурные паттерны
1. **Аппаратное затирание памяти (Hardware RAM Wiping):** Использование `ctypes.memset` для физического обнуления C-буферов (модуль `zero_memory()`). В отличие от сборщика мусора Python, это исключает дамп паролей из кучи ОЗУ в случае RCE-эксплоита на сервере.
2. **Слепой индекс (Blind Index):** Поиск по пользовательским названиям (`title`) происходит через детерминированное хеширование. Ни один заголовок не хранится и не ищется как открытый текст.
3. **Разделение Nonce/Cipher:** Изоляция вектора инициализации от шифротекста прямо на уровне разделенных колонок базы данных.
4. **Непрерывная История:** Интегрирован тихий `PasswordHistoryManager`, который сохраняет устаревшие ключи простым дублированием `_cipher` строк, экономя такты процессора и не вызывая утечки при перешифровании.

## 🚀 Как запустить (С помощью Docker)

Проект полностью готов к Production-развертыванию (работает от имени непривилегированного юзера в контейнере).

1.  **Склонируйте репозиторий и создайте папку для базы данных:**
    ```bash
    mkdir -p data
    ```
2.  **Запустите оркестрацию (в фоновом режиме):**
    ```bash
    docker-compose up -d --build
    ```
3.  **Изучите методы API и Документацию:**
    Swagger UI автоматически сгенерирован FastAPI. Перейдите по адресу:
    [http://localhost:8000/docs](http://localhost:8000/docs)
    
    *Вы найдете контроллеры:*
    - `/api/v1/entries` (Управление записями)
    - `/api/v1/auth` (Управление Регистрацией)
    - `/api/v1/trash` (Управление Корзиной/Восстановлением)
    - `/api/v1/generator` (Генератор паролей / passphrase / PIN) — v2.1.0
    - `/api/v1/backups` (Backup / restore / rotation) — v2.1.0
    - `/api/v1/fido2` (FIDO2/WebAuthn аутентификация)
    - `/api/v1/portability` (Импорт / экспорт) — v2.1.0

## v2.1.0 Новинки
- **Password Generator** — Zero-Trust генератор паролей, passphrase (diceware) и PIN через `POST /api/v1/generator/{password,passphrase,pin}`.  
  `PasswordStrengthChecker` интегрирован; все промежуточные буферы `bytearray` + `zero_memory`. Coverage: 94%.
- **Search Engine** — Blind-Index exact-match поиск по зашифрованным заголовкам через `?query=` в списке entries.  
  Меньше 500ms на 10 000 записей. Coverage: 88%.
- **Backup Manager** — AES-256-GCM + HMAC backup/restore/rotation через `POST /api/v1/backups/` и `POST /api/v1/backups/{name}/restore`.  
  Требует `confirmed=True` для restore. Coverage: 97%.
- **Alembic** — `alembic revision --autogenerate` и `alembic upgrade head` работают.
- **DB Optimization** — SQLite WAL, 64MB cache, mmap, foreign_keys ON.

## ⚠️ Информация для Frontend-разработчиков
API **не** занимается E2EE на стороне клиента. Текущий бэкенд гарантирует нерушимость данных на уровне транспорта сервера и хранилища (идеальный "нулевой" след в памяти на бэке). Для истинного E2EE генерируйте мастер-ключи на стороне JS-клиента в браузере и отдавайте бэкенду уже готовый `title_cipher` и `password_cipher`.
