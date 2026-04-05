## 🗺️ Дорожная карта разработки — Никита (BE1)
### Backend Developer 1 — Архитектор и специалист по безопасности
### 📚 Используемые технологии и инструменты
#### Языки программирования
- Python 3.11+ — основной язык backend разработки
- PyPy 7.3+ — JIT-компилятор Python для ускорения в 3-5 раз
#### Фреймворки и библиотеки
#### Криптография
- cryptography 41.0+ — основная библиотека криптографии
	- AESGCM — шифрование AES-256-GCM
	- hashes — хеширование (SHA-256, HMAC)
- argon2-cffi 23.1+ — деривация ключей (Argon2id)
- PyNaCl 1.5+ — дополнительные криптографические примитивы (libsodium)
#### Валидация конфигурации и данных
- Pydantic v2 — типизация и валидация конфигураций безопасности
	- SecretStr — безопасное хранение секретов (не светится в логах)
	- BaseSettings — конфигурация через переменные окружения
#### ORM (для таблицы AuditLog)
- SQLAlchemy 2.0+ — запись событий безопасности в БД
#### Утилиты
- secrets (встроенный) — криптостойкая генерация случайных чисел
- hashlib (встроенный) — хеширование
- hmac (встроенный) — подписи HMAC
#### База данных
- SQLite 3 — встроенная БД
- SQLCipher (опционально) — зашифрованный SQLite
#### Тестирование и качество кода
- pytest 7.4+ — фреймворк для тестирования
- pytest-cov 4.1+ — покрытие кода тестами
- pytest-benchmark — бенчмарки производительности
- bandit — статический анализ безопасности Python кода
- safety — проверка уязвимостей в зависимостях
- black 23.12+ — автоформатирование кода
- flake8 6.1+ — линтер Python
- mypy 1.7+ — статическая типизация
- pylint — углубленный анализ кода
#### Инструменты разработки
- Git — контроль версий
- GitHub — хостинг репозитория и Code Review
- GitHub Actions — CI/CD pipeline (матрица CPython + PyPy)
- VS Code / PyCharm — IDE
#### Документация
- Markdown — документация проекта
- draw.io — диаграммы архитектуры
### 🎯 Твоя роль и ответственность
Ты отвечаешь за весь слой безопасности приложения:
- Криптографическое ядро (шифрование, деривация ключей)
- Защита мастер-пароля и управление ключами в памяти
- Rate limiting и защита от брутфорса
- Аудит безопасности и логирование через SQLAlchemy
- Pydantic схемы для конфигурации безопасности
- Архитектура системы и code review
Принцип работы:
- Ты создаёшь безопасные модули (crypto_core.py, auth_manager.py)
- Алексей (BE2) использует твои модули через удобные обёртки
- Ты проверяешь код Алексея на уязвимости перед каждым мерджем
### 📅 Дорожная карта по спринтам
#### 🔴 Спринт 1-2 (Недели 1-4): Фундамент безопасности
Цель: Создать криптографическое ядро и базовую архитектуру
#### Неделя 1: Архитектура и планирование
День 1-2: Проектирование
- [x] Создать архитектурную диаграмму системы (draw.io)
- [x] Написать документ "Модель угроз" (Threat Model)
	- Определить активы (что защищаем)
	- Определить атакующих и сценарии атак
	- Описать угрозы и меры защиты
- [x] Выбрать и обосновать криптографические алгоритмы — документ docs/crypto_choices.md
День 3-4: Настройка проекта
- [x] Создать структуру проекта:
	- backend/core/ — твоя зона (crypto, auth, security)
	- backend/database/ — зона Алексея
	- backend/api/ — REST endpoints
	- backend/tests/ — тесты
- [x] Настроить PyPy virtual environment
- [x] Установить все зависимости (requirements.txt)
- [x] Настроить Git hooks для pre-commit проверок
- [x] Настроить CI/CD (GitHub Actions) с матрицей CPython + PyPy
- [x] ⚠️ **[ДОБАВЛЕНО]** Верифицировать совместимость PyPy 7.3+ с cryptography, argon2-cffi, PyNaCl — запустить базовые smoke-тесты (import + одна операция каждой библиотеки) в PyPy окружении. Зафиксировать результаты в `docs/pypy_compatibility.md`. Если совместимость неполная — принять решение о стратегии (например: CPython для крипто-операций, PyPy для остального) **до начала реализации**, а не в Неделю 8.
День 5: Написание спецификаций
- [x] Написать спецификацию crypto_core.py — методы, параметры, типы
- [x] Написать Pydantic схему конфигурации безопасности (Argon2 параметры, длина ключа и т.д.)
- [x] Создать SECURITY.md с правилами безопасности
- [ ] Согласовать интерфейсы с Алексеем
- [x] ⚠️ **[ДОБАВЛЕНО]** Создать EncryptionHelper stub (`core/encryption_helper_stub.py`) — заглушка с теми же сигнатурами методов что у финального EncryptionHelper, но без реальной криптографии (возвращает данные без изменений). Передать Алексею вместе со спецификацией — это разблокирует его разработку и тестирование CRUD с Недели 1 без ожидания Спринта 3.
Результат недели 1:
- ✅ Документация архитектуры
- ✅ Threat Model v1.0
- ✅ Структура проекта готова
- ✅ CI/CD настроен
- ✅ **[ДОБАВЛЕНО]** EncryptionHelper stub передан Алексею
#### Неделя 2: Криптографическое ядро
День 1-3: crypto_core.py
- [ ] Реализовать класс CryptoCore — принимает Pydantic конфиг
- [ ] Методы деривации ключа:
	- derive_master_key() — Argon2id
	- derive_subkey() — HKDF для производных ключей
	- generate_salt() — генерация соли
- [ ] Методы шифрования:
	- encrypt() — AES-256-GCM для строк
	- decrypt() — расшифровка
	- encrypt_bytes() — для файлов
	- decrypt_bytes() — для файлов
- [ ] Методы целостности:
	- sign() — HMAC-SHA256
	- verify_signature() — проверка подписи
	- hash_file() — SHA-256 хеш файла
День 4-5: Защита памяти и утилиты
- [ ] Методы защиты памяти:
	- zero_memory() — безопасное обнуление
	- _zero_bytes() — внутренняя реализация
	- ⚠️ **[ДОБАВЛЕНО]** Использовать `bytearray` вместо `bytes` для всех чувствительных данных — bytearray мутабельный и реально обнуляется через memoryview/ctypes. Задокументировать в docstring ограничения zero_memory() в CPython: GC не даёт гарантий немедленного освобождения, интерпретатор может держать копии строк в intern-пуле.
- [ ] Утилиты безопасности:
	- constant_time_compare() — защита от timing attacks
	- generate_random_bytes() — криптостойкие байты
	- generate_token() — для токенов и recovery codes
- [ ] Класс CryptoError — правильные exception messages без утечки информации
Результат недели 2:
- ✅ crypto_core.py полностью реализован
- ✅ Все функции задокументированы (docstrings)
#### Неделя 3: Тесты криптографии
День 1-3: Unit тесты
- [ ] Написать тесты для crypto_core.py:
	- test_generate_salt() — уникальность соли
	- test_derive_master_key() — детерминированность
	- test_encrypt_decrypt() — шифрование/расшифровка
	- test_decrypt_wrong_key() — неверный ключ
	- test_sign_verify() — HMAC подписи
	- test_zero_memory() — очистка памяти (**[ОБНОВЛЕНО]** писать как best-effort тест с явными оговорками в комментарии: Python GC не гарантирует мгновенное освобождение; тест проверяет что bytearray обнуляется, но не гарантирует отсутствие копий в стеке интерпретатора)
- [ ] Test vectors из NIST для AES-GCM
- [ ] Coverage > 95% для crypto_core
День 4-5: Бенчмарки производительности
- [ ] Бенчмарки деривации ключа — CPython vs PyPy, разные параметры Argon2
- [ ] Бенчмарки шифрования — 1000 операций encrypt/decrypt
- [ ] Документировать результаты в docs/benchmarks.md
Результат недели 3:
- ✅ Unit тесты покрытие >95%
- ✅ Бенчмарки производительности
- ✅ crypto_core.py готов к использованию
#### Неделя 4: Управление аутентификацией
День 1-3: auth_manager.py
- [ ] Класс AuthManager с Pydantic схемой состояния
- [ ] Методы:
	- unlock() — деривация ключа и сохранение в памяти
	- lock() — немедленное уничтожение ключа через zero_memory()
	- get_master_key() — получение копии ключа для операций
	- is_locked — property
- [ ] Таймер автоблокировки
	- ⚠️ **[ДОБАВЛЕНО]** Добавить спецификацию поведения таймера: что происходит при системном сне/гибернации ОС (сброс таймера vs продолжение), thread-safety через `threading.Lock`, что именно очищается при срабатывании (только мастер-ключ или также все производные ключи и активные сессии)
	- Добавить тест: `test_autolock_timer_thread_safety()` — конкурентный доступ к AuthManager не должен вызывать race condition
- [ ] Интеграция с RateLimiter
День 4-5: security_utils.py
- [ ] Pydantic схемы: RateLimitConfig, PasswordStrengthResult
- [ ] Класс RateLimiter:
	- can_attempt() — проверка можно ли попытку
	- register_failed() — учёт неудачной попытки
	- register_success() — сброс счётчика
	- get_delay() — exponential backoff
- [ ] Класс PasswordStrengthChecker:
	- calculate_entropy() — расчёт энтропии
	- check_strength() — оценка 0-4, возвращает PasswordStrengthResult
	- _estimate_crack_time() — примерное время взлома
- [ ] Тесты для обоих классов
Результат недели 4:
- ✅ auth_manager.py готов
- ✅ security_utils.py готов
- ✅ Защита от брутфорса реализована
🎉 Итого Спринт 1-2:
- ✅ Криптографическое ядро
- ✅ Управление аутентификацией
- ✅ Rate limiting
- ✅ Тесты покрытие >95%
#### 🟡 Спринт 3-4 (Недели 5-8): Интеграция и вспомогательные модули
Цель: Создать инструменты для Алексея и настроить аудит безопасности
#### Неделя 5: Обёртки для Алексея
День 1-3: encryption_helper.py
- [ ] Pydantic схемы полей записи — EntryFieldsRaw и EntryFieldsEncrypted
- [ ] Класс EncryptionHelper:
	- encrypt_entry_fields() — шифрование словаря полей записи
	- decrypt_entry_fields() — расшифровка полей
	- encrypt_custom_fields() — шифрование JSON
	- decrypt_custom_fields() — расшифровка JSON
	- _encrypt_single() / _decrypt_single() — внутренние методы
День 4-5: Документация для Алексея
- [ ] Написать docs/encryption_helper_guide.md:
	- Как использовать EncryptionHelper
	- Примеры использования для CRUD
	- Что делать и чего НЕ делать
- [ ] Встреча с Алексеем — объяснение интерфейсов
Результат недели 5:
- ✅ encryption_helper.py готов
- ✅ Документация для Алексея
- ✅ Алексей может начинать работу с БД
#### Неделя 6: Аудит и логирование
День 1-3: audit_logger.py
- [ ] SQLAlchemy модель AuditLog с индексами по timestamp и event_type
- [ ] Pydantic схема события AuditEventSchema с валидатором — блокирует sensitive data в логах
- [ ] Класс AuditLogger(session):
	- log(event) — запись события
	- get_log(limit, event_type) — получение лога
	- Запись в изолированной транзакции (не роллбекается вместе с основной)
День 4-5: Тесты
- [ ] Тест что валидатор блокирует пароли/ключи в логах (**[РАСШИРЕНО]** минимум 5 тест-кейсов с разными форматами утечки: пароль в строке, ключ в dict, token в nested поле, base64-encoded секрет, секрет в exception message)
- [ ] Тест записи в SQLAlchemy
- [ ] Coverage > 90%
#### Неделя 7: Безопасное удаление и очистка памяти
День 1-3: secure_delete.py
- [ ] Pydantic конфиг: количество проходов перезаписи
- [ ] Класс SecureFileDeleter:
	- delete_file() — перезапись + удаление
- [ ] MemoryGuard — context manager для автоматического обнуления ключа после использования (**[РАСШИРЕНО]** реализовать как класс с `__enter__`/`__exit__`, хранящий bytearray и обнуляющий его при выходе из блока — аналог SecureString в .NET; добавить тест что после `with MemoryGuard(key) as k:` значение k реально обнулено)
- [ ] Интеграция с BackupManager Алексея
День 4-5: Тесты
- [ ] Тесты безопасного удаления
- [ ] Тест MemoryGuard — ключ действительно обнуляется после выхода из контекста
#### Неделя 8: Оптимизация PyPy
День 1-2: JIT прогрев
- [ ] Создать core/pypy_warmup.py — запуск crypto операций при старте для прогрева JIT
- [ ] Замерить разницу: без прогрева vs после прогрева
- [ ] ⚠️ **[ОБНОВЛЕНО]** Целевой JIT warmup пересмотреть: < 5 секунд — неприемлемо для десктопного приложения (пользователь открывает менеджер чтобы быстро скопировать пароль). Цель — **< 1.5 секунды** до первого интерактивного ответа, или явно разделить: PyPy только для фоновых операций (массовое шифрование при импорте, поиск), интерактивные операции — на CPython. Добавить benchmark: время первого интерактивного ответа после запуска.
- [ ] Интегрировать в точку входа приложения
День 3-5: Профилирование
- [ ] Анализ узких мест
- [ ] Финальные бенчмарки CPython vs PyPy
- [ ] Обновление docs/benchmarks.md
Результат недели 8:
- ✅ PyPy JIT прогревается при старте
- ✅ Все модули оптимизированы
- ✅ Документация обновлена
🎉 Итого Спринт 3-4:
- ✅ EncryptionHelper для Алексея
- ✅ AuditLogger через SQLAlchemy
- ✅ Безопасное удаление
- ✅ Оптимизация PyPy
#### 🟢 Спринт 5-6 (Недели 9-12): Code Review и Security Audit
Цель: Проверка кода Алексея и финальный security audit
#### Недели 9-10: Code Review кода Алексея
- [ ] Проверить:
	- database/models.py — правильно ли хранятся зашифрованные поля
	- database/schemas.py — нет ли утечек через Pydantic repr
	- database/entry_service.py — используется ли EncryptionHelper
	- features/password_history_manager.py — шифруются ли старые пароли
	- features/import_export.py — есть ли валидация данных
	- features/search_engine.py — не кэшируются ли расшифрованные данные
- [ ] Чеклист:
	- Нет raw SQL с пользовательскими данными
	- Нет логирования паролей и ключей
	- Все чувствительные поля зашифрованы
	- confirmed=True проверяется на удалении и экспорте
	- Alembic миграции содержат только схему, не данные
- [ ] Написать замечания и рекомендации
- [ ] Встречи с Алексеем для обсуждения
#### Неделя 11: Security Audit
День 1-2: Статический анализ
- [ ] Запустить bandit на всём проекте
- [ ] Запустить safety check для зависимостей
- [ ] Проверить с pylint и mypy
- [ ] Исправить все найденные проблемы
День 3-4: Динамическое тестирование
- [ ] SQL injection — проверить все SQLAlchemy queries
- [ ] Брутфорс мастер-пароля — RateLimiter должен блокировать
- [ ] Извлечение ключей из памяти — zero_memory срабатывает
- [ ] Проверка логов на утечку данных — AuditEventSchema валидатор работает
День 5: Отчёт безопасности
- [ ] Написать docs/security_audit_report.md
- [ ] Перечислить найденные проблемы, оценка рисков, статус исправления
#### Неделя 12: Финализация документации
- [ ] Обновить docs/architecture.md
- [ ] Обновить docs/threat_model.md
- [ ] CONTRIBUTING.md — как безопасно контрибьютить
- [ ] SECURITY_GUIDELINES.md — правила безопасной разработки
- [ ] Презентация для команды о безопасности проекта
🎉 Итого Спринт 5-6:
- ✅ Code Review завершён
- ✅ Security Audit пройден
- ✅ Документация полная
#### 🔵 Спринт 7+ (Недели 13+): Продвинутые функции безопасности
Биометрическая аутентификация:
- [ ] Windows Hello API — хранение мастер-ключа через Credential Manager
- [ ] Fallback на мастер-пароль
Аппаратные ключи (FIDO2):
- [ ] Протокол FIDO2/U2F
- [ ] Интеграция с YubiKey
- [ ] Challenge-response для разблокировки
- [ ] ⚠️ **[ДОБАВЛЕНО]** Заранее добавить `python-fido2` в requirements.txt с пометкой `# future` и верифицировать совместимость с PyPy. Проверить доступность USB/NFC на всех целевых платформах (Windows Credential Manager vs Linux libfido2 — разные API).
Мониторинг утечек:
- [ ] Have I Been Pwned API (k-anonymity для безопасности)
- [ ] Проверка email на утечки
- [ ] Уведомления о новых breaches
2FA:
- [ ] TOTP (Time-based OTP)
- [ ] QR-код для настройки
- [ ] Recovery codes
### 📊 Метрики успеха
#### Покрытие тестами
- [ ] Unit тесты: >95% для crypto_core.py
- [ ] Unit тесты: >90% для всех security модулей
- [ ] Integration тесты: >80% для критичных потоков
#### Производительность
- [ ] Деривация ключа: < 500мс (CPython), < 300мс (PyPy)
- [ ] Шифрование 1000 паролей: < 100мс (PyPy)
- [ ] JIT warmup: **< 1.5 секунды** до первого интерактивного ответа (**[ОБНОВЛЕНО]** с < 5 секунд — см. Неделю 8)
#### Безопасность
- [ ] 0 критичных уязвимостей в bandit
- [ ] 0 уязвимых зависимостей в safety
- [ ] 0 SQL injection возможностей
- [ ] 0 утечек паролей в логах
### 🎯 Ключевые вехи (Milestones)
			Milestone
			Срок
			Статус
			M1: Криптографическое ядро готово
			Неделя 3
			⏳
			M2: Auth Manager + RateLimiter
			Неделя 4
			⏳
			M3: EncryptionHelper для Алексея
			Неделя 5
			⏳
			M4: AuditLogger через SQLAlchemy
			Неделя 6
			⏳
			M5: Безопасное удаление + MemoryGuard
			Неделя 7
			⏳
			M6: Оптимизация PyPy
			Неделя 8
			⏳
			M7: Code Review кода Алексея
			Неделя 10
			⏳
			M8: Security Audit пройден
			Неделя 11
			⏳
			M9: Документация полная
			Неделя 12
			⏳
### 📖 Ресурсы для изучения
#### 🐍 Python основы
- Stepik — Python для начинающих: https://stepik.org/course/67/promo
- Stepik — Поколение Python (ООП): https://stepik.org/course/114354/promo 
- YouTube — Python ООП (Тимофей Хирьянов): https://youtu.be/xIyVsGf0zbw?si=pleP423xyIdZfSzN 
#### 🔐 Криптография — основы
- YouTube — Криптография для начинающих: https://youtu.be/rQHOBmWza4k?si=awefT6jWRDKzxP7p 
- Stepik — Введение в криптографию: https://stepik.org/course/62247/syllabus?search=8840084507 
- YouTube — AES объяснение на пальцах: https://www.youtube.com/watch?v=O4xNJsjtN6E
- YouTube — Кратко что такое шифрование: https://youtu.be/qgofSZFTuVc?si=A-CWfuLvZccxFDQu 
#### 🔐 Криптография — библиотеки Python
- Официальная документация cryptography: https://cryptography.io/en/latest/ 
- Официальная документация argon2-cffi: https://argon2-cffi.readthedocs.io/en/stable/ 
- GitHub — примеры использования PyNaCl: https://github.com/pyca/pynacl/tree/main/docs 
#### 🛡️ Безопасность приложений
- OWASP Top 10 : https://owasp.org/www-project-top-ten/ 
- OWASP Cheat Sheets: https://cheatsheetseries.owasp.org/ 
	- Password Storage Cheat Sheet
	- Cryptographic Storage Cheat Sheet
	- Key Management Cheat Sheet
- YouTube — OWASP Top 10 простым языком: https://youtu.be/fgtuLbT4joI?si=JLn_oesjUY4LgrDm 
- NIST Password Guidelines: https://pages.nist.gov/800-63-3/ 
#### ✅ Pydantic (SecretStr и BaseSettings)
- Официальная документация Pydantic v2: https://docs.pydantic.dev/latest/ 
- YouTube — Pydantic Tutorial: https://youtu.be/zTSRygNQ_Fw?si=FFePpgCwX2W_z_vP 
- Документация pydantic-settings: https://docs.pydantic.dev/latest/concepts/pydantic_settings/ 
#### ⚙️ SQLAlchemy (для AuditLog)
- Официальная документация SQLAlchemy 2.0: https://docs.sqlalchemy.org/en/20/ 
- YouTube — SQLAlchemy Tutorial: https://www.youtube.com/watch?v=AKQ3XEDI9Mw 
#### 🧪 Тестирование и безопасность кода
- Stepik — Python: тестирование: https://stepik.org/course/259625/promo?search=8840111961 
- Официальная документация bandit: https://bandit.readthedocs.io/en/latest/ 
- Официальная документация pytest-benchmark: https://pytest-benchmark.readthedocs.io/en/latest/ 
- YouTube — pytest Tutorial: https://youtu.be/s_aG4tBJoeI?si=flWoxqU_Krst9_n1 
#### 🚀 PyPy
- Официальный сайт PyPy: https://pypy.org/ 
- YouTube — Зачем нужен PyPy: https://youtu.be/Cey8Jm9kRzY?si=L9RfmLkaLa67Fznt 
- Статья — PyPy совместимость с библиотеками: https://pypy.org/compat.html 
#### 🐙 Git и GitHub
- Stepik — Основы Git: https://stepik.org/course/3145/promo 
- YouTube — Git для начинающих (Тимофей Хирьянов): https://www.youtube.com/watch?v=SEvR78OhGtw 
- GitHub Actions — документация: https://docs.github.com/ru/actions 
#### 🏗️ Архитектура и проектирование
- YouTube — Threat Modeling : https://youtu.be/NKoak1UcIIk?si=m0cmB_WbMArYhsQQ 
- draw.io (онлайн, бесплатно): https://app.diagrams.net/ 
- YouTube — Что такое AES-GCM(Пример только на GO нашёл нормальный): https://youtu.be/NT0N8qyNjYo?si=_Hxelhf4Mnu1e1_y 
#### 📦 Менеджер паролей — вдохновение и референсы
- GitHub — KeePassXC исходный код: https://github.com/keepassxreboot/keepassxc 
- GitHub — Bitwarden server: https://github.com/bitwarden/server 
- YouTube — Как устроен менеджер паролей изнутри: https://youtu.be/w68BBPDAWr8?si=ySMzXDXwRrA3Bqd9 
### ⚠️ Важные напоминания
1. Никогда не изобретай криптографию — только проверенные алгоритмы
2. SecretStr вместо str для паролей — Pydantic не покажет в repr и логах
3. Безопасность — не чеклист — это образ мышления
4. Не логируй пароли и ключи — никогда, ни при каких условиях
5. Обнуляй память после использования — zero_memory() обязательно
6. Code review критичен — проверяй код Алексея на каждом PR
7. CI должен гонять тесты на PyPy — иначе проблемы найдём поздно
8. Документируй всё — другие должны понимать твои решения
### 🤝 Координация с командой
#### С Алексеем (BE2):
- Неделя 1 — согласовать архитектуру и интерфейсы
- Неделя 5 — передать EncryptionHelper + документацию
- Недели 9-10 — code review его кода
#### С Frontend (FE):
- API спецификация — какие endpoints нужны
- Безопасность UI — автоблокировка, скрытие паролей
#### С QA:
- Security test cases — что тестировать
- Bug triage — оценка серьёзности уязвимостей
### ✅ Финальный чеклист перед релизом
#### Код
- [ ] Coverage >95% crypto_core, >90% security модули
- [ ] Нет критичных замечаний в bandit/safety/mypy
- [ ] Code review завершён
- [ ] Нет TODO/FIXME в продакшен коде
#### Pydantic
- [ ] Все секреты через SecretStr
- [ ] Конфиги иммутабельны (frozen=True)
- [ ] AuditEventSchema блокирует sensitive data через validator
#### PyPy
- [ ] Все модули работают на PyPy 7.3+
- [ ] CI матрица: CPython + PyPy
- [ ] JIT warmup настроен
#### Безопасность
- [ ] Security Audit пройден
- [ ] Penetration testing выполнен
- [ ] Нет паролей/ключей в логах
- [ ] Все зависимости обновлены
Удачи, Никита! Безопасность проекта в твоих руках. 🛡️

