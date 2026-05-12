# Структура проекта BitNet Password Manager

## Обзор

```
bez/
├── backend/                    # Исходный код приложения
│   ├── core/                   # Криптографическое ядро
│   │   ├── __init__.py
│   │   ├── crypto_core.py      # AES-256-GCM, Argon2id, HMAC
│   │   ├── crypto_bridge.py    # Rust FFI bridge (`bitnet_crypto_rs`)
│   │   ├── auth_manager.py     # Управление сессиями и аутентификация
│   │   ├── security_utils.py   # Утилиты безопасности (RateLimiter и др.)
│   │   ├── audit_logger.py     # Логирование событий безопасности
│   │   ├── secure_delete.py    # Безопасное удаление данных
│   │   ├── advanced_security.py # TOTP, Recovery Codes
│   │   ├── fido2_auth.py       # FIDO2/WebAuthn аутентификация
│   │   ├── pypy_optimization.py # Оптимизации для PyPy
│   │   ├── key_manager.py      # Управление мастер-ключами (locked memory)
│   │   ├── encryption_helper.py   # Тонкий wrapper над crypto_bridge
│   │   └── config.py           # Конфигурация безопасности
│   │
│   ├── database/               # Работа с базой данных
│   │   ├── __init__.py
│   │   ├── models.py           # SQLAlchemy 2.0 модели (Mapped, mapped_column)
│   │   ├── schemas.py          # Pydantic v2 схемы
│   │   ├── session.py          # Session management (async + sync engines)
│   │   ├── db_security.py      # ACL / DB hardening (Windows ACL)
│   │   ├── db_optimization.py  # SQLite PRAGMA tuning (WAL, cache) — v2.1.0
│   │   └── entry_service.py    # Асинхронный CRUD (E2EE envelope + blind index)
│   │
│   ├── features/               # Дополнительные функции
│   │   ├── __init__.py
│   │   ├── qr_generator.py         # Генерация QR-кодов
│   │   ├── breach_monitor.py       # Мониторинг утечек
│   │   ├── password_generator.py   # Криптостойкий генератор паролей — v2.1.0
│   │   ├── search_engine.py        # Blind-Index поиск по title_search — v2.1.0
│   │   ├── backup_manager.py       # Zero-Trust backup / restore — v2.1.0
│   │   └── password_history_manager.py
│   │
│   ├── api/                    # REST API endpoints
│   │   ├── __init__.py
│   │   ├── dependencies.py
│   │   └── v1/endpoints/
│   │       ├── auth.py          # Регистрация, вход, get_current_user
│   │       ├── entries.py       # CRUD записей (E2EE, optimistic concurrency)
│   │       ├── trash.py         # Корзина
│   │       ├── fido2.py         # FIDO2/WebAuthn
│   │       ├── portability.py   # Импорт / экспорт (async)
│   │       ├── generator.py     # Генератор паролей / passphrase / PIN — v2.1.0
│   │       └── backups.py       # Backup / restore / rotate — v2.1.0
│   │
│   ├── services/               # Сервисный слой
│   │   └── import_export.py    # Реализация импорта/экспорта (async)
│   │
│   └── tests/                  # Тесты
│       ├── __init__.py
│       ├── conftest.py
│       ├── test_audit_secure.py
│       ├── test_password_generator.py   # v2.1.0
│       ├── test_search_engine.py        # v2.1.0
│       ├── test_backup_manager.py       # v2.1.0
│       ├── test_auth_security.py
│       ├── test_advanced_security.py
│       ├── test_crypto_flow.py
│       ├── test_crypto_core.py
│       ├── test_benchmarks.py
│       ├── test_entry_service.py
│       ├── test_fido2.py
│       ├── test_import_export_paths.py
│       ├── test_pypy_optimization.py
│       ├── test_security_dynamic.py
│       └── test_week13_features.py
│
├── alembic/                    # Миграции Alembic (autogenerate)
│   ├── env.py
│   ├── versions/16557111881b_initial.py
│   └── script.py.mako
│
├── docs/                       # Документация
│   ├── guides/
│   │   ├── DEPLOYMENT.md
│   │   ├── auth_security_guide.md
│   │   └── PRESENTATION.md
│   ├── security/
│   │   ├── threat_model.md
│   │   ├── final_security_audit.md
│   │   ├── BUG_BOUNTY.md
│   │   ├── SECURITY.md
│   │   ├── SECURITY_GUIDELINES.md
│   │   └── SECURITY_RESPONSE.md
│   ├── reports/
│   │   ├── CHANGELOG.md
│   │   └── RELEASE_NOTES_v2.0.0.md
│   ├── architecture.drawio
│   ├── crypto_choices.md
│   ├── crypto_core_spec.md
│   ├── FUTURE_ROADMAP.md
│   ├── MAINTENANCE_PLAN.md
│   ├── PROJECT_SUMMARY.md
│   ├── CONTINUOUS_IMPROVEMENT.md
│   ├── QUARTERLY_AUDIT_PLAN.md
│   ├── code_review_report.md
│   └── benchmarks_results.md
│
├── .github/workflows/ci.yml
├── README.md
├── CONTRIBUTING.md
├── requirements.txt
├── pyproject.toml
├── alembic.ini
└── .gitignore
```

## Описание модулей

### backend/core/

| Файл | Описание |
|------|----------|
| `crypto_core.py` | Базовые криптографические операции (AES-256-GCM, Argon2id, HMAC) |
| `crypto_bridge.py` | Python-Rust FFI bridge (`bitnet_crypto_rs`) — locked memory |
| `auth_manager.py` | Управление сессиями, аутентификация пользователей |
| `security_utils.py` | RateLimiter, PasswordStrengthChecker, MemoryGuard |
| `audit_logger.py` | Асинхронное логирование событий безопасности |
| `secure_delete.py` | Безопасное удаление файлов, zero_memory, zero_bytearray |
| `advanced_security.py` | TOTP (2FA), Recovery Codes |
| `fido2_auth.py` | Аппаратная аутентификация FIDO2/WebAuthn |
| `key_manager.py` | Управление мастер-ключами в непрерывной памяти |
| `encryption_helper.py` | Чистые функции для шифрования полей + batch helpers |
| `pypy_optimization.py` | Оптимизации производительности для PyPy |
| `config.py` | Конфигурация безопасности (Pydantic) |

### backend/database/

| Файл | Описание |
|------|----------|
| `models.py` | SQLAlchemy 2.0 модели: User, PasswordEntry, AuditLog, WebAuthnCredential … |
| `schemas.py` | Pydantic v2 request/response схемы |
| `session.py` | AsyncSession + sync engine, WAL, PRAGMA events |
| `db_security.py` | Windows ACL, secure db path |
| `db_optimization.py` | SQLite performance PRAGMA (`journal_mode=WAL`, `cache_size`, `mmap`) — v2.1.0 |
| `entry_service.py` | Асинхронный CRUD для E2EE записей (entry_envelope) |

### backend/features/

| Файл | Описание |
|------|----------|
| `password_generator.py` | Zero-Trust генератор паролей / passphrase / PIN (>=90% cov) — v2.1.0 |
| `search_engine.py` | Blind-Index exact-match поиск по `title_search` — v2.1.0 |
| `backup_manager.py` | AES-256-GCM + HMAC backup / restore, `confirmed=True` gate — v2.1.0 |
| `qr_generator.py` | Генерация QR-кодов для TOTP |
| `breach_monitor.py` | Мониторинг паролей через HIBP k-anonymity |
| `password_history_manager.py` | История смены паролей |

### backend/api/v1/endpoints/

| Файл | Описание |
|------|----------|
| `auth.py` | Регистрация, вход, сессии, `get_current_user` dependency |
| `entries.py` | CRUD записей, E2EE envelope API, история паролей |
| `trash.py` | Корзина, purge |
| `fido2.py` | FIDO2/WebAuthn challenge + assertion |
| `portability.py` | Импорт / экспорт зашифрованных данных |
| `generator.py` | POST `/api/v1/generator/{password,passphrase,pin}` — v2.1.0 |
| `backups.py` | POST/GET `/api/v1/backups`, restore, rotate — v2.1.0 |

### backend/tests/

| Файл | Назначение |
|------|------------|
| `test_password_generator.py` | Генерация, конфиги, Zero-Trust, API (26 тестов) — v2.1.0 |
| `test_search_engine.py` | Blind index match, pagination, zero-residual memory, perf — v2.1.0 |
| `test_backup_manager.py` | Create/list/restore/rotate, confirmed gate, tamper (11 тестов) — v2.1.0 |
| `test_audit_secure.py` | Audit logger cross-session, secure delete |
| `test_auth_security.py` | Регистрация, вход, rate limiting |
| `test_fido2.py` | FIDO2 async challenge flow |
| `test_entry_service.py` | Async E2EE CRUD |
| `test_import_export_paths.py` | Импорт/экспорт с моками |
| `test_advanced_security.py` | TOTP, Recovery Codes |
| `test_crypto_core.py` | Rust FFI crypto bridge |
| `test_crypto_flow.py` | E2EE pipeline end-to-end |
| `test_security_dynamic.py` | Rate limiter, entropy, слабые пароли |
| `test_pypy_optimization.py` | JIT warmup |
| `test_benchmarks.py` | Бенчмарки производительности |
| `test_week13_features.py` | Неделя 13+ |

## Исключаемые файлы

См. `.gitignore`:

- `.venv/`, `__pycache__/`, `.pytest_cache/`, `.mypy_cache/`
- `.idea/`
- `*.db`, `*.log`, `*.sqlite`, `backups/*.bin`
- `vault.db*`, `*.db-journal`, `*.db-shm`, `*.db-wal`
