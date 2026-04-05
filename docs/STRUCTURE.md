# Структура проекта Password Manager

## Обзор

```
bez/
├── backend/                    # Исходный код приложения
│   ├── core/                   # Криптографическое ядро
│   │   ├── __init__.py
│   │   ├── crypto_core.py      # AES-256-GCM, Argon2id, HMAC
│   │   ├── auth_manager.py     # Управление сессиями и аутентификация
│   │   ├── security_utils.py   # Утилиты безопасности (RateLimiter и др.)
│   │   ├── audit_logger.py     # Логирование событий безопасности
│   │   ├── secure_delete.py    # Безопасное удаление данных
│   │   ├── advanced_security.py # TOTP, Recovery Codes
│   │   ├── fido2_auth.py       # FIDO2/WebAuthn аутентификация
│   │   ├── pypy_optimization.py # Оптимизации для PyPy
│   │   └── config.py           # Конфигурация безопасности
│   │
│   ├── database/               # Работа с базой данных
│   │   ├── __init__.py
│   │   ├── schemas.py          # SQLAlchemy модели
│   │   └── entry_service.py    # CRUD операции
│   │
│   ├── features/               # Дополнительные функции
│   │   ├── __init__.py
│   │   ├── qr_generator.py     # Генерация QR-кодов
│   │   ├── breach_monitor.py   # Мониторинг утечек
│   │   ├── password_history_manager.py
│   │   └── import_export.py    # Импорт/экспорт данных
│   │
│   ├── api/                    # REST API endpoints
│   │   └── __init__.py
│   │
│   └── tests/                  # Тесты
│       ├── __init__.py
│       ├── conftest.py         # Фикстуры pytest
│       ├── test_crypto_core.py
│       ├── test_auth_security.py
│       ├── test_advanced_security.py
│       ├── test_audit_secure.py
│       ├── test_benchmarks.py
│       ├── test_pypy_optimization.py
│       ├── test_security_dynamic.py
│       └── test_week13_features.py
│
├── docs/                       # Документация
│   ├── guides/                 # Руководства
│   │   ├── DEPLOYMENT.md       # Развёртывание
│   │   ├── auth_security_guide.md
│   │   └── PRESENTATION.md
│   │
│   ├── security/               # Безопасность
│   │   ├── threat_model.md     # Модель угроз
│   │   ├── final_security_audit.md
│   │   ├── BUG_BOUNTY.md       # Bug bounty программа
│   │   ├── SECURITY.md
│   │   ├── SECURITY_GUIDELINES.md
│   │   └── SECURITY_RESPONSE.md
│   │
│   ├── reports/                # Отчёты
│   │   ├── CHANGELOG.md
│   │   └── RELEASE_NOTES_v2.0.0.md
│   │
│   ├── architecture.drawio     # Архитектурная диаграмма
│   ├── crypto_choices.md       # Выбор алгоритмов
│   ├── crypto_core_spec.md     # Спецификация crypto_core
│   ├── FUTURE_ROADMAP.md       # План развития
│   ├── MAINTENANCE_PLAN.md     # План поддержки
│   ├── PROJECT_SUMMARY.md      # Итоги проекта
│   ├── CONTINUOUS_IMPROVEMENT.md
│   ├── QUARTERLY_AUDIT_PLAN.md
│   ├── code_review_report.md
│   └── benchmarks_results.md
│
├── .github/
│   └── workflows/
│       └── ci.yml              # GitHub Actions CI/CD
│
├── .venv/                      # Виртуальное окружение (не в git)
├── .idea/                      # Настройки IDE (не в git)
│
├── README.md                   # Главная страница
├── CONTRIBUTING.md             # Как внести вклад
├── requirements.txt            # Зависимости Python
├── pyproject.toml              # Конфигурация проекта
└── .gitignore                  # Игнорируемые файлы
```

## Описание модулей

### backend/core/

Криптографическое ядро системы. Содержит все компоненты безопасности:

| Файл | Описание |
|------|----------|
| `crypto_core.py` | Базовые криптографические операции (шифрование, деривация ключей) |
| `auth_manager.py` | Управление сессиями, аутентификация пользователей |
| `security_utils.py` | RateLimiter, MemoryGuard и другие утилиты |
| `audit_logger.py` | Логирование всех событий безопасности |
| `secure_delete.py` | Безопасное удаление файлов и очистка памяти |
| `advanced_security.py` | TOTP (2FA), коды восстановления |
| `fido2_auth.py` | Аутентификация с аппаратными ключами |
| `pypy_optimization.py` | Оптимизации для запуска на PyPy |
| `config.py` | Конфигурация безопасности |

### backend/database/

Работа с базой данных:

| Файл | Описание |
|------|----------|
| `schemas.py` | SQLAlchemy модели данных |
| `entry_service.py` | CRUD операции для записей |

### backend/features/

Дополнительные функции:

| Файл | Описание |
|------|----------|
| `qr_generator.py` | Генерация QR-кодов для TOTP |
| `breach_monitor.py` | Проверка паролей по базам утечек |
| `password_history_manager.py` | История смены паролей |
| `import_export.py` | Импорт/экспорт данных |

### backend/tests/

Тестовое покрытие >85% для всех модулей.

## Документация

### guides/
Руководства по использованию и развёртыванию.

### security/
Документы по безопасности: модель угроз, аудиты, bug bounty.

### reports/
История изменений и релизы.

## Исключаемые файлы

Следующие папки не tracked в git (см. `.gitignore`):

- `.venv/` — виртуальное окружение
- `__pycache__/` — кэш Python
- `.pytest_cache/`, `.mypy_cache/` — кэши инструментов
- `.idea/` — настройки IDE
- `*.db`, `*.log` — файлы данных и логов
