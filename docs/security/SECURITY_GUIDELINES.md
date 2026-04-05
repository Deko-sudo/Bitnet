# Security Guidelines v2.0
## Руководство по безопасной разработке

**Версия:** 2.0.0  
**Дата:** Май 2026  
**Статус:** ✅ Обязательно для всех разработчиков

---

## 1. Основные принципы

### 1.1 Золотые правила безопасности

1. **Никогда не доверяй входным данным** — валидируй всё через Pydantic
2. **Никогда не логируй секреты** — используй SecretStr
3. **Всегда используй ORM** — нет raw SQL с конкатенацией
4. **Всегда шифруй чувствительные данные** — AES-256-GCM
5. **Всегда проверяй права доступа** — ownership validation
6. **Всегда обнуляй ключи** — zero_memory() после использования

---

## 2. Работа с паролями

### 2.1 Хранение паролей

```python
# ✅ ПРАВИЛЬНО
from pydantic import BaseModel, SecretStr

class UserCreate(BaseModel):
    password: SecretStr  # Не светится в логах

# ❌ НЕПРАВИЛЬНО
class UserCreate(BaseModel):
    password: str  # Может попасть в логи!
```

### 2.2 Деривация ключей

```python
# ✅ ПРАВИЛЬНО
from backend.core.crypto_core import CryptoCore

crypto = CryptoCore()
master_key = crypto.derive_master_key(password, salt)  # Argon2id, ~40ms

# ❌ НЕПРАВИЛЬНО
import hashlib
key = hashlib.md5(password.encode()).hexdigest()  # Слабый алгоритм!
```

### 2.3 Требования к паролям

```python
# ✅ ПРАВИЛЬНО
from backend.core.security_utils import PasswordStrengthChecker

checker = PasswordStrengthChecker(
    min_length=12,
    min_entropy_bits=60,
    require_uppercase=True,
    require_lowercase=True,
    require_digits=True,
)

is_valid, result = checker.is_strong_enough(password)
if not is_valid:
    for suggestion in result.suggestions:
        print(suggestion)

# ❌ НЕПРАВИЛЬНО
if len(password) >= 6:  # Слишком слабый пароль!
    accept_password(password)
```

---

## 3. Работа с ключами шифрования

### 3.1 Хранение ключей

```python
# ✅ ПРАВИЛЬНО
from backend.core.auth_manager import AuthManager

auth = AuthManager(crypto)
auth.unlock(password, salt)  # Ключ в памяти

with MemoryGuard(bytearray(key)) as guarded_key:
    encrypted = crypto.encrypt(data, guarded_key)
# Ключ автоматически обнулён

# ❌ НЕПРАВИЛЬНО
key = crypto.derive_master_key(password, salt)
# Ключ остаётся в памяти неопределённо долго!
```

### 3.2 Передача ключей

```python
# ✅ ПРАВИЛЬНО
def process_data(key: bytes):
    try:
        return crypto.encrypt(data, key)
    finally:
        zero_memory(bytearray(key))  # Обнуление после использования

# ❌ НЕПРАВИЛЬНО
def process_data(key: bytes):
    return crypto.encrypt(data, key)
    # Ключ не обнулён, может остаться в памяти!
```

---

## 4. Работа с базой данных

### 4.1 SQL запросы

```python
# ✅ ПРАВИЛЬНО (SQLAlchemy ORM)
from sqlalchemy import select

stmt = select(User).where(User.id == user_id)
user = session.execute(stmt).scalar()

# ✅ ПРАВИЛЬНО (параметризованный запрос)
from sqlalchemy import text

stmt = text("SELECT * FROM users WHERE id = :id")
user = session.execute(stmt, {"id": user_id}).scalar()

# ❌ НЕПРАВИЛЬНО (SQL injection!)
query = f"SELECT * FROM users WHERE id = {user_id}"  # УЯЗВИМОСТЬ!
user = session.execute(text(query)).scalar()
```

### 4.2 Валидация данных

```python
# ✅ ПРАВИЛЬНО
from pydantic import BaseModel, EmailStr, field_validator
import re

class UserCreate(BaseModel):
    email: EmailStr
    password: SecretStr
    
    @field_validator('password')
    @classmethod
    def validate_password(cls, v: SecretStr) -> SecretStr:
        password = v.get_secret_value()
        if len(password) < 12:
            raise ValueError('Password must be at least 12 characters')
        return v

# ❌ НЕПРАВИЛЬНО
class UserCreate:
    def __init__(self, email, password):
        self.email = email  # Нет валидации!
        self.password = password  # Нет проверки сложности!
```

### 4.3 Проверка прав доступа

```python
# ✅ ПРАВИЛЬНО
def get_entry_by_id(self, entry_id: int, user_id: int):
    stmt = select(PasswordEntry).where(
        and_(
            PasswordEntry.id == entry_id,
            PasswordEntry.user_id == user_id  # Проверка владельца!
        )
    )
    return self.db.execute(stmt).scalar()

# ❌ НЕПРАВИЛЬНО
def get_entry_by_id(self, entry_id: int):
    # Любой пользователь может получить доступ к чужим данным!
    query = f"SELECT * FROM entries WHERE id = {entry_id}"
    return self.db.execute(text(query)).scalar()
```

---

## 5. Логирование

### 5.1 Что можно логировать

```python
# ✅ МОЖНО
logger.info(f"User {user_id} logged in from {ip_address}")
logger.debug(f"Operation completed in {duration:.2f}ms")
logger.error(f"Database query failed: {error_code}")
audit.log_event(
    event_type=EventType.DATA_CREATED,
    user_id=user_id,
    details={"entry_id": entry_id}  # Без секретов!
)
```

### 5.2 Что нельзя логировать

```python
# ❌ НЕЛЬЗЯ
logger.error(f"Login failed, password={password}")
logger.debug(f"Master key: {master_key}")
logger.info(f"API token: {api_token}")
logger.debug(f"Request body: {request.body}")  # Может содержать секреты!

# В audit logger:
audit.log_event(
    event_type=EventType.LOGIN_ATTEMPT,
    details={"password": password}  # Попало в логи!
)
```

### 5.3 Использование Audit Logger

```python
# ✅ ПРАВИЛЬНО
from backend.core.audit_logger import AuditLogger, EventType

logger = AuditLogger(session)
logger.log_event(
    event_type=EventType.LOGIN_SUCCESS,
    user_id=user_id,
    ip_address=ip_address,
    details={"action": "login"},  # Без секретов!
)

# ❌ НЕПРАВИЛЬНО
logger.log_event(
    event_type=EventType.LOGIN_SUCCESS,
    details={"password": password},  # Попало в логи!
)
```

---

## 6. Rate Limiting

### 6.1 Защита от брутфорса

```python
# ✅ ПРАВИЛЬНО
from backend.core.security_utils import RateLimiter

limiter = RateLimiter(
    max_attempts=5,
    window_seconds=60,
    block_duration_seconds=1800  # 30 минут
)

@app.post("/login")
def login(user_id: str, password: str):
    if not limiter.can_attempt(user_id):
        delay = limiter.get_delay(user_id)
        raise HTTPException(429, f"Too many attempts. Wait {delay}s")
    
    if not authenticate(user_id, password):
        limiter.register_failed(user_id)
        raise HTTPException(401, "Invalid credentials")
    
    limiter.register_success(user_id)
    return {"status": "ok"}

# ❌ НЕПРАВИЛЬНО
@app.post("/login")
def login(user_id: str, password: str):
    # Нет rate limiting - уязвимо к брутфорсу!
    if authenticate(user_id, password):
        return {"status": "ok"}
    raise HTTPException(401, "Invalid credentials")
```

---

## 7. Импорт/Экспорт данных

### 7.1 Экспорт

```python
# ✅ ПРАВИЛЬНО
def export_to_json(self, entries, filepath, master_password):
    # Шифрование перед экспортом
    crypto = CryptoCore()
    key = derive_key(master_password, salt)
    
    encrypted_entries = []
    for entry in entries:
        entry_json = json.dumps(entry).encode()
        encrypted = crypto.encrypt(entry_json, key)
        encrypted_entries.append(encrypted.hex())
    
    with open(filepath, 'w') as f:
        json.dump({'entries': encrypted_entries}, f)

# ❌ НЕПРАВИЛЬНО
def export_to_json(self, entries, filepath):
    # Пароли экспортируются в plain text!
    with open(filepath, 'w') as f:
        json.dump({'entries': entries}, f)  # УЯЗВИМОСТЬ!
```

### 7.2 Импорт

```python
# ✅ ПРАВИЛЬНО
def import_from_json(self, filepath, master_password):
    # Валидация пути
    safe_dir = pathlib.Path("/safe/import").resolve()
    import_path = pathlib.Path(filepath).resolve()
    
    if not str(import_path).startswith(str(safe_dir)):
        raise ValueError("Invalid path")
    
    # Проверка размера файла
    if os.path.getsize(filepath) > 10 * 1024 * 1024:
        raise ValueError("File too large")
    
    # Валидация данных
    with open(filepath, 'r') as f:
        data = json.load(f)
    
    entries = [ImportEntry(**entry) for entry in data['entries']]
    return entries

# ❌ НЕПРАВИЛЬНО
def import_from_json(self, filepath):
    # Нет валидации пути (path traversal!)
    # Нет проверки размера (DoS!)
    # Нет валидации данных!
    with open(filepath, 'r') as f:
        return json.load(f)
```

---

## 8. Конфигурация безопасности

### 8.1 Хранение секретов

```python
# ✅ ПРАВИЛЬНО
import os
from pydantic_settings import BaseSettings
from pydantic import SecretStr

class SecurityConfig(BaseSettings):
    master_password: SecretStr = Field(..., env='MASTER_PASSWORD')
    api_key: SecretStr = Field(..., env='API_KEY')
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

# ❌ НЕПРАВИЛЬНО
class SecurityConfig:
    master_password = "hardcoded_password"  # В коде!
    api_key = "sk-123456789"  # В репозитории!
```

### 8.2 .env файл

```bash
# .env (ОБЯЗАТЕЛЬНО добавить в .gitignore!)
MASTER_PASSWORD=super_secret_password
API_KEY=sk-123456789
DATABASE_URL=postgresql://user:pass@localhost/db

# .gitignore
.env
.env.local
*.key
*.pem
secrets/
```

---

## 9. Pre-commit проверки

### 9.1 Настройка pre-commit

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/PyCQA/bandit
    rev: 1.7.5
    hooks:
      - id: bandit
        args: [-r, backend/, --exclude, backend/tests]
  
  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.7.0
    hooks:
      - id: mypy
        args: [--ignore-missing-imports]
  
  - repo: https://github.com/psf/black
    rev: 23.12.0
    hooks:
      - id: black
```

### 9.2 Запуск проверок

```bash
# Перед каждым коммитом
pre-commit run --all-files

# Проверка безопасности
bandit -r backend/ --exclude backend/tests -ll

# Проверка типов
mypy backend/ --ignore-missing-imports

# Проверка зависимостей
safety check -r requirements.txt
```

---

## 10. Чеклист перед мерджем

### 10.1 Обязательные проверки

- [ ] Bandit не нашёл уязвимостей
- [ ] Mypy не нашёл ошибок типов
- [ ] Все тесты проходят (pytest)
- [ ] Покрытие тестами >85%
- [ ] Нет секретов в коде (grep -r "password\|secret\|key")
- [ ] Нет raw SQL с конкатенацией строк

### 10.2 Проверка кода

- [ ] Все секреты через `SecretStr`
- [ ] Нет `print()` с чувствительными данными
- [ ] Все сравнения через `hmac.compare_digest()`
- [ ] Audit logging для критических операций
- [ ] Rate limiting для endpoints
- [ ] Валидация всех входных данных
- [ ] Проверка прав доступа (ownership)

### 10.3 Проверка документации

- [ ] Обновлены docstrings
- [ ] Добавлены примеры использования
- [ ] Обновлён CHANGELOG

---

## 11. Реагирование на инциденты

### 11.1 Уровни инцидентов

| Уровень | Описание | Пример | Реакция |
|---------|----------|--------|---------|
| **P0** | Активная утечка | SQL injection успешен | Немедленная блокировка |
| **P1** | Попытка атаки | 1000+ failed logins/min | Rate limiting, ban |
| **P2** | Подозрительная активность | Необычные паттерны | Мониторинг |
| **P3** | Единичные сбои | 5 failed logins | Логирование |

### 11.2 Процедура P0

1. **Обнаружение** → Alert от мониторинга
2. **Изоляция** → Отключить затронутый компонент
3. **Анализ** → Сбор логов, оценка масштаба
4. **Устранение** → Патч уязвимости
5. **Восстановление** → Ротация ключей, сброс сессий
6. **Отчёт** → Post-mortem документ

---

## 12. Приложения

### A. Примеры уязвимостей и исправлений

#### SQL Injection
```python
# Уязвимость
query = f"SELECT * FROM users WHERE id = {user_id}"

# Исправление
query = text("SELECT * FROM users WHERE id = :id")
session.execute(query, {"id": user_id})
```

#### XSS Attack
```python
# Уязвимость
return f"<div>{user_input}</div>"

# Исправление
import html
return f"<div>{html.escape(user_input)}</div>"
```

#### Timing Attack
```python
# Уязвимость
if user_hash == expected_hash:
    return True

# Исправление
if hmac.compare_digest(user_hash, expected_hash):
    return True
```

#### Plain Text Password
```python
# Уязвимость
entry = PasswordEntry(password=password)

# Исправление
encrypted = crypto.encrypt(password.encode(), key)
entry = PasswordEntry(password=encrypted.hex())
```

### B. Полезные ресурсы

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Cheat Sheets](https://cheatsheetseries.owasp.org/)
- [Python Security Best Practices](https://docs.python.org/3/library/security.html)
- [Cryptographic Best Practices](https://cryptography.io/en/latest/)
- [Have I Been Pwned API](https://haveibeenpwned.com/API/v3)

---

**Документ утверждён:**  
Никита (BE1) — Архитектор безопасности  
Алексей (BE2) — Backend Developer

**Дата:** Май 2026  
**Следующий пересмотр:** Август 2026

**Статус:** ✅ APPROVED FOR PRODUCTION v2.0.0

