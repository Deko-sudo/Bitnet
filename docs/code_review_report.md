# Code Review Report - Weeks 9-10
## Отчёт о проверке кода BE2 (Alexey)

**Версия:** 1.0  
**Дата:** Апрель 2026  
**Аудитор:** Никита (BE1)  
**Статус:** 🔴 КРИТИЧЕСКИЕ УЯЗВИМОСТИ

---

## 1. Резюме

### 1.1 Общая оценка: **F (FAIL)**

| Файл | Критических | Высоких | Средних | Низких |
|------|-------------|---------|---------|--------|
| models.py | 0 | 2 | 1 | 0 |
| schemas.py | 0 | 2 | 0 | 0 |
| entry_service.py | 5 | 1 | 0 | 0 |
| password_history_manager.py | 2 | 1 | 0 | 0 |
| import_export.py | 1 | 3 | 1 | 0 |
| **ВСЕГО** | **8** | **9** | **2** | **0** |

### 1.2 Статус релиза

```
╔══════════════════════════════════════════════════════════╗
║  🔴 BLOCKED FOR RELEASE                                 ║
║  8 CRITICAL VULNERABILITIES FOUND                        ║
║  MUST FIX BEFORE PRODUCTION                              ║
╚══════════════════════════════════════════════════════════╝
```

---

## 2. Критические уязвимости (8)

### CRIT-01: SQL Injection в entry_service.py

**Файл:** `backend/database/entry_service.py`  
**Строка:** 47-48  
**CVSS Score:** 9.8 (Critical)

```python
# ❌ УЯЗВИМОСТЬ
query = text(f"SELECT * FROM password_entries WHERE user_id = {user_id}")
results = self.db.execute(query).fetchall()
```

**Проблема:** Прямая конкатенация пользовательских данных в SQL запрос.

**Эксплуатация:**
```python
# Атакующий может ввести:
user_id = "1 OR 1=1 --"
# Получит доступ ко всем записям
```

**Исправление:**
```python
# ✅ ИСПОЛЬЗОВАТЬ ПАРАМЕТРИЗОВАННЫЕ ЗАПРОСЫ
from sqlalchemy import select

query = select(PasswordEntry).where(PasswordEntry.user_id == user_id)
results = db.execute(query).scalars().all()
```

---

### CRIT-02: SQL Injection в search_entries

**Файл:** `backend/database/entry_service.py`  
**Строка:** 62-64  
**CVSS Score:** 9.8 (Critical)

```python
# ❌ УЯЗВИМОСТЬ
query = text(f"SELECT * FROM password_entries WHERE user_id = {user_id} AND title LIKE '%{search_term}%'")
```

**Проблема:** Две переменные вставляются напрямую в SQL.

**Эксплуатация:**
```python
search_term = "' OR '1'='1"
# Вернёт все записи всех пользователей
```

**Исправление:**
```python
# ✅ ПАРАМЕТРИЗОВАННЫЙ ЗАПРОС
query = text(
    "SELECT * FROM password_entries WHERE user_id = :user_id AND title LIKE :search_term"
)
results = db.execute(query, {
    "user_id": user_id,
    "search_term": f"%{search_term}%"
}).fetchall()
```

---

### CRIT-03: SQL Injection в delete_entry

**Файл:** `backend/database/entry_service.py`  
**Строка:** 72-74  
**CVSS Score:** 9.8 (Critical)

```python
# ❌ УЯЗВИМОСТЬ
query = text(f"DELETE FROM password_entries WHERE id = {entry_id}")
self.db.execute(query)
```

**Проблема:** Удаление без проверки прав доступа + SQL injection.

**Эксплуатация:**
```python
entry_id = "1 OR 1=1"
# Удалит ВСЕ записи!
```

**Исправление:**
```python
# ✅ ПРОВЕРКА ПРАВ + ПАРАМЕТРИЗАЦИЯ
entry = db.get(PasswordEntry, entry_id)
if entry and entry.user_id == current_user.id:
    db.delete(entry)
    db.commit()
```

---

### CRIT-04: Хранение паролей в открытом виде

**Файл:** `backend/database/entry_service.py`  
**Строка:** 35-36  
**CVSS Score:** 9.1 (Critical)

```python
# ❌ УЯЗВИМОСТЬ
entry = PasswordEntry(
    password=password,  # Plain text!
    ...
)
```

**Проблема:** Пароли хранятся без шифрования.

**Последствия:**
- При компрометации БД все пароли утекают
- Нарушение GDPR/PCI DSS
- Полный доступ ко всем аккаунтам

**Исправление:**
```python
# ✅ ШИФРОВАНИЕ ПЕРЕД СОХРАНЕНИЕМ
from backend.core.crypto_core import CryptoCore

crypto = CryptoCore()
encrypted_password = crypto.encrypt(password.encode(), encryption_key)

entry = PasswordEntry(password=encrypted_password, ...)
```

---

### CRIT-05: Хранение истории паролей в открытом виде

**Файл:** `backend/features/password_history_manager.py`  
**Строка:** 23-27  
**CVSS Score:** 9.1 (Critical)

```python
# ❌ УЯЗВИМОСТЬ
query = text(
    f"INSERT INTO password_history (user_id, old_password, new_password, changed_at) "
    f"VALUES ({user_id}, '{old_password}', '{new_password}', NOW())"
)
```

**Проблема:** 
1. SQL injection через old_password/new_password
2. Пароли хранятся в открытом виде

**Исправление:**
```python
# ✅ ШИФРОВАНИЕ + ПАРАМЕТРИЗАЦИЯ
from sqlalchemy import insert

hashed_old = hash_password(old_password)
hashed_new = hash_password(new_password)

stmt = insert(PasswordHistory).values(
    user_id=user_id,
    old_password_hash=hashed_old,
    new_password_hash=hashed_new,
    changed_at=datetime.utcnow()
)
db.execute(stmt)
```

---

### CRIT-06: Экспорт паролей в plain text JSON

**Файл:** `backend/features/import_export.py`  
**Строка:** 23-30  
**CVSS Score:** 8.6 (Critical)

```python
# ❌ УЯЗВИМОСТЬ
data = {
    'entries': entries,  # Contains plain text passwords!
}
with open(filepath, 'w') as f:
    json.dump(data, f, indent=2)
```

**Проблема:** Пароли экспортируются без шифрования.

**Исправление:**
```python
# ✅ ШИФРОВАНИЕ ЭКСПОРТА
from cryptography.fernet import Fernet

# Generate key from master password
cipher = Fernet(derive_key(master_password))

encrypted_entries = []
for entry in entries:
    encrypted_entry = cipher.encrypt(json.dumps(entry).encode())
    encrypted_entries.append(encrypted_entry)

# Save encrypted data
with open(filepath, 'wb') as f:
    f.write(json.dumps({'entries': encrypted_entries}).encode())
```

---

### CRIT-07: Path traversal в cleanup_temp_files

**Файл:** `backend/features/import_export.py`  
**Строка:** 67-70  
**CVSS Score:** 7.5 (High)

```python
# ❌ УЯЗВИМОСТЬ
for filename in os.listdir(temp_dir):
    filepath = os.path.join(temp_dir, filename)
    os.remove(filepath)  # Could delete arbitrary files!
```

**Проблема:** Если temp_dir контролируется атакующим, можно удалить любые файлы.

**Эксплуатация:**
```python
temp_dir = "/etc"  # Или C:\Windows\System32
# Удалит все файлы в директории!
```

**Исправление:**
```python
# ✅ ПРОВЕРКА ПУТИ
import pathlib

temp_path = pathlib.Path(temp_dir).resolve()
if not str(temp_path).startswith('/safe/temp/dir'):
    raise ValueError("Invalid temp directory")

for filepath in temp_path.glob('*'):
    if filepath.is_file():
        filepath.unlink()
```

---

### CRIT-08: Логирование паролей в LoginRequest

**Файл:** `backend/database/schemas.py`  
**Строка:** 58-61  
**CVSS Score:** 7.5 (High)

```python
# ❌ УЯЗВИМОСТЬ
class LoginRequest(BaseModel):
    username: str
    password: str  # Will be logged in error messages!
```

**Проблема:** Pydantic может логировать все поля модели при ошибках.

**Исправление:**
```python
# ✅ ИСПОЛЬЗОВАТЬ SecretStr
from pydantic import BaseModel, SecretStr

class LoginRequest(BaseModel):
    username: str
    password: SecretStr  # Не светится в логах
    
    class Config:
        json_encoders = {
            SecretStr: lambda v: '**********' if v else None
        }
```

---

## 3. Уязвимости высокого уровня (9)

### HIGH-01: Password field не SecretStr

**Файл:** `backend/database/schemas.py`  
**Строка:** 14, 38

```python
# ❌ УЯЗВИМОСТЬ
class UserCreate(BaseModel):
    password: str  # Should be SecretStr
```

**Исправление:**
```python
from pydantic import SecretStr

class UserCreate(BaseModel):
    password: SecretStr
```

---

### HIGH-02: Отсутствие проверки прав доступа

**Файл:** `backend/database/entry_service.py`  
**Строка:** 54-58

```python
# ❌ УЯЗВИМОСТЬ
def get_entry_by_id(self, entry_id: int) -> Optional[PasswordEntry]:
    query = text(f"SELECT * FROM password_entries WHERE id = {entry_id}")
    # Нет проверки что entry принадлежит user_id!
```

**Исправление:**
```python
def get_entry_by_id(self, entry_id: int, user_id: int) -> Optional[PasswordEntry]:
    entry = db.get(PasswordEntry, entry_id)
    if entry and entry.user_id == user_id:
        return entry
    return None
```

---

### HIGH-03: Отсутствие валидации импорта

**Файл:** `backend/features/import_export.py`  
**Строка:** 47-52

```python
# ❌ УЯЗВИМОСТЬ
def import_from_json(self, user_id: int, filepath: str) -> List:
    with open(filepath, 'r') as f:
        data = json.load(f)
    # Нет валидации данных!
    return data.get('entries', [])
```

**Исправление:**
```python
from pydantic import ValidationError

def import_from_json(self, user_id: int, filepath: str) -> List:
    with open(filepath, 'r') as f:
        data = json.load(f)
    
    # Валидация
    try:
        entries = [PasswordEntryCreate(**entry) for entry in data.get('entries', [])]
        return entries
    except ValidationError as e:
        raise ValueError(f"Invalid import data: {e}")
```

---

## 4. Уязвимости среднего уровня (2)

### MED-01: Отсутствие ограничения размера импорта

**Файл:** `backend/features/import_export.py`  
**Проблема:** Нет лимита на количество импортируемых записей.

**Исправление:**
```python
MAX_IMPORT_ENTRIES = 1000

if len(entries) > MAX_IMPORT_ENTRIES:
    raise ValueError(f"Maximum {MAX_IMPORT_ENTRIES} entries allowed")
```

---

### MED-02: Нет audit logging для критических операций

**Файл:** `backend/database/entry_service.py`  
**Проблема:** Удаление/изменение не логируется.

**Исправление:**
```python
from backend.core.audit_logger import AuditLogger, EventType

def delete_entry(self, entry_id: int, user_id: int):
    # ... delete logic ...
    
    audit = AuditLogger(db)
    audit.log_event(
        event_type=EventType.DATA_DELETED,
        user_id=user_id,
        details={"entry_id": entry_id}
    )
```

---

## 5. Чеклист исправлений

### Блокирующие релиз (必须 fix)

- [ ] **CRIT-01**: Исправить SQL injection в get_entries
- [ ] **CRIT-02**: Исправить SQL injection в search_entries
- [ ] **CRIT-03**: Исправить SQL injection в delete_entry
- [ ] **CRIT-04**: Добавить шифрование паролей
- [ ] **CRIT-05**: Исправить password history (шифрование + SQL injection)
- [ ] **CRIT-06**: Шифрование экспорта
- [ ] **CRIT-07**: Исправить path traversal
- [ ] **CRIT-08**: Использовать SecretStr для паролей

### Высокий приоритет

- [ ] **HIGH-01**: Заменить str на SecretStr в схемах
- [ ] **HIGH-02**: Добавить проверку прав доступа
- [ ] **HIGH-03**: Валидация импортируемых данных

### Средний приоритет

- [ ] **MED-01**: Ограничение размера импорта
- [ ] **MED-02**: Audit logging для CRUD операций

---

## 6. Рекомендации для BE2 (Alexey)

### 6.1 Немедленные действия

1. **НЕ ИСПОЛЬЗОВАТЬ text() с конкатенацией строк**
   ```python
   # ❌ ПЛОХО
   query = text(f"SELECT * FROM users WHERE id = {user_id}")
   
   # ✅ ХОРОШО
   query = text("SELECT * FROM users WHERE id = :id")
   result = db.execute(query, {"id": user_id})
   ```

2. **ВСЕГДА шифровать чувствительные данные**
   ```python
   from backend.core.crypto_core import CryptoCore
   
   crypto = CryptoCore()
   encrypted = crypto.encrypt(password.encode(), key)
   ```

3. **Использовать SecretStr для паролей**
   ```python
   from pydantic import SecretStr
   
   password: SecretStr  # Не password: str
   ```

### 6.2 Обучение

- Пройти курс "SQL Injection Prevention"
- Изучить OWASP Top 10
- Прочитать документацию SQLAlchemy

### 6.3 Code Review процесс

1. Весь код должен проходить ревью перед мерджем
2. Использовать pre-commit хуки для автоматической проверки
3. Запустить bandit для статического анализа

---

## 7. План исправлений

### Спринт 1 (Неделя 9)

- Исправить все CRITICAL уязвимости
- Добавить шифрование для всех чувствительных полей
- Заменить raw SQL на ORM

### Спринт 2 (Неделя 10)

- Исправить HIGH уязвимости
- Добавить валидацию данных
- Настроить audit logging

### Спринт 3 (Неделя 11)

- Исправить MEDIUM уязвимости
- Финальный security audit
- Подготовка к релизу

---

## 8. Приложения

### A. Примеры безопасного кода

#### Безопасный SQL запрос
```python
from sqlalchemy import select, and_

# ✅ ПРАВИЛЬНО
stmt = select(PasswordEntry).where(
    and_(
        PasswordEntry.user_id == user_id,
        PasswordEntry.title.ilike(f"%{search_term}%")
    )
)
results = db.execute(stmt).scalars().all()
```

#### Безопасное шифрование
```python
from backend.core.crypto_core import CryptoCore

crypto = CryptoCore()

# Шифрование
encrypted = crypto.encrypt(
    plaintext=password.encode(),
    key=encryption_key
)

# Расшифровка
decrypted = crypto.decrypt(
    ciphertext=encrypted,
    key=encryption_key
).decode()
```

#### Безопасная работа с файлами
```python
import pathlib
import secrets

# ✅ ПРАВИЛЬНО
safe_dir = pathlib.Path("/safe/temp/dir").resolve()
filename = f"{secrets.token_hex(16)}.json"  # Random filename
filepath = (safe_dir / filename).resolve()

# Проверка что путь внутри safe_dir
if not str(filepath).startswith(str(safe_dir)):
    raise ValueError("Invalid file path")
```

---

**Отчёт составил:**  
Никита (BE1) — Архитектор безопасности  
**Дата:** Апрель 2026  
**Статус:** 🔴 TREQUIRES IMMEDIATE ACTION

