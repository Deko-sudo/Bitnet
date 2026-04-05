# Руководство по использованию Auth Manager и Security Utils

**Версия:** 1.0  
**Дата:** Март 2026

---

## 1. Auth Manager - Управление аутентификацией

### 1.1 Базовое использование

```python
from backend.core.crypto_core import CryptoCore
from backend.core.auth_manager import AuthManager

# Создаём CryptoCore и AuthManager
crypto = CryptoCore()
auth = AuthManager(crypto, auto_lock_timeout=300)  # 5 минут

# Разблокировка с паролем
auth.unlock("мой_пароль", salt)

# Проверка состояния
if auth.is_unlocked:
    print("Сессия разблокирована")

# Получение мастер-ключа
key = auth.get_master_key()

# Когда закончили - блокируем
auth.lock()
```

### 1.2 Контекстный менеджер

```python
# Автоматическая блокировка при выходе из блока
with AuthManager(crypto) as auth:
    auth.unlock("пароль", salt)
    # Работаем с ключом
    key = auth.get_master_key()
# Автоматически заблокировано
```

### 1.3 Callbacks

```python
def on_lock():
    print("Сессия заблокирована")

def on_unlock():
    print("Сессия разблокирована")

auth = AuthManager(
    crypto,
    on_lock=on_lock,
    on_unlock=on_unlock
)
```

### 1.4 Автоблокировка

```python
# Таймер автоблокировки запускается автоматически при unlock
auth.unlock("пароль", salt)

# Сброс таймера активности
auth.touch()  # Вызывать при действиях пользователя

# Проверка времени до автоблокировки
time_remaining = auth.time_until_auto_lock
print(f"До блокировки: {time_remaining:.0f} сек")
```

### 1.5 Производные ключи

```python
# Получение ключа для шифрования
enc_key = auth.get_derived_key(b"encryption")

# Получение ключа для HMAC
hmac_key = auth.get_derived_key(b"hmac")

# Ключи разные для разных целей
assert enc_key != hmac_key
```

---

## 2. Rate Limiter - Защита от брутфорса

### 2.1 Базовое использование

```python
from backend.core.security_utils import RateLimiter

limiter = RateLimiter(
    max_attempts=5,           # Максимум попыток
    window_seconds=60,        # Окно подсчёта (сек)
    block_duration_seconds=1800,  # Длительность блокировки (30 мин)
)

# Проверка возможности попытки
if limiter.can_attempt("user123"):
    # Пытаемся аутентифицировать
    success = authenticate(user, password)
    
    if success:
        limiter.register_success("user123")
    else:
        limiter.register_failed("user123")
else:
    print("Слишком много попыток. Попробуйте позже.")
```

### 2.2 Exponential Backoff

```python
# Получение задержки перед следующей попыткой
delay = limiter.get_delay("user123")

if delay > 0:
    print(f"Подождите {delay:.1f} сек")
    time.sleep(delay)
```

### 2.3 Проверка статуса

```python
# Проверка блокировки
if limiter.is_blocked("user123"):
    print("Пользователь заблокирован")

# Оставшиеся попытки
remaining = limiter.get_remaining_attempts("user123")
print(f"Осталось попыток: {remaining}")

# Сброс счётчика
limiter.reset("user123")
```

---

## 3. Password Strength Checker - Проверка сложности пароля

### 3.1 Базовое использование

```python
from backend.core.security_utils import PasswordStrengthChecker, PasswordStrength

checker = PasswordStrengthChecker(
    min_length=12,
    min_entropy_bits=60.0,
    require_uppercase=True,
    require_lowercase=True,
    require_digits=True,
    require_special=False,
)

# Проверка пароля
result = checker.check_strength("MyP@ssw0rd123")

print(f"Сложность: {result.strength}")  # PasswordStrength.GOOD
print(f"Энтропия: {result.entropy_bits:.1f} бит")
print(f"Время взлома: {result.crack_time_estimate}")
```

### 3.2 Проверка соответствия требованиям

```python
is_valid, result = checker.is_strong_enough("password123")

if not is_valid:
    print("Пароль не соответствует требованиям:")
    for suggestion in result.suggestions:
        print(f"  - {suggestion}")
```

### 3.3 Результаты проверки

```python
result = checker.check_strength("Str0ng@Password!")

# Доступные поля
print(result.strength)           # PasswordStrength.STRONG
print(result.entropy_bits)       # 85.2
print(result.crack_time_estimate) # "3.2 billion years"
print(result.has_uppercase)      # True
print(result.has_lowercase)      # True
print(result.has_digits)         # True
print(result.has_special)        # True
print(result.length)             # 18
print(result.suggestions)        # []
```

### 3.4 Уровни сложности

```python
from backend.core.security_utils import PasswordStrength

PasswordStrength.VERY_WEAK  # 0 - Очень слабый
PasswordStrength.WEAK       # 1 - Слабый
PasswordStrength.FAIR       # 2 - Средний
PasswordStrength.GOOD       # 3 - Хороший
PasswordStrength.STRONG     # 4 - Сильный
```

---

## 4. Session Manager - Управление сессиями

### 4.1 Создание сессий

```python
from backend.core.auth_manager import SessionManager

mgr = SessionManager(max_sessions_per_user=5)

# Создание новой сессии
session_id = mgr.create_session("user123")
print(f"Session ID: {session_id}")
```

### 4.2 Проверка сессии

```python
# Проверка валидности
if mgr.is_session_valid(session_id):
    print("Сессия активна")

# Обновление активности
mgr.touch_session(session_id)
```

### 4.3 Завершение сессии

```python
# Удаление сессии
mgr.destroy_session(session_id)

# Получение активных сессий
active = mgr.get_active_sessions()
print(f"Активных сессий: {len(active)}")
```

---

## 5. Интеграционный пример

### 5.1 Полный цикл аутентификации

```python
from backend.core.crypto_core import CryptoCore
from backend.core.auth_manager import AuthManager
from backend.core.security_utils import RateLimiter, PasswordStrengthChecker

# Инициализация
crypto = CryptoCore()
auth = AuthManager(crypto)
limiter = RateLimiter(max_attempts=5)
password_checker = PasswordStrengthChecker()

def login(username, password, salt):
    """Функция входа."""
    # Проверка rate limiting
    if not limiter.can_attempt(username):
        delay = limiter.get_delay(username)
        return False, f"Слишком много попыток. Подождите {delay:.0f} сек"
    
    # Проверка сложности пароля (опционально)
    is_strong, result = password_checker.is_strong_enough(password)
    if not is_strong:
        return False, "Пароль слишком слабый"
    
    # Попытка аутентификации
    try:
        auth.unlock(password, salt)
        limiter.register_success(username)
        return True, "Вход успешен"
    except Exception as e:
        limiter.register_failed(username)
        remaining = limiter.get_remaining_attempts(username)
        return False, f"Неверный пароль. Осталось попыток: {remaining}"

def logout(username):
    """Функция выхода."""
    if auth.is_unlocked:
        auth.lock()
    print(f"{username} вышел из системы")

# Пример использования
success, message = login("user123", "password", salt)
print(message)

if success:
    # Работаем с системой
    key = auth.get_master_key()
    # ...
    
    # Выход
    logout("user123")
```

### 5.2 Регистрация нового пользователя

```python
def register_password(new_password, confirm_password):
    """Проверка и регистрация пароля."""
    # Проверка совпадения
    if new_password != confirm_password:
        return False, "Пароли не совпадают"
    
    # Проверка сложности
    is_strong, result = password_checker.is_strong_enough(new_password)
    if not is_strong:
        return False, result.suggestions
    
    # Генерация соли и деривация ключа
    salt = crypto.generate_salt()
    master_key = crypto.derive_master_key(new_password, salt)
    
    # Сохранение salt (можно в открытом виде!)
    save_to_database(salt=salt.hex())
    
    # Очистка ключа из памяти
    from backend.core.crypto_core import zero_memory
    zero_memory(bytearray(master_key))
    
    return True, "Пароль зарегистрирован"
```

---

## 6. Best Practices

### 6.1 Безопасное хранение ключей

```python
# ✅ ПРАВИЛЬНО:
with AuthManager(crypto) as auth:
    auth.unlock(password, salt)
    key = auth.get_master_key()
    try:
        # Использовать ключ
        data = crypto.encrypt(secret, key)
    finally:
        # Очистка ключа
        zero_memory(bytearray(key))

# ❌ НЕПРАВИЛЬНО:
auth.unlock(password, salt)
key = auth.get_master_key()
# Ключ остаётся в памяти неопределённо долго
```

### 6.2 Rate limiting для API

```python
@app.post("/login")
async def login_endpoint(request: LoginRequest):
    if not limiter.can_attempt(request.ip):
        raise HTTPException(429, "Too many requests")
    
    try:
        auth.unlock(request.password, salt)
        limiter.register_success(request.ip)
        return {"status": "ok"}
    except:
        limiter.register_failed(request.ip)
        raise HTTPException(401, "Invalid credentials")
```

### 6.3 Обновление активности

```python
# Вызывать touch() при каждом действии пользователя
@app.get("/dashboard")
async def dashboard():
    auth.touch()  # Сброс таймера автоблокировки
    return render_dashboard()
```

---

## 7. API Reference

### AuthManager

| Метод | Описание |
|-------|----------|
| `unlock(password, salt)` | Разблокировать сессию |
| `lock()` | Заблокировать сессию |
| `touch()` | Обновить активность |
| `get_master_key()` | Получить мастер-ключ |
| `get_derived_key(context)` | Получить производный ключ |
| `is_locked` | Статус блокировки |
| `time_until_auto_lock` | Время до автоблокировки |

### RateLimiter

| Метод | Описание |
|-------|----------|
| `can_attempt(identifier)` | Проверка возможности попытки |
| `register_failed(identifier)` | Регистрация неудачи |
| `register_success(identifier)` | Регистрация успеха |
| `get_delay(identifier)` | Получить задержку |
| `is_blocked(identifier)` | Проверка блокировки |
| `get_remaining_attempts(identifier)` | Оставшиеся попытки |

### PasswordStrengthChecker

| Метод | Описание |
|-------|----------|
| `check_strength(password)` | Проверка сложности |
| `is_strong_enough(password)` | Проверка соответствия |

---

## 8. Тесты

Запуск тестов:
```bash
pytest backend/tests/test_auth_security.py -v
```

Покрытие: **85%** (49 тестов пройдено)
