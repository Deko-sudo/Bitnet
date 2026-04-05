# Contributing Guidelines
## Руководство по внесению изменений в проект

**Версия:** 1.0  
**Дата:** Март 2026

---

## 1. Введение

Спасибо за интерес к проекту! Это руководство поможет вам внести свой вклад.

### 1.1 Что можно улучшить

- 🐛 Исправление багов
- ✨ Новые функции
- 📝 Улучшение документации
- 🧹 Рефакторинг кода
- 🧪 Добавление тестов

---

## 2. Быстрый старт

### 2.1 Установка зависимостей

```bash
# Клонирование репозитория
git clone https://github.com/your-username/password-manager.git
cd password-manager

# Создание виртуального окружения
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Установка зависимостей
pip install -r requirements.txt

# Установка pre-commit хуков
pre-commit install
```

### 2.2 Запуск тестов

```bash
# Все тесты
pytest backend/tests/ -v

# С покрытием
pytest --cov=backend --cov-report=html

# Конкретный файл
pytest backend/tests/test_crypto_core.py -v
```

---

## 3. Процесс разработки

### 3.1 Ветвление

```
main          — стабильная версия
develop       — ветка разработки
feature/*     — новые функции
bugfix/*      — исправления багов
hotfix/*      — срочные исправления
```

### 3.2 Создание ветки

```bash
# Новая функция
git checkout develop
git checkout -b feature/add-2fa

# Исправление бага
git checkout develop
git checkout -b bugfix/fix-login-error
```

### 3.3 Именование коммитов

```
feat: добавить двухфакторную аутентификацию
fix: исправить ошибку входа при пустом пароле
docs: обновить README.md
test: добавить тесты для AuthManager
refactor: рефакторинг crypto_core
chore: обновить зависимости
```

---

## 4. Требования к коду

### 4.1 Стиль кода

```python
# ✅ ПРАВИЛЬНО
def encrypt_data(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypt data using AES-256-GCM.
    
    Args:
        plaintext: Data to encrypt
        key: Encryption key (32 bytes)
    
    Returns:
        Encrypted data
    """
    return crypto.encrypt(plaintext, key)

# ❌ НЕПРАВИЛЬНО
def encrypt(p, k):  # Нет типов, нет docstring
    return crypto.encrypt(p, k)
```

### 4.2 Аннотации типов

```python
# ✅ Обязательно для всех функций
def calculate_entropy(password: str) -> float:
    return len(password) * math.log2(26)

# ❌ Запрещено
def calculate_entropy(password):
    return len(password) * math.log2(26)
```

### 4.3 Обработка ошибок

```python
# ✅ ПРАВИЛЬНО
from backend.core.crypto_core import AuthenticationError

try:
    decrypted = crypto.decrypt(ciphertext, key)
except AuthenticationError:
    logger.warning("Authentication failed")
    raise
except Exception as e:
    logger.error(f"Decryption error: {e}")
    raise DecryptionError(f"Failed to decrypt: {e}")

# ❌ НЕПРАВИЛЬНО
try:
    decrypted = crypto.decrypt(ciphertext, key)
except:  # Catch all exceptions
    pass  # Silent failure
```

---

## 5. Требования к тестам

### 5.1 Покрытие тестами

```bash
# Минимальное покрытие
pytest --cov=backend --cov-fail-under=85

# Отчёт о покрытии
pytest --cov=backend --cov-report=html
# Откроется в browser: htmlcov/index.html
```

### 5.2 Структура тестов

```python
# ✅ ПРАВИЛЬНО
class TestCryptoCore:
    """Tests for CryptoCore class."""
    
    def test_encrypt_decrypt_basic(self, crypto, sample_key):
        """Test basic encrypt-decrypt cycle."""
        plaintext = b"test data"
        encrypted = crypto.encrypt(plaintext, sample_key)
        decrypted = crypto.decrypt(encrypted, sample_key)
        assert decrypted == plaintext
    
    def test_decrypt_wrong_key(self, crypto, sample_key):
        """Test decryption with wrong key raises error."""
        wrong_key = secrets.token_bytes(32)
        encrypted = crypto.encrypt(b"data", sample_key)
        with pytest.raises(AuthenticationError):
            crypto.decrypt(encrypted, wrong_key)

# ❌ НЕПРАВИЛЬНО
def test_stuff():  # Нет класса, нет описания
    crypto = CryptoCore()
    # ... тест без структуры
```

### 5.3 Фикстуры

```python
# ✅ ПРАВИЛЬНО
@pytest.fixture
def crypto():
    """Create CryptoCore instance."""
    return CryptoCore()

@pytest.fixture
def sample_key():
    """Generate sample 256-bit key."""
    return secrets.token_bytes(32)

# Использование
def test_encrypt(crypto, sample_key):
    encrypted = crypto.encrypt(b"data", sample_key)
```

---

## 6. Проверки перед коммитом

### 6.1 Pre-commit хуки

```bash
# Автоматический запуск перед коммитом
pre-commit run

# Пропустить проверки (не рекомендуется!)
git commit -m "WIP" --no-verify
```

### 6.2 Ручные проверки

```bash
# Форматирование
black backend/

# Линтинг
flake8 backend/

# Типы
mypy backend/ --ignore-missing-imports

# Безопасность
bandit -r backend/ -ll

# Тесты
pytest backend/tests/ -v
```

### 6.3 Чеклист PR

```markdown
## Checklist

- [ ] Код отформатирован (black)
- [ ] Нет предупреждений flake8
- [ ] Mypy не нашёл ошибок
- [ ] Bandit не нашёл уязвимостей
- [ ] Все тесты проходят
- [ ] Покрытие >85%
- [ ] Документация обновлена
- [ ] CHANGELOG обновлён
```

---

## 7. Безопасность

### 7.1 Запрещённые паттерны

```python
# ❌ НИКОГДА НЕ ДЕЛАЙ ТАК:

# Логирование паролей
logger.error(f"Password: {password}")

# Raw SQL
query = f"SELECT * FROM users WHERE id = {user_id}"

# Слабые алгоритмы
hashlib.md5(password.encode())

# Хардкод секретов
API_KEY = "sk-123456789"
```

### 7.2 Обязательные паттерны

```python
# ✅ ВСЕГДА ДЕЛАЙ ТАК:

# SecretStr для секретов
from pydantic import SecretStr

# Constant-time сравнение
hmac.compare_digest(a, b)

# ORM вместо raw SQL
session.query(User).filter(User.id == user_id)

# Переменные окружения
os.environ["API_KEY"]
```

---

## 8. Документация

### 8.1 Docstrings

```python
def encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypt data using AES-256-GCM.
    
    Args:
        plaintext: Data to encrypt (max 1GB)
        key: Encryption key (must be 32 bytes)
    
    Returns:
        Encrypted data with nonce and auth tag
    
    Raises:
        ValueError: If key length is not 32 bytes
        EncryptionError: If encryption fails
    
    Example:
        >>> key = secrets.token_bytes(32)
        >>> encrypted = encrypt(b"secret", key)
    """
```

### 8.2 Обновление документации

При добавлении новой функции:

1. Обновить README.md (если меняется API)
2. Добавить docstring
3. Обновить docs/*.md (если нужно)
4. Добавить пример использования

---

## 9. Code Review

### 9.1 Процесс review

```
1. Создать PR
2. Assign reviewer (BE1/BE2)
3. Исправить замечания
4. Получить approve
5. Merge в develop
```

### 9.2 Критерии acceptance

- [ ] Код соответствует стилю проекта
- [ ] Все тесты проходят
- [ ] Покрытие не уменьшилось
- [ ] Нет security issues
- [ ] Документация обновлена

### 9.3 Типичные замечания

```markdown
## Примеры замечаний

**Style:**
- Please add type annotations
- Missing docstring for public function
- Line too long (max 100 chars)

**Security:**
- Don't log sensitive data
- Use constant_time_compare for secrets
- Add rate limiting for this endpoint

**Tests:**
- Add test for edge case
- Mock external API calls
- Increase test coverage
```

---

## 10. Release Process

### 10.1 Версионирование

```
MAJOR.MINOR.PATCH

2.1.3
│ │ │
│ │ └─ Patch (bug fixes)
│ └─── Minor (new features, backward compatible)
└───── Major (breaking changes)
```

### 10.2 Процесс релиза

```bash
# 1. Обновить версию
# backend/__version__.py
__version__ = "1.2.0"

# 2. Обновить CHANGELOG
# docs/CHANGELOG.md

# 3. Создать тег
git tag -a v1.2.0 -m "Release 1.2.0"
git push origin v1.2.0

# 4. CI/CD создаст релиз автоматически
```

---

## 11. Сообщество

### 11.1 Где задать вопрос

- **GitHub Issues:** Баги, фичи
- **Discord:** Общие вопросы
- **Email:** security@example.com (безопасность)

### 11.2 Кодекс поведения

- Будьте уважительны
- Помогайте новичкам
- Конструктивная критика
- Нет токсичности

---

## 12. Приложения

### A. Шаблон Pull Request

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Tests added/updated
- [ ] All tests pass
- [ ] Coverage >85%

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] No new warnings
- [ ] Security reviewed

## Related Issues
Fixes #123
```

### B. Полезные команды

```bash
# Запустить все проверки
pre-commit run --all-files

# Проверить покрытие
pytest --cov=backend --cov-report=term-missing

# Найти дубликаты
flake8 --select=DUP

# Проверить сложность
flake8 --max-complexity=10

# Обновить зависимости
pip install --upgrade -r requirements.txt
```

---

**Документ утверждён:**  
Команда разработки  
**Дата:** Март 2026  
**Следующий пересмотр:** Июнь 2026
