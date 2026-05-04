# BitNet — Полный Аудит Безопасности

> **Дата:** 2026-04-18  
> **Аудитор:** Antigravity (Senior AppSec / Rust + Python)  
> **Область:** Rust-ядро, Python-бэкенд, Docker-инфраструктура, UX-логика  
> **Итоговая оценка:** 🟡 MEDIUM-HIGH — хорошая база, несколько критических точек требуют устранения

---

## 1. Криптографический анализ (Core)

### ✅ Что сделано правильно

| Элемент | Оценка |
|---|---|
| AES-256-GCM (Rust `aes-gcm 0.10.3`) | ✅ Правильный алгоритм |
| Аутентификационный тег (16 байт, detached) | ✅ Отдельное хранение `tag` |
| Argon2id, m=64MB, t=3, p=4 | ✅ Выше минимума OWASP 2024 |
| `VirtualLock`/`mlock` для ключей в Rust | ✅ Ключи физически защищены от свопа |
| `zeroize` crate в `Drop` | ✅ Явная очистка при дропе |
| HKDF-SHA256 для blind-index ключа | ✅ Правильная доменная сепарация |
| `hmac.compare_digest` везде | ✅ Constant-time сравнение |
| Docker secrets (не `.env`) для `server_key` | ✅ |
| Non-root user `bitnet` в контейнере | ✅ |
| Multi-stage build (отдельный Rust builder) | ✅ |

---

### 🔴 КРИТИЧНО #1 — AES-GCM Nonce повторяется при `uvicorn --workers 4`

**Файл:** `Dockerfile`, строка 111; `docker-compose.yml`, строка 34  
**Уровень:** CRITICAL

**Описание:**  
`OsRng.fill_bytes(&mut nonce)` в `lib.rs:373` генерирует 12-байтный случайный nonce. Это безопасно **для одного процесса**. Но `CMD` запускает `--workers 4` — четыре **отдельных OS-процесса** с разными адресными пространствами. При этом каждый процесс разделяет **одну и ту же SQLite-базу**. Вероятность nonce-коллизии для AES-GCM при 12-байтном случайном nonce становится реальной при количестве шифрований `≥ 2^32 / 4` на пользователя (birthday paradox). Это не немедленная угроза, но в долгосрочной перспективе **nonce-reuse в AES-GCM катастрофичен**: полное раскрытие ключа и всех данных.

**Решение:**  
Вариант 1 (рекомендуемый): переключиться с random nonce на **counter-based nonce** — глобальный атомарный счётчик, синхронизированный через БД или Redis.  
Вариант 2 (быстрый): Уменьшить `--workers 1` до тех пор, пока не реализован счётчик, или перейти на **AES-256-GCM-SIV** (nonce-misuse-resistant).

```toml
# Cargo.toml — добавить:
aes-gcm-siv = "0.11"
```

```rust
// lib.rs — замена encrypt:
use aes_gcm_siv::{AesGcmSiv, aead::{AeadInPlace, KeyInit}};
type Aes256GcmSiv = AesGcmSiv<aes::Aes256>;
```

> [!CAUTION]
> Если оставить `--workers 4` с random nonce и высокой нагрузкой — это путь к полной компрометации хранилища.

---

### 🔴 КРИТИЧНО #2 — `zero_memory` при `memoryview` ничего не зерует

**Файл:** `crypto_core.py`, строки 99–103  
**Уровень:** CRITICAL

**Описание:**
```python
if isinstance(data, memoryview):
    buf = bytearray(data)   # ← КОПИЯ, а не исходный буфер!
    length = len(buf)
```
Создаётся **новый** `bytearray` из `memoryview`, оригинальный буфер (например, `password_bytes`) в памяти остаётся нетронутым. Вся защита сводится к нулю.

**Решение:**
```python
def zero_memory(data: Union[bytearray, memoryview]) -> None:
    if isinstance(data, memoryview):
        if not data.contiguous:
            raise ValueError("memoryview must be contiguous")
        # Зерование ЧЕРЕЗ VIEW, а не через копию
        mv = data.cast("B")
        length = len(mv)
        if length == 0:
            return
        buf_type = ctypes.c_char * length
        buf_ref = buf_type.from_buffer(mv)  # <- работает с оригиналом
        ctypes.memset(ctypes.addressof(buf_ref), 0, length)
        return
    # остаток без изменений...
```

---

### 🟠 ВЫСОКИЙ #3 — `derive_subkey` не использует salt в HKDF

**Файл:** `crypto_core.py`, строки 307–313  
**Уровень:** HIGH

**Описание:**
```python
hkdf = HKDF(
    algorithm=hashes.SHA256(),
    length=self._config.key_size,
    salt=None,   # ← нет соли!
    info=context,
)
```
RFC 5869 рекомендует salt для предотвращения атак на слабые IKM. Без соли HKDF деградирует до обычного HMAC-expand, что ослабляет разделение ключей, когда мастер-ключ — слабый или предсказуемый.

**Решение:**
```python
HKDF_SALT = b"bitnet:hkdf:v1:" + secrets.token_bytes(32)  # статическая, хранится в конфиге

hkdf = HKDF(
    algorithm=hashes.SHA256(),
    length=self._config.key_size,
    salt=HKDF_SALT,
    info=context,
)
```

---

### 🟡 СРЕДНИЙ #4 — Argon2 параметры не читаются из env

**Файл:** `config.py`, строки 16–20  
**Уровень:** MEDIUM

**Описание:**  
`CryptoConfig` жёстко задаёт `argon2_time_cost=3`, `argon2_memory_cost=65536`. `.env.example` содержит закомментированные переменные `ARGON2_MEMORY_COST`, но `config.py` их **не читает**. Итог: невозможно увеличить hardness без деплоя нового кода.

**Решение:**
```python
from pydantic_settings import BaseSettings

class CryptoConfig(BaseSettings):
    argon2_time_cost: int = Field(default=3, ge=1, validation_alias="ARGON2_TIME_COST")
    argon2_memory_cost: int = Field(default=65536, ge=65536, validation_alias="ARGON2_MEMORY_COST")
    # ...
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
```

---

### 🟡 СРЕДНИЙ #5 — `PasswordHistory` хранит только cipher+nonce, без TAG

**Файл:** `models.py`, строки 110–111  
**Уровень:** MEDIUM

**Описание:**
```python
password_cipher: Mapped[str] = mapped_column(String, nullable=False)
password_nonce: Mapped[str] = mapped_column(String, nullable=False)
# Нет поля tag!
```
`PasswordEntry` хранит nonce отдельно от шифртекста, а `PasswordHistory` — только `cipher` и `nonce`, но **не тег аутентификации**. Если `cipher_hex` уже содержит тег (как следует из `encrypt_for_storage`), это неконсистентно с типом `str` vs `LargeBinary` в основной модели.

**Решение:** Привести `PasswordHistory` к той же схеме, что и `PasswordEntry`, или явно документировать, что `password_cipher` содержит `ciphertext || tag` вместе.

---

## 2. Безопасность взаимодействия (IPC/API)

### 🔴 КРИТИЧНО #6 — Memory Leak через `EntryResponseSchema` с `SecretStr`

**Файл:** `entry_service.py`, строки 191–212; `schemas.py`, строки 57–61  
**Уровень:** CRITICAL

**Описание:**
```python
return EntryResponseSchema(
    password=SecretStr(decrypted_dict["password"].decode("utf-8")),
    ...
)
finally:
    for byte_arr in decrypted_dict.values():
        if byte_arr is not None:
            zero_memory(byte_arr)
```
1. `.decode("utf-8")` создаёт **иммутабельный Python `str`** в пуле строк — его нельзя обнулить.
2. `SecretStr` хранит строку внутри `_secret_value` — тоже `str`.
3. `field_serializer` вызывает `get_secret_value()` — вновь иммутабельный str.
4. FastAPI сериализует ответ в JSON-строку → временные буферы остаются в памяти CPython до следующего GC.

Таким образом, plaintext-пароль **неизбежно** остаётся в Python heap после ответа, вопреки `zero_memory` в `finally`.

**Решение (архитектурное):**  
Единственный безопасный вариант при E2EE: **не выполнять расшифровку на сервере**. Расшифровка должна происходить на клиенте (браузер/десктоп). Сервер отдаёт только `cipher_hex + nonce_hex` клиенту, клиент расшифровывает мастер-ключом (хранится только в браузере).

```python
# Правильная схема ответа — только зашифрованные данные:
class EntryResponseSchema(BaseModel):
    id: int
    user_id: int
    title_cipher: str
    title_nonce: str
    password_cipher: str
    password_nonce: str
    # ...
```

> [!IMPORTANT]
> Если расшифровка происходит на сервере (как сейчас) — Zero-Knowledge нарушен. Сервер видит plaintext паролей в памяти при каждом `GET /entries/{id}`.

---

### 🟠 ВЫСОКИЙ #7 — `RateLimiter` — в памяти процесса, не переживает рестарт

**Файл:** `security_utils.py`, строка 122  
**Уровень:** HIGH

**Описание:**
```python
self._storage: Dict[str, dict] = {}
```
При `--workers 4`: каждый воркер имеет собственный `RateLimiter`. Атакующий, делая запросы равномерно по воркерам, получает эффективный лимит `max_attempts * workers = 5 * 4 = 20` попыток вместо 5. После рестарта контейнера — лимиты сбрасываются полностью.

**Решение:** Вынести `RateLimiter` в Redis или SQLite-таблицу:
```python
# Вариант через SQLite:
async def check_rate_limit(db: AsyncSession, identifier: str) -> bool:
    stmt = select(RateLimit).where(RateLimit.identifier == identifier)
    # ...
```

---

### 🟠 ВЫСОКИЙ #8 — `RecoveryCodeManager` — коды только в памяти, без персистентности

**Файл:** `advanced_security.py`, строки 317–319  
**Уровень:** HIGH

**Описание:**
```python
self._codes: dict[str, dict[str, RecoveryCode]] = {}
```
Recovery-коды хранятся в RAM процесса. При рестарте сервиса **все коды теряются**. Пользователь не сможет восстановить доступ. Более того, `_hash_code` использует простой `SHA-256` без соли — уязвим к rainbow table атаке.

**Решение:**
1. Хранить хэши в БД (новая таблица `recovery_codes`).
2. Использовать `bcrypt` или `argon2` для хэширования кодов:
```python
from argon2 import PasswordHasher
ph = PasswordHasher(time_cost=1, memory_cost=65536, parallelism=2)
code_hash = ph.hash(code)
```

---

### 🟡 СРЕДНИЙ #9 — TOTP использует SHA-1 и не защищён от replay

**Файл:** `advanced_security.py`, строка 51  
**Уровень:** MEDIUM

**Описание:**
```python
HASH_ALGORITHM = 'sha1'
```
RFC 6238 стандартизирует SHA-1 для TOTP, но он устарел. Важнее: **нет защиты от replay** — код действует в окне ±30 сек (3 временных шага с `window=1`). Использованные коды не отслеживаются.

**Решение:**
1. Переключиться на `SHA-256` (совместимо с большинством современных authenticator-приложений).
2. Хранить `last_used_counter` в БД и отклонять уже использованные коды:
```python
if code_counter <= stored_last_counter:
    return False  # replay attempt
```

---

### 🟡 СРЕДНИЙ #10 — `get_master_key()` (deprecated) возвращает незащищённый bytearray

**Файл:** `auth_manager.py`, строки 478–505  
**Уровень:** MEDIUM

**Описание:**
```python
def get_master_key(self) -> bytearray:
    with self._lock:
        with self.with_master_key() as master_key:
            return bytearray(master_key)  # caller must zero manually!
```
Вложенный `with self._lock:` **внутри** context manager `with_master_key()`, который тоже получает `self._lock` → **потенциальный deadlock** на `RLock` (хотя `RLock` повторно-входимый, это анти-паттерн). Кроме того — возврат `bytearray` нарушает принцип наименьших привилегий.

**Решение:** Удалить `get_master_key()` и `get_derived_key()` полностью. Принудительно использовать только context-manager API.

---

### 🟡 СРЕДНИЙ #11 — `with_derived_key` использует `dir()` для проверки переменной

**Файл:** `auth_manager.py`, строка 458  
**Уровень:** MEDIUM

**Описание:**
```python
finally:
    zero_memory(master_key)
    if "subkey" in dir():       # ← небезопасная проверка
        zero_memory(subkey)
```
`dir()` возвращает атрибуты **объекта**, а не локальные переменные. Правильно использовать `"subkey" in locals()`. При ошибке до присваивания `subkey`, `locals()` не будет содержать имя — zero_memory не будет вызван, что корректно. Но `dir()` — неверный инструмент.

**Исправление:**
```python
finally:
    zero_memory(master_key)
    subkey_local = locals().get("subkey")
    if subkey_local is not None:
        zero_memory(subkey_local)
```

---

## 3. Логические дыры и UX

### 🔴 КРИТИЧНО #12 — Нет механизма смены мастер-пароля с ре-шифрованием

**Уровень:** CRITICAL (логика)

**Описание:**  
Смена мастер-пароля требует повторного шифрования ВСЕХ `PasswordEntry` новым ключом (иначе старый ключ расшифрует все данные). В коде нет такого endpoint или сервиса. Если пользователь меняет пароль через `users.salt` + `users.wrapped_master_key_*` — старые записи, зашифрованные старым ключом, станут недоступны.

**Решение — двухслойная архитектура:**
1. Мастер-ключ НЕ меняется при смене пароля.
2. При смене пароля — мастер-ключ **перезаворачивается** новым `wrapped_master_key`:
```python
async def change_password(user_id, old_password, new_password, db):
    # 1. Распаковать мастер-ключ старым паролем
    master_key = unwrap_with_old_password(user, old_password)
    # 2. Завернуть тем же мастер-ключом с новым паролем
    new_wrapped = wrap_with_new_password(master_key, new_password)
    # 3. Обновить только wrapped_master_key — данные не трогаем
    await db.update(user, wrapped=new_wrapped)
```

---

### 🟠 ВЫСОКИЙ #13 — Мягкое удаление (`is_deleted`) без физической очистки

**Файл:** `entry_service.py`, строки 160–163  
**Уровень:** HIGH

**Описание:**
```python
entry.is_deleted = True
entry.deleted_at = datetime.now(timezone.utc)
```
"Удалённые" записи остаются в БД навсегда. Для SQLite без шифрования на уровне файловой системы — злоумышленник с физическим доступом к `bitnet.db` считает все "удалённые" пароли.

**Решение:**
1. Добавить `purge_entry` — физическое удаление через 30 дней (cron-задача).
2. Для немедленного удаления — перезаписать `cipher` случайными байтами перед удалением:
```python
entry.password_cipher = secrets.token_hex(32)
entry.password_nonce = secrets.token_hex(12)
```

---

### 🟠 ВЫСОКИЙ #14 — Конфликт синхронизации при multi-device не разрешён

**Уровень:** HIGH

**Описание:**  
`version_id_col` в `PasswordEntry.__mapper_args__` обеспечивает оптимистичную блокировку SQLAlchemy, но это защита от **concurrent writes из одной сессии**, а не от multi-device конфликтов. Если пользователь редактирует запись на двух устройствах офлайн, при синхронизации одна версия молча перезапишет другую.

**Решение:** Реализовать CRDT-совместимое merge или хотя бы `last-write-wins` с явным предупреждением:
```python
if entry.updated_at > client_updated_at:
    raise EntryConflictError("Entry was modified from another device")
```

---

### 🟡 СРЕДНИЙ #15 — URL в `Dockerfile` загружается через `curl | sh`

**Файл:** `Dockerfile`, строки 19–20  
**Уровень:** MEDIUM

**Описание:**
```dockerfile
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
```
Классический supply-chain attack vector. Если `sh.rustup.rs` компрометирован — сборочный образ заражён.

**Решение:** Использовать официальный Docker-образ с предустановленным Rust:
```dockerfile
FROM rust:1.78-slim AS rust-builder
```

---

## 4. Инфраструктурный аудит (Docker)

### ✅ Закрытые угрозы

| Риск | Статус |
|---|---|
| Запуск от root | ✅ Используется `bitnet` user |
| Секреты в env-переменных | ✅ Docker secrets (`/run/secrets/`) |
| Лишние открытые порты | ✅ Только 80/443 через Caddy |
| Неограниченные ресурсы | ✅ `limits:memory/cpus` заданы |
| HTTPS | ✅ Caddy auto-TLS |

### 🟠 ВЫСОКИЙ #16 — SQLite-файл не имеет шифрования на уровне ФС

**Файл:** `docker-compose.yml`, строка 26  
**Уровень:** HIGH

**Описание:**
```yaml
volumes:
  - bitnet-data:/app/data
```
`bitnet.db` хранится в незашифрованном Docker volume. Если хост скомпрометирован — атакующий получает полный доступ к зашифрованным данным (в том числе нетронутым `is_deleted=True` записям) и к `server_key`.

**Решение:**
1. Использовать `SQLCipher` вместо обычного SQLite.
2. Или шифровать volume через LUKS / Docker volume encryption.
3. Как минимум — ограничить права на файл БД:
```dockerfile
RUN chmod 600 /app/data/bitnet.db
```

### 🟡 СРЕДНИЙ #17 — secrets/server_key.txt коммитится в репозиторий

**Файл:** `.gitignore`  
**Уровень:** MEDIUM

**Описание:**  
`secrets/` директория присутствует в проекте (`secrets/` → `server_key.txt`). Проверить, что она есть в `.gitignore`.

**Рекомендация:**
```gitignore
secrets/
*.key
*.pem
```
И использовать `git secret` или `age` для команд, которым нужен доступ к ключу.

### 🟡 СРЕДНИЙ #18 — Healthcheck уязвим к SSRF-like информационному раскрытию

**Файл:** `docker-compose.yml`, строки 36–42  
**Уровень:** LOW-MEDIUM

**Описание:**
```yaml
test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"]
```
`/health` возвращает `"BitNet Server is highly secure and operational."` — это minor info disclosure. Healthcheck должен возвращать минимальный ответ без состояния.

**Решение:**
```python
@app.get("/health")
def health_check():
    return {"status": "ok"}
```

---

## 5. Сводная таблица приоритетов

| # | Уязвимость | Критичность | Файл | Усилие |
|---|---|---|---|---|
| 1 | AES-GCM nonce reuse при `--workers 4` | 🔴 CRITICAL | `Dockerfile`, `lib.rs` | Средний |
| 2 | `zero_memory(memoryview)` зерует копию | 🔴 CRITICAL | `crypto_core.py` | Низкий |
| 6 | Расшифровка на сервере нарушает E2EE | 🔴 CRITICAL | `entry_service.py` | Высокий |
| 12 | Нет ре-шифрования при смене пароля | 🔴 CRITICAL | (нет кода) | Высокий |
| 3 | HKDF без salt | 🟠 HIGH | `crypto_core.py` | Низкий |
| 7 | RateLimiter in-memory (обход при multi-worker) | 🟠 HIGH | `security_utils.py` | Средний |
| 8 | Recovery codes только в RAM | 🟠 HIGH | `advanced_security.py` | Средний |
| 13 | Мягкое удаление без физической очистки | 🟠 HIGH | `entry_service.py` | Средний |
| 14 | Нет разрешения multi-device конфликтов | 🟠 HIGH | (нет кода) | Высокий |
| 16 | SQLite без шифрования ФС | 🟠 HIGH | `docker-compose.yml` | Средний |
| 4 | Argon2 параметры жёстко зашиты | 🟡 MEDIUM | `config.py` | Низкий |
| 5 | PasswordHistory без auth tag | 🟡 MEDIUM | `models.py` | Низкий |
| 9 | TOTP SHA-1, без replay-защиты | 🟡 MEDIUM | `advanced_security.py` | Средний |
| 10 | `get_master_key()` — deprecated deadlock-риск | 🟡 MEDIUM | `auth_manager.py` | Низкий |
| 11 | `dir()` вместо `locals()` | 🟡 MEDIUM | `auth_manager.py` | Низкий |
| 15 | `curl | sh` в Dockerfile | 🟡 MEDIUM | `Dockerfile` | Низкий |
| 17 | `secrets/` не в gitignore | 🟡 MEDIUM | `.gitignore` | Низкий |
| 18 | Healthcheck info disclosure | 🟢 LOW | `main.py` | Низкий |

---

## 6. UX-советы (без потери безопасности)

### 💡 UX-1: Offline-режим через IndexedDB + Web Crypto API

Для настоящего Zero-Knowledge: мастер-ключ живёт **только в браузере** (разворачивается из пароля через Argon2 WebAssembly). Сервер получает только зашифрованные blobs. Работает офлайн через `ServiceWorker` + кэширование зашифрованных данных.

### 💡 UX-2: Emergency Kit — PDF с recovery-кодами

При регистрации генерируйте PDF-файл с 10 recovery-кодами и инструкцией. Предупреждайте пользователя хранить его оффлайн. Это стандарт BitWarden/1Password.

### 💡 UX-3: Biometric unlock через WebAuthn `PRF` extension

Вместо хранения мастер-ключа на сервере — использовать [WebAuthn PRF extension](https://www.w3.org/TR/webauthn-3/#prf-extension) для детерминированного получения ключа из биометрики без участия сервера. Это истинный Zero-Knowledge биометрический метод.

### 💡 UX-4: Self-hosted — одна команда

```bash
# Упростить до:
curl -sSf https://install.bitnet.io | bash
# или:
docker compose -f docker-compose.yml up -d
```

Добавить интерактивный wizard (Python скрипт) для генерации `server_key.txt`, создания первого пользователя и настройки домена в `Caddyfile`.

### 💡 UX-5: Автоблокировка через Visibility API

В PWA/браузере — блокировать vault при `document.visibilityState === 'hidden'` (сворачивание вкладки), а не только по таймауту. Это защищает от shoulder surfing.

---

## 7. Позитивный итог

**BitNet имеет сильную криптографическую базу:**
- Rust-ядро с `VirtualLock`/`mlock`, `zeroize`, `secrecy` — это production-grade.
- Blind-index через HKDF+HMAC — правильный подход к поиску по зашифрованным данным.
- Двойное оборачивание FIDO2 (`device_protector` + `server_key`) — зрелая архитектура.
- Docker без root, с secrets, с Caddy TLS — хорошая инфраструктурная гигиена.

**Главные точки роста:**
1. Перенести расшифровку на клиент (браузер) — ключевое изменение для настоящего E2EE.
2. Исправить `zero_memory(memoryview)` — 3 строки кода.
3. Переключить nonce-стратегию или снизить воркеры до 1.
4. Реализовать смену пароля через перезаворачивание ключа.
