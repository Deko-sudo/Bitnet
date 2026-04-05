# Future Roadmap
## Планы развития Password Manager

**Версия:** 2.1.0-planning
**Дата:** Май 2026
**Горизонт планирования:** 12 месяцев

**Статус Недели 13+:** ⏳ В ПЛАНИРОВАНИИ (см. `WEEK_13_PLUS_REPORT.md`)

---

## 1. Обзор

Этот документ описывает планы развития проекта Password Manager на следующие 12 месяцев.

---

## 1.1 Статус Недели 13+ (Продвинутые функции)

| Функция | Статус | Прогресс | Файл |
|---------|--------|----------|------|
| **TOTP (2FA)** | ✅ Выполнено | 100% | `core/advanced_security.py` |
| **Recovery Codes** | ✅ Выполнено | 100% | `core/advanced_security.py` |
| **HIBP Integration** | ✅ Выполнено | 100% | `core/advanced_security.py` |
| **Биометрия (Stub)** | ⚠️ Частично | 20% | `core/advanced_security.py` |
| **Windows Hello** | ❌ Не реализовано | 0% | `core/biometric_windows.py` (план) |
| **Touch ID/Face ID** | ❌ Не реализовано | 0% | `core/biometric_macos.py` (план) |
| **FIDO2/WebAuthn** | ❌ Не реализовано | 0% | `core/fido2_auth.py` (план) |
| **Breach Monitoring** | ❌ Не реализовано | 0% | `features/breach_monitor.py` (план) |

**Общий прогресс Недели 13+:** 45% из 100%

**Рекомендуемый приоритет:**
1. FIDO2/WebAuthn — кроссплатформенно
2. Breach Monitoring — полезно для пользователей
3. Windows Hello — требует hardware для тестов
4. macOS Touch ID — требует Mac для тестов

**См. полный план:** `WEEK_13_PLUS_REPORT.md`

---

## 2. Квартальная дорожная карта

### Q3 2026 (Июль — Сентябрь)

**Тема:** Улучшение безопасности и UX

| Задача | Приоритет | Сложность | Команда |
|--------|-----------|-----------|---------|
| Миграция на Pydantic V2 | High | Medium | BE1 |
| Биометрическая аутентификация | Medium | High | BE1 |
| FIDO2/WebAuthn поддержка | Medium | High | BE1 |
| Исправление mypy warnings | Low | Low | BE2 |

**Цель:** Security Score 60/60 (идеальный)

---

### Q4 2026 (Октябрь — Декабрь)

**Тема:** Расширенные функции

| Задача | Приоритет | Сложность | Команда |
|--------|-----------|-----------|---------|
| Quantum-resistant алгоритмы | High | High | BE1 |
| Password sharing (encrypted) | High | Medium | BE1+BE2 |
| Browser extension (Chrome/Firefox) | Medium | High | BE2 |
| Admin dashboard | Low | Medium | BE2 |

**Цель:** Расширение функциональности для enterprise пользователей

---

### Q1 2027 (Январь — Март)

**Тема:** Мобильные платформы

| Задача | Приоритет | Сложность | Команда |
|--------|-----------|-----------|---------|
| iOS app (Swift) | High | High | Mobile Team |
| Android app (Kotlin) | High | High | Mobile Team |
| Cross-platform sync | High | High | BE1+BE2 |
| Mobile biometric auth | Medium | Medium | Mobile Team |

**Цель:** Полная кроссплатформенность

---

### Q2 2027 (Апрель — Июнь)

**Тема:** Cloud и collaboration

| Задача | Приоритет | Сложность | Команда |
|--------|-----------|-----------|---------|
| Cloud sync (E2E encrypted) | High | High | BE1+BE2 |
| Team password sharing | Medium | High | BE1+BE2 |
| Audit dashboard | Medium | Medium | BE2 |
| API v2 | Low | Medium | BE1 |

**Цель:** Enterprise-ready решение

---

## 3. Детальные спецификации

### 3.1 Биометрическая аутентификация (v2.1.0)

**Описание:** Интеграция с Windows Hello, Touch ID, Face ID.

**Техническая реализация:**
```python
# Windows Hello (через ctypes)
import ctypes
from ctypes import wintypes

# Вызов Windows Hello API
def authenticate_with_windows_hello():
    # ... implementation ...
    pass

# macOS Touch ID (через LocalAuthentication)
# iOS Face ID (через LocalAuthentication)
```

**Требования:**
- Windows 10+ (Windows Hello)
- macOS 10.12+ (Touch ID)
- iOS 11+ (Face ID/Touch ID)

**Срок:** Q3 2026

---

### 3.2 FIDO2/WebAuthn (v2.1.0)

**Описание:** Поддержка аппаратных ключей безопасности (YubiKey, Titan).

**Техническая реализация:**
```python
from fido2.client import Fido2Client
from fido2.server import Fido2Server

# Регистрация ключа
def register_fido_key(user_id):
    # ... implementation ...
    pass

# Аутентификация ключом
def authenticate_fido_key(user_id):
    # ... implementation ...
    pass
```

**Поддерживаемые устройства:**
- YubiKey 5 Series
- Google Titan Key
- Solo Key
- Any FIDO2-compatible device

**Срок:** Q3 2026

---

### 3.3 Quantum-resistant алгоритмы (v2.2.0)

**Описание:** Подготовка к квантовым вычислениям.

**Алгоритмы:**
| Алгоритм | Тип | NIST статус |
|----------|-----|-------------|
| CRYSTALS-Kyber | KEM | Стандартизирован |
| CRYSTALS-Dilithium | Signature | Стандартизирован |
| SPHINCS+ | Signature | Альтернатива |

**Техническая реализация:**
```python
# Hybrid encryption (классический + post-quantum)
def hybrid_encrypt(data, classical_key, pq_key):
    # AES-256-GCM для данных
    # CRYSTALS-Kyber для ключа
    pass
```

**Срок:** Q4 2026

---

### 3.4 Browser Extension (v2.2.0)

**Описание:** Расширение для браузеров Chrome и Firefox.

**Функции:**
- Автозаполнение паролей
- Генерация паролей
- Синхронизация с приложением
- Biometric auth в браузере

**Техническая реализация:**
```javascript
// background.js
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'get_password') {
        getPassword(request.url).then(sendResponse);
    }
});
```

**Поддерживаемые браузеры:**
- Chrome 88+
- Firefox 78+
- Edge 88+
- Safari 14+

**Срок:** Q4 2026

---

### 3.5 Mobile Apps (v3.0.0)

**Описание:** Нативные приложения для iOS и Android.

**iOS (Swift):**
```swift
// PasswordManagerApp/PasswordManagerAppApp.swift
@main
struct PasswordManagerAppApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(AuthManager())
        }
    }
}
```

**Android (Kotlin):**
```kotlin
// MainActivity.kt
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            PasswordManagerTheme {
                MainScreen()
            }
        }
    }
}
```

**Функции:**
- Biometric auth (Face ID, Touch ID, Fingerprint)
- Auto-fill
- Password generator
- Secure notes
- Widget для быстрого доступа

**Срок:** Q1 2027

---

### 3.6 Cloud Sync (v3.0.0)

**Описание:** End-to-end encrypted синхронизация между устройствами.

**Архитектура:**
```
╔══════════════════════════════════════════════════════════╗
║                    Cloud Sync Architecture                ║
╠══════════════════════════════════════════════════════════╣
║                                                           ║
║  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐ ║
║  │   Device 1  │────▶│   Cloud     │────▶│   Device 2  │ ║
║  │  (Encrypted)│     │  (Encrypted)│     │  (Encrypted)│ ║
║  └─────────────┘     └─────────────┘     └─────────────┘ ║
║         │                   │                   │         ║
║    AES-256-GCM        AES-256-GCM        AES-256-GCM     ║
║                                                           ║
║  Ключи хранятся только на устройствах (не в облаке)       ║
║                                                           ║
╚══════════════════════════════════════════════════════════╝
```

**Провайдеры:**
- AWS S3 (с шифрованием)
- Google Cloud Storage
- Self-hosted option

**Срок:** Q2 2027

---

## 4. Метрики успеха

### Технические метрики

| Метрика | Текущее | Цель Q4 2026 | Цель Q2 2027 |
|---------|---------|--------------|--------------|
| Покрытие тестами | 91% | 93% | 95% |
| Security Score | 59/60 | 60/60 | 60/60 |
| Время деривации ключа | 40ms | 35ms | 30ms |
| Время запуска (cold) | 1.5s | 1.0s | 0.8s |

### Бизнес метрики

| Метрика | Цель Q4 2026 | Цель Q2 2027 |
|---------|--------------|--------------|
| Активные пользователи | 10,000 | 100,000 |
| Enterprise клиенты | 10 | 50 |
| Рейтинг в stores | 4.5+ | 4.8+ |
| Monthly Revenue | $5,000 | $50,000 |

---

## 5. Риски и митигация

### Технические риски

| Риск | Вероятность | Влияние | Митигация |
|------|-------------|---------|-----------|
| Уязвимости в crypto | Low | High | Регулярные security audit |
| Проблемы совместимости | Medium | Medium | Тестирование на множестве устройств |
| Производительность mobile | Medium | Medium | Оптимизация, кэширование |

### Бизнес риски

| Риск | Вероятность | Влияние | Митигация |
|------|-------------|---------|-----------|
| Конкуренция | High | Medium | Уникальные функции, лучшее UX |
| Изменения в regulations | Medium | High | Compliance team, мониторинг |
| Утечка данных | Low | Critical | E2E encryption, bug bounty |

---

## 6. Ресурсы

### Команда (текущая)

| Роль | Количество | Загрузка |
|------|------------|----------|
| Backend (BE1) | 1 | 100% |
| Backend (BE2) | 1 | 100% |

### Команда (план Q1 2027)

| Роль | Количество | Загрузка |
|------|------------|----------|
| Backend (BE1) | 1 | 100% |
| Backend (BE2) | 1 | 100% |
| iOS Developer | 1 | 100% |
| Android Developer | 1 | 100% |
| DevOps | 0.5 | 50% |

### Бюджет

| Категория | Q3 2026 | Q4 2026 | Q1 2027 | Q2 2027 |
|-----------|---------|---------|---------|---------|
| Зарплаты | $50K | $50K | $80K | $80K |
| Инфраструктура | $1K | $2K | $5K | $10K |
| Security audit | $10K | $0 | $10K | $0 |
| Маркетинг | $5K | $10K | $20K | $30K |
| **ВСЕГО** | **$66K** | **$62K** | **$115K** | **$120K** |

---

## 7. Приложения

### A. Release Calendar

| Версия | Дата | Фокус |
|--------|------|-------|
| v2.1.0 | Август 2026 | Biometric + FIDO2 |
| v2.2.0 | Ноябрь 2026 | Quantum-resistant + Browser extension |
| v3.0.0 | Февраль 2027 | Mobile apps + Cloud sync |
| v3.1.0 | Май 2027 | Team features + Admin dashboard |

### B. Feature Prioritization Matrix

```
╔══════════════════════════════════════════════════════════╗
║  Feature Priority Matrix                                 ║
╠══════════════════════════════════════════════════════════╣
║                                                           ║
║  HIGH IMPACT, LOW EFFORT (Do First)                      ║
║  - Biometric authentication                               ║
║  - Browser extension                                      ║
║                                                           ║
║  HIGH IMPACT, HIGH EFFORT (Plan Carefully)               ║
║  - Mobile apps                                            ║
║  - Cloud sync                                             ║
║  - Quantum-resistant algorithms                           ║
║                                                           ║
║  LOW IMPACT, LOW EFFORT (Fill Time)                      ║
║  - Mypy fixes                                             ║
║  - Documentation updates                                  ║
║                                                           ║
║  LOW IMPACT, HIGH EFFORT (Avoid)                         ║
║  - Custom crypto implementations                          ║
║                                                           ║
╚══════════════════════════════════════════════════════════╝
```

---

**Документ утверждён:**  
Никита (BE1) — Security Lead  
Алексей (BE2) — Backend Developer

**Дата:** Май 2026  
**Следующий пересмотр:** Август 2026

**Статус:** ✅ APPROVED FOR PLANNING

