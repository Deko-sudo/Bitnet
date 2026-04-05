# Bug Bounty Program
## Программа вознаграждения за обнаружение уязвимостей

**Версия:** 1.0  
**Дата:** Май 2026  
**Статус:** ✅ ACTIVE

---

## 1. Обзор

Password Manager запускает программу Bug Bounty для поощрения исследователей безопасности за обнаружение и ответственное раскрытие уязвимостей.

---

## 2. Правила программы

### 2.1 Eligible уязвимости

| Категория | Включено | Примеры |
|-----------|----------|---------|
| **Cryptographic** | ✅ Да | Слабые алгоритмы, weak keys |
| **Authentication** | ✅ Да | Bypass, privilege escalation |
| **Authorization** | ✅ Да | Access control bypass |
| **Data Protection** | ✅ Да | Data leakage, encryption issues |
| **Session Management** | ✅ Да | Session fixation, hijacking |
| **Input Validation** | ✅ Да | SQL injection, XSS, RCE |

### 2.2 Not Eligible уязвимости

| Категория | Включено | Описание |
|-----------|----------|----------|
| **Low severity** | ❌ Нет | Missing security headers (без эксплуатации) |
| **Theoretical** | ❌ Нет | Уязвимости без proof-of-concept |
| **Social engineering** | ❌ Нет | Фишинг, физический доступ |
| **DoS** | ❌ Нет | DDoS, resource exhaustion |
| **Third-party** | ❌ Нет | Уязвимости в зависимостях (сообщите им) |
| **Already known** | ❌ Нет | Публичные уязвимости |

---

## 3. Rewards

### 3.1 Reward таблица

| Severity | CVSS Range | Reward | Примеры |
|----------|------------|--------|---------|
| **Critical** | 9.0-10.0 | $5,000 - $10,000 | RCE, SQL injection, auth bypass |
| **High** | 7.0-8.9 | $2,000 - $5,000 | XSS, CSRF, privilege escalation |
| **Medium** | 4.0-6.9 | $500 - $2,000 | Information disclosure |
| **Low** | 0.1-3.9 | $50 - $500 | Minor security issues |

### 3.2 Reward критерии

| Фактор | Влияние | Описание |
|--------|---------|----------|
| **Severity** | High | Более серьёзные уязвимости = больше reward |
| **Impact** | High | Больше受影响ных пользователей = больше reward |
| **Quality** | Medium | Детальный report = bonus |
| **First report** | High | Только первый репортёр получает reward |
| **Fix contribution** | Medium | Если предлагаете fix = bonus |

### 3.3 Bonus multipliers

| Bonus | Multiplier | Описание |
|-------|------------|----------|
| **Detailed PoC** | +20% | Полный proof-of-concept |
| **Fix suggestion** | +10% | Предложение по исправлению |
| **Multiple issues** | +5% each | За каждую дополнительную уязвимость |
| **Responsible disclosure** | +10% | Соблюдение правил disclosure |

---

## 4. Process

### 4.1 Submission process

```
1. Обнаружение уязвимости
   ↓
2. Подготовка отчёта
   ↓
3. Отправка на security@example.com
   ↓
4. Confirmation (в течение 48 часов)
   ↓
5. Triage и assessment (7 дней)
   ↓
6. Fix development (14-30 дней)
   ↓
7. Fix deployment
   ↓
8. Public disclosure (после fix)
   ↓
9. Reward payment (в течение 30 дней)
```

### 4.2 Report template

```markdown
# Vulnerability Report

## Summary
[Brief description of the vulnerability]

## Severity
- [ ] Critical
- [ ] High
- [ ] Medium
- [ ] Low

## Affected Version
[e.g., v2.0.0]

## Steps to Reproduce
1. Step 1
2. Step 2
3. Step 3

## Proof of Concept
[Code, screenshots, videos]

## Impact
[What can an attacker do?]

## Suggested Fix
[Optional: Your suggestion]

## Contact Information
- Name: [Your name]
- Email: [Your email]
- Twitter: [Optional]
- Website: [Optional]
```

### 4.3 Timeline

| Этап | Время | Описание |
|------|-------|----------|
| **Acknowledgement** | 48 часов | Подтверждение получения |
| **Triage** | 7 дней | Оценка severity |
| **Fix** | 14-30 дней | Разработка исправления |
| **Disclosure** | После fix | Публичное раскрытие |
| **Payment** | 30 дней после disclosure | Выплата reward |

---

## 5. Disclosure Policy

### 5.1 Responsible Disclosure

**Исследователи должны:**
- ✅ Предоставить достаточно времени на fix до публикации
- ✅ Не эксплуатировать уязвимость за пределами тестирования
- ✅ Не раскрывать данные пользователей
- ✅ Сотрудничать с командой безопасности

**Команда Password Manager должна:**
- ✅ Ответить в течение 48 часов
- ✅ Предоставить timeline для fix
- ✅ Обновлять исследователя о прогрессе
- ✅ Выплатить reward вовремя

### 5.2 Public Disclosure

**После fix:**
- Исследователь может опубликовать детали уязвимости
- Password Manager опубликует security advisory
- Исследователь будет указан в credits (если желает)

**Без fix:**
- Если fix не предоставлен в течение 90 дней, исследователь может опубликовать
- Password Manager опубликует advisory с warning

---

## 6. Legal

### 6.1 Safe Harbor

**Исследователи защищены если:**
- ✅ Действуют в рамках этой программы
- ✅ Не нарушают законы
- ✅ Не причиняют вред пользователям
- ✅ Сотрудничают с командой безопасности

**Не защищено:**
- ❌ Нарушение законов
- ❌ Кража данных
- ❌ Причинение вреда
- ❌ Нарушение privacy пользователей

### 6.2 Confidentiality

**Исследователи соглашаются:**
- Не раскрывать детали уязвимости до fix
- Не использовать уязвимость в коммерческих целях
- Не передавать информацию третьим лицам

### 6.3 Liability

**Password Manager не несёт ответственности за:**
- Косвенные убытки исследователя
- Потерю данных при тестировании
- Юридические последствия в вашей юрисдикции

---

## 7. Hall of Fame

### 7.1 Top Researchers

| Rank | Researcher | Issues Found | Total Rewards |
|------|------------|--------------|---------------|
| 🥇 | [TBA] | 0 | $0 |
| 🥈 | [TBA] | 0 | $0 |
| 🥉 | [TBA] | 0 | $0 |

### 7.2 Recent Disclosures

| Date | Researcher | Severity | Issue |
|------|------------|----------|-------|
| [TBA] | [TBA] | [TBA] | [TBA] |

*Hall of Fame будет обновляться после первого disclosure*

---

## 8. FAQ

### Q: Кто может участвовать?
**A:** Любой исследователь безопасности 18+.

### Q: Могу ли я тестировать на production?
**A:** Нет, используйте staging environment.

### Q: Сколько времени занимает выплата?
**A:** В течение 30 дней после public disclosure.

### Q: Могу ли я остаться анонимным?
**A:** Да, мы уважаем анонимность исследователей.

### Q: Что если я не согласен с severity оценкой?
**A:** Можно обсудить с командой безопасности.

### Q: Могу ли я получить credit без reward?
**A:** Да, укажите это в отчёте.

---

## 9. Контакты

### 9.1 Security Team

| Канал | Использование |
|-------|---------------|
| **Email** | security@example.com |
| **PGP Key** | [TBA] |
| **Twitter** | @PasswordManagerSec |

### 9.2 Response Time

| Тип | Время |
|-----|-------|
| **Initial response** | 48 часов |
| **Triage complete** | 7 дней |
| **Fix deployed** | 14-30 дней |

---

## 10. Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | Май 2026 | Initial release |

---

## 11. Приложения

### A. Example Vulnerability Reports

#### Critical: SQL Injection

```markdown
# Vulnerability Report

## Summary
SQL Injection in search_entries endpoint allows arbitrary SQL execution.

## Severity
- [x] Critical

## Affected Version
v2.0.0

## Steps to Reproduce
1. Login as normal user
2. Send POST to /api/search with payload: {"search": "' OR '1'='1"}
3. Observe all entries returned

## Proof of Concept
```bash
curl -X POST https://api.password-manager.example.com/search \
  -H "Authorization: Bearer <token>" \
  -d '{"search": "\' OR \'1\'=\'1"}'
```

## Impact
Attacker can access all user entries, bypass authentication.

## Suggested Fix
Use parameterized queries instead of string concatenation.
```

#### High: XSS in Entry Title

```markdown
# Vulnerability Report

## Summary
Stored XSS in entry title field allows script injection.

## Severity
- [x] High

## Affected Version
v2.0.0

## Steps to Reproduce
1. Create new entry with title: `<script>alert('XSS')</script>`
2. View entry list
3. Script executes

## Proof of Concept
[Screenshot/Video]

## Impact
Attacker can steal session tokens, perform actions as user.

## Suggested Fix
Sanitize input, use Content-Security-Policy header.
```

### B. Reward Payment Methods

| Method | Regions | Processing Time |
|--------|---------|-----------------|
| **Bank Transfer** | Global | 5-10 business days |
| **PayPal** | Most countries | 1-3 business days |
| **Bitcoin** | Global | 1-2 business days |
| **Bugcrowd/HackerOne** | Global | Via platform |

---

**Программа утверждена:**  
Никита (BE1) — Security Lead

**Дата:** Май 2026  
**Статус:** ✅ ACTIVE

**Следующий пересмотр:** Ноябрь 2026
