# Security Response Procedure
## Процедура реагирования на инциденты безопасности

**Версия:** 2.0.0  
**Дата:** Май 2026  
**Статус:** ✅ Обязательно для Security Team

---

## 1. Обзор

Этот документ описывает процедуру реагирования на инциденты безопасности в проекте Password Manager.

### 1.1 Контакты

| Роль | Контакт | Доступность |
|------|---------|-------------|
| Security Lead | security@example.com | 24/7 |
| BE1 (Architect) | nikita@example.com | Пн-Пт 9-18 |
| BE2 (Developer) | alexey@example.com | Пн-Пт 9-18 |
| DevOps | devops@example.com | 24/7 |

### 1.2 Каналы связи

- **Экстренно:** security@example.com (тема: [P0 SECURITY])
- **Slack:** #security-alerts
- **Telegram:** Security Team Chat

---

## 2. Классификация инцидентов

### 2.1 Уровни критичности

| Уровень | Название | Время реакции | Примеры |
|---------|----------|---------------|---------|
| **P0** | Critical | 15 минут | Активная утечка данных, SQL injection успешен |
| **P1** | High | 1 час | Брутфорс атака, DDoS |
| **P2** | Medium | 4 часа | Подозрительная активность |
| **P3** | Low | 24 часа | Единичные failed logins |

### 2.2 Критерии P0

Инцидент классифицируется как P0 если:

- [ ] Подтверждена утечка чувствительных данных
- [ ] Злоумышленник получил доступ к системе
- [ ] Критическая уязвимость эксплуатируется
- [ ] Массовая компрометация аккаунтов пользователей

---

## 3. Процедура реагирования P0

### 3.1 Этап 1: Обнаружение (0-15 минут)

**Ответственный:** Security Lead

#### Действия:

1. **Получить alert** от системы мониторинга
2. **Подтвердить инцидент**
   ```bash
   # Проверка логов
   grep "SQL injection" /var/log/app/*.log
   grep "failed login" /var/log/auth/*.log | wc -l
   ```
3. **Классифицировать инцидент** (P0/P1/P2/P3)
4. **Созвать Security Team** в Slack #security-alerts
5. **Открыть incident ticket** в Jira

#### Чеклист:

- [ ] Alert получен
- [ ] Инцидент подтверждён
- [ ] Уровень определён (P0)
- [ ] Команда собрана
- [ ] Ticket открыт

---

### 3.2 Этап 2: Изоляция (15-30 минут)

**Ответственный:** DevOps + Security Lead

#### Действия:

1. **Отключить затронутый компонент**
   ```bash
   # Пример: отключить endpoint
   kubectl scale deployment api --replicas=0
   ```
2. **Заблокировать атакующего**
   ```bash
   # Заблокировать IP
   iptables -A INPUT -s <attacker_ip> -j DROP
   ```
3. **Сохранить логи для анализа**
   ```bash
   # Копирование логов
   cp /var/log/app/*.log /var/log/incident/2026-05-01/
   ```
4. **Уведомить стейкхолдеров**

#### Чеклист:

- [ ] Компонент отключён
- [ ] IP заблокирован
- [ ] Логи сохранены
- [ ] Стейкхолдеры уведомлены

---

### 3.3 Этап 3: Анализ (30 минут - 2 часа)

**Ответственный:** Security Lead + BE1

#### Действия:

1. **Собрать доказательства**
   - Логи атак
   - Сетевые пакеты (если есть)
   - Access logs
2. **Определить масштаб**
   - Сколько пользователей затронуто
   - Какие данные скомпрометированы
   - Как долго длилась атака
3. **Найти корневую причину**
   ```
   5 Whys technique:
   1. Почему произошла утечка? → SQL injection
   2. Почему SQL injection возможен? → Raw SQL в коде
   3. Почему raw SQL использовался? → Code review не прошёл
   4. Почему code review не прошёл? → Срочный релиз
   5. Почему срочный релиз без review? → Процесс не соблюдён
   ```
4. **Документировать находки**

#### Чеклист:

- [ ] Доказательства собраны
- [ ] Масштаб определён
- [ ] Корневая причина найдена
- [ ] Находки задокументированы

---

### 3.4 Этап 4: Устранение (2-4 часа)

**Ответственный:** BE1 + BE2

#### Действия:

1. **Разработать патч**
   ```python
   # Пример исправления SQL injection
   # До:
   query = f"SELECT * FROM users WHERE id = {user_id}"
   
   # После:
   query = text("SELECT * FROM users WHERE id = :id")
   result = db.execute(query, {"id": user_id})
   ```
2. **Протестировать патч**
   ```bash
   # Security тесты
   pytest backend/tests/test_security_dynamic.py -v
   
   # Bandit scan
   bandit -r backend/ -ll
   ```
3. **Code Review** (ускоренный)
   - Security Lead approves
   - BE1 approves
4. **Задеплоить патч**
   ```bash
   git checkout hotfix/security-patch
   git push origin hotfix/security-patch
   # CI/CD deploy to production
   ```

#### Чеклист:

- [ ] Патч разработан
- [ ] Тесты прошли
- [ ] Code Review завершён
- [ ] Патч задеплоен

---

### 3.5 Этап 5: Восстановление (4-6 часов)

**Ответственный:** DevOps + Security Lead

#### Действия:

1. **Включить компонент**
   ```bash
   kubectl scale deployment api --replicas=3
   ```
2. **Мониторить активность**
   ```bash
   # Проверка на аномалии
   tail -f /var/log/app/*.log | grep -i "error\|warning"
   ```
3. **Ротация ключей** (если компрометированы)
   ```bash
   # Перегенерировать master keys
   python manage.py rotate_keys --all-users
   ```
4. **Сброс сессий** (если нужно)
   ```bash
   # Invalidate all sessions
   python manage.py invalidate_sessions --all
   ```
5. **Уведомить пользователей** (если затронуты)

#### Чеклист:

- [ ] Компонент включён
- [ ] Мониторинг активен
- [ ] Ключи ротированы
- [ ] Сессии сброшены
- [ ] Пользователи уведомлены

---

### 3.6 Этап 6: Post-Mortem (24-48 часов)

**Ответственный:** Security Lead

#### Действия:

1. **Написать post-mortem отчёт**
2. **Провести retrospective встречу**
3. **Создать action items**
4. **Обновить процедуры**

#### Шаблон Post-Mortem:

```markdown
# Post-Mortem: [Incident Name]

## Дата и время
- Start: 2026-05-01 14:30 UTC
- End: 2026-05-01 20:45 UTC
- Duration: 6 hours 15 minutes

## Impact
- Users affected: 1,234
- Data compromised: Passwords, emails
- Revenue impact: $0 (no direct impact)

## Root Cause
SQL injection vulnerability in entry_service.py

## Timeline
- 14:30 - Alert received
- 14:35 - Incident confirmed (P0)
- 14:45 - Team assembled
- 15:00 - Component isolated
- 17:00 - Root cause identified
- 19:00 - Patch deployed
- 20:00 - Service restored
- 20:45 - Incident closed

## Action Items
- [ ] Fix all SQL injection vulnerabilities (BE2, due: 2026-05-08)
- [ ] Add automated SQL injection tests (BE1, due: 2026-05-15)
- [ ] Update code review checklist (Security Lead, due: 2026-05-03)
```

#### Чеклист:

- [ ] Post-Mortem написан
- [ ] Retrospective проведена
- [ ] Action items созданы
- [ ] Процедуры обновлены

---

## 4. Процедура реагирования P1

### 4.1 Время реакции: 1 час

#### Действия:

1. **Получить alert**
2. **Подтвердить инцидент**
3. **Применить rate limiting**
4. **Заблокировать IP если нужно**
5. **Задокументировать инцидент**

### 4.2 Пример: Брутфорс атака

```bash
# Обнаружение
grep "failed login" /var/log/auth/*.log | \
    awk '{print $1}' | sort | uniq -c | sort -rn | head -10

# Блокировка
for ip in $(cat attackers.txt); do
    iptables -A INPUT -s $ip -j DROP
done

# Rate limiting
python manage.py enable_rate_limit --strict
```

---

## 5. Процедура реагирования P2

### 5.1 Время реакции: 4 часа

#### Действия:

1. **Задокументировать активность**
2. **Добавить в monitoring dashboard**
3. **Уведомить Security Lead**
4. **Создать ticket для анализа**

### 5.2 Пример: Подозрительная активность

```bash
# Проверка паттернов
python analyze_logs.py --suspicious --date 2026-05-01

# Добавление в мониторинг
grafana-cli dashboard import --name "Suspicious Activity"
```

---

## 6. Процедура реагирования P3

### 6.1 Время реакции: 24 часа

#### Действия:

1. **Задокументировать в логах**
2. **Создать ticket**
3. **Назначить на разработчика**
4. **Закрыть после анализа**

### 6.2 Пример: Единичные failed logins

```bash
# Просто логируем
logger.info(f"Failed login attempt for user {user_id}")

# Создаём ticket
jira create --project SEC --type "Security Review" \
    --summary "Failed login attempts for user123"
```

---

## 7. Инструменты

### 7.1 Мониторинг

| Инструмент | Назначение | URL |
|------------|------------|-----|
| Grafana | Dashboards | https://grafana.example.com |
| Prometheus | Metrics | https://prometheus.example.com |
| ELK Stack | Log analysis | https://kibana.example.com |

### 7.2 Alerting

| Канал | Уровень | Настройка |
|-------|---------|-----------|
| PagerDuty | P0 | 24/7 on-call |
| Slack | P0-P1 | #security-alerts |
| Email | P2-P3 | security@example.com |

### 7.3 Security Tools

| Инструмент | Назначение | Команда |
|------------|------------|---------|
| Bandit | Static analysis | `bandit -r backend/ -ll` |
| Safety | Dependency check | `safety check -r requirements.txt` |
| pytest | Security tests | `pytest test_security_dynamic.py` |

---

## 8. Тренировки

### 8.1 Регулярные учения

| Тип | Частота | Участники | Длительность |
|-----|---------|-----------|--------------|
| Tabletop exercise | Ежемесячно | Security Team | 2 часа |
| Full simulation | Ежеквартально | All Team | 4 часа |
| External audit | Ежегодно | Third party | 1 неделя |

### 8.2 Сценарии для тренировок

1. **SQL Injection Attack**
2. **Brute Force Attack**
3. **Data Exfiltration**
4. **DDoS Attack**
5. **Insider Threat**

---

## 9. Приложения

### A. Template: Security Incident Report

```markdown
# Security Incident Report

## Incident ID
SEC-2026-001

## Classification
- [ ] P0 - Critical
- [ ] P1 - High
- [ ] P2 - Medium
- [ ] P3 - Low

## Description
[Brief description of the incident]

## Impact
- Users affected: X
- Data compromised: [List]
- Business impact: [Description]

## Timeline
- [Time] - Event 1
- [Time] - Event 2
- ...

## Root Cause
[Root cause analysis]

## Remediation
[Actions taken]

## Prevention
[Future prevention measures]

## Action Items
- [ ] Item 1 (Owner, Due Date)
- [ ] Item 2 (Owner, Due Date)
```

### B. Template: Security Advisory

```markdown
# Security Advisory

## Advisory ID
SA-2026-001

## Date
2026-05-01

## Severity
- [ ] Critical
- [ ] High
- [ ] Medium
- [ ] Low

## Affected Versions
- v1.0.0 - v1.9.9

## Description
[Description of vulnerability]

## Impact
[Potential impact if exploited]

## Mitigation
[Steps to mitigate]

## Patch
[Link to patch/upgrade]

## Credits
[Who reported/fixed]
```

---

**Документ утверждён:**  
Никита (BE1) — Security Lead

**Дата:** Май 2026  
**Следующий пересмотр:** Август 2026

**Статус:** ✅ APPROVED FOR PRODUCTION v2.0.0

