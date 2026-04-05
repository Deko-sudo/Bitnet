# Deployment Security Guide
## Руководство по безопасному развёртыванию

**Версия:** 2.0.0  
**Дата:** Май 2026  
**Статус:** ✅ Обязательно для DevOps

---

## 1. Обзор

Этот документ описывает требования безопасности для развёртывания Password Manager в production.

---

## 2. Требования к инфраструктуре

### 2.1 Минимальные требования

| Компонент | Требование | Примечание |
|-----------|------------|------------|
| **CPU** | 4 cores | Для Argon2id вычислений |
| **RAM** | 8 GB | 64MB на процесс Argon2id |
| **Storage** | SSD | Для быстрой работы SQLite |
| **Network** | 1 Gbps | Для HTTPS трафика |

### 2.2 Рекомендуемые требования

| Компонент | Требование | Примечание |
|-----------|------------|------------|
| **CPU** | 8 cores | Для высокой нагрузки |
| **RAM** | 16 GB | Для кэширования |
| **Storage** | NVMe SSD | Для максимальной скорости |
| **Network** | 10 Gbps | Для DDoS устойчивости |

---

## 3. Безопасность ОС

### 3.1 Linux Hardening

```bash
# Обновление системы
apt update && apt upgrade -y

# Установка firewall
apt install ufw -y
ufw default deny incoming
ufw default allow outgoing
ufw allow 443/tcp  # HTTPS only
ufw enable

# Отключение root login
sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
systemctl restart sshd

# Установка fail2ban
apt install fail2ban -y
systemctl enable fail2ban
systemctl start fail2ban

# Настройка audit logging
apt install auditd -y
systemctl enable auditd
systemctl start auditd
```

### 3.2 Windows Hardening

```powershell
# Включение Windows Firewall
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# Отключение SMBv1 (уязвимость)
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol

# Включение BitLocker
Enable-BitLocker -MountPoint "C:" -EncryptionMethod Aes256

# Настройка Windows Update
Set-Service wuauserv -StartupType Automatic
Start-Service wuauserv
```

---

## 4. Безопасность сети

### 4.1 HTTPS конфигурация

```nginx
# /etc/nginx/sites-available/password-manager

server {
    listen 80;
    server_name password-manager.example.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name password-manager.example.com;
    
    # SSL сертификаты (Let's Encrypt)
    ssl_certificate /etc/letsencrypt/live/password-manager.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/password-manager.example.com/privkey.pem;
    
    # TLS настройки
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_stapling on;
    ssl_stapling_verify on;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=63072000" always;
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Content-Security-Policy "default-src 'self'";
    add_header Referrer-Policy "strict-origin-when-cross-origin";
    
    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req zone=api burst=20 nodelay;
    
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### 4.2 Firewall правила

```bash
# iptables правила
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT  # HTTPS
iptables -A INPUT -p tcp --dport 22 -j ACCEPT   # SSH (ограничить по IP)
iptables -A INPUT -j DROP

# Сохранение правил
iptables-save > /etc/iptables/rules.v4
```

---

## 5. Безопасность приложения

### 5.1 Переменные окружения

```bash
# /etc/password-manager/.env

# Приложение
APP_ENV=production
APP_DEBUG=false
APP_SECRET_KEY=<32-byte-random-hex>

# База данных
DATABASE_URL=sqlite:///var/lib/password-manager/data.db

# Криптография
MASTER_SALT=<32-byte-random-hex>
ENCRYPTION_KEY=<32-byte-random-hex>

# Rate limiting
RATE_LIMIT_MAX_ATTEMPTS=5
RATE_LIMIT_WINDOW=60
RATE_LIMIT_BLOCK=1800

# Логирование
LOG_LEVEL=WARNING
LOG_FILE=/var/log/password-manager/app.log

# Аудит
AUDIT_LOG_ENABLED=true
AUDIT_LOG_FILE=/var/log/password-manager/audit.log
```

### 5.2 Systemd service

```ini
# /etc/systemd/system/password-manager.service

[Unit]
Description=Password Manager API
After=network.target

[Service]
Type=exec
User=password-manager
Group=password-manager
WorkingDirectory=/opt/password-manager
EnvironmentFile=/etc/password-manager/.env
ExecStart=/opt/password-manager/venv/bin/uvicorn backend.api.main:app \
    --host 127.0.0.1 \
    --port 8000 \
    --workers 4

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/password-manager /var/log/password-manager

# Restart policy
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

---

## 6. Безопасность базы данных

### 6.1 SQLite настройки

```python
# database.py

from sqlalchemy import create_engine

# Production настройки
engine = create_engine(
    'sqlite:///var/lib/password-manager/data.db',
    connect_args={
        'timeout': 30,
        'check_same_thread': False,
    },
    pool_pre_ping=True,
    pool_recycle=3600,
)

# Включение WAL режима для производительности
from sqlalchemy import text
with engine.connect() as conn:
    conn.execute(text("PRAGMA journal_mode=WAL"))
    conn.execute(text("PRAGMA synchronous=NORMAL"))
    conn.execute(text("PRAGMA cache_size=10000"))
    conn.execute(text("PRAGMA temp_store=MEMORY"))
    conn.commit()
```

### 6.2 Бэкапы

```bash
#!/bin/bash
# /opt/password-manager/scripts/backup.sh

BACKUP_DIR="/var/backups/password-manager"
DATE=$(date +%Y%m%d_%H%M%S)
DB_FILE="/var/lib/password-manager/data.db"

# Создание бэкапа
sqlite3 "$DB_FILE" ".backup '$BACKUP_DIR/backup_$DATE.db'"

# Шифрование бэкапа
openssl enc -aes-256-cbc -salt -pbkdf2 \
    -in "$BACKUP_DIR/backup_$DATE.db" \
    -out "$BACKUP_DIR/backup_$DATE.db.enc" \
    -pass file:/etc/password-manager/backup.key

# Удаление незашифрованного бэкапа
rm "$BACKUP_DIR/backup_$DATE.db"

# Удаление старых бэкапов (>30 дней)
find "$BACKUP_DIR" -name "*.db.enc" -mtime +30 -delete

# Логирование
echo "[$(date)] Backup completed: backup_$DATE.db.enc" >> /var/log/password-manager/backup.log
```

```ini
# /etc/systemd/system/password-manager-backup.timer

[Unit]
Description=Daily Password Manager Backup

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

---

## 7. Мониторинг и логирование

### 7.1 Логирование

```python
# logging_config.py

import logging
from logging.handlers import RotatingFileHandler
import os

def setup_logging():
    # Создание директории для логов
    os.makedirs('/var/log/password-manager', exist_ok=True)
    
    # App logger
    app_logger = logging.getLogger('password_manager')
    app_logger.setLevel(logging.WARNING)  # WARNING в production
    
    handler = RotatingFileHandler(
        '/var/log/password-manager/app.log',
        maxBytes=10*1024*1024,  # 10 MB
        backupCount=5
    )
    handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    ))
    app_logger.addHandler(handler)
    
    # Audit logger (отдельный файл)
    audit_logger = logging.getLogger('password_manager.audit')
    audit_logger.setLevel(logging.INFO)
    
    audit_handler = RotatingFileHandler(
        '/var/log/password-manager/audit.log',
        maxBytes=50*1024*1024,  # 50 MB
        backupCount=10
    )
    audit_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    ))
    audit_logger.addHandler(audit_handler)
    
    # Security logger (критичные события)
    security_logger = logging.getLogger('password_manager.security')
    security_logger.setLevel(logging.CRITICAL)
    
    security_handler = RotatingFileHandler(
        '/var/log/password-manager/security.log',
        maxBytes=10*1024*1024,
        backupCount=10
    )
    security_handler.setFormatter(logging.Formatter(
        '%(asctime)s - CRITICAL - %(message)s'
    ))
    security_logger.addHandler(security_handler)
```

### 7.2 Prometheus метрики

```python
# metrics.py

from prometheus_client import Counter, Histogram, Gauge

# Метрики
REQUEST_COUNT = Counter(
    'http_requests_total',
    'Total HTTP requests',
    ['method', 'endpoint', 'status']
)

REQUEST_LATENCY = Histogram(
    'http_request_duration_seconds',
    'HTTP request latency',
    ['method', 'endpoint']
)

ACTIVE_USERS = Gauge(
    'active_users',
    'Number of active users'
)

FAILED_LOGINS = Counter(
    'failed_logins_total',
    'Total failed login attempts',
    ['user_id']
)

ENCRYPTION_OPERATIONS = Counter(
    'encryption_operations_total',
    'Total encryption/decryption operations',
    ['operation']
)
```

---

## 8. CI/CD Security

### 8.1 GitHub Actions pipeline

```yaml
# .github/workflows/deploy.yml

name: Deploy to Production

on:
  push:
    tags:
      - 'v*'

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Bandit security scan
        run: |
          pip install bandit
          bandit -r backend/ --exclude backend/tests -ll
      
      - name: Safety dependency check
        run: |
          pip install safety
          safety check -r requirements.txt
      
      - name: Mypy type checking
        run: |
          pip install mypy
          mypy backend/ --ignore-missing-imports

  test:
    runs-on: ubuntu-latest
    needs: security-scan
    steps:
      - uses: actions/checkout@v4
      
      - name: Run tests
        run: |
          pip install -r requirements.txt
          pytest backend/tests/ -v --cov=backend --cov-fail-under=85

  deploy:
    runs-on: ubuntu-latest
    needs: test
    environment: production
    steps:
      - uses: actions/checkout@v4
      
      - name: Deploy to production
        run: |
          # SSH deploy
          ssh -o StrictHostKeyChecking=no user@server << 'EOF'
            cd /opt/password-manager
            git pull origin main
            source venv/bin/activate
            pip install -r requirements.txt
            systemctl restart password-manager
          EOF
```

### 8.2 Pre-deployment checklist

```markdown
# Pre-Deployment Checklist

## Security
- [ ] Bandit scan passed (0 issues)
- [ ] Safety check passed (0 vulnerabilities)
- [ ] All tests passed (100%)
- [ ] Code coverage >85%
- [ ] Security review completed

## Configuration
- [ ] .env file configured
- [ ] Secrets stored securely
- [ ] HTTPS configured
- [ ] Firewall rules applied

## Monitoring
- [ ] Logging configured
- [ ] Alerts configured
- [ ] Dashboard updated
- [ ] Backup tested

## Rollback Plan
- [ ] Rollback procedure documented
- [ ] Previous version available
- [ ] Database backup created
```

---

## 9. Disaster Recovery

### 9.1 Recovery Time Objectives

| Метрика | Значение | Примечание |
|---------|----------|------------|
| **RTO** (Recovery Time Objective) | 4 часа | Максимальное время простоя |
| **RPO** (Recovery Point Objective) | 1 час | Максимальная потеря данных |

### 9.2 Процедура восстановления

```bash
#!/bin/bash
# /opt/password-manager/scripts/restore.sh

BACKUP_FILE="$1"

if [ -z "$BACKUP_FILE" ]; then
    echo "Usage: $0 <backup_file>"
    exit 1
fi

# Остановка приложения
systemctl stop password-manager

# Расшифровка бэкапа
openssl enc -aes-256-cbc -d -pbkdf2 \
    -in "$BACKUP_FILE" \
    -out /tmp/restored.db \
    -pass file:/etc/password-manager/backup.key

# Восстановление базы данных
cp /tmp/restored.db /var/lib/password-manager/data.db

# Очистка
rm /tmp/restored.db

# Запуск приложения
systemctl start password-manager

# Проверка
systemctl status password-manager

echo "[$(date)] Restore completed from $BACKUP_FILE" >> /var/log/password-manager/restore.log
```

---

## 10. Приложения

### A. Production checklist

```markdown
# Production Deployment Checklist

## Pre-Deployment
- [ ] Security scan passed
- [ ] All tests passed
- [ ] Code review completed
- [ ] Documentation updated

## Infrastructure
- [ ] OS hardened
- [ ] Firewall configured
- [ ] HTTPS configured
- [ ] Monitoring enabled

## Application
- [ ] Environment variables set
- [ ] Database configured
- [ ] Backups configured
- [ ] Logging configured

## Post-Deployment
- [ ] Health check passed
- [ ] Metrics verified
- [ ] Alerts tested
- [ ] Rollback tested
```

### B. Emergency contacts

| Role | Name | Phone | Email |
|------|------|-------|-------|
| Security Lead | Nikita | +1-234-567-8901 | nikita@example.com |
| DevOps Lead | Alex | +1-234-567-8902 | alex@example.com |
| Backend Lead | Alexey | +1-234-567-8903 | alexey@example.com |

---

**Документ утверждён:**  
Никита (BE1) — Security Lead  
Alex — DevOps Lead

**Дата:** Май 2026  
**Следующий пересмотр:** Август 2026

**Статус:** ✅ APPROVED FOR PRODUCTION v2.0.0

