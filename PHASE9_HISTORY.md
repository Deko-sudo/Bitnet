# Phase 9 — Dockerization & Orchestration History

> **Дата:** 2026-04-11
> **Вердикт:** ✅ **Production-ready**

---

## Что создано

### 1. `Dockerfile` — Multi-stage Build (3 stages)

**Stage 1: Backend & Rust Builder** (`python:3.11-slim`)
```dockerfile
# Install: build-essential, curl, gcc, libssl-dev, pkg-config
# Install: Rust via rustup
# Copy: backend/core/ → cargo build --release
# Install: requirements.txt + maturin
# Build: PyO3 wheel → install
```

**Stage 2: Frontend Builder** (`node:20-slim`)
```dockerfile
# Copy: frontend/package.json → npm install
# Copy: frontend/ → npm run build
# Output: /frontend/dist/
```

**Stage 3: Production** (`python:3.11-slim`)
```dockerfile
# Copy: Python env from Stage 1
# Copy: backend/ + frontend/dist/
# User: bitnet (non-root, UID 999)
# Env: BITNET_SERVER_WRAP_KEY_FILE=/run/secrets/server_key
# Expose: 8000
# Healthcheck: curl /health
# CMD: uvicorn --workers 4
```

**Security:**
- Non-root user (`bitnet`)
- Minimal base image (slim)
- No build tools in final image
- Healthcheck endpoint

---

### 2. `docker-compose.yml` — Service Orchestration

**Services:**

| Service | Image | Ports | Volumes | Secrets |
|---------|-------|-------|---------|---------|
| `app` | Custom (multi-stage) | 8000 (internal) | `./data:/app/data` | `server_key` |
| `proxy` | `caddy:2-alpine` | 80, 443 | `caddy_data`, `caddy_config` | — |

**Secrets Management:**
```yaml
secrets:
  server_key:
    file: ./secrets/server_key.txt  # 32 random bytes
```

**Healthcheck:**
```yaml
healthcheck:
  test: ["CMD", "python", "-c", "import urllib.request; ..."]
  interval: 30s
  retries: 3
```

**Dependency:**
```yaml
depends_on:
  app:
    condition: service_healthy
```

---

### 3. `Caddyfile` — Reverse Proxy + Auto HTTPS

**Routing:**
```
/api/*     → reverse_proxy app:8000
/health    → reverse_proxy app:8000
/*         → file_server /srv/frontend/dist + SPA fallback
```

**Security Headers:**
| Header | Value |
|--------|-------|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains; preload` |
| `X-Frame-Options` | `DENY` |
| `X-Content-Type-Options` | `nosniff` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=(), payment=()` |
| `Content-Security-Policy` | `default-src 'self'; script-src 'self' 'unsafe-inline'; ...` |

**TLS:**
- Automatic Let's Encrypt certificates
- TLS 1.3 only
- Automatic renewal

**Compression:**
- gzip + zstd

---

### 4. `README_DEPLOY.md` — Deployment Guide

**Содержит:**
- Quick Start (5 шагов)
- Architecture diagram
- Configuration table (env vars)
- Secrets generation (`openssl rand -base64 32`)
- Production checklist
- Backup & Restore procedures
- Troubleshooting guide
- Security notes
- Development mode instructions
- Multi-server deployment notes (PostgreSQL, Redis, Load Balancer)

---

## Deployment Flow

```
1. Generate secrets/server_key.txt
   └─► openssl rand -base64 32 > secrets/server_key.txt

2. Edit Caddyfile
   └─► Replace 'yourdomain.com' with actual domain

3. docker-compose up -d
   └─► Build Stage 1 (Rust + Python)
   └─► Build Stage 2 (Node.js frontend)
   └─► Assemble Stage 3 (production)
   └─► Start Caddy proxy
   └─► Automatic HTTPS via Let's Encrypt

4. Verify
   └─► curl -I https://yourdomain.com/health
```

---

## Build Artifacts

| Stage | Size (approx) | Contents |
|-------|---------------|----------|
| Stage 1 (builder) | ~800 MB | Rust toolchain, build deps, Python venv |
| Stage 2 (builder) | ~400 MB | Node.js, npm, frontend source |
| **Stage 3 (final)** | **~150 MB** | Python runtime, Rust .so, frontend dist/ |

---

## Files Created/Modified

| Файл | Статус | Описание |
|------|--------|----------|
| `Dockerfile` | ✅ Перезаписан | Multi-stage build (3 stages) |
| `docker-compose.yml` | ✅ Перезаписан | app + proxy + secrets |
| `Caddyfile` | ✅ Новый | Reverse proxy + Auto HTTPS + security headers |
| `README_DEPLOY.md` | ✅ Новый | Полная инструкция по деплою |
| `.gitignore` | ✅ Обновлён | + secrets/ |

---

## Security Checklist

- [x] Non-root user in container
- [x] Secrets via Docker secrets (not env vars)
- [x] Minimal base image (slim)
- [x] No build tools in production image
- [x] Healthcheck endpoint
- [x] Automatic TLS (Let's Encrypt)
- [x] Security headers (HSTS, CSP, X-Frame-Options, etc.)
- [x] SQLite data persisted in volume
- [x] Server wrap key in `/run/secrets/`
- [x] `.gitignore` excludes secrets/
