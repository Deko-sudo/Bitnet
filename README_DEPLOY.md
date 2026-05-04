# BitNet — Deployment Guide

> Production-ready Docker setup with automatic HTTPS via Caddy.

---

## Quick Start

```bash
# 1. Clone repository
git clone https://github.com/yourorg/bitnet.git
cd bitnet

# 2. Generate server wrap key (32 random bytes)
mkdir -p secrets
openssl rand -base64 32 > secrets/server_key.txt

# 3. Configure domain
# Edit Caddyfile and replace 'yourdomain.com' with your actual domain
nano Caddyfile

# 4. Start services
docker-compose up -d

# 5. Check status
docker-compose ps
docker-compose logs -f app
docker-compose logs -f proxy
```

---

## Architecture

```
┌─────────────────────────────────────────────┐
│              Internet (443)                  │
└──────────────────┬──────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────┐
│           Caddy (Auto HTTPS)                 │
│  - TLS certificates via Let's Encrypt        │
│  - Security headers (HSTS, CSP, etc.)        │
│  - Gzip/Zstd compression                     │
└──────┬──────────────────────┬────────────────┘
       │                      │
       │ /api/*               │ /*
       ▼                      ▼
┌──────────────┐    ┌────────────────────┐
│  FastAPI     │    │  Frontend Static   │
│  (port 8000) │    │  (dist/)           │
│  + Rust      │    │  React SPA         │
│  Crypto      │    │                    │
└──────┬───────┘    └────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────┐
│     SQLite Database (./data/bitnet.db)       │
└─────────────────────────────────────────────┘
```

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `BITNET_SERVER_WRAP_KEY_FILE` | `/run/secrets/server_key` | Path to 32-byte server wrap key |
| `SQLALCHEMY_DATABASE_URL` | `sqlite:////app/data/bitnet.db` | Database connection string |
| `BITNET_FIDO2_RP_ID` | `localhost` | WebAuthn relying party ID |
| `BITNET_FIDO2_ORIGIN` | `http://localhost:3000` | WebAuthn origin URL |
| `BITNET_FIDO2_RP_NAME` | `BitNet Vault` | WebAuthn RP display name |

### Secrets

The server wrap key must be exactly 32 bytes of random data:

```bash
# Generate key
openssl rand -base64 32 > secrets/server_key.txt

# Verify length
wc -c secrets/server_key.txt  # Should be 45 (32 bytes base64 + newline)
```

**Never commit this file to version control.** It's in `.gitignore`.

---

## Docker Compose Services

| Service | Image | Ports | Description |
|---------|-------|-------|-------------|
| `app` | Custom (multi-stage) | 8000 (internal) | FastAPI + Rust bridge |
| `proxy` | `caddy:2-alpine` | 80, 443 | Reverse proxy + TLS |

### Volumes

| Volume | Purpose |
|--------|---------|
| `./data` | SQLite database persistence |
| `caddy_data` | TLS certificates (managed by Caddy) |
| `caddy_config` | Caddy configuration cache |

---

## Production Checklist

- [ ] Replace `yourdomain.com` in `Caddyfile` with actual domain
- [ ] Generate unique `server_key.txt` (32 bytes)
- [ ] Configure DNS A record pointing to server IP
- [ ] Verify firewall allows ports 80 and 443
- [ ] Set `BITNET_FIDO2_RP_ID` to your domain
- [ ] Set `BITNET_FIDO2_ORIGIN` to `https://yourdomain.com`
- [ ] Run `docker-compose up -d`
- [ ] Verify HTTPS: `curl -I https://yourdomain.com/health`

---

## Health Checks

```bash
# Check app health
curl http://localhost:8000/health
# Expected: {"status": "ok", "message": "BitNet Server is highly secure and operational."}

# Check via proxy (HTTPS)
curl -I https://yourdomain.com/health

# Check container health
docker-compose ps
```

---

## Backup & Restore

### Backup

```bash
# Stop services
docker-compose down

# Backup database
cp -r ./data ./data-backup-$(date +%Y%m%d)

# Backup secrets
cp -r ./secrets ./secrets-backup-$(date +%Y%m%d)
```

### Restore

```bash
# Stop services
docker-compose down

# Restore database
rm -rf ./data
cp -r ./data-backup-YYYYMMDD ./data

# Restore secrets
rm -rf ./secrets
cp -r ./secrets-backup-YYYYMMDD ./secrets

# Start services
docker-compose up -d
```

---

## Troubleshooting

### View Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f app
docker-compose logs -f proxy
```

### Rebuild After Code Changes

```bash
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

### Check SSL Certificates

```bash
docker-compose exec proxy ls -la /data/caddy/certificates/
```

### Database Issues

```bash
# Enter app container
docker-compose exec app sh

# Check database file
ls -la /app/data/

# Test connectivity
python -c "from backend.database.session import engine; print('OK')"
```

---

## Security Notes

1. **Never expose port 8000 directly** — always use Caddy proxy
2. **Rotate `server_key.txt`** periodically (requires re-registration of FIDO2 credentials)
3. **Enable firewall** — only allow ports 22, 80, 443
4. **Run as non-root** — app container uses `bitnet` user (UID 999)
5. **Automatic TLS** — Caddy handles Let's Encrypt renewal automatically

---

## Development Mode

For local development without HTTPS:

1. Uncomment the `localhost` block in `Caddyfile`
2. Comment out the `yourdomain.com` block
3. Run:

```bash
docker-compose -f docker-compose.yml up -d
```

Access at: `http://localhost`

---

## Multi-Server Deployment

For horizontal scaling:

1. Use PostgreSQL instead of SQLite (update `SQLALCHEMY_DATABASE_URL`)
2. Add Redis for session management
3. Use a load balancer instead of single Caddy instance
4. Store `server_key.txt` in a secrets manager (HashiCorp Vault, AWS Secrets Manager)

Example with PostgreSQL:

```yaml
services:
  db:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: bitnet
      POSTGRES_PASSWORD_FILE: /run/secrets/db_password
      POSTGRES_DB: bitnet
    volumes:
      - pg_data:/var/lib/postgresql/data
    secrets:
      - db_password

secrets:
  server_key:
    file: ./secrets/server_key.txt
  db_password:
    file: ./secrets/db_password.txt
```
