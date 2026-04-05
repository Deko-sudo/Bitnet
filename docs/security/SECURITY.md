# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability:

1. **DO NOT create a public issue** on GitHub
2. Send email to: security@example.com
3. Include: vulnerability type, steps to reproduce, potential impact

We will respond within 48 hours.

---

## Secure Development Rules

### 1. Never log sensitive data
```python
# FORBIDDEN:
logger.error(f"Login failed, password={password}")

# ALLOWED:
logger.error(f"Login failed for user {user_id}")
```

### 2. Use SecretStr for all secrets
```python
from pydantic import SecretStr
class Config(BaseModel):
    master_password: SecretStr
```

### 3. Zero memory after use
```python
zero_memory(bytearray(master_key))
```

### 4. constant_time_compare for all comparisons
```python
hmac.compare_digest(user_hash, expected_hash)
```

---

## Pre-merge Checklist

- [ ] All secrets via SecretStr
- [ ] No print() with sensitive data
- [ ] All comparisons via hmac.compare_digest()
- [ ] Unit tests for new features
- [ ] Bandit found no issues
- [ ] Mypy found no type errors
