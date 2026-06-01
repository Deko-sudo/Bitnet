# BitNet Bug Bounty Program

## Program Overview

BitNet Password Manager welcomes security research from the global community.  
We follow a **coordinated vulnerability disclosure** (CVD) model and pay cash  
bounties for novel, reproducible vulnerabilities that affect user data  
confidentiality, integrity, or availability.

**Contact:** `security@bitnet.dev` (PGP key in `SECURITY.md`)  
**Scope:** All components listed below in **In Scope**.  
**Exclusions:** All items in **Out of Scope** will not receive a bounty.

---

## Scope (In Scope)

| Component | Technology | Priority | Notes |
|-----------|------------|----------|-------|
| `crates/bitnet-kdbx` | Rust (KDBX engine) | **Critical** | Vault deserialization, encryption (argon2), entry storage |
| `crates/bitnet-crypto` | Rust (Crypto primitives) | **Critical** | PBKDF2, Argon2, SHA-256, TOTP, key derivation |
| `crates/bitnet-ffi` | Rust (C FFI layer) | **Critical** | Buffer bounds, memory safety, pointer validation |
| `crates/bitnet-core` | Rust (Session manager) | **High** | Session state, group/entry CRUD |
| `crates/bitnet-native-host` | Rust (Native messaging) | **High** | Message framing, origin validation, privilege isolation |
| `crates/bitnet-cli` | Rust (CLI) | **Medium** | Argument parsing, file I/O, secret display |
| `crates/bitnet-dpapi` | Rust (Windows DPAPI) | **Medium** | Credential encryption at rest |
| `browser-extension/` | JS (Chrome/Firefox extension) | **Critical** | Content scripts, popup, background, messaging |
| `BitNet.Desktop/` | C# (WinUI 3 GUI) | **Critical** | Vault UI, FFI interop, secure memory |

---

## Out of Scope

**No bounty will be paid for:**

1. **Known / Accepted Risks** documented in `docs/THREAT_MODEL.md` (R001–R006):
   - DPAPI bypass (requires session compromise)
   - Clipboard leakage after autofill
   - Memory dump to crash dump / hibernation
   - Side-channel key timing
   - Compromised browser extension store
   - Weak end-user master password entropy

2. **Infrastructure / Third-party:**
   - TLS downgrade on our web site (handled by cloudflare)
   - Dependency vulnerabilities without exploit path (report via `cargo audit`)
   - Social engineering of employees/users
   - Physical device theft or tampering

3. **Unsupported configurations:**
   - Running on OS older than Windows 10 / macOS 12 / Ubuntu 22.04
   - Browser extensions installed from unofficial sources
   - Debug / unoptimized builds (`cargo build` without `--release`)
   - Running with `RUST_BACKTRACE=full` in production

4. **Denial of Service (DoS) without security impact:**
   - CPU exhaustion via legitimate operations (e.g., large Argon2 params already validated)
   - Memory exhaustion within documented vault limits (see `MAX_CIPHERTEXT_LENGTH`)

5. **UI / UX annoyances** without security impact (e.g., missing dark mode)

---

## Severity & Bounty Matrix

We use **CVSS v3.1** for initial triage.  Final bounty amount may be adjusted  
up or down based on exploit complexity and user impact.

| Severity | CVSS Score | Typical bounty range | Response SLA |
|----------|------------|----------------------|--------------|
| **Critical** | 9.0–10.0 | $2,500 – $5,000 | 24 hours |
| **High** | 7.0–8.9 | $1,000 – $2,000 | 48 hours |
| **Medium** | 4.0–6.9 | $300 – $800 | 72 hours |
| **Low** | 0.1–3.9 | $100 – $200 | 7 days |
| **Informational** | 0.0 | Recognition only | 14 days |

### Bonus multipliers
- **Full exploit chain** (e.g., popup XSS → native host code execution): **+50%**
- **Remote exploitation without user interaction**: **+100%**
- **Complete vault extraction** (master password not known): **+100%**
- **Zero-day in upstream dependency** with demonstrated exploit path: **+25%**

---

## What Makes a Good Report

1. **Clear reproduction steps** — какой компонент, какие шаги, какая нагрузка
2. **Minimal PoC** — чем проще, тем лучше
3. **Impact statement** — что злоумышленник может сделать
4. **Suggested fix** (optional but appreciated)
5. **No public disclosure** until we agree on disclosure timeline

### Preferred format
```
Title: [Component] Brief description
Severity: Critical / High / Medium / Low
CVSS: 3.1 /AV:L/AC:H/... (if known)

Summary: One-paragraph impact.

Steps to reproduce:
1. ...
2. ...
3. ...

PoC: [attach script / payload / curl command]

Expected result: ...
Actual result: ...

Suggested fix: ...
```

---

## Safe Harbor

We authorize testing **only** against your own vaults and installations.  
Do NOT test against:
- Other users' vaults or machines
- Production infrastructure (ci.bitnet.dev, update servers)
- Third-party services integrated with BitNet

We will not pursue civil or criminal action against researchers who:
- Act in good faith
- Stay within the scope above
- Do not exfiltrate user data
- Give us reasonable time to fix before public disclosure (90 days default)

---

## Disclosure Timeline

| Day | Action |
|-----|--------|
| 0 | Report received — auto-ack within 24h |
| 1–3 | Triage + severity assignment |
| 3–10 | Fix developed + internal QA |
| 10–30 | Fix released in next patch version |
| 90 | Public disclosure (if both parties agree) |

Researchers may request an extension if fix proves complex.  
We may request earlier disclosure for Critical vulnerabilities already exploited in the wild.

---

## Duplicate Policy

- **First valid report wins** bounty
- If your report is duplicate but adds **new exploitation path** or **higher severity**, we pay proportionally
- Known issues from `THREAT_MODEL.md` and previous security hardening are **not eligible**

---

## Hall of Fame

We maintain a public Hall of Fame page at `https://bitnet.dev/security/hall-of-fame`  
(until then, recognized researchers are listed in `SECURITY.md`).

---

*Last updated: 2026-06-01*  
*Program version: 1.0*
