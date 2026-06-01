# BitNet Security — Triage Guide (Internal)

This document is for **core maintainers** who process incoming bug bounty  
and security reports.  It standardizes severity assignment, reproduction  
workflows, and SLA tracking.

---

## Severity Matrix (CVSS v3.1)

| Component | Critical (9.0–10.0) | High (7.0–8.9) | Medium (4.0–6.9) | Low (0.1–3.9) |
|-----------|----------------------|----------------|------------------|---------------|
| **Vault crypto** | Key recovery without password; total vault decryption | Side-channel key leak; Argon2 param bypass | Weak default params exposed | Cosmetic crypto UI bug |
| **Native host** | Code execution from browser; path traversal read arbitrary file | Info disclosure (password leak via error); format string | Unhandled panic kills host; DoS via large message | Memory profiling visible to non-admin |
| **Browser extension** | XSS in popup/content leading to vault extraction | CSP bypass; HTML injection in entry list | Origin spoofing on allowed_origins | Missing `escapeHtml` edge case (handled) |
| **Desktop GUI** | C# FFI memory corruption; arbitrary code execution via vault file | Password visible in memory dump; insecure temp file | Clipboard not cleared after timeout | UI does not indicate vault lock state |
| **CLI** | `--no-echo` bypass (password printed) | Path traversal via `--vault-path` | Weak password generator output | Help text exposes internal flag |

---

## Triage Workflow

### Step 1 — Receipt (auto)
- Auto-acknowledge via `security@bitnet.dev` within **24h**
- Create private GitHub Security Advisory ( draft )
- Assign internal ID: `BITNET-SEC-YYYY-<nnn>`

### Step 2 — Reproduction
1. Researcher must provide **PoC** or detailed steps
2. Maintainer runs PoC in **isolated VM** (Windows Sandbox / VM with snapshot)
3. Record:
   - OS version, browser version, BitNet version
   - Screenshot / video of exploit
   - Output of `cargo test --workspace` before/after

### Step 3 — Severity Assignment
- Use CVSS calculator: `https://www.first.org/cvss/calculator/3.1`
- If disagreement with researcher, explain within 48h
- Document rationale in Security Advisory

### Step 4 — Fix & QA
- Branch: `security/BITNET-SEC-YYYY-nnn`
- Must pass:
  ```bash
  cargo clippy --workspace -- -D warnings
  cargo test --workspace
  cargo audit
  cargo deny check
  ```
- For browser changes: manual popup/overlay check
- For desktop changes: run `BitNet.Desktop.Tests` xUnit suite

### Step 5 — Release
- Merge via **security-maintainer review** (not regular PR)
- Tag patch release: `vX.Y.Z-security`
- Publish release notes describing fix *without* exploitation details
- Notify researcher that fix is live

### Step 6 — Disclosure
- Default: **90 days** from report
- Researcher may request earlier or later
- Publish Security Advisory with researcher credit
- Update `SECURITY.md` Hall of Fame

---

## SLA Clock

| Severity | Ack | Triage | Fix decision | Patch deployed |
|----------|-----|--------|--------------|----------------|
| Critical | 24h | 48h | 7 days | 14 days |
| High | 48h | 72h | 14 days | 30 days |
| Medium | 72h | 7 days | 30 days | 60 days |
| Low | 7 days | 14 days | 60 days | 90 days |

*SLA paused if researcher does not respond to clarification requests within 5 days.*

---

## Out-of-Scope Quick Reference

Before assigning severity, verify report is **not**:
- A known accepted risk (see `THREAT_MODEL.md` R001–R006)
- A debug-build-only issue
- A social engineering attack
- Missing rate limiting on public endpoints (BitNet has no public API)
- Theoretical vulnerability without PoC (informational, no bounty)

---

## Communication Templates

### Initial Acknowledgment
```
Subject: [BITNET-SEC-YYYY-nnn] Acknowledged — severity triage in progress

Hi {name},

Thank you for your report on [brief summary].

Internal ID: BITNET-SEC-YYYY-nnn
Status: Under triage
Estimated severity: {Critical / High / Medium / Low / TBD}

We will update you within {timeframe}.

Regards,
BitNet Security Team
```

### Duplicate Notification
```
Subject: [BITNET-SEC-YYYY-nnn] Duplicate — see BITNET-SEC-YYYY-mmm

Hi {name},

Thank you for your report. Unfortunately this is a duplicate of
BITNET-SEC-YYYY-mmm (reported on {date}).

[If applicable: Your report adds new exploitation path X, so we will
award a partial bounty of $Y.]

Regards,
BitNet Security Team
```

### Bounty Decision
```
Subject: [BITNET-SEC-YYYY-nnn] Bounty awarded — ${amount}

Hi {name},

After triage we have assigned severity {severity} (CVSS {score}).
Bounty: ${amount}
Hall of Fame: [yes / pending your consent]

Payment method: [PayPal / Wise / Crypto]
Payment details: [request from researcher]

Regards,
BitNet Security Team
```

---

*Internal document — do not distribute.*
