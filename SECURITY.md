# BitNet Password Manager — Vulnerability Disclosure Policy

> **Убрать дедлайн нельзя, только отложить его на ровном месте.**

We take security seriously. BitNet is an **offline** password manager with Zero Trust architecture. All user data remains on the local device.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ Active |
| < 0.1   | ❌ Not supported |

## Reporting a Vulnerability

**Please DO NOT** open a public issue for security vulnerabilities.

Send reports to: **security@bitnet.dev** (PGP key below)

### What to include
- Clear reproduction steps
- Affected component (Rust core / C# GUI / browser extension / CLI / installer)
- CVSS estimate (if possible)
- Minimal test case or proof-of-concept
- Your disclosure timeline preference

### Response timeline

| Stage | Timeline |
|-------|---------|
| Acknowledgment | Within 48 hours |
| Initial assessment | Within 7 days |
| Fix + patch release | Within 30 days (Critical/High) |
| Public disclosure | Coordinated with reporter, 90 days max |

## Scope

Components in scope:
- Rust workspace (`crates/*`, `bitnet-cli/`)
- C# WinUI 3 application (`BitNet.Desktop/`)
- Browser extension (`browser-extension/`)
- Installer (`scripts/bitnet-setup.iss`)
- Native Messaging host (`crates/bitnet-native-host/`)

Out of scope:
- Physical device access (if encrypted, BitNet cannot help)
- OS-level vulnerabilities (report to Microsoft)
- Third-party browser vulnerabilities (report to vendor)

## Accepted Risks (Known Limitations)

| ID | Risk | Reason | Mitigation Plan |
|----|------|--------|-----------------|
| M-004 | `chrome-extension://*/*` wildcard allows any extension | Dev convenience | Production builds pin `allowed_origins` to specific extension ID |
| L-002 | UTF-8 lossy conversion for passwords with invalid bytes | C ABI limitation | Documented; all interfaces treat passwords as UTF-8 |
| L-003 | Browser origin not validated in Native Host | OS/browser sandbox assumed | Rely on `allowed_origins` manifest + OS sandbox |
| L-004 | Clipboard not auto-cleared after copy | C# side implementation pending | Auto-clear after 30s planned for v0.2 |

## Bug Bounty

We run periodic **bug bounty programs** through HackerOne. Eligibility:
- First valid Critical/High finding per category
- Full reproduction steps + CVSS
- Coordination before public disclosure
- No social engineering or physical attacks

## PGP Key

```
security@bitnet.dev
Fingerprint: [TO BE PUBLISHED ON FIRST BOUNTY LAUNCH]
```

## Security Headers

All CI builds enforce:
- **Control Flow Guard** (CFG)
- **ASLR** (`/DYNAMICBASE`)
- **CET Shadow Stack** (`/CETCOMPAT`)
- **Code signing** (production builds only)
- **cargo-deny** — banned crate patterns, license policy, and yanked-package check (see [`deny.toml`](deny.toml))
- **Pre-commit secret scan** — runs before every commit to detect hardcoded secrets ([`scripts/pre-commit-secret-scan.ps1`](scripts/pre-commit-secret-scan.ps1))
- **Fuzzing gate** — 120-second run of the KDBX deserializer fuzz target (`cargo +nightly fuzz run kdbx_deserialize -- -max_total_time=120`)

All policies, thresholds, and allowed test fixtures are defined in [`.cargo/security.yaml`](.cargo/security.yaml), which is the **source of truth** for security enforcement configuration.

## References

- [THREAT_MODEL.md](docs/THREAT_MODEL.md)
- [SECURITY_NOTES.md](docs/SECURITY_NOTES.md)
- [SECURITY_AUDIT.md](SECURITY_AUDIT.md)
- [security.yaml](.cargo/security.yaml)
