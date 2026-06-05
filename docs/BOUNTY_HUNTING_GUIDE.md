# BitNet — Bug Bounty Hunting Guide for Researchers

This guide walks you through our codebase and highlights **where** to look  
for vulnerabilities, **what** tools we use, and **how** to build a minimal PoC.

---

## Quick Start (5 minutes)

1. **Clone and build**
   ```bash
   git clone https://github.com/bitnet/bitnet.git
   cd BitNet
   cargo build --workspace --release
   ```

2. **Run tests** (to confirm your environment)
   ```bash
   cargo test --workspace
   cargo clippy --workspace -- -D warnings
   cargo audit
   cargo deny check
   cargo +nightly fuzz run kdbx_deserialize -- -max_total_time=60
   ```

3. **Install C# test runner** (for desktop interop bugs)
   ```bash
   # Windows only
   cd BitNet.Desktop.Tests
   dotnet test
   ```

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────┐
│  Browser Extension (JS) — Content scripts, popup, background │
│     ↕  Native Messaging (stdio, 4-byte length prefix)     │
│  Native Host (Rust) — bitnet-native-host                    │
│     ↕  C FFI calls                                          │
│  Core Engine (Rust) — bitnet-ffi → bitnet-core → bitnet-kdbx│
│     ↕  Crypto primitives                                    │
│  Crypto (Rust) — bitnet-crypto (Argon2, TOTP, SHA-256)      │
└──────────────────────────────────────────────────────────────┘
│  Desktop GUI (C#) — WinUI 3 app calling bitnet-ffi.dll      │
└──────────────────────────────────────────────────────────────┘
```

---

## High-Value Targets (Ranked)

### T1 — Vault Decryption (Crypto)
**Goal:** Decrypt `.bitnet` file without master password.

Where to look:
- `crates/bitnet-kdbx/src/lib.rs` — `load_vault()`, `derive_key()`
- `crates/bitnet-crypto/src/lib.rs` — Argon2 params, TOTP generation
- Check: is Argon2 validation bypassable? Buffer overflow in key derivation?
- Fuzz target: `crates/bitnet-kdbx/fuzz/fuzz_targets/kdbx_deserialize.rs`

Questions to ask:
- What happens if `version > CURRENT_VERSION`? (Should reject — check `test_future_version_rejected`)
- What is `MAX_CIPHERTEXT_LENGTH`? Can we hit an integer overflow before it?
- Is there a timing side-channel in password comparison?

### T2 — FFI Memory Safety
**Goal:** Achieve memory corruption from C# or native host.

Where to look:
- `crates/bitnet-ffi/src/lib.rs` — every `pub extern "C"` function
- Buffer APIs: `bitnet_entry_get_password`, `bitnet_entry_get_totp_to_buffer`
- Null pointer: are all `*.is_null()` checks correct?
- String handling: are all strings freed via `bitnet_free_string`?

Questions to ask:
- What if `out_len` is 0? (Should return -1 — is it?)
- What if entry_uuid contains embedded null byte? (Should fail parsing)
- Can we trigger `unwrap()` or `expect()` to cause panic?

### T3 — Native Messaging Protocol
**Goal:** Elevate from browser JavaScript to native code execution.

Where to look:
- `crates/bitnet-native-host/src/main.rs` — message loop
- Check: origin validation of `allowed_origins` in `com.bitnet.nativehost.json`
- Check: action whitelist — are unknown actions silently ignored?

Questions to ask:
- Can we forge a message > 1MB to trigger heap exhaustion?
- What happens if `msg_len` is malformed? (u32::from_ne_bytes — endianness?)
- Is `send_response` vulnerable to format string if error contains `{}`?
- Can we inject JSON to confuse parser? (e.g., Unicode BOM, duplicate keys)

### T4 — Browser Extension XSS / Injection
**Goal:** Execute arbitrary JavaScript in extension context.

Where to look:
- `browser-extension/popup.js` — entry rendering
- `browser-extension/content.js` — DOM manipulation on third-party sites
- `browser-extension/background.js` — message passing

Questions to ask:
- Is `escapeHtml()` sufficient for all contexts? (attribute vs text vs URL)
- Can crafted entry title break out of HTML attribute?
- Does content.js inject `<script>` into untrusted pages?
- Is `innerHTML` used anywhere to render entries? (Previously was — verify it's gone)

### T5 — Desktop GUI Privilege Escalation
**Goal:** Escape WinUI 3 sandbox or read other users' vaults.

Where to look:
- `BitNet.Desktop/Native/BitnetCore.cs` — `DllImport` and string marshaling
- `BitNet.Desktop/` — file picker, temp file handling
- Windows DPAPI: `crates/bitnet-dpapi/src/lib.rs`

Questions to ask:
- Does the GUI pass vault path to FFI without validation?
- Are decrypted passwords zeroized in C# memory?
- Can a crafted vault file trigger WinUI exception handler leak?
- Is DPAPI scope `CurrentUser` or `LocalMachine`?

---

## Fuzzing

We provide two built-in fuzz targets:

### KDBX deserialization fuzzer
```bash
cargo +nightly fuzz run kdbx_deserialize
```
This mutates raw KDBX bytes to find deserialization panics.

### Custom fuzzer ideas
- **JSON entry parser:** Mutate `entry_json` passed to `bitnet_add_entry`
- **UUID parser:** Mutate hex string passed to every entry function
- **Native messaging:** Mutate the 4-byte length + JSON payload

---

## Static Analysis Tools

Recommended for Bug Bounty hunters:

| Tool | Purpose | Command |
|------|---------|---------|
| `cargo audit` | Known CVEs in deps | `cargo audit` |
| `cargo deny` | License / advisory / ban checks | `cargo deny check` |
| `cargo clippy` | Lint + performance | `cargo clippy --workspace -- -D warnings` |
| `cargo +nightly fuzz` | Coverage-guided fuzz | see above |
| `Semgrep` | JS rule-based scanning | `semgrep --config=auto browser-extension/` |
| `CodeQL` | Rust / C# deep analysis | GitHub Advanced Security |
| `mimalloc-heap-check` | Heap corruption detection | `MIMALLOC_SHOW_ERRORS=1` |

---

## Report Checklist

Before submitting, ensure:

- [ ] You can reproduce the issue **from a clean build**
- [ ] You tested against the **latest `main` branch**
- [ ] Your PoC works on a **supported platform** (Windows 10+, macOS 12+, Ubuntu 22.04+)
- [ ] You did **not** test against other users' data or production
- [ ] Report includes **CVSS v3.1** score with rationale
- [ ] Report includes **suggested fix** (optional but appreciated)
- [ ] You agree to **90-day disclosure** timeline

---

## Contact

- Email: `security@bitnet.dev`
- PGP: see `SECURITY.md`
- Response SLA: 24h for Critical, 48h for High, 72h for Medium

Good luck hunting! 🐛
