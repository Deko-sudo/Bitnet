# BitNet Password Manager

Offline password manager for Windows with Zero Trust architecture, built in Rust + WinUI 3.

## Features
- **Zero Trust**: Auto-lock, memory zeroization, access mediation
- **Custom vault format** (`.bitnet`): Argon2id + AES-256-GCM + HMAC-SHA-256 (KDBX 4.x inspired)
- **TOTP**: RFC 6238 authenticator (SHA-1 & SHA-256)
- **Password Generator**: CSPRNG-based with rejection sampling
- **Autofill**: Windows native + Browser extension (Chrome/Edge/Firefox)
- **WinUI 3**: Fluent Design, Acrylic/Mica, dark theme support

## Architecture
- **Rust Core** (`crates/`): Crypto, KDBX, TOTP, Session Manager, FFI
- **C# GUI** (`BitNet.Desktop/`): WinUI 3 frontend
- **Browser Extension** (`browser-extension/`): Manifest V3 + Native Messaging
- **CLI** (`bitnet-cli/`): Command-line MVP

---

## Quick Start

### 1. Build Rust Workspace

```bash
cd BitNet
cargo build --release --workspace
```

> **Note:** The repository is a single Cargo workspace rooted at `D:\BitNet\`.
> There is no `bitnet/bitnet/` subdirectory anymore.

This produces:
- `target/release/bitnet-cli.exe`
- `target/release/bitnet-native-host.exe`
- `target/release/bitnet_ffi.dll`

### 2. Run CLI

```bash
# Create a new vault
cargo run --release --bin bitnet-cli -- create C:\Users\You\vault.bitnet

# Unlock vault
cargo run --release --bin bitnet-cli -- unlock C:\Users\You\vault.bitnet

# List entries
cargo run --release --bin bitnet-cli -- list

# Get password (use --no-echo to avoid terminal scrollback)
cargo run --release --bin bitnet-cli -- get --no-echo <uuid>

# Generate password
cargo run --release --bin bitnet-cli -- generate --length 20

# Show vault fingerprint
cargo run --release --bin bitnet-cli -- info C:\Users\You\vault.bitnet
```

### 3. Run WinUI 3 Desktop App

**Prerequisites:** .NET 8 SDK + Windows App SDK

```powershell
# Copy native binaries first
Copy-Item target\release\bitnet_ffi.dll BitNet.Desktop\Native\
Copy-Item target\release\bitnet-native-host.exe BitNet.Desktop\Native\

# Build and run
cd BitNet.Desktop
dotnet run
```

Or use the build script:
```powershell
.\scripts\build-desktop.ps1 -Configuration Release -Platform x64
```

### 4. Load Browser Extension

**Chrome / Edge:**
1. Open `chrome://extensions/` (or `edge://extensions/`)
2. Enable **Developer Mode**
3. Click **Load unpacked** → select `browser-extension/` folder
4. Register Native Host:
   ```powershell
   .\scripts\install-host.ps1
   # or manually:
   .\install_host.bat
   ```

**Firefox:**
1. Open `about:debugging#/runtime/this-firefox`
2. Click **Load Temporary Add-on** → select `browser-extension/manifest-firefox.json`
3. Register Native Host via `install-host.ps1` (Firefox registry keys included)

### 5. Run Tests

```bash
# Rust unit tests (111+ tests across all crates)
cargo test --workspace

# Clippy (zero warnings policy)
cargo clippy --workspace -- -D warnings

# Format check
cargo fmt --all -- --check

# Fuzzing (requires Rust nightly)
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly
cargo +nightly install cargo-fuzz
cargo +nightly fuzz run kdbx_deserialize -- -max_total_time=60
```

### 6. E2E Browser Tests (Playwright)

```bash
cd tests/e2e
npm install
npx playwright install chromium
npm test
```

### 7. Build Windows Installer

**Prerequisites:** Inno Setup 6+

```powershell
# Build everything + create installer
.\scripts\build-desktop.ps1 -Configuration Release -Platform x64 -CreateInstaller

# Installer output:
# target/installer/BitNet-Setup-0.1.0.exe
```

### 8. Code Sign Binaries (Optional)

```powershell
# Using PFX
.\scripts\sign-binaries.ps1 -CertificatePath "C:\Certs\bitnet.pfx"

# Using Windows Certificate Store thumbprint
.\scripts\sign-binaries.ps1 -CertificateThumbprint "A1B2C3D4..."
```

See [docs/CODE_SIGNING.md](docs/CODE_SIGNING.md) for details.

---

## Security

- **[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)** — Detailed threat model, trust boundaries, and ASVS mapping (including accepted risks such as native host origin verification).
- **[SECURITY_AUDIT.md](SECURITY_AUDIT.md)** — Security audit findings and their fixes.
- **[docs/SECURITY_NOTES.md](docs/SECURITY_NOTES.md)** — Accepted security limitations and platform-specific considerations (.NET managed-heap strings, terminal scrollback, etc.).

### Key security properties

| Property | Implementation |
|----------|---------------|
| Memory zeroization | `Zeroizing<String>` (Rust), `CryptographicOperations.ZeroMemory()` (C#) |
| Locking | `Mutex`-based `SessionManager` — no writer starvation |
| Password derivation | Argon2id (t=3, m=64 MB, p=4) |
| Encryption | AES-256-GCM with unique nonce per vault |
| Integrity | HMAC-SHA-256 over vault header |
| Comparison | Constant-time `subtle::ConstantTimeEq` for TOTP and HMAC |
| Path hardening | `validate_vault_path()` enforces `.bitnet` and rejects `..` |

## License

MIT OR Apache-2.0