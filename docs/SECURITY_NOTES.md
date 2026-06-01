# Security Notes

This document records accepted security limitations and design decisions for the BitNet password manager.

## L-001: C# `StringBuilder` Password Leakage in `VaultPage`

**Location**: `BitNet.Desktop/Views/VaultPage.xaml.cs` — `CopyPassword_Click`

Passwords copied from the native core into a `System.Text.StringBuilder` and then assigned to a managed `String` remain in the .NET managed heap until garbage collection. The CLR provides no guaranteed zeroization API for managed strings or `StringBuilder` internal buffers.

**Mitigation**: Best-effort `StringBuilder.Clear()` and variable overwrite are performed immediately after copying the password to the clipboard. This reduces the window of exposure but does not eliminate it.

**Status**: Accepted limitation of the .NET runtime. Use a future pure-Rust GUI or memory-protected interop if stronger guarantees are required.

## L-003: `MasterPasswordBox.Password` String Persists in Managed Heap

**Location**: `BitNet.Desktop/Views/UnlockPage.xaml.cs`

The WinUI `PasswordBox.Password` property returns a standard managed `String`. Even though the secure wrapper zeroizes the pinned UTF-8 buffer passed to the Rust core, the original managed string survives in the .NET heap until the next garbage collection cycle. There is no `SecureString` usage in the current WinUI implementation.

**Mitigation**: Accepted .NET limitation. Developers should be aware that the master password may briefly exist as a managed string in the heap.

**Status**: Documented accepted risk.

## L-005: `scripts/sign-binaries.ps1` Plain-Text Password Exposure

**Location**: `scripts/sign-binaries.ps1`

When a PFX file is supplied, the script decrypts the secure-string password to plain text via `[Runtime.InteropServices.Marshal]::PtrToStringAuto(...)` so that `signtool` can consume it. This plain-text string exists in PowerShell memory for the duration of the signing operation.

**Mitigation**:
- A `try/finally` block performs best-effort zeroization after signing.
- For CI and automated environments, **always prefer `-CertificateThumbprint`** to avoid PFX passwords in memory entirely.

**Status**: Accepted for local/interactive signing scripts; CI must use thumbprint-based signing.

## M-004: Native Messaging Host `allowed_origins` Wildcard for Development vs. Production Pinning

**Location**: `browser-extension/com.bitnet.nativehost.json`

The committed host manifest template ships with `chrome-extension://YOUR_EXTENSION_ID_HERE/` as a placeholder in `allowed_origins`. In development, replacing this with `chrome-extension://*/` is acceptable for rapid iteration, but the wildcard allows **any** extension to connect to the native host.

**Mitigation**:
- For production or any release build, `allowed_origins` must be pinned to a single, known Chrome/Edge Extension ID.
- `scripts/install-host.ps1` already enforces this: the `-ExtensionId` parameter is **Mandatory** and writes the exact `chrome-extension://$ExtensionId/` entry into the manifest before registry registration.
- The placeholder string in the committed JSON ensures that an unconfigured manifest cannot accidentally open a wildcard channel.

**Status**: Documented accepted risk in development; pinned ExtensionId is mandatory for production.
