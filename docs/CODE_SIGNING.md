# Code Signing Guide for BitNet

## Overview

This document describes how to sign `bitnet_ffi.dll` and `bitnet-native-host.exe` with a code signing certificate to ensure integrity and avoid Windows SmartScreen warnings.

## Prerequisites

1. **Windows SDK** — includes `signtool.exe`
   - Download from: https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/
2. **Code Signing Certificate**
   - **Test/Development**: Self-signed certificate (`New-SelfSignedCertificate`)
   - **Production**: EV Code Signing certificate (DigiCert, Sectigo, etc.) or Azure Trusted Signing

## Quick Start

```powershell
# Using a .pfx file
.\scripts\sign-binaries.ps1 -CertificatePath "C:\Certs\bitnet.pfx"

# Using Windows Certificate Store thumbprint
.\scripts\sign-binaries.ps1 -CertificateThumbprint "A1B2C3D4E5F6..."
```

## Creating a Self-Signed Certificate (Development Only)

```powershell
# Run as Administrator
$cert = New-SelfSignedCertificate `
    -Subject "CN=BitNet Dev" `
    -Type CodeSigning `
    -CertStoreLocation Cert:\CurrentUser\My

Export-PfxCertificate `
    -Cert $cert `
    -FilePath "bitnet-dev.pfx" `
    -Password (ConvertTo-SecureString -String "devpassword" -Force -AsPlainText)
```

> ⚠️ Self-signed certificates are NOT trusted by Windows by default. Install the certificate into `Trusted Root` or `Trusted Publishers` for local testing.

## Azure Trusted Signing (Recommended for CI/CD)

1. Create an Azure Trusted Signing Account
2. Configure `TrustedSigningAccount` and `CertificateProfile`
3. Use `signtool` with `/tr` pointing to Azure endpoint:

```powershell
signtool sign `
    /fd sha256 `
    /tr "https://weu.codesigning.azure.net?..." `
    /td sha256 `
    bitnet_ffi.dll
```

## Verification

```powershell
# Check signature
signtool verify /pa BitNet.Desktop\Native\bitnet_ffi.dll

# Check certificate details
Get-AuthenticodeSignature BitNet.Desktop\Native\bitnet_ffi.dll | Format-List
```

## CI Integration

Add the signing step to `.github/workflows/ci.yml` after `cargo build --release`:

```yaml
- name: Sign binaries
  if: github.ref == 'refs/heads/main'
  run: |
    .\scripts\sign-binaries.ps1 -CertificateThumbprint ${{ secrets.CODESIGN_THUMBPRINT }}
  env:
    TIMESTAMP_URL: http://timestamp.digicert.com
```

## Files to Sign

| File | Purpose |
|------|---------|
| `BitNet.Desktop\Native\bitnet_ffi.dll` | Rust FFI library loaded by WinUI 3 |
| `BitNet.Desktop\Native\bitnet-native-host.exe` | Browser extension native messaging host |

## Security Notes

- Never commit private keys or `.pfx` files to version control.
- Store thumbprints and secrets in GitHub Secrets or Azure Key Vault.
- Use SHA-256 (`/fd sha256`) as minimum hashing algorithm.
- Always timestamp signatures to ensure validity after certificate expiration.