#Requires -Version 5.1
<#
.SYNOPSIS
    Code-signing helper for BitNet native binaries.

.DESCRIPTION
    Signs bitnet_ffi.dll and bitnet-native-host.exe using a code signing certificate.
    For production, use an EV code signing certificate or Windows Trusted Signing (Azure Key Vault).

.REQUIREMENTS
    - Windows SDK (signtool.exe)
    - Valid code signing certificate (PFX or Windows Certificate Store)

.PARAMETER CertificatePath
    Path to .pfx certificate file. If omitted, uses certificate from Windows store by thumbprint.

.PARAMETER CertificateThumbprint
    Thumbprint of certificate in Windows Certificate Store (CurrentUser\\My).

.PARAMETER TimestampUrl
    RFC 3161 timestamp server URL. Default: http://timestamp.digicert.com
#>

[CmdletBinding()]
param(
    [string]$CertificatePath = "",
    [string]$CertificateThumbprint = "",
    [string]$TimestampUrl = "http://timestamp.digicert.com"
)

$ErrorActionPreference = "Stop"

# Find signtool
$sdkPaths = @(
    "${env:ProgramFiles(x86)}\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe",
    "${env:ProgramFiles(x86)}\Windows Kits\10\bin\10.0.22000.0\x64\signtool.exe",
    "${env:ProgramFiles(x86)}\Windows Kits\10\bin\10.0.19041.0\x64\signtool.exe",
    "${env:ProgramFiles(x86)}\Windows Kits\10\bin\10.0.18362.0\x64\signtool.exe",
    "${env:ProgramFiles(x86)}\Windows Kits\8.1\bin\x64\signtool.exe"
)
$signtool = $sdkPaths | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $signtool) {
    Write-Error "signtool.exe not found. Install Windows SDK."
    exit 1
}
Write-Host "Found signtool: $signtool" -ForegroundColor Gray

# Resolve project root
$ProjectRoot = Resolve-Path (Join-Path $PSScriptRoot "..")

$binaries = @(
    (Join-Path $ProjectRoot "BitNet.Desktop\Native\bitnet_ffi.dll"),
    (Join-Path $ProjectRoot "BitNet.Desktop\Native\bitnet-native-host.exe")
)

foreach ($binary in $binaries) {
    if (-not (Test-Path $binary)) {
        Write-Warning "Binary not found, skipping: $binary"
        continue
    }

    Write-Host "Signing: $binary" -ForegroundColor Yellow

    if ($CertificatePath) {
        if (-not (Test-Path $CertificatePath)) {
            Write-Error "Certificate not found: $CertificatePath"
        }
        $password = Read-Host -Prompt "Enter PFX password" -AsSecureString
        $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))
        & $signtool sign `
            /f "$CertificatePath" `
            /p "$plainPassword" `
            /tr "$TimestampUrl" `
            /td sha256 `
            /fd sha256 `
            "$binary"
    } elseif ($CertificateThumbprint) {
        & $signtool sign `
            /sha1 "$CertificateThumbprint" `
            /tr "$TimestampUrl" `
            /td sha256 `
            /fd sha256 `
            "$binary"
    } else {
        Write-Error "Provide either -CertificatePath or -CertificateThumbprint"
    }

    if ($LASTEXITCODE -eq 0) {
        Write-Host "  [OK] Signed successfully" -ForegroundColor Green
        # Verify signature
        & $signtool verify /pa "$binary" | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  [OK] Signature verified" -ForegroundColor Green
        }
    } else {
        Write-Error "Signing failed for $binary"
    }
}

Write-Host "Done." -ForegroundColor Cyan