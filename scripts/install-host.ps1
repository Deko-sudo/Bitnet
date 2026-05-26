#Requires -Version 5.1
<#
.SYNOPSIS
    Installs BitNet Native Messaging host for Chrome, Edge, and Firefox.

.DESCRIPTION
    Registers bitnet-native-host.exe as a Native Messaging host
    by writing registry keys and creating the host manifest JSON.
    For production, supply -ExtensionId to restrict allowed_origins.
#>

[CmdletBinding()]
param(
    [string]$HostName = "com.bitnet.nativehost",
    [string]$ExtensionId = "",
    [string]$ChromeRegistryPath = "HKCU:\Software\Google\Chrome\NativeMessagingHosts\$HostName",
    [string]$EdgeRegistryPath = "HKCU:\Software\Microsoft\Edge\NativeMessagingHosts\$HostName",
    [string]$FirefoxRegistryPath = "HKCU:\Software\Mozilla\NativeMessagingHosts\$HostName"
)

$ErrorActionPreference = "Stop"

# Resolve path to bitnet-native-host.exe
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ProjectRoot = Resolve-Path (Join-Path $ScriptDir "..")
$HostExe = Join-Path $ProjectRoot "target\release\bitnet-native-host.exe"

if (-not (Test-Path $HostExe)) {
    $HostExe = Join-Path $ProjectRoot "target\debug\bitnet-native-host.exe"
}

if (-not (Test-Path $HostExe)) {
    Write-Error "bitnet-native-host.exe not found. Build the project first:`r`n  cargo build --release --workspace"
    exit 1
}

$HostExe = Resolve-Path $HostExe | Select-Object -ExpandProperty Path

# Determine allowed_origins
$allowedOrigins = @("chrome-extension://*/")
if ($ExtensionId) {
    $allowedOrigins = @("chrome-extension://$ExtensionId/")
}

# Create manifest JSON
$ManifestPath = Join-Path $ProjectRoot "browser-extension\$HostName.json"
$Manifest = @{
    name = $HostName
    description = "BitNet Password Manager Native Host"
    path = $HostExe
    type = "stdio"
    allowed_origins = $allowedOrigins
    allowed_extensions = @("bitnet@bitnet.dev")
} | ConvertTo-Json -Depth 3

$Manifest | Set-Content -Path $ManifestPath -Encoding UTF8
Write-Host "[OK] Manifest written to: $ManifestPath" -ForegroundColor Green
if (-not $ExtensionId) {
    Write-Host "[WARN] allowed_origins is wildcard. For production, run with -ExtensionId your_id" -ForegroundColor Yellow
}

# Register for Chrome
if (-not (Test-Path (Split-Path $ChromeRegistryPath -Parent))) {
    New-Item -Path (Split-Path $ChromeRegistryPath -Parent) -Force | Out-Null
}
New-Item -Path $ChromeRegistryPath -Force | Out-Null
Set-ItemProperty -Path $ChromeRegistryPath -Name "(Default)" -Value $ManifestPath
Write-Host "[OK] Chrome registry key: $ChromeRegistryPath" -ForegroundColor Green

# Register for Edge
if (-not (Test-Path (Split-Path $EdgeRegistryPath -Parent))) {
    New-Item -Path (Split-Path $EdgeRegistryPath -Parent) -Force | Out-Null
}
New-Item -Path $EdgeRegistryPath -Force | Out-Null
Set-ItemProperty -Path $EdgeRegistryPath -Name "(Default)" -Value $ManifestPath
Write-Host "[OK] Edge registry key: $EdgeRegistryPath" -ForegroundColor Green

# Register for Firefox
if (-not (Test-Path (Split-Path $FirefoxRegistryPath -Parent))) {
    New-Item -Path (Split-Path $FirefoxRegistryPath -Parent) -Force | Out-Null
}
New-Item -Path $FirefoxRegistryPath -Force | Out-Null
Set-ItemProperty -Path $FirefoxRegistryPath -Name "(Default)" -Value $ManifestPath
Write-Host "[OK] Firefox registry key: $FirefoxRegistryPath" -ForegroundColor Green

Write-Host "`nBitNet Native Messaging host installed successfully!" -ForegroundColor Cyan
Write-Host "`nNext steps:"
Write-Host "  1. Open Chrome/Edge/Firefox and navigate to extensions page"
Write-Host "  2. Enable 'Developer mode' (Chrome/Edge) or 'Debug Add-ons' (Firefox)"
Write-Host "  3. Click 'Load unpacked' / 'Load Temporary Add-on' and select:"
Write-Host "     $(Join-Path $ProjectRoot "browser-extension")"
Write-Host "  4. The extension will communicate with:"
Write-Host "     $HostExe"