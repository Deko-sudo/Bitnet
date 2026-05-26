#Requires -Version 5.1
<#
.SYNOPSIS
    Uninstalls BitNet Native Messaging host from Chrome, Edge, and Firefox.
#\u003e

[CmdletBinding()]
param(
    [string]$HostName = "com.bitnet.nativehost",
    [string]$ChromeRegistryPath = "HKCU:\Software\Google\Chrome\NativeMessagingHosts\$HostName",
    [string]$EdgeRegistryPath = "HKCU:\Software\Microsoft\Edge\NativeMessagingHosts\$HostName",
    [string]$FirefoxRegistryPath = "HKCU:\Software\Mozilla\NativeMessagingHosts\$HostName"
)

$ErrorActionPreference = "SilentlyContinue"

$removed = $false

if (Test-Path $ChromeRegistryPath) {
    Remove-Item -Path $ChromeRegistryPath -Recurse -Force
    Write-Host "[OK] Removed Chrome registry: $ChromeRegistryPath" -ForegroundColor Green
    $removed = $true
} else {
    Write-Host "[INFO] Chrome registry not found: $ChromeRegistryPath" -ForegroundColor Yellow
}

if (Test-Path $EdgeRegistryPath) {
    Remove-Item -Path $EdgeRegistryPath -Recurse -Force
    Write-Host "[OK] Removed Edge registry: $EdgeRegistryPath" -ForegroundColor Green
    $removed = $true
} else {
    Write-Host "[INFO] Edge registry not found: $EdgeRegistryPath" -ForegroundColor Yellow
}

if (Test-Path $FirefoxRegistryPath) {
    Remove-Item -Path $FirefoxRegistryPath -Recurse -Force
    Write-Host "[OK] Removed Firefox registry: $FirefoxRegistryPath" -ForegroundColor Green
    $removed = $true
} else {
    Write-Host "[INFO] Firefox registry not found: $FirefoxRegistryPath" -ForegroundColor Yellow
}

if ($removed) {
    Write-Host "`nBitNet Native Messaging host uninstalled." -ForegroundColor Cyan
} else {
    Write-Host "`nNothing to uninstall." -ForegroundColor Cyan
}
