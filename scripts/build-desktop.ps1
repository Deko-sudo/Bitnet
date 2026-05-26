#Requires -Version 5.1
<#
.SYNOPSIS
    Build script for BitNet Desktop (WinUI 3 + Rust FFI).

.DESCRIPTION
    Builds the Rust workspace in release mode, copies DLL to Desktop project,
    and compiles the WinUI 3 app via MSBuild or dotnet CLI.

.REQUIREMENTS
    - Visual Studio 2022 with "Windows application development" workload
    - Windows App SDK 1.6+ (via VS Installer or standalone)
    - .NET 8 SDK
    - Rust toolchain (cargo)
#>

[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",

    [ValidateSet("x64", "x86", "ARM64")]
    [string]$Platform = "x64",

    [switch]$SkipRust,
    [switch]$SkipDesktop,
    [switch]$CreateInstaller
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$DesktopDir = Join-Path $ProjectRoot "BitNet.Desktop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  BitNet Desktop Build Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# 1. Build Rust workspace
# ---------------------------------------------------------------------------
if (-not $SkipRust) {
    Write-Host "`n[1/4] Building Rust workspace ($Configuration)..." -ForegroundColor Yellow
    Set-Location $ProjectRoot

    $cargoConfig = @"
[target.x86_64-pc-windows-msvc]
rustflags = ["-C", "link-arg=/guard:cf", "-C", "link-arg=/DYNAMICBASE", "-C", "link-arg=/CETCOMPAT"]
"@
    $cargoConfig | Set-Content -Path (Join-Path $ProjectRoot ".cargo\config.toml") -Encoding UTF8 -Force

    cargo build --release --workspace
    if ($LASTEXITCODE -ne 0) { throw "Rust build failed" }

    Write-Host "[OK] Rust build completed" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# 2. Copy native artifacts
# ---------------------------------------------------------------------------
if (-not $SkipRust) {
    Write-Host "`n[2/4] Copying native artifacts..." -ForegroundColor Yellow
    $srcDll = Join-Path $ProjectRoot "target\release\bitnet_ffi.dll"
    $srcHost = Join-Path $ProjectRoot "target\release\bitnet-native-host.exe"
    $destDir = Join-Path $DesktopDir "Native"

    if (-not (Test-Path $srcDll)) { throw "bitnet_ffi.dll not found. Build Rust first." }
    if (-not (Test-Path $srcHost)) { throw "bitnet-native-host.exe not found. Build Rust first." }

    Copy-Item $srcDll $destDir -Force
    Copy-Item $srcHost $destDir -Force
    Write-Host "[OK] Artifacts copied to $destDir" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# 3. Build WinUI 3 Desktop app
# ---------------------------------------------------------------------------
if (-not $SkipDesktop) {
    Write-Host "`n[3/4] Building WinUI 3 Desktop app ($Configuration | $Platform)..." -ForegroundColor Yellow

    # Find MSBuild
    $vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    $msbuild = $null
    if (Test-Path $vsWhere) {
        $msbuild = & $vsWhere -latest -products * -requires Microsoft.Component.MSBuild -property installationPath
        if ($msbuild) {
            $msbuild = Join-Path $msbuild "MSBuild\Current\Bin\MSBuild.exe"
        }
    }

    if (-not $msbuild -or -not (Test-Path $msbuild)) {
        # Fallback: try dotnet build
        Write-Host "MSBuild not found, trying dotnet build..." -ForegroundColor Yellow
        Set-Location $DesktopDir
        dotnet build BitNet.Desktop.csproj -c $Configuration -p:Platform=$Platform
        if ($LASTEXITCODE -ne 0) { throw "Desktop build failed" }
    } else {
        Write-Host "Using MSBuild: $msbuild" -ForegroundColor Gray
        Set-Location $DesktopDir
        & $msbuild BitNet.Desktop.csproj /p:Configuration=$Configuration /p:Platform=$Platform /restore
        if ($LASTEXITCODE -ne 0) { throw "Desktop build failed" }
    }

    Write-Host "[OK] Desktop build completed" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# 4. Create installer (optional)
# ---------------------------------------------------------------------------
if ($CreateInstaller) {
    Write-Host "`n[4/4] Creating installer..." -ForegroundColor Yellow
    $innoScript = Join-Path $ProjectRoot "scripts\bitnet-setup.iss"
    if (Test-Path $innoScript) {
        $iscc = "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe"
        if (Test-Path $iscc) {
            & $iscc $innoScript
            Write-Host "[OK] Installer created" -ForegroundColor Green
        } else {
            Write-Warning "Inno Setup not found. Skipping installer creation."
        }
    } else {
        Write-Warning "Inno Setup script not found at $innoScript"
    }
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Build completed successfully!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan