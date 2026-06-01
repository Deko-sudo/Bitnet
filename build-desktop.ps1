#requires -Version 5.1
param(
    [ValidateSet("Debug","Release")]
    [string]$Configuration = "Debug",
    [ValidateSet("x64","x86","ARM64")]
    [string]$Platform = "x64"
)

$ErrorActionPreference = "Stop"

$RepoRoot    = Split-Path -Parent $PSScriptRoot
$DesktopDir  = Join-Path $RepoRoot "BitNet.Desktop"
$MsBuildPath = "${env:ProgramFiles}\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe"

# Fallback: search for MSBuild via vswhere
if (-not (Test-Path $MsBuildPath)) {
    $VsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $VsWhere) {
        $VsInstall = & $VsWhere -latest -products * -requires Microsoft.Component.MSBuild -property installationPath
        if ($VsInstall) {
            $MsBuildPath = Join-Path $VsInstall "MSBuild\Current\Bin\MSBuild.exe"
        }
    }
}

if (-not (Test-Path $MsBuildPath)) {
    Write-Error "MSBuild.exe not found. Install Visual Studio 2022 with 'Universal Windows Platform' workload."
    exit 1
}

Write-Host "=== BitNet Desktop (WinUI 3) Build ===" -ForegroundColor Cyan
Write-Host "MSBuild : $MsBuildPath"
Write-Host "Config  : $Configuration"
Write-Host "Platform: $Platform"
Write-Host ""

# Build Rust workspace first
Write-Host "[1/3] Building Rust workspace..." -ForegroundColor Yellow
$RustDir = Join-Path $RepoRoot "bitnet"
Push-Location $RustDir
try {
    cargo build --release --workspace
    if ($LASTEXITCODE -ne 0) { throw "Rust build failed" }
} finally { Pop-Location }

# Copy native binaries
Write-Host "[2/3] Copying native binaries..." -ForegroundColor Yellow
$NativeDir = Join-Path $DesktopDir "Native"
$OutputDir = Join-Path $DesktopDir "bin\$Platform\$Configuration\net9.0-windows10.0.19041.0"
if (-not (Test-Path $NativeDir)) { New-Item -ItemType Directory -Path $NativeDir | Out-Null }
Copy-Item -Force (Join-Path $RustDir "target\release\bitnet_ffi.dll") $NativeDir
Copy-Item -Force (Join-Path $RustDir "target\release\bitnet-native-host.exe") $NativeDir

# Build Desktop
Write-Host "[3/3] Building WinUI 3 Desktop..." -ForegroundColor Yellow
& $MsBuildPath `
    (Join-Path $DesktopDir "BitNet.Desktop.csproj") `
    /t:Build `
    /p:Configuration=$Configuration `
    /p:Platform=$Platform `
    /restore

if ($LASTEXITCODE -ne 0) { throw "Desktop build failed" }

# Post-build: copy DLL to output
Copy-Item -Force (Join-Path $NativeDir "bitnet_ffi.dll") $OutputDir
Copy-Item -Force (Join-Path $NativeDir "bitnet-native-host.exe") $OutputDir

Write-Host ""
Write-Host "SUCCESS!" -ForegroundColor Green
Write-Host "EXE: $OutputDir\BitNet.Desktop.exe"
Write-Host ""
Write-Host "Launch: .\BitNet.Desktop\bin\$Platform\$Configuration\net9.0-windows10.0.19041.0\BitNet.Desktop.exe"
