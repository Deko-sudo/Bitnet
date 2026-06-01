#requires -Version 5.1
param(
    [ValidateSet("Debug","Release")]
    [string]$Configuration = "Debug"
)

$ErrorActionPreference = "Stop"

$RepoRoot   = Split-Path -Parent $PSScriptRoot
$RustDir    = Join-Path $RepoRoot "bitnet"
$WpfDir     = Join-Path $RepoRoot "BitNet.Wpf"

Write-Host "=== BitNet WPF Build ===" -ForegroundColor Cyan

# Build Rust
Write-Host "[1/2] Building Rust workspace..." -ForegroundColor Yellow
Push-Location $RustDir
try {
    cargo build --release --workspace
    if ($LASTEXITCODE -ne 0) { throw "Rust build failed" }
} finally { Pop-Location }

# Copy DLL
Write-Host "[2/2] Building WPF..." -ForegroundColor Yellow
Copy-Item -Force (Join-Path $RustDir "target\release\bitnet_ffi.dll") (Join-Path $WpfDir "..\BitNet.Desktop\Native\")
Push-Location $WpfDir
try {
    dotnet build -c $Configuration
    if ($LASTEXITCODE -ne 0) { throw "WPF build failed" }
} finally { Pop-Location }

$Exe = Join-Path $WpfDir "bin\$Configuration\net9.0-windows\BitNet.Wpf.exe"
Write-Host ""
Write-Host "SUCCESS!" -ForegroundColor Green
Write-Host "EXE: $Exe"
Write-Host "Launch: dotnet run --project BitNet.Wpf"
