#requires -Version 5.1
$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot

function Step($n, $total, $name) {
    Write-Host "" 
    Write-Host "[$n/$total] $name" -ForegroundColor Cyan
    Write-Host ("-" * 50)
}

# 1. Build Rust
Step 1 4 "Building Rust workspace"
Push-Location (Join-Path $RepoRoot "bitnet")
try {
    cargo build --release --workspace
    if ($LASTEXITCODE -ne 0) { throw "Rust build failed" }
} finally { Pop-Location }

# 2. CLI Demo
Step 2 4 "CLI Quick Demo"
$Cli = Join-Path $RepoRoot "bitnet\target\release\bitnet-cli.exe"
& $Cli generate --length 20
Write-Host ""
& $Cli info demo.bitnet

# 3. C# FFI Demo
Step 3 4 "C# FFI Console Demo"
Push-Location (Join-Path $RepoRoot "BitNet.Demo")
try {
    dotnet run
} finally { Pop-Location }

# 4. WPF GUI
Step 4 4 "WPF GUI (will open a window)"
Push-Location (Join-Path $RepoRoot "BitNet.Wpf")
try {
    Start-Process dotnet -ArgumentList "run" -Wait
} finally { Pop-Location }

Write-Host ""
Write-Host "All done!" -ForegroundColor Green
Write-Host "For WinUI 3 Desktop, run: .\build-desktop.ps1" -ForegroundColor Yellow
