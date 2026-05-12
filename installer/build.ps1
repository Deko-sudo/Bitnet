$ErrorActionPreference = "Stop"

$ROOT = Split-Path -Parent $PSScriptRoot
$INSTALLER_DIR = $PSScriptRoot
$DIST_DIR = Join-Path $INSTALLER_DIR "dist"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " BitNet Windows Installer Build Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$env:BITNET_SERVER_WRAP_KEY_FILE = Join-Path $env:APPDATA "BitNet\server_key.txt"

if (Test-Path $DIST_DIR) {
    Remove-Item -Recurse -Force $DIST_DIR
}

Write-Host "[1/4] Building frontend..." -ForegroundColor Yellow
Push-Location (Join-Path $ROOT "frontend")
npm run build 2>&1 | Write-Host
if ($LASTEXITCODE -ne 0) { throw "Frontend build failed" }
Pop-Location
Write-Host "      Frontend built OK" -ForegroundColor Green

Write-Host "[2/4] Verifying Rust crypto bridge..." -ForegroundColor Yellow
Push-Location $ROOT
python -c "from backend.core import bitnet_crypto_rs; print('  Crypto bridge OK')" 2>&1 | Write-Host
if ($LASTEXITCODE -ne 0) { throw "Crypto bridge import failed" }
Pop-Location
Write-Host "      Crypto bridge OK" -ForegroundColor Green

Write-Host "[3/4] Building PyInstaller bundle..." -ForegroundColor Yellow
Push-Location $INSTALLER_DIR

$env:PYTHONDONTWRITEBYTECODE = "1"

python -m PyInstaller bitnet.spec `
    --workpath (Join-Path $DIST_DIR "build") `
    --distpath (Join-Path $DIST_DIR "dist") `
    --noconfirm `
    2>$null

if ($LASTEXITCODE -ne 0) { throw "PyInstaller build failed" }
Pop-Location
Write-Host "      PyInstaller bundle OK" -ForegroundColor Green

$nsisPath = "C:\Program Files (x86)\NSIS\makensis.exe"
if (-not (Test-Path $nsisPath)) {
    $nsisPath = Get-Command makensis -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
}

if ($nsisPath -and (Test-Path $nsisPath)) {
    Write-Host "[4/4] Building NSIS installer..." -ForegroundColor Yellow
    Push-Location $INSTALLER_DIR
    & $nsisPath bitnet.nsi 2>&1 | Write-Host
    if ($LASTEXITCODE -ne 0) { throw "NSIS build failed" }
    Pop-Location
    Write-Host "      NSIS installer OK" -ForegroundColor Green
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host " Build complete!" -ForegroundColor Green
    Write-Host " Installer: $INSTALLER_DIR\BitNet-2.2.0-setup.exe" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
} else {
    Write-Host "[4/4] NSIS not found - skipping installer .exe" -ForegroundColor Yellow
    Write-Host "      Install NSIS from https://nsis.sourceforge.net to build the installer" -ForegroundColor Yellow
    Write-Host "      Then run: makensis bitnet.nsi" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host " PyInstaller bundle complete!" -ForegroundColor Green
    Write-Host " Bundle: $DIST_DIR\dist\BitNet\" -ForegroundColor Green
    Write-Host " Run: $DIST_DIR\dist\BitNet\BitNet.exe" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
}

Write-Host ""
Write-Host "To run BitNet without installer:" -ForegroundColor Cyan
Write-Host "  $DIST_DIR\dist\BitNet\BitNet.exe" -ForegroundColor White
Write-Host ""
Write-Host "The app will start on http://127.0.0.1:8200" -ForegroundColor Cyan