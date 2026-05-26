@echo off
setlocal

set "HOST_NAME=com.bitnet.nativehost"
set "EXE_PATH=%~dp0target\release\bitnet-native-host.exe"
set "CHROME_REG=HKEY_CURRENT_USER\Software\Google\Chrome\NativeMessagingHosts\%HOST_NAME%"
set "EDGE_REG=HKEY_CURRENT_USER\Software\Microsoft\Edge\NativeMessagingHosts\%HOST_NAME%"
set "FIREFOX_REG=HKEY_CURRENT_USER\Software\Mozilla\NativeMessagingHosts\%HOST_NAME%"

if not exist "%EXE_PATH%" (
    echo ERROR: bitnet-native-host.exe not found at %EXE_PATH%
    echo Please build the project first: cargo build --release --workspace
    exit /b 1
)

reg add "%CHROME_REG%" /ve /t REG_SZ /d "%~dp0browser-extension\%HOST_NAME%.json" /f
if %errorlevel% neq 0 (
    echo Failed to register Chrome native messaging host.
    exit /b 1
)

echo [OK] Chrome Native Messaging host registered.

reg add "%EDGE_REG%" /ve /t REG_SZ /d "%~dp0browser-extension\%HOST_NAME%.json" /f
if %errorlevel% neq 0 (
    echo Failed to register Edge native messaging host.
    exit /b 1
)

echo [OK] Edge Native Messaging host registered.

reg add "%FIREFOX_REG%" /ve /t REG_SZ /d "%~dp0browser-extension\%HOST_NAME%.json" /f
if %errorlevel% neq 0 (
    echo Failed to register Firefox native messaging host.
    exit /b 1
)

echo [OK] Firefox Native Messaging host registered.
echo.
echo BitNet Native Messaging host installed for Chrome, Edge, and Firefox.
echo Extension ID: bitnet@bitnet.dev
