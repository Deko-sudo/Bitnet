@echo off
setlocal

set CONFIG=%1
if "%CONFIG%"=="" set CONFIG=Debug

echo === BitNet WPF Build ===
echo.

echo [1/2] Building Rust workspace...
cd /d "%~dp0bitnet"
cargo build --release --workspace
if %ERRORLEVEL% neq 0 exit /b 1

echo.
echo [2/2] Building WPF...
cd /d "%~dp0BitNet.Wpf"
dotnet build -c %CONFIG%
if %ERRORLEVEL% neq 0 exit /b 1

echo.
echo SUCCESS!
echo Launch: dotnet run --project BitNet.Wpf
endlocal
