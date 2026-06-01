@echo off
setlocal

set CONFIG=%1
if "%CONFIG%"=="" set CONFIG=Debug

set PLATFORM=%2
if "%PLATFORM%"=="" set PLATFORM=x64

echo === BitNet Desktop (WinUI 3) Build ===
echo Config  : %CONFIG%
echo Platform: %PLATFORM%
echo.

echo [1/3] Building Rust workspace...
cd /d "%~dp0bitnet"
cargo build --release --workspace
if %ERRORLEVEL% neq 0 exit /b 1

echo.
echo [2/3] Copying native binaries...
copy /Y "target\release\bitnet_ffi.dll" "..\BitNet.Desktop\Native\"
copy /Y "target\release\bitnet-native-host.exe" "..\BitNet.Desktop\Native\"

echo.
echo [3/3] Building WinUI 3 Desktop...
cd /d "%~dp0BitNet.Desktop"

set MSBUILD="%ProgramFiles%\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe"
if not exist %MSBUILD% (
    for /f "delims=" %%i in ('"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.Component.MSBuild -property installationPath') do set MSBUILD="%%i\MSBuild\Current\Bin\MSBuild.exe"
)

%MSBUILD% BitNet.Desktop.csproj /t:Build /p:Configuration=%CONFIG% /p:Platform=%PLATFORM% /restore
if %ERRORLEVEL% neq 0 exit /b 1

set OUTDIR=bin\%PLATFORM%\%CONFIG%\net9.0-windows10.0.19041.0
copy /Y Native\bitnet_ffi.dll %OUTDIR%\
copy /Y Native\bitnet-native-host.exe %OUTDIR%\

echo.
echo SUCCESS!
echo EXE: %OUTDIR%\BitNet.Desktop.exe
endlocal
