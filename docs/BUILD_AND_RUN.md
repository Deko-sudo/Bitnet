# BitNet — Build & Run Guide

## Build Status (Last Verified)

| Компонент | Статус | Команда |
|-----------|--------|---------|
| Rust workspace | OK | `cargo build --release --workspace` |
| Rust tests (111+) | OK | `cargo test --workspace` |
| C# FFI roundtrip (7/7) | OK | `dotnet test BitNet.Desktop.Tests/` |
| Playwright E2E (5/5) | OK | `npx playwright test` |
| **C# WinUI 3 Desktop** | **REQUIRES VISUAL STUDIO BUILD TOOLS** | `dotnet build BitNet.Desktop/` |

## Desktop Build Issue (Known)

The WinUI 3 desktop app (`BitNet.Desktop/`) requires **Visual Studio Build Tools 2022** with:
- **.NET desktop build tools** workload
- **MSIX Packaging Tools** (provides `Microsoft.Build.Packaging.Pri.Tasks.dll`)

This DLL is NOT included in the standalone .NET SDK. Without it, you get:

```
error MSB4062: Не удалось загрузить задачу "Microsoft.Build.Packaging.Pri.Tasks.ExpandPriContent"
из сборки "...\Microsoft.Build.Packaging.Pri.Tasks.dll".
```

## Build Steps (Windows)

### Step 1 — Install Visual Studio Build Tools 2022

#### Option A: winget (Recommended)
```powershell
winget install Microsoft.VisualStudio.2022.BuildTools --override "--quiet --add Microsoft.VisualStudio.Workload.UniversalBuildTools"
```

#### Option B: Manual download
1. Go to https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022
2. Download "Build Tools for Visual Studio 2022"
3. Run installer, select:
   - ✅ **.NET desktop build tools**
   - ✅ **MSIX Packaging Tools**
   - ✅ **Windows 10/11 SDK** (latest)
4. Click Install (~3-5 GB)

### Step 2 — Verify installation
```powershell
where.exe Microsoft.Build.Packaging.Pri.Tasks.dll
# Should show: C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Microsoft\VisualStudio\v17.0\AppxPackage\Microsoft.Build.Packaging.Pri.Tasks.dll
```

### Step 3 — Set environment variables (if not auto-detected)
```powershell
$env:VSINSTALLDIR = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools"
$env:VisualStudioVersion = "17.0"
```

### Step 4 — Build BitNet Desktop

```powershell
cd D:\BitNet\BitNet.Desktop
dotnet build -c Release
```

Expected: `Build succeeded. 0 Errors. 14 Warnings (nullable annotations).`

### Step 5 — Run

```powershell
dotnet run -c Release
```

## Pre-build Verification (Before Step 4)

Always run these first to catch Rust-side issues:

```powershell
cd D:\BitNet
cargo clippy --workspace -- -D warnings
cargo test --workspace
```

## Native FFI Pre-requisite

`BitNet.Desktop` requires `bitnet_ffi.dll` in `Native/`:
```powershell
cargo build --release -p bitnet-ffi
cp target\release\bitnet_ffi.dll BitNet.Desktop\Native\
```

## See Also

- `docs/BUILD_REQUIREMENTS.md` — Full system requirements
- `docs/QUICKSTART.md` — 5-minute CLI setup
- `docs/BUG_BOUNTY.md` — Bug bounty program
- `SECURITY.md` — Security policy
