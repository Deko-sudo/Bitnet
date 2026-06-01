# Zed IDE Setup for BitNet

## 🚀 Quick Start

Open this folder in Zed. All configurations are in `.zed/`.

### Run Tasks (`Ctrl+Shift+T`)
- **🦀 Rust: build debug/release** — compile Rust workspace
- **🦀 Rust: test** — run all Rust tests
- **📟 CLI: * ** — run CLI commands
- **🔷 C# Demo: build debug** — build console demo
- **🖥️ WPF: build debug** — build WPF GUI
- **🖥️ WPF: run** — launch WPF window
- **🪟 WinUI 3: build (MSBuild)** — build WinUI 3 (requires VS2022)
- **🪟 WinUI 3: run** — launch WinUI 3 Desktop app

### Debug (`Ctrl+Shift+D` or `debug: open`)

Pick a configuration and press F5 to start debugging.

#### 🦀 Rust debugging (via LLDB)
Requires **LLVM** installed (provides `lldb-dap`).

Available configs:
- `🦀 Rust: debug CLI (generate)` — debug `bitnet-cli generate`
- `🦀 Rust: debug CLI (unlock)` — debug `bitnet-cli unlock`
- `🦀 Rust: debug tests (bitnet-cli)` — debug test binary

Breakpoints work in `.rs` files. Watch/stack/locals panels available.

#### 🔷 C# debugging (via netcoredbg)
Requires **netcoredbg** installed (Samsung DAP adapter for .NET).

Available configs:
- `🔷 C# Demo: debug (console)` — debug `BitNet.Demo`
- `🔷 C# WPF: debug` — debug `BitNet.Wpf` GUI
- `🪟 WinUI 3: attach to Desktop` — attach to running WinUI 3 process

Breakpoints work in `.cs` files.

### Keybindings
| Action | Key |
|---|---|
| Task palette | `Ctrl+Shift+T` |
| Debug panel | `Ctrl+Shift+D` |
| Start debug (F5) | `F5` |
| Step over | `F10` |
| Step into | `F11` |
| Continue | `F5` |
| Terminal | `` Ctrl+` `` |

## 🔧 Installed Tools

| Tool | Purpose | Install path |
|---|---|---|
| `rust-analyzer` | Rust LSP | `~/.cargo/bin` |
| `csharp-ls` | C# LSP | `dotnet tool -g` |
| `lldb-dap.exe` | Rust debugger (DAP) | `C:\Program Files\LLVM\bin` |
| `netcoredbg.exe` | C# debugger (DAP) | `WinGet\Packages\Samsung.NetCoreDbg...` |
| `MSBuild.exe` | WinUI 3 build | `VS2022 Community` |
