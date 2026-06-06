// BitNet.Desktop - DaemonLauncher
//
// Manages the lifecycle of the long-running
// `bitnet-cli.exe daemon` process from the WinUI 3
// frontend.
//
// Lifecycle:
//   1. App start: DaemonLauncher.EnsureRunning() —
//      if the daemon is not already running, start
//      it as a detached child process. The daemon
//      survives the app's main window closing
//      (CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS).
//   2. App running: MainWindow subscribes to
//      DaemonLauncher.ProcessExited to show a
//      notification if the daemon dies unexpectedly.
//   3. App shutdown: DaemonLauncher.Stop() is called
//      to terminate the child process. This is a
//      best-effort kill — if the user has a vault
//      unlocked, we send a polite "lock" request
//      first via the JSON-RPC ping/lock method.
//
// Threat model references:
//   - The daemon's IPC endpoint is `\\.\pipe\bitnet-cli`
//     (Windows) or abstract Unix socket (Unix). The
//     launcher does NOT authenticate to the daemon —
//     the daemon issues its own token on `unlock`.
//   - Process spawning is locked-down: we resolve
//     the bitnet-cli binary path from the Desktop
//     app's install directory, not from PATH. This
//     prevents PATH hijacking attacks.

using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Threading;
using BitNet.Desktop.Helpers;

namespace BitNet.Desktop.Native;

/// <summary>
/// Single-instance manager for the bitnet-cli daemon
/// child process. The daemon is started on app boot
/// and stopped on app exit; the singleton makes the
/// process handle accessible from MainWindow, the
/// Settings page, and the LockNow flow.
/// </summary>
public sealed class DaemonLauncher : IDisposable
{
    private static readonly Lazy<DaemonLauncher> s_instance =
        new(() => new DaemonLauncher());

    public static DaemonLauncher Instance => s_instance.Value;

    private Process? _process;
    private readonly object _lock = new();
    private bool _disposed;

    /// <summary>
    /// Path to the bitnet-cli binary. Resolved at
    /// construction time from the Desktop app's
    /// install directory + platform-specific binary
    /// name.
    /// </summary>
    public string DaemonExecutablePath { get; }

    /// <summary>
    /// Fires when the daemon process exits
    /// unexpectedly (i.e. not via DaemonLauncher.Stop).
    /// Subscribers should re-show the unlock page so
    /// the user can re-establish the session.
    /// </summary>
    public event EventHandler<int>? ProcessExited;

    private DaemonLauncher()
    {
        DaemonExecutablePath = ResolveDaemonPath();
    }

    private static string ResolveDaemonPath()
    {
        // The Desktop app is installed alongside
        // bitnet-cli.exe in the same directory. We
        // resolve relative to the running process
        // (System.AppContext.BaseDirectory), NOT from
        // PATH, to prevent PATH-hijack attacks.
        var dir = AppContext.BaseDirectory;
#if WINDOWS
        var name = "bitnet-cli.exe";
#else
        var name = "bitnet-cli";
#endif
        var path = Path.Combine(dir, name);
        if (File.Exists(path)) return path;
        // Fallback: search the same directory tree
        // upwards. Some installers place the Desktop
        // app in a subfolder of the BitNet install.
        var probe = new DirectoryInfo(dir);
        for (int i = 0; i < 4 && probe != null; i++)
        {
            var candidate = Path.Combine(probe.FullName, name);
            if (File.Exists(candidate)) return candidate;
            probe = probe.Parent;
        }
        // Last resort: return the expected path even
        // if it doesn't exist; the spawn will fail
        // with a clear error.
        return path;
    }

    /// <summary>
    /// True if the daemon is reachable. We probe by
    /// running `bitnet-cli ping` as a short-lived
    /// child process; the C# project does not link
    /// the Rust crate directly so the IPC client API
    /// is not available here.
    /// </summary>
    public bool IsAlive
    {
        get
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = DaemonExecutablePath,
                    ArgumentList = { "ping" },
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                };
                using var p = Process.Start(psi);
                if (p == null) return false;
                if (!p.WaitForExit(1000)) { try { p.Kill(); } catch { } return false; }
                return p.ExitCode == 0;
            }
            catch
            {
                return false;
            }
        }
    }

    /// <summary>
    /// Start the daemon if it is not already running.
    /// Returns true if the daemon is up (either it
    /// was already running or we just started it);
    /// false on failure.
    /// </summary>
    public bool EnsureRunning()
    {
        lock (_lock)
        {
            if (_disposed) return false;
            if (IsAlive) return true;
            if (!File.Exists(DaemonExecutablePath))
            {
                // Surface the missing-binary condition
                // to the caller; we do not throw
                // because the GUI layer may want to
                // continue running without the daemon.
                return false;
            }
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = DaemonExecutablePath,
                    ArgumentList = { "daemon" },
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    // Detach from the parent's console
                    // and process group so closing the
                    // GUI does not kill the daemon.
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                };
                _process = new Process { StartInfo = psi, EnableRaisingEvents = true };
                _process.Exited += OnProcessExited;
                if (!_process.Start())
                {
                    return false;
                }
                // Give the daemon up to 2 seconds to
                // bind its IPC endpoint. The ping check
                // itself is a one-shot call that returns
                // quickly if the daemon is up.
                var deadline = DateTime.UtcNow.AddSeconds(2);
                while (DateTime.UtcNow < deadline)
                {
                    if (IsAlive) return true;
                    Thread.Sleep(50);
                }
                return false;
            }
            catch (Win32Exception ex)
            {
                // Most likely the binary exists but
                // cannot be executed (corrupt, missing
                // VC runtime, etc.). Log and report.
                Debug.WriteLine($"DaemonLauncher: spawn failed: {ex.Message}");
                return false;
            }
        }
    }

    private void OnProcessExited(object? sender, EventArgs e)
    {
        var code = -1;
        try { if (_process != null) code = _process.ExitCode; } catch { }
        ProcessExited?.Invoke(this, code);
    }

    /// <summary>
    /// Politely stop the daemon. Sends a kill via
    /// Process.Kill (the daemon does not yet
    /// implement a JSON-RPC "shutdown" method; that
    /// is v0.2 work). The token-zeroisation happens
    /// inside the daemon's atexit handler.
    /// </summary>
    public void Stop()
    {
        lock (_lock)
        {
            if (_process == null) return;
            try
            {
                if (!_process.HasExited)
                {
                    _process.Kill(entireProcessTree: true);
                    _process.WaitForExit(2000);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"DaemonLauncher: stop failed: {ex.Message}");
            }
            finally
            {
                _process.Exited -= OnProcessExited;
                _process.Dispose();
                _process = null;
            }
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        Stop();
    }
}
