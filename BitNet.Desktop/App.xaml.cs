using Microsoft.UI.Xaml;
using BitNet.Desktop.Helpers;
using BitNet.Desktop.Native;
using System;

namespace BitNet.Desktop
{
    public partial class App : Application
    {
        public static Window? MainWindow { get; private set; }
        public static string VaultPath { get; set; } = "";

        public App()
        {
            this.InitializeComponent();
        }

        protected override void OnLaunched(LaunchActivatedEventArgs args)
        {
            // Start the bitnet-cli daemon as a detached
            // child process BEFORE the main window is
            // shown. The daemon survives this app's
            // lifetime (it has no parent window) so the
            // browser extension and other clients can
            // attach to it as long as the user is
            // logged in. The launcher is best-effort:
            // if the binary is missing or the spawn
            // fails, the GUI still works in standalone
            // mode (the FFI calls the Rust core
            // directly).
            try
            {
                DaemonLauncher.Instance.EnsureRunning();
            }
            catch (Exception ex)
            {
                // [BITNET-I2] CWE-396: log the failure
                // type and message so missing DLLs, VC
                // runtime issues, or permission errors
                // are visible in the diagnostic log. The
                // GUI still works without the daemon
                // (FFI calls go directly to the Rust
                // core in-process), so we do not
                // propagate the exception.
                System.Diagnostics.Debug.WriteLine(
                    $"DaemonLauncher.EnsureRunning failed: {ex.Message}");
            }

            MainWindow = new MainWindow();
            MainWindow.Closed += (s, e) =>
            {
                // On app exit: lock the vault (zeroises
                // the in-process session token) and
                // stop the daemon so we don't leave a
                // child process running after the user
                // closes the window. The user can opt
                // out by setting the auto-launch flag
                // (v0.2 work).
                //
                // [BITNET-M12] CWE-754: each step is
                // wrapped in its own try/catch so an
                // FFI panic in one step (e.g. the
                // native DLL unloaded mid-shutdown) does
                // not skip a later step. The previous
                // version ran `bitnet_vault_lock` and
                // `WindowsHelloHelper.RemoveCredential`
                // sequentially with no per-step
                // isolation; a panic in the first call
                // would leave the WindowsHello credential
                // intact while the vault was still
                // technically unlocked, locking the user
                // out of the next session.
                try
                {
                    BitnetCore.bitnet_vault_lock();
                }
                catch (Exception ex)
                {
                    // [BITNET-I2] log the failure so it is
                    // not silent; the message helps
                    // operators diagnose the cause.
                    System.Diagnostics.Debug.WriteLine(
                        $"vault_lock failed on close: {ex.Message}");
                }

                try
                {
                    DaemonLauncher.Instance.Dispose();
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine(
                        $"daemon stop failed on close: {ex.Message}");
                }

                if (!string.IsNullOrEmpty(VaultPath))
                {
                    try
                    {
                        WindowsHelloHelper.RemoveCredential(VaultPath);
                    }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Debug.WriteLine(
                            $"RemoveCredential failed on close: {ex.Message}");
                    }
                }
            };
            MainWindow.Activate();
        }
    }
}
