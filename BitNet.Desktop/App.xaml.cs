using Microsoft.UI.Xaml;
using BitNet.Desktop.Helpers;
using BitNet.Desktop.Native;

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
            catch
            {
                // swallow; the GUI works without the
                // daemon.
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
                BitnetCore.bitnet_vault_lock();
                DaemonLauncher.Instance.Dispose();
                if (!string.IsNullOrEmpty(VaultPath))
                {
                    WindowsHelloHelper.RemoveCredential(VaultPath);
                }
            };
            MainWindow.Activate();
        }
    }
}
