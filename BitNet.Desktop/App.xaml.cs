using Microsoft.UI.Xaml;
using BitNet.Desktop.Helpers;

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
            MainWindow = new MainWindow();
            MainWindow.Closed += (s, e) => {
                if (!string.IsNullOrEmpty(VaultPath))
                {
                    WindowsHelloHelper.RemoveCredential(VaultPath);
                }
                BitNet.Desktop.Native.BitnetCore.bitnet_vault_lock();
            };
            MainWindow.Activate();
        }
    }
}
