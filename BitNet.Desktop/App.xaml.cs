using Microsoft.UI.Xaml;

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
            MainWindow.Activate();
        }
    }
}
