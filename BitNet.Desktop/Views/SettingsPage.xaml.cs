using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using BitNet.Desktop.Native;

namespace BitNet.Desktop.Views
{
    public sealed partial class SettingsPage : Page
    {
        public SettingsPage()
        {
            this.InitializeComponent();
            AutoLockValueLabel.Text = $"{AutoLockSlider.Value} minutes";
        }

        private void AutoLockSlider_ValueChanged(object sender, RangeBaseValueChangedEventArgs e)
        {
            if (AutoLockValueLabel != null)
            {
                AutoLockValueLabel.Text = $"{e.NewValue} minutes";
            }
        }

        private void LockNow_Click(object sender, RoutedEventArgs e)
        {
            BitnetCore.bitnet_vault_lock();
            // Navigate to unlock page via the root frame
            var rootFrame = ((Microsoft.UI.Xaml.Controls.Panel)this.XamlRoot.Content).FindName("ContentFrame") as Frame;
            if (rootFrame != null)
            {
                rootFrame.Navigate(typeof(UnlockPage));
            }
            else
            {
                // Fallback: use Window.Content frame
                if (App.MainWindow?.Content is Panel panel)
                {
                    var frame = panel.FindName("ContentFrame") as Frame;
                    frame?.Navigate(typeof(UnlockPage));
                }
            }
        }
    }
}
