using BitNet.Desktop.Helpers;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace BitNet.Desktop
{
    public sealed partial class MainWindow : Window
    {
        public MainWindow()
        {
            this.InitializeComponent();
            ExtendsContentIntoTitleBar = true;
            SetTitleBar(null);
            NavView.Visibility = Visibility.Collapsed;
            ContentFrame.Navigate(typeof(Views.UnlockPage));
            ContentFrame.Navigated += ContentFrame_Navigated;

            // Wire up the AutoLockService. When the idle
            // timer fires, we navigate back to the unlock
            // page (which discards any in-memory secrets)
            // and clear the clipboard just in case.
            AutoLockService.Instance.Load();
            AutoLockService.Instance.AutoLock += (_, _) =>
            {
                DispatcherQueue.TryEnqueue(() =>
                {
                    ClipboardHelper.ClearClipboard();
                    ContentFrame.Navigate(typeof(Views.UnlockPage));
                });
            };
        }

        private void ContentFrame_Navigated(object sender, Microsoft.UI.Xaml.Navigation.NavigationEventArgs e)
        {
            if (e.SourcePageType == typeof(Views.UnlockPage))
            {
                NavView.Visibility = Visibility.Collapsed;
                // Entering the unlock page means the vault
                // is locked; the AutoLockService no longer
                // needs to fire.
                AutoLockService.Instance.LockNow();
            }
            else
            {
                NavView.Visibility = Visibility.Visible;
                // Successful navigation to a non-unlock
                // page = successful unlock. Reset the idle
                // timer.
                AutoLockService.Instance.Reset();
            }
        }

        private void NavView_SelectionChanged(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
        {
            if (args.SelectedItem is NavigationViewItem item)
            {
                var tag = item.Tag?.ToString();
                switch (tag)
                {
                    case "vault":
                        ContentFrame.Navigate(typeof(Views.VaultPage));
                        break;
                    case "generator":
                        ContentFrame.Navigate(typeof(Views.GeneratorPage));
                        break;
                    case "settings":
                        ContentFrame.Navigate(typeof(Views.SettingsPage));
                        break;
                }
            }
        }
    }
}
