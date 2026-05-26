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
        }

        private void ContentFrame_Navigated(object sender, Microsoft.UI.Xaml.Navigation.NavigationEventArgs e)
        {
            if (e.SourcePageType == typeof(Views.UnlockPage))
            {
                NavView.Visibility = Visibility.Collapsed;
            }
            else
            {
                NavView.Visibility = Visibility.Visible;
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
