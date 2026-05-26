using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using BitNet.Desktop.Native;
using System;
using Windows.Storage;
using Windows.Storage.Pickers;
using WinRT.Interop;

namespace BitNet.Desktop.Views
{
    public sealed partial class UnlockPage : Page
    {
        public UnlockPage()
        {
            this.InitializeComponent();
            BitnetCore.bitnet_init();
        }

        private void UnlockButton_Click(object sender, RoutedEventArgs e)
        {
            var path = VaultPathBox.Text;
            var password = MasterPasswordBox.Password;
            if (string.IsNullOrWhiteSpace(path))
            {
                ShowError("Please select a vault file.");
                return;
            }
            if (string.IsNullOrWhiteSpace(password))
            {
                ShowError("Please enter your master password.");
                return;
            }
            var result = BitnetCore.bitnet_vault_unlock(path, password);
            if (result == 0)
            {
                ErrorText.Visibility = Visibility.Collapsed;
                App.VaultPath = path;
                Frame.Navigate(typeof(VaultPage));
            }
            else if (result == -4)
            {
                ShowError("Invalid vault path. Must be a .bitnet file.");
            }
            else
            {
                ShowError("Failed to unlock vault. Check your password and file path.");
            }
        }

        private async void CreateButton_Click(object sender, RoutedEventArgs e)
        {
            var picker = new FileSavePicker();
            picker.SuggestedStartLocation = PickerLocationId.DocumentsLibrary;
            picker.FileTypeChoices.Add("BitNet Vault", new[] { ".bitnet" });
            picker.SuggestedFileName = "MyVault";
            var hwnd = WindowNative.GetWindowHandle(App.MainWindow);
            InitializeWithWindow.Initialize(picker, hwnd);
            var file = await picker.PickSaveFileAsync();
            if (file == null) return;

            var path = file.Path;

            // Step 1: ask for master password
            var pwdDialog = new ContentDialog
            {
                Title = "Create Vault — Set Password",
                Content = new PasswordBox { PlaceholderText = "Master password" },
                PrimaryButtonText = "Next",
                CloseButtonText = "Cancel",
                XamlRoot = this.XamlRoot
            };
            var r1 = await pwdDialog.ShowAsync();
            if (r1 != ContentDialogResult.Primary) return;
            var password = (pwdDialog.Content as PasswordBox)?.Password ?? "";
            if (string.IsNullOrWhiteSpace(password)) { ShowError("Password cannot be empty."); return; }

            // Step 2: confirm password
            var confirmDialog = new ContentDialog
            {
                Title = "Create Vault — Confirm Password",
                Content = new PasswordBox { PlaceholderText = "Confirm password" },
                PrimaryButtonText = "Create",
                CloseButtonText = "Cancel",
                XamlRoot = this.XamlRoot
            };
            var r2 = await confirmDialog.ShowAsync();
            if (r2 != ContentDialogResult.Primary) return;
            var confirm = (confirmDialog.Content as PasswordBox)?.Password ?? "";

            if (password != confirm)
            {
                ShowError("Passwords do not match.");
                return;
            }

            var result = BitnetCore.bitnet_vault_create(path, password);
            if (result == 0)
            {
                App.VaultPath = path;
                ErrorText.Visibility = Visibility.Collapsed;
                Frame.Navigate(typeof(VaultPage));
            }
            else
            {
                ShowError($"Failed to create vault (error {result}).");
            }
        }

        private async void BrowseButton_Click(object sender, RoutedEventArgs e)
        {
            var picker = new FileOpenPicker();
            picker.FileTypeFilter.Add(".bitnet");
            var hwnd = WindowNative.GetWindowHandle(App.MainWindow);
            InitializeWithWindow.Initialize(picker, hwnd);
            var file = await picker.PickSingleFileAsync();
            if (file != null)
            {
                VaultPathBox.Text = file.Path;
                ErrorText.Visibility = Visibility.Collapsed;
            }
        }

        private void MasterPasswordBox_KeyDown(object sender, Microsoft.UI.Xaml.Input.KeyRoutedEventArgs e)
        {
            if (e.Key == Windows.System.VirtualKey.Enter)
            {
                UnlockButton_Click(sender, e);
            }
        }

        private void VaultPathBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            ErrorText.Visibility = Visibility.Collapsed;
        }

        private void ShowError(string message)
        {
            ErrorText.Text = message;
            ErrorText.Visibility = Visibility.Visible;
        }
    }
}
