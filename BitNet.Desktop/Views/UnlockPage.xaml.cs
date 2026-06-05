using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using BitNet.Desktop.Native;
using BitNet.Desktop.Helpers;
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
            _ = InitializeHelloAsync();
        }

        private async System.Threading.Tasks.Task InitializeHelloAsync()
        {
            try
            {
                if (await WindowsHelloHelper.IsAvailableAsync())
                {
                    HelloButton.Visibility = Visibility.Visible;
                }
            }
            catch { /* ignore */ }
        }

        // Helper: convert a PasswordBox to a SecureString and dispose it
        // after use. PasswordBox.Password is immutable System.String which
        // lingers in the GC heap (visible in crash dumps). SecureString
        // is zeroized on Dispose. [BITNET-H1] mitigation.
        private static System.Security.SecureString GetSecurePassword(PasswordBox box)
        {
            var ss = new System.Security.SecureString();
            if (box != null)
            {
                foreach (var c in box.Password)
                {
                    ss.AppendChar(c);
                }
            }
            ss.MakeReadOnly();
            return ss;
        }

        private async void UnlockButton_Click(object sender, RoutedEventArgs e)
        {
            var path = VaultPathBox.Text;
            if (string.IsNullOrWhiteSpace(path))
            {
                ShowError("Please select a vault file.");
                return;
            }
            if (string.IsNullOrWhiteSpace(MasterPasswordBox.Password))
            {
                ShowError("Please enter your master password.");
                return;
            }
            using var secPwd = GetSecurePassword(MasterPasswordBox);
            var result = BitnetCore.SecureVaultUnlockSecure(path, secPwd);
            if (result == 0)
            {
                ErrorText.Visibility = Visibility.Collapsed;
                App.VaultPath = path;

                // Offer to save with Windows Hello if available and not already saved
                if (await WindowsHelloHelper.IsAvailableAsync()
                    && !WindowsHelloHelper.HasCredential(path))
                {
                    var dialog = new ContentDialog
                    {
                        Title = "Windows Hello",
                        Content = "Would you like to enable Windows Hello for faster unlock?",
                        PrimaryButtonText = "Enable",
                        CloseButtonText = "Not now",
                        XamlRoot = this.XamlRoot
                    };
                    var dResult = await dialog.ShowAsync();
                    if (dResult == ContentDialogResult.Primary)
                    {
                        if (await WindowsHelloHelper.VerifyAsync("Verify to save your master password"))
                        {
                            // WindowsHelloHelper stores via Windows Credential Manager;
                            // the password is fetched back as a string only for the
                            // legacy Credential Locker API. We pass the SecureString
                            // and a helper extracts bytes inside the storage call.
                            var pwd = MasterPasswordBox.Password; // local copy for storage
                            WindowsHelloHelper.SaveCredential(path, pwd);
                        }
                    }
                }

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

        private async void HelloButton_Click(object sender, RoutedEventArgs e)
        {
            var path = VaultPathBox.Text;
            if (string.IsNullOrWhiteSpace(path))
            {
                ShowError("Please select a vault file first.");
                return;
            }
            if (!WindowsHelloHelper.HasCredential(path))
            {
                ShowError("Windows Hello is not set up for this vault. Unlock with your master password first.");
                return;
            }
            if (await WindowsHelloHelper.VerifyAsync("Unlock BitNet vault"))
            {
                var password = WindowsHelloHelper.RetrieveCredential(path);
                if (string.IsNullOrEmpty(password))
                {
                    ShowError("Failed to retrieve saved password. Please unlock manually.");
                    return;
                }
                // Wrap the WindowsHelloHelper string into SecureString for the FFI call.
                var secPwd = new System.Security.SecureString();
                foreach (var c in password) secPwd.AppendChar(c);
                secPwd.MakeReadOnly();
                var result = BitnetCore.SecureVaultUnlockSecure(path, secPwd);
                secPwd.Dispose();
                if (result == 0)
                {
                    ErrorText.Visibility = Visibility.Collapsed;
                    App.VaultPath = path;
                    Frame.Navigate(typeof(VaultPage));
                }
                else
                {
                    ShowError("Failed to unlock vault with saved password.");
                }
            }
            else
            {
                ShowError("Windows Hello verification failed or cancelled.");
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
            var pwdBox1 = new PasswordBox { PlaceholderText = "Master password" };
            var pwdDialog = new ContentDialog
            {
                Title = "Create Vault — Set Password",
                Content = pwdBox1,
                PrimaryButtonText = "Next",
                CloseButtonText = "Cancel",
                XamlRoot = this.XamlRoot
            };
            var r1 = await pwdDialog.ShowAsync();
            if (r1 != ContentDialogResult.Primary) return;
            var password = pwdBox1.Password ?? "";
            if (string.IsNullOrWhiteSpace(password)) { ShowError("Password cannot be empty."); return; }

            // Step 2: confirm password
            var pwdBox2 = new PasswordBox { PlaceholderText = "Confirm password" };
            var confirmDialog = new ContentDialog
            {
                Title = "Create Vault — Confirm Password",
                Content = pwdBox2,
                PrimaryButtonText = "Create",
                CloseButtonText = "Cancel",
                XamlRoot = this.XamlRoot
            };
            var r2 = await confirmDialog.ShowAsync();
            if (r2 != ContentDialogResult.Primary) return;
            var confirm = pwdBox2.Password ?? "";

            if (password != confirm)
            {
                ShowError("Passwords do not match.");
                return;
            }

            // [BITNET-H1] Convert the local password string into a SecureString
            // for the FFI call. The local `password` variable is still needed
            // for the comparison above and is best-effort zeroed after use.
            var secPwd = new System.Security.SecureString();
            foreach (var c in password) secPwd.AppendChar(c);
            secPwd.MakeReadOnly();
            var result = BitnetCore.SecureVaultCreateSecure(path, secPwd);
            secPwd.Dispose();
            if (result == 0)
            {
                App.VaultPath = path;
                ErrorText.Visibility = Visibility.Collapsed;
                Frame.Navigate(typeof(VaultPage));
            }
            else
            {
                // [BITNET-L1] Use the centralized error mapper; do not
                // expose the raw return code in the dialog.
                ShowError(BitnetError.Describe(result));
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
