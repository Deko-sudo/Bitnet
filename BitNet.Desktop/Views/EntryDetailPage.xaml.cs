using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using BitNet.Desktop.Native;
using System;
using System.Runtime.InteropServices;
using System.Text;
using Windows.ApplicationModel.DataTransfer;

namespace BitNet.Desktop.Views
{
    public sealed partial class EntryDetailPage : Page
    {
        public VaultEntry Entry { get; private set; } = new();
        private DispatcherTimer? _totpTimer;
        private DispatcherTimer? _clipboardClearTimer;
        private bool _passwordRevealed = false;

        public EntryDetailPage()
        {
            this.InitializeComponent();
        }

        protected override void OnNavigatedTo(Microsoft.UI.Xaml.Navigation.NavigationEventArgs e)
        {
            base.OnNavigatedTo(e);
            if (e.Parameter is VaultEntry entry)
            {
                Entry = entry;
                TitleBlock.Text = entry.Title;
                UrlBlock.Text = entry.Url;
                UsernameBox.Text = entry.Username;
                NotesBox.Text = "";
                LoadPassword();
                if (entry.HasTOTP)
                {
                    TOTPPanel.Visibility = Visibility.Visible;
                    LoadTOTP();
                    StartTOTPTimer();
                }
                else
                {
                    TOTPPanel.Visibility = Visibility.Collapsed;
                }
                MetaBlock.Text = $"UUID: {entry.UUID}";
            }
        }

        protected override void OnNavigatedFrom(Microsoft.UI.Xaml.Navigation.NavigationEventArgs e)
        {
            base.OnNavigatedFrom(e);
            _totpTimer?.Stop();
            _clipboardClearTimer?.Stop();
            if (_passwordRevealed)
            {
                PasswordVisibleBox.Text = "";
                PasswordVisibleBox.Visibility = Visibility.Collapsed;
                PasswordHiddenBox.Visibility = Visibility.Visible;
                _passwordRevealed = false;
            }
        }

        private void LoadPassword()
        {
            var sb = new StringBuilder(1024);
            var result = BitnetCore.bitnet_entry_get_password(Entry.UUID, sb, (nuint)sb.Capacity);
            if (result == 0)
            {
                var password = sb.ToString();
                PasswordHiddenBox.Password = "********";
                PasswordVisibleBox.Text = password;
            }
            else
            {
                PasswordHiddenBox.Password = "********";
                PasswordVisibleBox.Text = "***";
            }
        }

        private void RevealButton_Click(object sender, RoutedEventArgs e)
        {
            _passwordRevealed = !_passwordRevealed;
            if (_passwordRevealed)
            {
                PasswordHiddenBox.Visibility = Visibility.Collapsed;
                PasswordVisibleBox.Visibility = Visibility.Visible;
            }
            else
            {
                PasswordHiddenBox.Visibility = Visibility.Visible;
                PasswordVisibleBox.Visibility = Visibility.Collapsed;
            }
        }

        private void LoadTOTP()
        {
            var ptr = BitnetCore.bitnet_entry_get_totp(Entry.UUID);
            if (ptr != IntPtr.Zero)
            {
                try
                {
                    var result = Marshal.PtrToStringUTF8(ptr);
                    if (!string.IsNullOrEmpty(result))
                    {
                        var parts = result.Split(',');
                        if (parts.Length == 2)
                        {
                            TOTPCodeBlock.Text = parts[0].Trim();
                            if (int.TryParse(parts[1].Trim(), out var remaining))
                            {
                                TOTPProgress.Value = 30 - remaining;
                            }
                        }
                    }
                }
                finally
                {
                    BitnetCore.bitnet_free_string(ptr);
                }
            }
        }

        private void StartTOTPTimer()
        {
            _totpTimer?.Stop();
            _totpTimer = new DispatcherTimer();
            _totpTimer.Interval = TimeSpan.FromSeconds(1);
            _totpTimer.Tick += (s, e) =>
            {
                LoadTOTP();
            };
            _totpTimer.Start();
        }

        private void CopyPassword_Click(object sender, RoutedEventArgs e)
        {
            var password = PasswordVisibleBox.Text;
            if (string.IsNullOrEmpty(password) || password == "***")
            {
                var sb = new StringBuilder(1024);
                var result = BitnetCore.bitnet_entry_get_password(Entry.UUID, sb, (nuint)sb.Capacity);
                if (result == 0)
                {
                    password = sb.ToString();
                }
            }
            CopyToClipboard(password, "Password copied. Clipboard will clear in 30 seconds.");
        }

        private void CopyUsername_Click(object sender, RoutedEventArgs e)
        {
            CopyToClipboard(UsernameBox.Text, "Username copied. Clipboard will clear in 30 seconds.");
        }

        private void CopyTOTP_Click(object sender, RoutedEventArgs e)
        {
            CopyToClipboard(TOTPCodeBlock.Text, "TOTP code copied. Clipboard will clear in 30 seconds.");
        }

        private void CopyToClipboard(string text, string notification)
        {
            if (string.IsNullOrEmpty(text)) return;
            var package = new DataPackage();
            package.SetText(text);
            Clipboard.SetContent(package);
            ClipboardInfoBar.Message = notification;
            ClipboardInfoBar.IsOpen = true;
            StartClipboardClearTimer();
        }

        private void StartClipboardClearTimer()
        {
            _clipboardClearTimer?.Stop();
            _clipboardClearTimer = new DispatcherTimer();
            _clipboardClearTimer.Interval = TimeSpan.FromSeconds(30);
            _clipboardClearTimer.Tick += (s, e) =>
            {
                Clipboard.Clear();
                ClipboardInfoBar.IsOpen = false;
                _clipboardClearTimer?.Stop();
            };
            _clipboardClearTimer.Start();
        }

        private void EditEntry_Click(object sender, RoutedEventArgs e)
        {
            Frame.Navigate(typeof(EntryEditorPage), Entry);
        }

        private async void DeleteEntry_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new ContentDialog
            {
                Title = "Delete Entry",
                Content = "Are you sure you want to delete this entry? This cannot be undone.",
                PrimaryButtonText = "Delete",
                CloseButtonText = "Cancel",
                XamlRoot = this.XamlRoot
            };
            var result = await dialog.ShowAsync();
            if (result == ContentDialogResult.Primary)
            {
                var delResult = BitnetCore.bitnet_delete_entry(Entry.UUID);
                if (delResult == 0)
                {
                    Frame.GoBack();
                }
                else
                {
                    var errorDialog = new ContentDialog
                    {
                        Title = "Error",
                        Content = $"Failed to delete entry (error {delResult}).",
                        CloseButtonText = "OK",
                        XamlRoot = this.XamlRoot
                    };
                    await errorDialog.ShowAsync();
                }
            }
        }

        private void BackButton_Click(object sender, RoutedEventArgs e)
        {
            Frame.GoBack();
        }
    }
}
