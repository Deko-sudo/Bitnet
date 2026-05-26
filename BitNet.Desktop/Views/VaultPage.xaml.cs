using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using System;
using System.Collections.ObjectModel;
using System.Runtime.InteropServices;
using System.Text.Json;
using BitNet.Desktop.Native;
using Windows.ApplicationModel.DataTransfer;

namespace BitNet.Desktop.Views
{
    public sealed partial class VaultPage : Page
    {
        public ObservableCollection<VaultEntry> Entries { get; } = new();
        private DispatcherTimer? _clipboardClearTimer;

        public VaultPage()
        {
            this.InitializeComponent();
            EntriesList.ItemsSource = Entries;
            LoadEntries();
        }

        private void LoadEntries()
        {
            Entries.Clear();
            var ptr = BitnetCore.bitnet_list_entries();
            if (ptr == IntPtr.Zero)
            {
                CountLabel.Text = "0 entries";
                return;
            }
            try
            {
                var json = Marshal.PtrToStringUTF8(ptr);
                if (!string.IsNullOrEmpty(json))
                {
                    var entries = JsonSerializer.Deserialize<VaultEntry[]>(json);
                    if (entries != null)
                    {
                        foreach (var entry in entries)
                        {
                            entry.IconGlyph = GetIconForUrl(entry.Url);
                            Entries.Add(entry);
                        }
                    }
                }
            }
            finally
            {
                BitnetCore.bitnet_free_string(ptr);
            }
            CountLabel.Text = $"{Entries.Count} entries";
        }

        private static string GetIconForUrl(string url)
        {
            if (string.IsNullOrEmpty(url)) return "\uE8D7";
            var lower = url.ToLowerInvariant();
            if (lower.Contains("github")) return "\uE774";
            if (lower.Contains("google") || lower.Contains("gmail")) return "\uE774";
            if (lower.Contains("microsoft")) return "\uE774";
            if (lower.Contains("bank")) return "\uE8CB";
            if (lower.Contains("shop") || lower.Contains("store")) return "\uE719";
            return "\uE8D7";
        }

        private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            var filter = SearchBox.Text.ToLowerInvariant();
            EntriesList.ItemsSource = string.IsNullOrEmpty(filter)
                ? Entries
                : new ObservableCollection<VaultEntry>(
                    System.Linq.Enumerable.Where(Entries, en =>
                        en.Title.ToLowerInvariant().Contains(filter) ||
                        en.Username.ToLowerInvariant().Contains(filter) ||
                        en.Url.ToLowerInvariant().Contains(filter)));
        }

        private void EntriesList_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
        }

        private void EntriesList_ItemClick(object sender, ItemClickEventArgs e)
        {
            if (e.ClickedItem is VaultEntry entry)
            {
                Frame.Navigate(typeof(EntryDetailPage), entry);
            }
        }

        private void CopyPassword_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is string uuid)
            {
                var sb = new System.Text.StringBuilder(1024);
                var result = BitnetCore.bitnet_entry_get_password(uuid, sb, (nuint)sb.Capacity);
                if (result == 0)
                {
                    var password = sb.ToString();
                    var package = new DataPackage();
                    package.SetText(password);
                    Clipboard.SetContent(package);
                    ShowClipboardNotification("Password copied. Clipboard will clear in 30 seconds.");
                    StartClipboardClearTimer();
                }
            }
        }

        private async void DeleteEntry_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is string uuid)
            {
                var dialog = new ContentDialog
                {
                    Title = "Delete Entry",
                    Content = "Are you sure you want to delete this entry?",
                    PrimaryButtonText = "Delete",
                    CloseButtonText = "Cancel",
                    XamlRoot = this.XamlRoot
                };
                var result = await dialog.ShowAsync();
                if (result == ContentDialogResult.Primary)
                {
                    var delResult = BitnetCore.bitnet_delete_entry(uuid);
                    if (delResult == 0)
                    {
                        LoadEntries();
                    }
                }
            }
        }

        private void Refresh_Click(object sender, RoutedEventArgs e)
        {
            LoadEntries();
        }

        private async void SaveVault_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(App.VaultPath))
            {
                var errDialog = new ContentDialog
                {
                    Title = "Error",
                    Content = "No vault path is set. Please unlock or create a vault first.",
                    CloseButtonText = "OK",
                    XamlRoot = this.XamlRoot
                };
                await errDialog.ShowAsync();
                return;
            }

            var pwdDialog = new ContentDialog
            {
                Title = "Save Vault",
                Content = new PasswordBox { PlaceholderText = "Enter master password to save vault" },
                PrimaryButtonText = "Save",
                CloseButtonText = "Cancel",
                XamlRoot = this.XamlRoot
            };
            var result = await pwdDialog.ShowAsync();
            if (result != ContentDialogResult.Primary) return;

            var password = (pwdDialog.Content as PasswordBox)?.Password ?? "";
            if (string.IsNullOrWhiteSpace(password))
            {
                var errDialog = new ContentDialog
                {
                    Title = "Error",
                    Content = "Password is required to save vault.",
                    CloseButtonText = "OK",
                    XamlRoot = this.XamlRoot
                };
                await errDialog.ShowAsync();
                return;
            }

            var saveResult = BitnetCore.bitnet_vault_save(App.VaultPath, password);
            if (saveResult == 0)
            {
                var okDialog = new ContentDialog
                {
                    Title = "Saved",
                    Content = "Vault saved successfully.",
                    CloseButtonText = "OK",
                    XamlRoot = this.XamlRoot
                };
                await okDialog.ShowAsync();
            }
            else
            {
                var errDialog = new ContentDialog
                {
                    Title = "Error",
                    Content = $"Failed to save vault (error {saveResult}).",
                    CloseButtonText = "OK",
                    XamlRoot = this.XamlRoot
                };
                await errDialog.ShowAsync();
            }
        }

        private void AddEntry_Click(object sender, RoutedEventArgs e)
        {
            Frame.Navigate(typeof(EntryEditorPage));
        }

        private void ShowClipboardNotification(string message)
        {
            // In a real app, show a TeachingTip or InfoBar
        }

        private void StartClipboardClearTimer()
        {
            _clipboardClearTimer?.Stop();
            _clipboardClearTimer = new DispatcherTimer();
            _clipboardClearTimer.Interval = TimeSpan.FromSeconds(30);
            _clipboardClearTimer.Tick += (s, e) =>
            {
                Clipboard.Clear();
                _clipboardClearTimer?.Stop();
            };
            _clipboardClearTimer.Start();
        }
    }

    public class VaultEntry
    {
        public string UUID { get; set; } = "";
        public string Title { get; set; } = "";
        public string Username { get; set; } = "";
        public string Url { get; set; } = "";
        public bool HasTOTP { get; set; }
        public string IconGlyph { get; set; } = "\uE8D7";
    }
}
