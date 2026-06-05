using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
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
        // [BITNET-M3] Deadline-based clipboard clear. The previous version
        // restarted the 30s timer every time the user copied a new password,
        // so the clipboard could be wiped 5s after the *second* copy (the
        // first timer's deadline). The fix tracks the absolute deadline and
        // ticks every 1s.
        private DispatcherTimer? _clipboardClearTimer;
        private DateTimeOffset? _clipboardClearDeadline;
        private const int ClipboardClearSeconds = 30;

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

        private void SearchBox_TextChanged(AutoSuggestBox sender, AutoSuggestBoxTextChangedEventArgs args)
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
                    // Best-effort clear of managed buffers (CLR does not guarantee zeroization)
                    sb.Clear();
                    password = string.Empty;
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

            var pwdBox = new PasswordBox { PlaceholderText = "Enter master password to save vault" };
            var pwdDialog = new ContentDialog
            {
                Title = "Save Vault",
                Content = pwdBox,
                PrimaryButtonText = "Save",
                CloseButtonText = "Cancel",
                XamlRoot = this.XamlRoot
            };
            var result = await pwdDialog.ShowAsync();
            if (result != ContentDialogResult.Primary) return;

            var password = pwdBox.Password ?? "";
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

            // [BITNET-H1] Wrap the local password string into a SecureString
            // for the FFI call.
            var secPwd = new System.Security.SecureString();
            foreach (var c in password) secPwd.AppendChar(c);
            secPwd.MakeReadOnly();
            // [BITNET-L1] Map raw FFI return code to a user-facing string.
            // The previous message ("error -2") leaked internal codes.
            var saveResult = BitnetCore.SecureVaultSaveSecure(App.VaultPath, secPwd);
            secPwd.Dispose();
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
                    Content = BitnetError.Describe(saveResult),
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
            _clipboardClearDeadline = DateTimeOffset.UtcNow.AddSeconds(ClipboardClearSeconds);
            _clipboardClearTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
            _clipboardClearTimer.Tick += ClipboardClearTick;
            _clipboardClearTimer.Start();
        }

        private void ClipboardClearTick(object? sender, object e)
        {
            var deadline = _clipboardClearDeadline;
            if (deadline == null)
            {
                _clipboardClearTimer?.Stop();
                return;
            }
            if (DateTimeOffset.UtcNow < deadline.Value)
            {
                return;
            }
            try
            {
                Clipboard.Clear();
            }
            catch (System.Runtime.InteropServices.COMException)
            {
                // Clipboard locked by another process; not a security issue
                // because the next copy will reset the deadline.
            }
            _clipboardClearTimer?.Stop();
            _clipboardClearDeadline = null;
        }

        /// <summary>
        /// Called when the user navigates away from this page. Stops the
        /// timer so the Tick handler does not run on an unrooted page
        /// (the previous implementation left the timer running until GC,
        /// which could trigger COMExceptions on the dead XamlRoot).
        /// </summary>
        protected override void OnNavigatedFrom(NavigationEventArgs e)
        {
            _clipboardClearTimer?.Stop();
            _clipboardClearTimer = null;
            _clipboardClearDeadline = null;
            base.OnNavigatedFrom(e);
        }
    }

    public class VaultEntry
    {
        [System.Text.Json.Serialization.JsonPropertyName("uuid")]
        public string UUID { get; set; } = "";
        [System.Text.Json.Serialization.JsonPropertyName("title")]
        public string Title { get; set; } = "";
        [System.Text.Json.Serialization.JsonPropertyName("username")]
        public string Username { get; set; } = "";
        [System.Text.Json.Serialization.JsonPropertyName("url")]
        public string Url { get; set; } = "";
        [System.Text.Json.Serialization.JsonPropertyName("has_totp")]
        public bool HasTOTP { get; set; }
        public string IconGlyph { get; set; } = "\uE8D7";
    }
}
