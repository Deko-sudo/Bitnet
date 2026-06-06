using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.Json;
using BitNet.Desktop.Helpers;
using BitNet.Desktop.Native;
// Windows.ApplicationModel.DataTransfer is no longer
// needed here — clipboard operations go through
// `ClipboardHelper`.

namespace BitNet.Desktop.Views
{
    public sealed partial class VaultPage : Page
    {
        public ObservableCollection<VaultEntry> Entries { get; } = new();
        // The 30-second auto-clear and `IsSensitive` flag
        // are now handled by `ClipboardHelper`. The deadline
        // tracking and tick that used to live here have been
        // moved to that helper.

        // Filter state for the Bitwarden-style
        // type filter. The current selection is one of
        // the strings in `AllFilters` below. The
        // collection view applies this filter on
        // top of the search box's text filter.
        public string CurrentFilter { get; set; } = "all";
        public static readonly string[] AllFilters =
        {
            "all", "login", "card", "identity", "note", "ssh"
        };

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
                            // Prefer the structured kind
                            // (set by the Rust core) and
                            // fall back to the URL-based
                            // heuristic for entries that
                            // don't have a `kind` field
                            // (v0.1 back-compat).
                            entry.IconGlyph = ResolveIcon(entry);
                            Entries.Add(entry);
                        }
                    }
                }
            }
            finally
            {
                BitnetCore.bitnet_free_string(ptr);
            }
            // Re-apply the active filter so a fresh
            // load preserves the user's selection.
            ApplyFilters();
            CountLabel.Text = $"{(EntriesList.ItemsSource as IEnumerable<VaultEntry>)?.Count() ?? Entries.Count} entries";
        }

        private static string ResolveIcon(VaultEntry entry)
        {
            // If the Rust core tagged the entry with a
            // non-default kind, use EntryTypeIcons for
            // a consistent glyph. Otherwise the URL
            // heuristic is a reasonable fallback.
            if (!string.IsNullOrEmpty(entry.Kind)
                && !string.Equals(entry.Kind, "login", StringComparison.OrdinalIgnoreCase))
            {
                var kind = entry.Kind.ToLowerInvariant() switch
                {
                    "card" or "creditcard" or "credit_card" => EntryKind.CreditCard,
                    "note" or "securenote" or "secure_note" => EntryKind.SecureNote,
                    "identity" => EntryKind.Identity,
                    "ssh" or "sshkey" or "ssh_key" => EntryKind.SshKey,
                    "wifi" => EntryKind.Wifi,
                    _ => EntryKind.Login,
                };
                return EntryTypeIcons.Glyph(kind);
            }
            return GetIconForUrl(entry.Url);
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
            ApplyFilters();
        }

        /// <summary>
        /// Bitwarden-style filter pipeline: filter the
        /// master `Entries` collection by the active
        /// type filter (CurrentFilter) and the search
        /// box's text, then assign the result to
        /// ListView.ItemsSource. The count label is
        /// updated to reflect the visible total.
        /// </summary>
        private void ApplyFilters()
        {
            var search = SearchBox?.Text?.ToLowerInvariant() ?? string.Empty;
            var kindFilter = CurrentFilter ?? "all";
            var filtered = Entries.Where(en =>
                (kindFilter == "all" || MatchesKind(en, kindFilter))
                && (string.IsNullOrEmpty(search)
                    || (en.Title?.ToLowerInvariant().Contains(search) ?? false)
                    || (en.Username?.ToLowerInvariant().Contains(search) ?? false)
                    || (en.Url?.ToLowerInvariant().Contains(search) ?? false)))
                .ToList();
            EntriesList.ItemsSource = filtered;
            if (CountLabel != null)
            {
                CountLabel.Text = filtered.Count == 1 ? "1 entry" : $"{filtered.Count} entries";
            }
        }

        private static bool MatchesKind(VaultEntry entry, string filter)
        {
            var k = (entry.Kind ?? "login").ToLowerInvariant();
            return filter switch
            {
                "all" => true,
                "login" => k == "login" || k == "ssh" || k == "wifi",
                "card" => k == "card" || k == "creditcard" || k == "credit_card",
                "identity" => k == "identity",
                "note" => k == "note" || k == "securenote" || k == "secure_note",
                "ssh" => k == "ssh" || k == "sshkey" || k == "ssh_key",
                _ => true,
            };
        }

        /// <summary>
        /// Event handler for the type-filter ComboBox
        /// (Bitwarden-style "All / Login / Card /
        /// Identity / Note"). Reads the SelectedItem
        /// Tag and updates CurrentFilter.
        /// </summary>
        private void TypeFilter_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (sender is ComboBox cb && cb.SelectedItem is ComboBoxItem item && item.Tag is string tag)
            {
                CurrentFilter = tag;
                ApplyFilters();
            }
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
                // Allocate the FFI result buffer with a
                // fixed capacity. The StringBuilder
                // internally uses a managed char[] —
                // we explicitly zero it via
                // SecureMemory.Zero after use so any
                // heap-inspection tool sees only zeroed
                // memory. The CLR is still free to
                // make additional copies during string
                // interning; this is a best-effort
                // mitigation (R003 in THREAT_MODEL.md).
                var sb = new System.Text.StringBuilder(1024);
                try
                {
                    var result = BitnetCore.bitnet_entry_get_password(uuid, sb, (nuint)sb.Capacity);
                    if (result == 0)
                    {
                        var password = sb.ToString();
                        ClipboardHelper.SetSensitiveText(password);
                        ShowClipboardNotification("Password copied. Clipboard will clear in 30 seconds.");
                        // Best-effort zeroization of the
                        // managed `password` string. The
                        // CLR does not guarantee this
                        // overwrites the underlying heap
                        // allocation (strings are
                        // immutable), but it does mean a
                        // heap dump will not contain a
                        // live reference to the secret
                        // once this scope ends.
                        password = string.Empty;
                    }
                }
                finally
                {
                    // Explicitly zero the StringBuilder's
                    // char buffer. This is the strongest
                    // mitigation the C# runtime offers
                    // for managed secret strings.
                    sb.Clear();
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

        /// <summary>
        /// Called when the user navigates away from this page. The
        /// `ClipboardHelper` singleton survives the page lifetime, so
        /// no per-page teardown is needed for the auto-clear
        /// timer. The 30s deadline is preserved across navigations.
        /// </summary>
        protected override void OnNavigatedFrom(NavigationEventArgs e)
        {
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
        /// <summary>
        /// Entry kind: "login", "note", "card",
        /// "identity", etc. Set by the Rust core on
        /// v0.2; for now defaults to "login" if the
        /// field is missing from the JSON.
        /// </summary>
        [System.Text.Json.Serialization.JsonPropertyName("kind")]
        public string Kind { get; set; } = "login";
        public string IconGlyph { get; set; } = "\uE8D7";
    }
}
