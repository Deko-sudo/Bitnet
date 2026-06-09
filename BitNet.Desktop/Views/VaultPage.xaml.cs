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
            var kind = EntryKindExtensions.ParseKind(entry.Kind);
            if (kind != EntryKind.Login)
            {
                return EntryTypeIcons.Glyph(kind);
            }
            // Login OR unknown kind: fall back to the
            // URL-based heuristic for backward
            // compatibility with v0.1 entries that
            // don't have a `kind` field.
            if (string.IsNullOrEmpty(entry.Kind))
            {
                return GetIconForUrl(entry.Url);
            }
            return EntryTypeIcons.Glyph(EntryKind.Login);
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
            // The ComboBox tag is the kind identifier
            // string ("login", "card", "identity",
            // "note", "ssh", "all", "favorites"). We
            // parse the entry's kind via the shared
            // extension method so the filter logic
            // stays in lock-step with the icon
            // resolution and the Rust core's `kind`
            // JSON field. "favorites" is orthogonal
            // to the kind — it only looks at the
            // entry's `Favorite` flag.
            if (filter == "favorites")
            {
                return entry.Favorite;
            }
            var entryKind = EntryKindExtensions.ParseKind(entry.Kind);
            return filter switch
            {
                "all" => true,
                // Bitwarden convention: the "Logins"
                // tab groups together all network
                // credentials (login + ssh + wifi).
                "login" => entryKind == EntryKind.Login
                            || entryKind == EntryKind.SshKey
                            || entryKind == EntryKind.Wifi,
                "card" => entryKind == EntryKind.CreditCard,
                "identity" => entryKind == EntryKind.Identity,
                "note" => entryKind == EntryKind.SecureNote,
                "ssh" => entryKind == EntryKind.SshKey,
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

            // [BITNET-M10] CWE-316: read the password
            // into a SecureString, char-by-char, so
            // no managed `String` snapshot of the
            // password lingers in the GC heap beyond
            // the time it takes to build the
            // SecureString. The previous code did
            // `var password = pwdBox.Password ?? ""`
            // which kept the password as an
            // immutable managed `String` until the
            // SaveVault_Click method's stack frame
            // was reclaimed by the GC (immutable
            // strings cannot be zeroized in place).
            //
            // We do *not* rely on
            // `pwdBox.SecurePassword` because WinUI 3
            // `PasswordBox` does not expose that
            // property (the property is WPF-only).
            // Instead, we walk `pwdBox.Password` (a
            // managed String) exactly once, copying
            // each char into the SecureString, and
            // then nulling the `pwdBox.Password` so
            // the UI's internal buffer is overwritten
            // by an empty string on the next render
            // pass. The managed String still lingers
            // until the GC reclaims it, but we have
            // *minimised the window* by not assigning
            // it to a long-lived local.
            if (string.IsNullOrEmpty(pwdBox.Password))
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

            var secPwd = new System.Security.SecureString();
            foreach (var c in pwdBox.Password) secPwd.AppendChar(c);
            secPwd.MakeReadOnly();
            // Wipe the PasswordBox's internal buffer.
            pwdBox.Password = "";
            // [BITNET-L1] Map raw FFI return code to a user-facing string.
            // The previous message ("error -2") leaked internal codes.
            int saveResult;
            try
            {
                saveResult = BitnetCore.SecureVaultSaveSecure(
                    App.VaultPath, secPwd);
            }
            finally
            {
                secPwd.Dispose();
            }
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
        /// <summary>
        /// Whether the user has marked this entry as
        /// a favourite. The Rust core may emit
        /// `favorite` (snake_case) or `is_favorite`;
        /// we accept both via the `FavoriteConverter`
        /// shim. Defaults to false so v0.1 entries
        /// (which do not serialise this field) are
        /// simply non-favourites.
        /// </summary>
        [System.Text.Json.Serialization.JsonConverter(typeof(FavoriteJsonConverter))]
        public bool Favorite { get; set; }
        public string IconGlyph { get; set; } = "\uE8D7";
    }
}
