using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using BitNet.Desktop.Native;
using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

namespace BitNet.Desktop.Views
{
    public sealed partial class EntryEditorPage : Page
    {
        private VaultEntry? _editingEntry;

        public EntryEditorPage()
        {
            this.InitializeComponent();
        }

        protected override void OnNavigatedTo(Microsoft.UI.Xaml.Navigation.NavigationEventArgs e)
        {
            base.OnNavigatedTo(e);
            if (e.Parameter is VaultEntry entry)
            {
                _editingEntry = entry;
                PageTitle.Text = "Edit Entry";
                TitleBox.Text = entry.Title;
                UsernameBox.Text = entry.Username;
                UrlBox.Text = entry.Url;
                PasswordBox.Password = "";
                NotesBox.Text = "";
                TOTPUriBox.Text = "";
            }
            else
            {
                _editingEntry = null;
                PageTitle.Text = "Add Entry";
                TitleBox.Text = "";
                UsernameBox.Text = "";
                UrlBox.Text = "";
                PasswordBox.Password = "";
                TOTPUriBox.Text = "";
                NotesBox.Text = "";
            }
        }

        private void GeneratePassword_Click(object sender, RoutedEventArgs e)
        {
            var ptr = BitnetCore.bitnet_generate_password(16, 1, 1, 1, 1, 0);
            if (ptr != IntPtr.Zero)
            {
                try
                {
                    var password = Marshal.PtrToStringUTF8(ptr);
                    if (password != null)
                    {
                        PasswordBox.Password = password;
                    }
                }
                finally
                {
                    BitnetCore.bitnet_free_string(ptr);
                }
            }
        }

        private async void SaveButton_Click(object sender, RoutedEventArgs e)
        {
            var title = TitleBox.Text.Trim();
            var username = UsernameBox.Text.Trim();
            var password = PasswordBox.Password;
            var url = UrlBox.Text.Trim();
            var notes = NotesBox.Text.Trim();
            var totp = TOTPUriBox.Text.Trim();

            if (string.IsNullOrEmpty(title))
            {
                await ShowErrorAsync("Title is required.");
                return;
            }

            var jsonBuilder = new StringBuilder();
            using (var stream = new System.IO.MemoryStream())
            {
                using (var writer = new Utf8JsonWriter(stream))
                {
                    writer.WriteStartObject();
                    if (_editingEntry != null)
                        writer.WriteString("uuid", _editingEntry.UUID);
                    else
                        writer.WriteString("uuid", "00000000000000000000000000000000");
                    writer.WriteString("title", title);
                    writer.WriteString("username", username);
                    writer.WriteString("password", password);
                    writer.WriteString("url", url);
                    writer.WriteString("notes", notes);
                    if (!string.IsNullOrEmpty(totp))
                        writer.WriteString("totp_secret", totp);
                    writer.WriteEndObject();
                    writer.Flush();
                }
                jsonBuilder.Append(Encoding.UTF8.GetString(stream.ToArray()));
            }

            var json = jsonBuilder.ToString();
            int result;
            if (_editingEntry != null)
            {
                result = BitnetCore.SecureUpdateEntry(_editingEntry.UUID, json);
            }
            else
            {
                // Use root group fallback (all-zero UUID triggers first group in Rust core)
                result = BitnetCore.SecureAddEntry("00000000000000000000000000000000", json);
            }

            if (result != 0)
            {
                await ShowErrorAsync($"Failed to save entry (error {result}).");
                return;
            }

            // Persist vault
            // We need the vault path and password to save. In a real app, keep these in secure storage.
            // For now, we just save via backend (bitnet_vault_save requires path+password).
            // Since we don't have them here, we rely on the session keeping data in memory.
            // Note: Changes are kept in memory. Use Save Vault button in VaultPage to persist to disk.

            Frame.GoBack();
        }

        private void CancelButton_Click(object sender, RoutedEventArgs e)
        {
            Frame.GoBack();
        }

        private async System.Threading.Tasks.Task ShowErrorAsync(string message)
        {
            var dialog = new ContentDialog
            {
                Title = "Error",
                Content = message,
                CloseButtonText = "OK",
                XamlRoot = this.XamlRoot
            };
            await dialog.ShowAsync();
        }
    }
}
