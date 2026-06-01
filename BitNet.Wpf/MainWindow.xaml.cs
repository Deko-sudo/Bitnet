using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using BitNet.Desktop.Native;

namespace BitNet.Wpf;

public partial class MainWindow : Window
{
    public ObservableCollection<EntryVm> Entries { get; } = new();

    public MainWindow()
    {
        InitializeComponent();
        EntriesList.ItemsSource = Entries;
        GenLength.ValueChanged += (_, __) => GenLengthLabel.Text = ((int)GenLength.Value).ToString();
        BitnetCore.bitnet_init();
    }

    private void SetStatus(string text)
    {
        StatusText.Text = $"Status: {text}";
    }

    private string GetVaultPath() => VaultPathBox.Text.Trim();
    private string GetPassword() => VaultPassBox.Password;

    private void BtnCreate_Click(object sender, RoutedEventArgs e)
    {
        var path = GetVaultPath();
        if (string.IsNullOrWhiteSpace(path)) { SetStatus("Enter vault path"); return; }
        var rc = BitnetCore.SecureVaultCreate(Path.GetFullPath(path), GetPassword());
        SetStatus(rc == 0 ? "Vault created" : $"Create failed ({rc})");
    }

    private void BtnUnlock_Click(object sender, RoutedEventArgs e)
    {
        var path = GetVaultPath();
        if (string.IsNullOrWhiteSpace(path)) { SetStatus("Enter vault path"); return; }
        var rc = BitnetCore.SecureVaultUnlock(Path.GetFullPath(path), GetPassword());
        if (rc == 0)
        {
            SetStatus("Unlocked");
            RefreshEntries();
        }
        else
        {
            SetStatus($"Unlock failed ({rc})");
        }
    }

    private void BtnLock_Click(object sender, RoutedEventArgs e)
    {
        var rc = BitnetCore.bitnet_vault_lock();
        Entries.Clear();
        SetStatus(rc == 0 ? "Locked" : $"Lock failed ({rc})");
    }

    private void BtnSave_Click(object sender, RoutedEventArgs e)
    {
        var path = GetVaultPath();
        if (string.IsNullOrWhiteSpace(path)) { SetStatus("Enter vault path"); return; }
        var rc = BitnetCore.SecureVaultSave(Path.GetFullPath(path), GetPassword());
        SetStatus(rc == 0 ? "Saved" : $"Save failed ({rc})");
    }

    private void BtnPick_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog { Filter = "BitNet vaults (*.bitnet)|*.bitnet|All files (*.*)|*.*" };
        if (dlg.ShowDialog() == true)
            VaultPathBox.Text = dlg.FileName;
    }

    private void RefreshEntries()
    {
        Entries.Clear();
        var ptr = BitnetCore.bitnet_list_entries();
        if (ptr == IntPtr.Zero) return;
        var json = Marshal.PtrToStringUTF8(ptr);
        BitnetCore.bitnet_free_string(ptr);
        if (string.IsNullOrWhiteSpace(json)) return;

        try
        {
            using var doc = JsonDocument.Parse(json);
            foreach (var el in doc.RootElement.EnumerateArray())
            {
                var title = el.GetProperty("title").GetString() ?? "";
                var user = el.GetProperty("username").GetString() ?? "";
                var url = el.GetProperty("url").GetString() ?? "";
                var hasTotp = el.TryGetProperty("has_totp", out var ht) && ht.GetBoolean();
                Entries.Add(new EntryVm { Title = title, Username = user, Url = url, HasTotp = hasTotp });
            }
        }
        catch (Exception ex)
        {
            SetStatus($"Parse error: {ex.Message}");
        }
    }

    private void BtnAddEntry_Click(object sender, RoutedEventArgs e)
    {
        var json = $"{{\"title\":\"{EscapeJson(EntryTitle.Text)}\",\"username\":\"{EscapeJson(EntryUsername.Text)}\",\"password\":\"{EscapeJson(EntryPassword.Text)}\",\"url\":\"{EscapeJson(EntryUrl.Text)}\",\"notes\":\"{EscapeJson(EntryNotes.Text)}\"}}";
        var rc = BitnetCore.SecureAddEntry(GroupUuidBox.Text.Trim(), json);
        if (rc == 0)
        {
            SetStatus("Entry added");
            RefreshEntries();
        }
        else
        {
            SetStatus($"Add failed ({rc})");
        }
    }

    private void BtnDelEntry_Click(object sender, RoutedEventArgs e)
    {
        SetStatus("Delete requires selected entry with UUID (not exposed in simple UI)");
    }

    private void BtnGenerate_Click(object sender, RoutedEventArgs e)
    {
        var len = (int)GenLength.Value;
        var upper = GenUpper.IsChecked == true ? 1 : 0;
        var lower = GenLower.IsChecked == true ? 1 : 0;
        var digits = GenDigits.IsChecked == true ? 1 : 0;
        var symbols = GenSymbols.IsChecked == true ? 1 : 0;
        var ambig = GenAmbiguous.IsChecked == true ? 1 : 0;
        var ptr = BitnetCore.bitnet_generate_password(len, upper, lower, digits, symbols, ambig);
        if (ptr != IntPtr.Zero)
        {
            GenResult.Text = Marshal.PtrToStringUTF8(ptr) ?? "";
            BitnetCore.bitnet_free_string(ptr);
        }
    }

    private static string EscapeJson(string? s)
    {
        if (s == null) return "";
        return s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", "\\n").Replace("\r", "\\r");
    }
}

public class EntryVm
{
    public string Title { get; set; } = "";
    public string Username { get; set; } = "";
    public string Url { get; set; } = "";
    public bool HasTotp { get; set; }
}
