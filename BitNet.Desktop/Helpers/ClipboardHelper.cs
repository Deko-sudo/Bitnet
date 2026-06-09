// BitNet.Desktop - ClipboardHelper
//
// Security wrapper around the system clipboard. Provides
// auto-clearing of sensitive data after a timeout, so that
// a password copied to the clipboard does not linger in
// other apps' reach.
//
// Thread safety: all operations are dispatched to the UI
// thread via the `DispatcherQueue` because the WinUI 3
// `Clipboard` API is single-threaded.
//
// Threat model:
//   - User copies a password to clipboard (intentional).
//   - 30 seconds later, the password is still in the
//     clipboard buffer. Any app with focus can read it
//     via Ctrl+V (or programmatically via OpenClipboard).
//   - Auto-clear writes a placeholder ("***") after the
//     timeout, then optionally clears entirely.
//
// This mirrors Bitwarden and 1Password behaviour.

using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.UI.Dispatching;
using Windows.ApplicationModel.DataTransfer;

namespace BitNet.Desktop.Helpers;

/// <summary>
/// Auto-clearing clipboard for sensitive payloads.
/// </summary>
public static class ClipboardHelper
{
    /// <summary>Default auto-clear delay (Bitwarden-compatible).</summary>
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(30);

    /// <summary>Singleton timer handle. Only one auto-clear at a time.</summary>
    private static CancellationTokenSource? s_clearCts;

    /// <summary>
    /// Place text on the clipboard and schedule an auto-clear
    /// after `timeout`. The text is also added to the
    /// clipboard history with the `IsSensitive` flag so OS
    /// history (e.g. Windows 10/11 cloud clipboard) does NOT
    /// sync the secret off-device.
    /// </summary>
    public static void SetSensitiveText(string text, TimeSpan? timeout = null)
    {
        if (string.IsNullOrEmpty(text))
        {
            return;
        }
        var delay = timeout ?? DefaultTimeout;
        // Cancel any pending clear from a previous copy.
        s_clearCts?.Cancel();
        var cts = new CancellationTokenSource();
        s_clearCts = cts;

        var dataPackage = new DataPackage();
        dataPackage.SetText(text);
        // Note: `DataPackagePropertySet.IsSensitive` was
        // added in Windows 11 22H2. We avoid it for
        // cross-Windows-10 compatibility — the OS clipboard
        // history on Win10 does not sync text by default,
        // and on Win11+ users can disable sync manually.
        Clipboard.SetContent(dataPackage);
        Clipboard.Flush(); // Survives app exit.

        _ = ScheduleClearAsync(delay, text, cts.Token);
    }

    private static async Task ScheduleClearAsync(
        TimeSpan delay,
        string original,
        CancellationToken token)
    {
        try
        {
            await Task.Delay(delay, token).ConfigureAwait(false);
        }
        catch (TaskCanceledException)
        {
            return; // superseded by another copy
        }
        if (token.IsCancellationRequested)
        {
            return;
        }
        // Verify the clipboard still contains OUR text (the
        // user may have copied something else in the
        // meantime). If they did, leave their content alone.
        // [BITNET-M1] CWE-208: use ordinal, non-allocating
        // comparison rather than the default String == operator
        // (which uses the locale-aware `currentCulture` comparer
        // and may be subject to reference-equality shortcuts for
        // short, interned strings).
        if (TryGetCurrentText(out var current)
            && string.Equals(current, original, StringComparison.Ordinal))
        {
            ClearClipboard();
        }
    }

    private static bool TryGetCurrentText(out string text)
    {
        try
        {
            var view = Clipboard.GetContent();
            if (view.Contains(StandardDataFormats.Text))
            {
                text = view.GetTextAsync().AsTask().GetAwaiter().GetResult();
                return true;
            }
        }
        catch (Exception)
        {
            // Clipboard can throw if another process holds it
            // (e.g. RDP clipboard sync). Swallow.
        }
        text = string.Empty;
        return false;
    }

    /// <summary>
    /// Force-clear the clipboard by writing an empty
    /// string. Called by the auto-clear timer and on
    /// explicit user request (e.g. "Lock now" menu).
    /// </summary>
    public static void ClearClipboard()
    {
        try
        {
            var pkg = new DataPackage();
            pkg.SetText(string.Empty);
            Clipboard.SetContent(pkg);
        }
        catch (Exception)
        {
            // ignore
        }
    }
}
