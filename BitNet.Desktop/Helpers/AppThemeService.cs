// BitNet.Desktop - AppThemeService
//
// Persists the user's theme preference (System /
// Light / Dark) to LocalSettings. Bitwarden / Proton
// Pass have the same tri-state toggle in their
// settings; matching it gives a familiar feel to
// migrating users.
//
// The actual theme application (ElementTheme on
// the root visual) is done at the page level —
// App.xaml.cs reads the preference on launch and
// applies it. The service is the persistence +
// notification layer.

using System;
using Microsoft.UI.Xaml;

namespace BitNet.Desktop.Helpers;

// `AppThemePreference` enum is defined in
// `AppThemePreference.cs` so the test project (and
// any future cross-platform consumer) can reference
// it without pulling in the WinUI 3 dependencies.

public static class AppThemeService
{
    private const string Key = "app_theme_preference";

    // [BITNET-L2] CWE-459: LocalSettings.Values[…] is
    // a synchronous disk write on the UI thread. We
    // debounce rapid-fire `Save` calls (e.g. a fast
    // click on the Light → Dark radio buttons would
    // otherwise trigger two consecutive writes). The
    // timer fires at most once per 500 ms; the most
    // recent preference value wins.
    private const int DebounceMs = 500;
    private static AppThemePreference? _pending;
    private static Microsoft.UI.Dispatching.DispatcherQueueTimer? _timer;

    /// <summary>
    /// Load the saved theme preference. Defaults to
    /// `SystemDefault` if no preference has been
    /// stored yet.
    /// </summary>
    public static AppThemePreference Load()
    {
        try
        {
            var local = Windows.Storage.ApplicationData.Current.LocalSettings;
            if (local.Values.TryGetValue(Key, out var raw) && raw is int i)
            {
                return (AppThemePreference)i;
            }
        }
        catch
        {
            // If LocalSettings is unavailable for any
            // reason (sandboxed, missing permissions),
            // fall back to the system default.
        }
        return AppThemePreference.SystemDefault;
    }

    /// <summary>
    /// Persist the chosen preference. The actual write
    /// to LocalSettings is debounced through
    /// `_timer` so rapid-fire calls coalesce into a
    /// single disk write. If the timer is null (called
    /// before the UI is up), we fall back to a direct
    /// synchronous write.
    /// </summary>
    public static void Save(AppThemePreference preference)
    {
        // [BITNET-M11] The initial population in
        // SettingsPage.OnLoaded is guarded by the
        // `_isLoadingPreference` flag in the page, so
        // we do not need to add another guard here.
        // However, callers from elsewhere (e.g. the
        // future CLI / daemon IPC handlers) might
        // pass the same value repeatedly. The
        // debounce handles that case.
        _pending = preference;
        if (_timer == null)
        {
            try
            {
                var q = Microsoft.UI.Dispatching.DispatcherQueue
                    .GetForCurrentThread();
                if (q == null)
                {
                    // Not on a UI thread. Write through
                    // synchronously.
                    Flush();
                    return;
                }
                _timer = q.CreateTimer();
                _timer.Interval = TimeSpan.FromMilliseconds(DebounceMs);
                _timer.IsRepeating = false;
                _timer.Tick += (_, _) =>
                {
                    _timer?.Stop();
                    var t = _timer;
                    _timer = null;
                    // [BITNET-L2] null out the timer
                    // before Flush so that if Flush
                    // itself triggers a Save (unlikely
                    // but possible from a test), a new
                    // timer is created. `t` is captured
                    // locally so the closure is safe
                    // even after `_timer` is reassigned.
                    _ = t;
                    Flush();
                };
            }
            catch
            {
                Flush();
                return;
            }
        }
        // [BITNET-L2] re-start the timer on every Save.
        // `DispatcherQueueTimer.Start()` resets the
        // interval, so successive calls within
        // `DebounceMs` collapse into a single tick.
        _timer.Start();
    }

    private static void Flush()
    {
        var pref = _pending;
        _pending = null;
        if (pref == null) return;
        try
        {
            var local = Windows.Storage.ApplicationData.Current.LocalSettings;
            local.Values[Key] = (int)pref.Value;
        }
        catch
        {
            // Same fallback as Load — best-effort
            // persistence. The user's choice is still
            // applied for the current session via the
            // page-level event handler.
        }
    }

    /// <summary>
    /// Map a preference onto a WinUI 3 `ElementTheme`.
    /// `SystemDefault` is represented by
    /// `ElementTheme.Default` which the framework
    /// resolves against the OS theme.
    /// </summary>
    public static ElementTheme ToElementTheme(AppThemePreference p) => p switch
    {
        AppThemePreference.Light => ElementTheme.Light,
        AppThemePreference.Dark => ElementTheme.Dark,
        _ => ElementTheme.Default,
    };
}
