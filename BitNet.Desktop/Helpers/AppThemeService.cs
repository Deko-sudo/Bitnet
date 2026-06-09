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
    /// Persist the chosen preference. The setting
    /// takes effect on the next page navigation
    /// or window activation.
    /// </summary>
    public static void Save(AppThemePreference preference)
    {
        try
        {
            var local = Windows.Storage.ApplicationData.Current.LocalSettings;
            local.Values[Key] = (int)preference;
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
