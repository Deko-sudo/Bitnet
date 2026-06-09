// BitNet.Desktop - AppThemePreference (pure enum)
//
// The WinUI 3 ElementTheme mapping lives in
// `AppThemeService.ToElementTheme` and cannot be
// unit-tested without a Microsoft.UI.Xaml reference.
// The enum itself is pure data and lives here so
// the test project can reference it.

namespace BitNet.Desktop.Helpers;

public enum AppThemePreference
{
    SystemDefault = 0,
    Light = 1,
    Dark = 2,
}
