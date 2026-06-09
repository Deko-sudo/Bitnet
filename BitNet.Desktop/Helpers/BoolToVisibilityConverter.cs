// BitNet.Desktop - BoolToVisibilityConverter
//
// Maps a bool to a `Microsoft.UI.Xaml.Visibility`
// value. The two values that matter for the
// VaultPage:
//
//   true  -> Visible
//   false -> Collapsed
//
// This is the WinUI 3 equivalent of the Silverlight
// / WPF built-in converter of the same name. We
// keep it in a tiny standalone file so the test
// project can reference its sibling enum helpers
// without dragging in the WinUI 3 runtime.

using System;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Data;

namespace BitNet.Desktop.Helpers;

public sealed class BoolToVisibilityConverter : IValueConverter
{
    /// <summary>Visible iff `value` is true. Null
    /// and any other type are treated as false.</summary>
    public object Convert(object value, Type targetType, object parameter, string language)
    {
        return (value is bool b && b) ? Visibility.Visible : Visibility.Collapsed;
    }

    /// <summary>Inverse of Convert: Visible -> true,
    /// anything else -> false.</summary>
    public object ConvertBack(object value, Type targetType, object parameter, string language)
    {
        return value is Visibility v && v == Visibility.Visible;
    }
}
