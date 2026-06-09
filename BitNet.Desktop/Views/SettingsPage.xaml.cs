// BitNet.Desktop - SettingsPage code-behind.
//
// Provides the user-visible controls for the
// AutoLockService. The previous version had a Slider
// 1-30 min that was never wired to the service; this
// version uses a ComboBox with the same discrete
// options as Bitwarden / Proton Pass and persists the
// choice through `AutoLockService.SetTimeout`.
//
// The `Tag` attribute on each ComboBoxItem carries the
// timeout in seconds (matching `AutoLockTimeout` enum
// values). Selection is restored from
// `AutoLockService.Timeout` on page load.

using System;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using BitNet.Desktop.Helpers;
using BitNet.Desktop.Native;
namespace BitNet.Desktop.Views
{
    public sealed partial class SettingsPage : Page
    {
        /// <summary>True when this page was created via
        /// the settings nav (vs. the Lock-now flow which
        /// navigates directly to the unlock page).</summary>
        private bool _initialised;

        // [BITNET-M11] CWE-841: when the page is first
        // loaded, OnLoaded sets `ThemeRadioButtons.SelectedIndex`
        // to reflect the persisted preference. That
        // assignment fires the `SelectionChanged` event,
        // which would normally persist the preference
        // back to LocalSettings. On a first launch (or any
        // time the radio buttons are in a transient
        // state) the SelectionChanged can race with the
        // initial wiring and overwrite the user's
        // saved Light/Dark with the placeholder
        // SystemDefault. The flag suppresses the Save
        // call during the initial population.
        private bool _isLoadingPreference;

        public SettingsPage()
        {
            this.InitializeComponent();
            Loaded += OnLoaded;
        }

        private void OnLoaded(object sender, RoutedEventArgs e)
        {
            if (_initialised) return;
            _initialised = true;

            // Reflect the AutoLockService state into the
            // UI. The service is a singleton so this
            // value is shared with the rest of the app
            // (MainWindow reads it too).
            var timeout = AutoLockService.Instance.Timeout;
            AutoLockToggle.IsOn = timeout != AutoLockTimeout.Never;
            SelectTimeout(timeout);

            // Reflect the persisted theme preference.
            // RadioButtons with string content lets us
            // map the displayed text directly onto the
            // AppThemePreference enum. The
            // `_isLoadingPreference` guard prevents the
            // SelectionChanged handler from re-saving
            // the value we just loaded (which would race
            // with the first launch and could clobber a
            // saved Light / Dark preference with the
            // SystemDefault placeholder).
            var theme = AppThemeService.Load();
            _isLoadingPreference = true;
            try
            {
                ThemeRadioButtons.SelectedIndex = (int)theme;
            }
            finally
            {
                _isLoadingPreference = false;
            }
        }

        private void SelectTimeout(AutoLockTimeout timeout)
        {
            var seconds = (int)timeout;
            foreach (var item in AutoLockTimeoutCombo.Items)
            {
                if (item is ComboBoxItem cbi
                    && cbi.Tag is string s
                    && int.TryParse(s, out var n)
                    && n == seconds)
                {
                    AutoLockTimeoutCombo.SelectedItem = cbi;
                    return;
                }
            }
            // Fallback: first item.
            AutoLockTimeoutCombo.SelectedIndex = 0;
        }

        private void AutoLockToggle_Toggled(object sender, RoutedEventArgs e)
        {
            if (AutoLockToggle.IsOn)
            {
                // When the user enables auto-lock, default
                // to 15 minutes if they had "Never"
                // selected. The setter persists to
                // LocalSettings.
                AutoLockService.Instance.SetTimeout(AutoLockTimeout.FifteenMinutes);
                SelectTimeout(AutoLockTimeout.FifteenMinutes);
            }
            else
            {
                AutoLockService.Instance.SetTimeout(AutoLockTimeout.Never);
                SelectTimeout(AutoLockTimeout.Never);
            }
        }

        private void AutoLockTimeoutCombo_SelectionChanged(
            object sender, SelectionChangedEventArgs e)
        {
            if (AutoLockTimeoutCombo.SelectedItem is ComboBoxItem cbi
                && cbi.Tag is string s
                && int.TryParse(s, out var seconds))
            {
                AutoLockService.Instance.SetTimeout((AutoLockTimeout)seconds);
                // Keep the toggle in sync.
                AutoLockToggle.IsOn = seconds != 0;
            }
        }

        private void LockNow_Click(object sender, RoutedEventArgs e)
        {
            // Lock at the FFI level (zeroises the
            // in-process session token) AND fire the
            // AutoLock event so the navigation handler
            // in MainWindow takes us to the unlock page.
            BitnetCore.bitnet_vault_lock();
            AutoLockService.Instance.LockNow();
        }

        /// <summary>
        /// Persist the theme selection whenever the
        /// user picks a different option. The actual
        /// theme application is the responsibility of
        /// MainWindow (which owns the root visual);
        /// the page only saves the preference and
        /// emits a debug log so we can trace
        /// unexpected navigations.
        /// </summary>
        private void ThemeRadioButtons_SelectionChanged(
            object sender, SelectionChangedEventArgs e)
        {
            // [BITNET-M11] ignore the SelectionChanged
            // raised by the initial population in
            // OnLoaded; only persist on user-initiated
            // changes.
            if (_isLoadingPreference) return;
            if (ThemeRadioButtons.SelectedIndex < 0) return;
            var pref = (AppThemePreference)ThemeRadioButtons.SelectedIndex;
            AppThemeService.Save(pref);
            // Apply the theme immediately. The root
            // visual is the MainWindow's content; we
            // look it up by walking the visual tree
            // from the page's XamlRoot.
            if (XamlRoot?.Content is FrameworkElement root)
            {
                root.RequestedTheme = AppThemeService.ToElementTheme(pref);
            }
        }
    }
}
