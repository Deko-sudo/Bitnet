using System;
using System.Runtime.InteropServices;
using BitNet.Desktop.Helpers;
using BitNet.Desktop.Native;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;

namespace BitNet.Desktop
{
    public sealed partial class MainWindow : Window
    {
        public MainWindow()
        {
            this.InitializeComponent();
            ExtendsContentIntoTitleBar = true;
            SetTitleBar(null);
            NavView.Visibility = Visibility.Collapsed;

            // [BITNET-L3] CWE-841 (documentation): the
            // `AutoLockService.Load()` call below must run
            // BEFORE `ContentFrame.Navigate(typeof(UnlockPage))`,
            // because the navigation fires
            // `ContentFrame_Navigated` which calls
            // `AutoLockService.Instance.LockNow()`. The
            // Load is harmless whether it runs before or
            // after the LockNow (it only reads from
            // LocalSettings), but the relative ordering
            // matters: if a future refactor moves the
            // `Navigate` call up, the auto-lock timer
            // will be running with the *default* 15 min
            // timeout during the first user-visible
            // frame, instead of the persisted value.
            //
            // Apply the persisted theme preference on
            // launch. The Settings page handles
            // user-driven changes at runtime.
            try
            {
                var pref = AppThemeService.Load();
                if (Content is FrameworkElement root)
                {
                    root.RequestedTheme = AppThemeService.ToElementTheme(pref);
                }
            }
            catch
            {
                // best-effort: if LocalSettings is
                // unavailable, fall back to the system
                // default.
            }

            // Wire up the AutoLockService. When the idle
            // timer fires, we navigate back to the unlock
            // page (which discards any in-memory secrets)
            // and clear the clipboard just in case.
            //
            // [BITNET-L3] Load BEFORE Navigate (see the
            // long comment above).
            AutoLockService.Instance.Load();

            // [BITNET-L3] navigate to the unlock page
            // AFTER wiring up `ContentFrame.Navigated`
            // so the very first navigation event is
            // observed (the old code navigated first and
            // wired second; the event still fired because
            // WinUI 3 fires the event synchronously on
            // the current thread, but the ordering was
            // fragile). The order is now:
            //   1. InitializeComponent
            //   2. Apply theme
            //   3. AutoLockService.Load()
            //   4. Wire Navigated handler
            //   5. Wire Touch() handlers (H4)
            //   6. Wire AutoLock event handler (H5)
            //   7. Navigate(UnlockPage)
            ContentFrame.Navigated += ContentFrame_Navigated;

            // [BITNET-H4] CWE-613: AutoLockService.Touch() used to
            // be dead code (no callers). Wire the root ContentFrame
            // to fire Touch() on every user input event so the
            // idle window resets on real activity.
            ContentFrame.AddHandler(
                UIElement.PointerPressedEvent,
                new PointerEventHandler(OnUserActivity),
                handledEventsToo: true);
            ContentFrame.AddHandler(
                UIElement.KeyDownEvent,
                new KeyEventHandler(OnUserActivity),
                handledEventsToo: true);

            AutoLockService.Instance.AutoLock += (_, _) =>
            {
                DispatcherQueue.TryEnqueue(() =>
                {
                    // [BITNET-H5] CWE-613: zeroise the in-process
                    // session token BEFORE navigating away. The
                    // previous version only navigated, leaving the
                    // Rust-core session token resident and re-usable
                    // on the next unlock.
                    try
                    {
                        BitnetCore.bitnet_vault_lock();
                    }
                    catch
                    {
                        // best-effort: a stale or never-initialised
                        // FFI state must not crash the auto-lock path
                    }
                    ClipboardHelper.ClearClipboard();
                    ContentFrame.Navigate(typeof(Views.UnlockPage));
                });
            };

            // [BITNET-L3] navigate AFTER all wiring
            // (see comment above).
            ContentFrame.Navigate(typeof(Views.UnlockPage));
        }

        // [BITNET-H4] Any pointer press or key press anywhere inside
        // the main frame counts as user activity and resets the
        // auto-lock idle window. The handler is hooked with
        // `handledEventsToo: true` so children that mark the event
        // handled (e.g. a TextBox committing a keystroke) still
        // bubble up here.
        private void OnUserActivity(object sender, object e)
        {
            AutoLockService.Instance.Touch();
        }

        private void ContentFrame_Navigated(object sender, Microsoft.UI.Xaml.Navigation.NavigationEventArgs e)
        {
            if (e.SourcePageType == typeof(Views.UnlockPage))
            {
                NavView.Visibility = Visibility.Collapsed;
                // Entering the unlock page means the vault
                // is locked; the AutoLockService no longer
                // needs to fire.
                AutoLockService.Instance.LockNow();
            }
            else
            {
                NavView.Visibility = Visibility.Visible;
                // Successful navigation to a non-unlock
                // page = successful unlock. Reset the idle
                // timer.
                AutoLockService.Instance.Reset();
            }
        }

        private void NavView_SelectionChanged(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
        {
            if (args.SelectedItem is NavigationViewItem item)
            {
                var tag = item.Tag?.ToString();
                switch (tag)
                {
                    case "vault":
                        ContentFrame.Navigate(typeof(Views.VaultPage));
                        break;
                    case "generator":
                        ContentFrame.Navigate(typeof(Views.GeneratorPage));
                        break;
                    case "settings":
                        ContentFrame.Navigate(typeof(Views.SettingsPage));
                        break;
                }
            }
        }
    }
}
