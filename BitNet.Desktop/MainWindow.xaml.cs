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
            ContentFrame.Navigate(typeof(Views.UnlockPage));
            ContentFrame.Navigated += ContentFrame_Navigated;

            // Wire up the AutoLockService. When the idle
            // timer fires, we navigate back to the unlock
            // page (which discards any in-memory secrets)
            // and clear the clipboard just in case.
            AutoLockService.Instance.Load();

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
