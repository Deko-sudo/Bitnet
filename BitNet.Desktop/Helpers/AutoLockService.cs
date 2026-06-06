// BitNet.Desktop - AutoLockService
//
// Watches user activity (keyboard / mouse) and locks the
// vault after a configurable idle timeout. This is the
// same security feature as Bitwarden's "Vault timeout" and
// Proton Pass's "Auto-lock".
//
// Implementation: we hook the `DispatcherQueue` for a
// timer tick every 1 second. On each tick we check the
// last-known activity timestamp. If the elapsed time
// exceeds the timeout, we fire `OnAutoLock` which the
// `MainWindow` handles by navigating back to the unlock
// page and zeroising the session token.
//
// Settings (default values match Bitwarden's defaults):
//   - Never (0)
//   - 1 minute
//   - 5 minutes
//   - 15 minutes
//   - 1 hour
//   - 4 hours
//
// The check granularity is 1 second. The accuracy of the
// timer is sufficient for security purposes — sub-second
// granularity would burn CPU for no real benefit.

using System;
using Microsoft.UI.Dispatching;

namespace BitNet.Desktop.Helpers;

public enum AutoLockTimeout
{
    Never = 0,
    OneMinute = 60,
    FiveMinutes = 300,
    FifteenMinutes = 900,
    OneHour = 3600,
    FourHours = 14400,
}

/// <summary>
/// Singleton service that fires `AutoLock` after an idle
/// period. Settings are persisted via the standard
/// `ApplicationData.Current.LocalSettings` keys.
/// </summary>
public sealed class AutoLockService
{
    private static readonly Lazy<AutoLockService> s_instance =
        new(() => new AutoLockService());

    public static AutoLockService Instance => s_instance.Value;

    private readonly DispatcherQueueTimer _timer;
    private DateTimeOffset _lastActivity;
    private AutoLockTimeout _timeout;
    private bool _isLocked;

    /// <summary>
    /// Fired on the UI thread when the idle timeout expires
    /// and the vault should be locked.
    /// </summary>
    public event EventHandler? AutoLock;

    private AutoLockService()
    {
        _timer = DispatcherQueue.GetForCurrentThread().CreateTimer();
        _timer.Interval = TimeSpan.FromSeconds(1);
        _timer.IsRepeating = true;
        _timer.Tick += OnTick;
        _lastActivity = DateTimeOffset.UtcNow;
        _timeout = AutoLockTimeout.FifteenMinutes;
        _timer.Start();
    }

    /// <summary>
    /// Update the timeout (called from Settings page).
    /// Persists the choice to local settings.
    /// </summary>
    public void SetTimeout(AutoLockTimeout timeout)
    {
        _timeout = timeout;
        Windows.Storage.ApplicationData.Current.LocalSettings.Values["auto_lock_timeout"] = (int)timeout;
    }

    /// <summary>
    /// Load the saved timeout at app startup. Default is
    /// 15 minutes (Bitwarden default).
    /// </summary>
    public void Load()
    {
        if (Windows.Storage.ApplicationData.Current.LocalSettings.Values.TryGetValue("auto_lock_timeout", out var raw) && raw is int i)
        {
            _timeout = (AutoLockTimeout)i;
        }
    }

    /// <summary>
    /// Record user activity. Called from any input event
    /// handler in the unlocked pages.
    /// </summary>
    public void Touch()
    {
        _lastActivity = DateTimeOffset.UtcNow;
    }

    /// <summary>
    /// Force-lock the vault (e.g. "Lock now" button).
    /// Fires AutoLock immediately.
    /// </summary>
    public void LockNow()
    {
        if (_isLocked) return;
        _isLocked = true;
        AutoLock?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>
    /// Reset the lock state after a successful unlock.
    /// </summary>
    public void Reset()
    {
        _isLocked = false;
        _lastActivity = DateTimeOffset.UtcNow;
    }

    private void OnTick(DispatcherQueueTimer sender, object args)
    {
        if (_isLocked) return;
        if (_timeout == AutoLockTimeout.Never) return;
        var idle = DateTimeOffset.UtcNow - _lastActivity;
        if (idle.TotalSeconds >= (int)_timeout)
        {
            LockNow();
        }
    }
}
