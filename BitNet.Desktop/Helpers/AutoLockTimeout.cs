// BitNet.Desktop - AutoLockTimeout (pure enum)
//
// The WinUI 3 timer plumbing lives in `AutoLockService`
// and cannot be unit-tested without a DispatcherQueue.
// The enum values themselves are pure data and live
// here so the test project (and any future
// cross-platform consumer) can reference them.
//
// Bitwarden / Proton Pass auto-lock values used in
// production: Never, 1 minute, 5 minutes, 15 minutes
// (default), 1 hour, 4 hours.

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
