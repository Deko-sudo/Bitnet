// BitNet.Desktop.Tests - HelperTests
//
// xunit tests for the small helper classes that do
// not require a DispatcherQueue or the WinUI 3
// runtime. Helpers that DO need a DispatcherQueue
// (AutoLockService, ClipboardHelper) are tested in
// their own files to keep the test surface clear.

using System;
using System.IO;
using BitNet.Desktop.Helpers;
using BitNet.Desktop.Native;
using Xunit;

namespace BitNet.Desktop.Tests;

public class PasswordStrengthTests
{
    [Fact]
    public void Score_EmptyInput_ReturnsVeryWeakZero()
    {
        var (score, label) = PasswordStrength.Score("");
        Assert.Equal(0, score);
        Assert.Equal(PasswordStrength.Strength.VeryWeak, label);
    }

    [Fact]
    public void Score_NullInput_ReturnsVeryWeakZero()
    {
        var (score, label) = PasswordStrength.Score(null);
        Assert.Equal(0, score);
        Assert.Equal(PasswordStrength.Strength.VeryWeak, label);
    }

    [Fact]
    public void Score_ShortNumericOnly_StaysWeak()
    {
        // "1234" — 4 digits, ~13 bits. Should be weak.
        var (score, label) = PasswordStrength.Score("1234");
        Assert.True(score < 40, $"expected weak, got {score}");
        Assert.True(
            label == PasswordStrength.Strength.VeryWeak
            || label == PasswordStrength.Strength.Weak,
            $"expected very weak or weak, got {label}");
    }

    [Fact]
    public void Score_LongMixedChar_ReachesStrong()
    {
        // 16 chars, 3 character classes: digits, lower,
        // upper. ~120 bits nominal; with 20% length
        // bonus for >= 12 chars, that's ~144 bits.
        // Mapped to 0..100, capped at 100.
        var (score, label) = PasswordStrength.Score("Abcdef123456789X");
        Assert.True(score >= 70, $"expected strong, got {score}");
        Assert.True(
            label == PasswordStrength.Strength.Strong
            || label == PasswordStrength.Strength.VeryStrong,
            $"expected strong or very strong, got {label}");
    }

    [Fact]
    public void Score_OnlyLowerLettersLongerThan12_GetsLengthBonus()
    {
        // "abcdefghijklmnop" — only lower, 16 chars.
        // 4.7 bits/char * 16 = ~75 bits. After 20%
        // length bonus (>= 12): ~90 bits. Mapped to
        // ~94/100. Should hit Fair or better.
        var (score, label) = PasswordStrength.Score("abcdefghijklmnop");
        Assert.True(score >= 50, $"expected fair+, got {score}");
        Assert.True(
            label != PasswordStrength.Strength.VeryWeak
            && label != PasswordStrength.Strength.Weak,
            $"long single-class password should not be weak, got {label}");
    }

    [Fact]
    public void Score_ShortAllClasses_DoesNotGetLengthBonus()
    {
        // 6 chars, three character classes
        // (digits + lower + upper): ~12.7 bits/char * 6
        // = ~76 bits. No length bonus (< 12 chars).
        // Falls in the < 80 band, so the label is
        // `Strong` (NOT `Fair` — Fair is 36-60).
        // We assert the label and a score range.
        var (score, label) = PasswordStrength.Score("Abc123");
        Assert.InRange(score, 70, 90);
        Assert.Equal(PasswordStrength.Strength.Strong, label);
    }

    [Fact]
    public void Score_PunctuationIncreasesEntropy()
    {
        // We compare two passwords of the same length
        // and base classes; the second adds
        // punctuation. Both should cap at 100 (the
        // entropy is well above 96 bits), so we verify
        // via a lower-entropy baseline that
        // punctuation does contribute to the score.
        var baseline = PasswordStrength.Score("aabbccddee");
        var withPunct = PasswordStrength.Score("aabb!ccdd@e");
        // Adding two punctuation classes should
        // bump the bits/char and the score.
        Assert.True(
            withPunct.Score > baseline.Score,
            $"expected punctuation to increase score, got {withPunct.Score} vs {baseline.Score}");
    }

    [Theory]
    [InlineData(PasswordStrength.Strength.VeryWeak, "Very weak")]
    [InlineData(PasswordStrength.Strength.Weak, "Weak")]
    [InlineData(PasswordStrength.Strength.Fair, "Fair")]
    [InlineData(PasswordStrength.Strength.Strong, "Strong")]
    [InlineData(PasswordStrength.Strength.VeryStrong, "Very strong")]
    public void LabelText_ReturnsEnglishLabel(PasswordStrength.Strength strength, string expected)
    {
        Assert.Equal(expected, PasswordStrength.LabelText(strength));
    }

    [Theory]
    [InlineData(PasswordStrength.Strength.VeryWeak)]
    [InlineData(PasswordStrength.Strength.Weak)]
    [InlineData(PasswordStrength.Strength.Fair)]
    [InlineData(PasswordStrength.Strength.Strong)]
    [InlineData(PasswordStrength.Strength.VeryStrong)]
    public void AccentBrushKey_ReturnsNonEmpty(PasswordStrength.Strength strength)
    {
        // We just verify the resource key is non-empty
        // and well-formed; resolving the actual brush
        // requires an Application instance.
        var key = PasswordStrength.AccentBrushKey(strength);
        Assert.False(string.IsNullOrWhiteSpace(key));
        Assert.EndsWith("Brush", key);
    }
}

public class EntryKindTests
{
    [Theory]
    [InlineData("login", EntryKind.Login)]
    [InlineData("note", EntryKind.SecureNote)]
    [InlineData("securenote", EntryKind.SecureNote)]
    [InlineData("secure_note", EntryKind.SecureNote)]
    [InlineData("card", EntryKind.CreditCard)]
    [InlineData("creditcard", EntryKind.CreditCard)]
    [InlineData("credit_card", EntryKind.CreditCard)]
    [InlineData("identity", EntryKind.Identity)]
    [InlineData("ssh", EntryKind.SshKey)]
    [InlineData("sshkey", EntryKind.SshKey)]
    [InlineData("ssh_key", EntryKind.SshKey)]
    [InlineData("wifi", EntryKind.Wifi)]
    [InlineData("wi-fi", EntryKind.Wifi)]
    [InlineData("database", EntryKind.Database)]
    [InlineData("passport", EntryKind.Passport)]
    [InlineData("driver", EntryKind.Driver)]
    [InlineData("software", EntryKind.Software)]
    public void ParseKind_AllKnownStrings(string raw, EntryKind expected)
    {
        Assert.Equal(expected, EntryKindExtensions.ParseKind(raw));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    [InlineData("unknown_kind")]
    [InlineData("Login")] // case sensitivity — we lowercase
    public void ParseKind_UnknownOrEmpty_ReturnsLogin(string? raw)
    {
        Assert.Equal(EntryKind.Login, EntryKindExtensions.ParseKind(raw));
    }

    [Fact]
    public void ToWireString_AllEnumValues_NonEmpty()
    {
        foreach (var kind in Enum.GetValues<EntryKind>())
        {
            var s = kind.ToWireString();
            Assert.False(string.IsNullOrWhiteSpace(s),
                $"ToWireString for {kind} returned empty");
        }
    }

    [Fact]
    public void ToWireString_ThenParseKind_RoundTrips()
    {
        foreach (var kind in Enum.GetValues<EntryKind>())
        {
            var wire = kind.ToWireString();
            var parsed = EntryKindExtensions.ParseKind(wire);
            Assert.Equal(kind, parsed);
        }
    }
}

public class AutoLockTimeoutTests
{
    [Fact]
    public void Never_IsZero()
    {
        // 0 is the "off" sentinel value; the
        // AutoLockService treats any timeout of 0
        // as "never lock" and skips the timer.
        Assert.Equal(0, (int)AutoLockTimeout.Never);
    }

    [Theory]
    [InlineData(AutoLockTimeout.Never, 0)]
    [InlineData(AutoLockTimeout.OneMinute, 60)]
    [InlineData(AutoLockTimeout.FiveMinutes, 300)]
    [InlineData(AutoLockTimeout.FifteenMinutes, 900)]
    [InlineData(AutoLockTimeout.OneHour, 3600)]
    [InlineData(AutoLockTimeout.FourHours, 14400)]
    public void EnumValues_HaveExpectedSeconds(AutoLockTimeout t, int expectedSeconds)
    {
        Assert.Equal(expectedSeconds, (int)t);
    }

    [Fact]
    public void AllValues_AreUnique()
    {
        var seen = new System.Collections.Generic.HashSet<int>();
        foreach (var t in Enum.GetValues<AutoLockTimeout>())
        {
            Assert.True(seen.Add((int)t),
                $"timeout {t} duplicates an earlier value");
        }
    }

    [Fact]
    public void Never_AndOtherValues_HaveDistinctSeconds()
    {
        // The "Never" sentinel is a special case; all
        // other timeouts must have non-zero seconds
        // so the idle timer can compute a non-zero
        // delta.
        foreach (var t in Enum.GetValues<AutoLockTimeout>())
        {
            if (t == AutoLockTimeout.Never) continue;
            Assert.NotEqual(0, (int)t);
        }
    }
}

public class DaemonLauncherTests
{
    [Fact]
    public void DaemonExecutablePath_IsNotEmpty()
    {
        // The launcher resolves the binary path
        // at construction. We just verify the
        // property is populated.
        var launcher = DaemonLauncher.Instance;
        Assert.False(string.IsNullOrWhiteSpace(launcher.DaemonExecutablePath));
    }

    [Fact]
    public void DaemonExecutablePath_HasExpectedFileName()
    {
        var launcher = DaemonLauncher.Instance;
#if WINDOWS
        Assert.EndsWith("bitnet-cli.exe", launcher.DaemonExecutablePath);
#else
        Assert.EndsWith("bitnet-cli", launcher.DaemonExecutablePath);
#endif
    }

    [Fact]
    public void DaemonExecutablePath_IsAbsolute()
    {
        // The launcher MUST use an absolute path so
        // PATH-hijack attacks cannot redirect the
        // spawn to a malicious binary earlier in
        // PATH. If the resolution fallback is
        // broken, we end up with a non-absolute
        // (or even empty) path; this test catches
        // that regression.
        var launcher = DaemonLauncher.Instance;
        Assert.True(
            Path.IsPathRooted(launcher.DaemonExecutablePath),
            $"expected absolute path, got '{launcher.DaemonExecutablePath}'");
    }

    [Fact]
    public void IsAlive_FalseWhenBinaryMissing()
    {
        // When bitnet-cli.exe is not co-located
        // with the test runner (the common case
        // for unit tests run from the test bin
        // folder), IsAlive should return false
        // rather than throwing. We assert
        // non-throw behaviour here.
        var launcher = DaemonLauncher.Instance;
        var ex = Record.Exception(() => launcher.IsAlive);
        Assert.Null(ex);
    }

    [Fact]
    public void EnsureRunning_DoesNotThrow_WhenBinaryMissing()
    {
        // The launcher is best-effort: if the
        // binary is not found, EnsureRunning
        // returns false instead of throwing. This
        // lets the GUI keep working in standalone
        // mode.
        var launcher = DaemonLauncher.Instance;
        var ex = Record.Exception(() => launcher.EnsureRunning());
        // We don't assert the boolean value
        // (depends on the host machine) — only
        // that the call does not throw.
        Assert.Null(ex);
    }
}

public class AppThemeServiceTests
{
    [Fact]
    public void EnumValues_AreZeroIndexed()
    {
        // The RadioButtons.SelectedIndex is
        // cast directly to AppThemePreference, so
        // the enum order must match the UI
        // ordering (SystemDefault / Light / Dark).
        // A re-order would silently swap the
        // user's selection.
        Assert.Equal(0, (int)AppThemePreference.SystemDefault);
        Assert.Equal(1, (int)AppThemePreference.Light);
        Assert.Equal(2, (int)AppThemePreference.Dark);
    }

    [Fact]
    public void EnumValues_AreUnique()
    {
        // Two preferences with the same int value
        // would cause the RadioButtons control to
        // jump to the wrong entry on Load().
        var seen = new System.Collections.Generic.HashSet<int>();
        foreach (var p in Enum.GetValues<AppThemePreference>())
        {
            Assert.True(seen.Add((int)p),
                $"preference {p} duplicates an earlier value");
        }
    }
}
