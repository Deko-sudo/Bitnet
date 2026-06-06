// BitNet.Desktop - EntryTypeIcons
//
// Maps entry types to Segoe Fluent Icons glyphs and accent
// colours. The icon set follows the Bitwarden / Proton
// Pass conventions so the UI is instantly familiar to
// users migrating from other password managers.
//
// Glyph codes are from the Segoe Fluent Icons font that
// ships with Windows 11. On Windows 10 they fall back to
// the older Segoe MDL2 Assets codes (close enough for v1;
// the font fallback in WinUI 3 handles the difference).

using Microsoft.UI;

namespace BitNet.Desktop.Helpers;

public enum EntryKind
{
    Login,
    SecureNote,
    CreditCard,
    Identity,
    SshKey,
    Wifi,
    Database,
    Passport,
    Driver,
    Software,
}

public static class EntryTypeIcons
{
    /// <summary>Map entry kind to Segoe Fluent glyph codepoint.</summary>
    public static string Glyph(EntryKind kind) => kind switch
    {
        EntryKind.Login       => "\uE7AD", // Person / user
        EntryKind.SecureNote  => "\uE8A5", // Document
        EntryKind.CreditCard  => "\uE8C7", // Credit card
        EntryKind.Identity    => "\uE716", // Contact
        EntryKind.SshKey      => "\uE8D7", // Lock (and key)
        EntryKind.Wifi        => "\uE701", // Wi-Fi
        EntryKind.Database    => "\uE968", // Database
        EntryKind.Passport    => "\uE7C3", // Globe
        EntryKind.Driver      => "\uE7F4", // Driver
        EntryKind.Software    => "\uE73E", // App
        _                     => "\uE7C3", // fallback globe
    };

    /// <summary>Accent brush key for the entry kind.</summary>
    public static Windows.UI.Color AccentColor(EntryKind kind) => kind switch
    {
        EntryKind.Login       => Colors.SteelBlue,
        EntryKind.SecureNote  => Colors.MediumPurple,
        EntryKind.CreditCard  => Colors.MediumSeaGreen,
        EntryKind.Identity    => Colors.Orange,
        EntryKind.SshKey      => Colors.Crimson,
        EntryKind.Wifi        => Colors.Teal,
        EntryKind.Database    => Colors.DarkSlateBlue,
        EntryKind.Passport    => Colors.DarkCyan,
        EntryKind.Driver      => Colors.SlateGray,
        EntryKind.Software    => Colors.SteelBlue,
        _                     => Colors.Gray,
    };

    /// <summary>Human-readable kind label (English; localise later).</summary>
    public static string Label(EntryKind kind) => kind switch
    {
        EntryKind.Login       => "Login",
        EntryKind.SecureNote  => "Secure note",
        EntryKind.CreditCard  => "Credit card",
        EntryKind.Identity    => "Identity",
        EntryKind.SshKey      => "SSH key",
        EntryKind.Wifi        => "Wi-Fi",
        EntryKind.Database    => "Database",
        EntryKind.Passport    => "Passport",
        EntryKind.Driver      => "Driver's licence",
        EntryKind.Software    => "Software licence",
        _                     => "Other",
    };
}
