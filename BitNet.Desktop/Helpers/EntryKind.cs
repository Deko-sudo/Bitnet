// BitNet.Desktop - EntryKind
//
// Pure enum + metadata for the supported entry types.
// This file has no WinUI 3 / Windows-specific
// dependencies, so it can be referenced from unit
// tests and (eventually) cross-platform code.
//
// The `Label` and `Glyph` mapping used by the GUI
// lives in `EntryTypeIcons` (Windows-only). When the
// Rust core starts emitting a `kind` field, we map
// its string values onto the `EntryKind` enum
// here.

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

/// <summary>
/// Non-UI metadata for the `EntryKind` enum. The
/// WinUI-specific glyph/accent mappings live in
/// `EntryTypeIcons` to keep this file free of
/// `Microsoft.UI` references (so the enum can be
/// used in unit tests and shared with future
/// cross-platform code).
/// </summary>
public static class EntryKindExtensions
{
    /// <summary>
    /// Map a string from the Rust core's `kind`
    /// JSON field onto an `EntryKind`. Unknown
    /// values default to `Login` (the most common
    /// case) so the v0.1 fallback path is a no-op
    /// for entries that don't yet have a kind.
    /// </summary>
    public static EntryKind ParseKind(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return EntryKind.Login;
        }
        return raw.Trim().ToLowerInvariant() switch
        {
            "login" => EntryKind.Login,
            "note" or "securenote" or "secure_note" => EntryKind.SecureNote,
            "card" or "creditcard" or "credit_card" => EntryKind.CreditCard,
            "identity" => EntryKind.Identity,
            "ssh" or "sshkey" or "ssh_key" => EntryKind.SshKey,
            "wifi" or "wi-fi" => EntryKind.Wifi,
            "database" => EntryKind.Database,
            "passport" => EntryKind.Passport,
            "driver" or "drivers_licence" or "driverslicence" => EntryKind.Driver,
            "software" or "software_licence" or "softwarelicence" => EntryKind.Software,
            _ => EntryKind.Login,
        };
    }

    /// <summary>
    /// Stable lowercase string identifier that the
    /// Rust core can use to identify this kind in
    /// JSON. Mirrors the keys accepted by
    /// `ParseKind`.
    /// </summary>
    public static string ToWireString(this EntryKind kind) => kind switch
    {
        EntryKind.Login => "login",
        EntryKind.SecureNote => "note",
        EntryKind.CreditCard => "card",
        EntryKind.Identity => "identity",
        EntryKind.SshKey => "ssh",
        EntryKind.Wifi => "wifi",
        EntryKind.Database => "database",
        EntryKind.Passport => "passport",
        EntryKind.Driver => "driver",
        EntryKind.Software => "software",
        _ => "login",
    };
}
