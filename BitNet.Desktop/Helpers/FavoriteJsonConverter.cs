// BitNet.Desktop - FavoriteJsonConverter
//
// `System.Text.Json` converter for the `VaultEntry.Favorite`
// property. The Rust core serialises the field as
// `"favorite": true|false` (snake-case, per the core
// convention) and older vaults may not include the field at
// all. The converter:
//
//   - accepts `true` / `false` (the canonical form)
//   - accepts `1` / `0` (interop with crates that may
//     serialise booleans as integers)
//   - accepts the strings `"true"` / `"false"` (defensive)
//   - treats `null` or a missing field as `false` (the
//     "non-favourite" default for v0.1 entries that did
//     not serialise the field at all)
//
// The converter is a write-side no-op (emits the canonical
// `true` / `false` JSON literals).

using System;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace BitNet.Desktop.Helpers;

public sealed class FavoriteJsonConverter : JsonConverter<bool>
{
    public override bool Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options)
    {
        switch (reader.TokenType)
        {
            case JsonTokenType.True:
                return true;
            case JsonTokenType.False:
                return false;
            case JsonTokenType.Number:
                // 1 -> true, 0 -> false. Any other value
                // defaults to false (defensive: we never
                // want to crash the UI on a malformed
                // entry from the core).
                if (reader.TryGetInt32(out var i))
                {
                    return i != 0;
                }
                return false;
            case JsonTokenType.String:
                var s = reader.GetString();
                return s != null
                    && (s.Equals("true", StringComparison.OrdinalIgnoreCase)
                        || s == "1");
            case JsonTokenType.Null:
                return false;
            default:
                // Unknown shape — fall back to false rather
                // than throwing, so a single malformed entry
                // cannot lock the user out of the vault.
                return false;
        }
    }

    public override void Write(
        Utf8JsonWriter writer,
        bool value,
        JsonSerializerOptions options)
    {
        // Canonical output: `true` / `false` literals.
        // Avoid string-quoted booleans so downstream
        // consumers (other Rust crates, the Browser
        // extension) parse it as a real boolean.
        if (value)
        {
            writer.WriteBooleanValue(true);
        }
        else
        {
            writer.WriteBooleanValue(false);
        }
    }
}
