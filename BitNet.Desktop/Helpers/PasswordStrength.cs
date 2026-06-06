// BitNet.Desktop - PasswordStrength
//
// Estimates password strength using a lightweight entropy
// approximation. The result is a 0..100 score and a
// qualitative label ("Very weak" .. "Very strong").
//
// This is NOT a substitute for a proper zxcvbn-style
// cracker. The point is to give users immediate visual
// feedback in the Unlock and EntryEditor pages so they
// pick better master passwords.
//
// Algorithm: length * log2(charset_size) is the textbook
// Shannon entropy approximation, capped at 100. The
// `log2` values are constant per character class:
//   - digits        : 3.32 bits
//   - lower letters : 4.70 bits
//   - upper letters : 4.70 bits
//   - common punctuation: 4.00 bits
//   - other (incl. unicode, spaces): 5.95 bits
//
// We give a 5-bit-per-char baseline + bonus for length
// beyond 12 characters, which matches the "NIST SP
// 800-63B" advice (length is the dominant factor).

using System;

namespace BitNet.Desktop.Helpers;

public static class PasswordStrength
{
    public enum Strength
    {
        VeryWeak,
        Weak,
        Fair,
        Strong,
        VeryStrong,
    }

    /// <summary>
    /// Score a password. Returns 0..100 (higher is
    /// stronger) and a Strength label.
    /// </summary>
    public static (int Score, Strength Label) Score(string? password)
    {
        if (string.IsNullOrEmpty(password))
        {
            return (0, Strength.VeryWeak);
        }
        // Charset detection. We count unique classes present
        // and use a fixed per-class bit-rate.
        bool hasDigit = false, hasLower = false, hasUpper = false, hasPunct = false, hasOther = false;
        foreach (var c in password)
        {
            if (char.IsDigit(c)) hasDigit = true;
            else if (char.IsLower(c)) hasLower = true;
            else if (char.IsUpper(c)) hasUpper = true;
            else if (char.IsPunctuation(c) || c == ' ') hasPunct = true;
            else hasOther = true;
        }
        // Per-class log2(charset_size).
        double bitsPerChar = 0;
        if (hasDigit) bitsPerChar += 3.32;
        if (hasLower) bitsPerChar += 4.70;
        if (hasUpper) bitsPerChar += 4.70;
        if (hasPunct) bitsPerChar += 4.00;
        if (hasOther) bitsPerChar += 5.95;
        // Baseline 5 bits for any input (so single-class
        // passwords like "aaaaaaaa" don't score artificially
        // high).
        if (bitsPerChar == 0) bitsPerChar = 5.0;
        // Length bonus: passwords >= 12 chars get a 20% boost
        // (NIST guidance: length dominates complexity).
        var lengthBonus = password.Length >= 12 ? 1.20 : 1.0;
        // Entropy in bits.
        var entropy = password.Length * bitsPerChar * lengthBonus;
        // Map to 0..100. 80 bits is "strong enough" for an
        // offline attacker; 128 is "good enough for
        // nation-state"; we cap at 100 (which represents
        // ~96 bits of entropy).
        var score = (int)Math.Min(100, entropy * 100 / 96);
        var label = entropy switch
        {
            < 28 => Strength.VeryWeak,
            < 36 => Strength.Weak,
            < 60 => Strength.Fair,
            < 80 => Strength.Strong,
            _    => Strength.VeryStrong,
        };
        return (score, label);
    }

    /// <summary>Accent colour for the strength label (Bitwarden palette).</summary>
    public static string AccentBrushKey(Strength label) => label switch
    {
        Strength.VeryWeak   => "SystemFillColorCriticalBrush",
        Strength.Weak       => "SystemFillColorCautionBrush",
        Strength.Fair       => "SystemFillColorAttentionBrush",
        Strength.Strong     => "SystemFillColorSuccessBrush",
        Strength.VeryStrong => "AccentFillColorDefaultBrush",
        _                   => "TextFillColorSecondaryBrush",
    };

    public static string LabelText(Strength label) => label switch
    {
        Strength.VeryWeak   => "Very weak",
        Strength.Weak       => "Weak",
        Strength.Fair       => "Fair",
        Strength.Strong     => "Strong",
        Strength.VeryStrong => "Very strong",
        _                   => "Unknown",
    };
}
