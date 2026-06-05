using System;

namespace BitNet.Desktop.Native
{
    /// <summary>
    /// Centralized mapping of FFI negative return codes to user-facing
    /// messages. UI code MUST use <see cref="Describe"/> instead of
    /// interpolating the raw int into the dialog content — the raw code
    /// is an internal detail that leaks information about the failure
    /// (CWE-209, see [BITNET-L1] in the audit report).
    /// </summary>
    public static class BitnetError
    {
        public const int Ok = 0;
        public const int ErrNull = -1;
        public const int ErrGeneric = -2;
        public const int ErrSessionLocked = -3;
        public const int ErrInvalidPath = -4;
        public const int ErrBufferTooSmall = -5;
        public const int ErrEntryNotFound = -6;
        public const int ErrEntryJsonTooLarge = -7;
        public const int ErrGroupNotFound = -8;
        public const int ErrInternal = -99;

        /// <summary>True when the error is informational and the operation
        /// can be retried after the user takes some action (e.g. unlock).</summary>
        public static bool IsRetryable(int code)
        {
            return code switch
            {
                ErrSessionLocked => true,
                ErrInvalidPath => true,
                _ => false,
            };
        }

        /// <summary>Human-readable description of the error for end users.</summary>
        public static string Describe(int code) => code switch
        {
            Ok => "Success",
            ErrNull => "Invalid input. Please check your entry and try again.",
            ErrGeneric => "Operation failed. Please try again.",
            ErrSessionLocked => "The vault is locked. Please unlock it first.",
            ErrInvalidPath => "Invalid vault path. Must be a .bitnet file on a local drive.",
            ErrBufferTooSmall => "The value is too long for the output buffer.",
            ErrEntryNotFound => "Entry not found in the current vault.",
            ErrEntryJsonTooLarge => "Entry data exceeds the 10 MiB limit.",
            ErrGroupNotFound => "Group not found.",
            _ => "An unexpected error occurred. Please try again."
        };
    }
}
