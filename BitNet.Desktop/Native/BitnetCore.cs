using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace BitNet.Desktop.Native
{
    internal static class BitnetCore
    {
        private const string DllName = "bitnet_ffi.dll";

        // -------------------------------------------------------------------
        // Raw pointer imports (used by secure wrappers below)
        // -------------------------------------------------------------------
        [DllImport(DllName, EntryPoint = "bitnet_vault_unlock")]
        private static extern int bitnet_vault_unlock_raw(IntPtr path, IntPtr password);

        [DllImport(DllName, EntryPoint = "bitnet_vault_create")]
        private static extern int bitnet_vault_create_raw(IntPtr path, IntPtr password);

        [DllImport(DllName, EntryPoint = "bitnet_vault_save")]
        private static extern int bitnet_vault_save_raw(IntPtr path, IntPtr password);

        [DllImport(DllName, EntryPoint = "bitnet_add_entry")]
        private static extern int bitnet_add_entry_raw(IntPtr groupUuid, IntPtr entryJson);

        [DllImport(DllName, EntryPoint = "bitnet_update_entry")]
        private static extern int bitnet_update_entry_raw(IntPtr uuid, IntPtr entryJson);

        // -------------------------------------------------------------------
        // Standard imports
        // -------------------------------------------------------------------
        [DllImport(DllName)]
        [return: MarshalAs(UnmanagedType.I4)]
        public static extern int bitnet_init();

        [DllImport(DllName)]
        [return: MarshalAs(UnmanagedType.I4)]
        public static extern int bitnet_vault_lock();

        [DllImport(DllName)]
        [return: MarshalAs(UnmanagedType.I4)]
        public static extern int bitnet_vault_is_unlocked();

        [DllImport(DllName)]
        [return: MarshalAs(UnmanagedType.I4)]
        public static extern int bitnet_entry_get_password([MarshalAs(UnmanagedType.LPUTF8Str)] string uuid, [MarshalAs(UnmanagedType.LPUTF8Str)] StringBuilder outBuf, nuint outLen);

        [DllImport(DllName, EntryPoint = "bitnet_entry_get_totp_to_buffer")]
        private static extern int bitnet_entry_get_totp_to_buffer_raw([MarshalAs(UnmanagedType.LPUTF8Str)] string uuid, [MarshalAs(UnmanagedType.LPUTF8Str)] StringBuilder outBuf, nuint outLen);

        [DllImport(DllName)]
        public static extern IntPtr bitnet_entry_get_totp([MarshalAs(UnmanagedType.LPUTF8Str)] string uuid);

        [DllImport(DllName)]
        public static extern IntPtr bitnet_entry_get_details([MarshalAs(UnmanagedType.LPUTF8Str)] string uuid);

        [DllImport(DllName)]
        public static extern IntPtr bitnet_list_entries();

        [DllImport(DllName)]
        [return: MarshalAs(UnmanagedType.I4)]
        public static extern int bitnet_delete_entry([MarshalAs(UnmanagedType.LPUTF8Str)] string uuid);

        [DllImport(DllName)]
        public static extern IntPtr bitnet_create_group([MarshalAs(UnmanagedType.LPUTF8Str)] string parentUuid, [MarshalAs(UnmanagedType.LPUTF8Str)] string name);

        [DllImport(DllName)]
        public static extern IntPtr bitnet_generate_password(int length, int upper, int lower, int digits, int symbols, int ambiguous);

        [DllImport(DllName, EntryPoint = "bitnet_free_string")]
        public static extern void bitnet_free_string(IntPtr ptr);

        [DllImport(DllName)]
        [return: MarshalAs(UnmanagedType.I4)]
        public static extern int bitnet_vault_fingerprint([MarshalAs(UnmanagedType.LPUTF8Str)] string path);

        // -------------------------------------------------------------------
        // Secure wrappers – zeroize temporary UTF-8 buffers after native call
        // -------------------------------------------------------------------
        private static IntPtr Utf8ToPinnedPointer(string s, out GCHandle handle, out byte[] bytes)
        {
            bytes = Encoding.UTF8.GetBytes(s + "\0"); // null-terminated for CStr
            handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            return handle.AddrOfPinnedObject();
        }

        private static void ZeroizeAndFree(ref GCHandle handle, byte[] bytes)
        {
            if (handle.IsAllocated)
            {
                CryptographicOperations.ZeroMemory(bytes.AsSpan());
                handle.Free();
            }
        }

        /// <summary>
        /// Convert a managed string into a SecureString so that the cleartext
        /// password is no longer reachable as an immutable System.String.
        /// Note: the caller still owns the original string and is responsible
        /// for any in-place zeroization of it (managed strings are immutable
        /// so this is best-effort — pin and zero via the returned SecureString
        /// when full control is required).
        /// </summary>
        public static System.Security.SecureString ToSecureString(string value)
        {
            var ss = new System.Security.SecureString();
            if (value != null)
            {
                foreach (char c in value)
                {
                    ss.AppendChar(c);
                }
            }
            ss.MakeReadOnly();
            return ss;
        }

        // SECURITY: Only SecureString-aware variants are exposed publicly.
        // The legacy (string, string) overloads were removed in v0.2.0 as part
        // of [BITNET-H1] CWE-316 mitigation — System.String is immutable and
        // leaks the master password into the GC heap (visible in crash dumps).
        // All call-sites use PasswordBox.SecurePassword -> SecureString.

        /// <summary>
        /// Unlock an existing vault. The password is read directly from the
        /// unmanaged BSTR (no managed String allocation), and the BSTR is
        /// zeroized before the handle is released via Marshal.ZeroFreeBSTR.
        /// </summary>
        public static int SecureVaultUnlockSecure(string path, System.Security.SecureString password)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));
            IntPtr pPath = Utf8ToPinnedPointer(path, out GCHandle hPath, out byte[] bPath);
            IntPtr pPwd = IntPtr.Zero;
            try
            {
                pPwd = Marshal.SecureStringToBSTR(password);
                return bitnet_vault_unlock_raw(pPath, pPwd);
            }
            finally
            {
                if (pPwd != IntPtr.Zero)
                {
                    // ZeroFreeBSTR overwrites the BSTR buffer with zeros before
                    // freeing, so the password does not linger in unmanaged
                    // memory after this call.
                    Marshal.ZeroFreeBSTR(pPwd);
                }
                ZeroizeAndFree(ref hPath, bPath);
            }
        }

        /// <summary>SecureString variant of SecureVaultCreate.</summary>
        /// <summary>Create a new vault with SecureString password.</summary>
        public static int SecureVaultCreateSecure(string path, System.Security.SecureString password)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));
            IntPtr pPath = Utf8ToPinnedPointer(path, out GCHandle hPath, out byte[] bPath);
            IntPtr pPwd = IntPtr.Zero;
            try
            {
                pPwd = Marshal.SecureStringToBSTR(password);
                return bitnet_vault_create_raw(pPath, pPwd);
            }
            finally
            {
                if (pPwd != IntPtr.Zero) Marshal.ZeroFreeBSTR(pPwd);
                ZeroizeAndFree(ref hPath, bPath);
            }
        }

        /// <summary>SecureString variant of SecureVaultSave.</summary>
        public static int SecureVaultSaveSecure(string path, System.Security.SecureString password)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));
            IntPtr pPath = Utf8ToPinnedPointer(path, out GCHandle hPath, out byte[] bPath);
            IntPtr pPwd = IntPtr.Zero;
            try
            {
                pPwd = Marshal.SecureStringToBSTR(password);
                return bitnet_vault_save_raw(pPath, pPwd);
            }
            finally
            {
                if (pPwd != IntPtr.Zero) Marshal.ZeroFreeBSTR(pPwd);
                ZeroizeAndFree(ref hPath, bPath);
            }
        }

        // (non-Secure SecureVaultCreate removed in v0.2.0 - see [BITNET-H1])

        // (non-Secure SecureVaultSave removed in v0.2.0 - see [BITNET-H1])

        public static int SecureAddEntry(string groupUuid, string entryJson)
        {
            IntPtr pGroup = Utf8ToPinnedPointer(groupUuid, out GCHandle hGroup, out byte[] bGroup);
            IntPtr pJson = Utf8ToPinnedPointer(entryJson, out GCHandle hJson, out byte[] bJson);
            try
            {
                return bitnet_add_entry_raw(pGroup, pJson);
            }
            finally
            {
                ZeroizeAndFree(ref hJson, bJson); // entryJson may contain passwords
                ZeroizeAndFree(ref hGroup, bGroup);
            }
        }

        public static int SecureUpdateEntry(string uuid, string entryJson)
        {
            IntPtr pUuid = Utf8ToPinnedPointer(uuid, out GCHandle hUuid, out byte[] bUuid);
            IntPtr pJson = Utf8ToPinnedPointer(entryJson, out GCHandle hJson, out byte[] bJson);
            try
            {
                return bitnet_update_entry_raw(pUuid, pJson);
            }
            finally
            {
                ZeroizeAndFree(ref hJson, bJson); // entryJson may contain passwords
                ZeroizeAndFree(ref hUuid, bUuid);
            }
        }

        /// <summary>
        /// Get TOTP code and remaining seconds into a caller-provided buffer.
        /// Returns (code, remaining) on success, null on failure.
        /// </summary>
        public static (string code, int remaining)? GetTotpBuffered(string uuid)
        {
            var sb = new StringBuilder(32);
            int result = bitnet_entry_get_totp_to_buffer_raw(uuid, sb, (nuint)sb.Capacity);
            if (result != 0)
                return null;
            string value = sb.ToString();
            int commaIdx = value.LastIndexOf(',');
            if (commaIdx < 0)
                return null;
            string code = value.Substring(0, commaIdx).Trim();
            string remainingStr = value.Substring(commaIdx + 1).Trim();
            if (int.TryParse(remainingStr, out int remaining))
                return (code, remaining);
            return null;
        }
    }
}
