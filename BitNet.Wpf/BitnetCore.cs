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

        [DllImport(DllName)]
        [return: MarshalAs(UnmanagedType.I4)]
        public static extern int bitnet_free_string(IntPtr ptr);

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

        public static int SecureVaultUnlock(string path, string password)
        {
            IntPtr pPath = Utf8ToPinnedPointer(path, out GCHandle hPath, out byte[] bPath);
            IntPtr pPwd = Utf8ToPinnedPointer(password, out GCHandle hPwd, out byte[] bPwd);
            try
            {
                return bitnet_vault_unlock_raw(pPath, pPwd);
            }
            finally
            {
                ZeroizeAndFree(ref hPwd, bPwd);
                ZeroizeAndFree(ref hPath, bPath);
            }
        }

        public static int SecureVaultCreate(string path, string password)
        {
            IntPtr pPath = Utf8ToPinnedPointer(path, out GCHandle hPath, out byte[] bPath);
            IntPtr pPwd = Utf8ToPinnedPointer(password, out GCHandle hPwd, out byte[] bPwd);
            try
            {
                return bitnet_vault_create_raw(pPath, pPwd);
            }
            finally
            {
                ZeroizeAndFree(ref hPwd, bPwd);
                ZeroizeAndFree(ref hPath, bPath);
            }
        }

        public static int SecureVaultSave(string path, string password)
        {
            IntPtr pPath = Utf8ToPinnedPointer(path, out GCHandle hPath, out byte[] bPath);
            IntPtr pPwd = Utf8ToPinnedPointer(password, out GCHandle hPwd, out byte[] bPwd);
            try
            {
                return bitnet_vault_save_raw(pPath, pPwd);
            }
            finally
            {
                ZeroizeAndFree(ref hPwd, bPwd);
                ZeroizeAndFree(ref hPath, bPath);
            }
        }

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
    }
}
