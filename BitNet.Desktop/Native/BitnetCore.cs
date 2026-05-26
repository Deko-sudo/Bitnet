using System;
using System.Runtime.InteropServices;
using System.Text;

namespace BitNet.Desktop.Native
{
    internal static partial class BitnetCore
    {
    // SECURITY NOTE: [MarshalAs(UnmanagedType.LPUTF8Str)] causes the CLR to allocate a
    // temporary unmanaged UTF-8 buffer. The CLR does NOT guarantee zeroization of this
    // buffer after the native call returns. Passwords and master passwords may briefly
    // persist in process memory. For higher assurance, consider manual CoTaskMem allocation
    // with SecureZeroMemory (CryptProtectMemory) or passing handles instead of raw strings.

        private const string DllName = "bitnet_ffi.dll";

        [LibraryImport(DllName)]
        [return: MarshalAs(UnmanagedType.I4)]
        public static partial int bitnet_init();

        [LibraryImport(DllName)]
        [return: MarshalAs(UnmanagedType.I4)]
        public static partial int bitnet_vault_create([MarshalAs(UnmanagedType.LPUTF8Str)] string path, [MarshalAs(UnmanagedType.LPUTF8Str)] string password);

        [LibraryImport(DllName)]
        [return: MarshalAs(UnmanagedType.I4)]
        public static partial int bitnet_vault_unlock([MarshalAs(UnmanagedType.LPUTF8Str)] string path, [MarshalAs(UnmanagedType.LPUTF8Str)] string password);

        [LibraryImport(DllName)]
        [return: MarshalAs(UnmanagedType.I4)]
        public static partial int bitnet_vault_lock();

        [LibraryImport(DllName)]
        [return: MarshalAs(UnmanagedType.I4)]
        public static partial int bitnet_vault_is_unlocked();

        [LibraryImport(DllName)]
        [return: MarshalAs(UnmanagedType.I4)]
        public static partial int bitnet_vault_save([MarshalAs(UnmanagedType.LPUTF8Str)] string path, [MarshalAs(UnmanagedType.LPUTF8Str)] string password);

        [LibraryImport(DllName)]
        [return: MarshalAs(UnmanagedType.I4)]
        public static partial int bitnet_entry_get_password([MarshalAs(UnmanagedType.LPUTF8Str)] string uuid, [MarshalAs(UnmanagedType.LPUTF8Str)] StringBuilder outBuf, nuint outLen);

        [LibraryImport(DllName)]
        public static partial IntPtr bitnet_entry_get_totp([MarshalAs(UnmanagedType.LPUTF8Str)] string uuid);

        [LibraryImport(DllName)]
        public static partial IntPtr bitnet_list_entries();

        [LibraryImport(DllName)]
        [return: MarshalAs(UnmanagedType.I4)]
        public static partial int bitnet_add_entry([MarshalAs(UnmanagedType.LPUTF8Str)] string groupUuid, [MarshalAs(UnmanagedType.LPUTF8Str)] string entryJson);

        [LibraryImport(DllName)]
        [return: MarshalAs(UnmanagedType.I4)]
        public static partial int bitnet_update_entry([MarshalAs(UnmanagedType.LPUTF8Str)] string uuid, [MarshalAs(UnmanagedType.LPUTF8Str)] string entryJson);

        [LibraryImport(DllName)]
        [return: MarshalAs(UnmanagedType.I4)]
        public static partial int bitnet_delete_entry([MarshalAs(UnmanagedType.LPUTF8Str)] string uuid);

        [LibraryImport(DllName)]
        public static partial IntPtr bitnet_create_group([MarshalAs(UnmanagedType.LPUTF8Str)] string parentUuid, [MarshalAs(UnmanagedType.LPUTF8Str)] string name);

        [LibraryImport(DllName)]
        public static partial IntPtr bitnet_generate_password(int length, int upper, int lower, int digits, int symbols, int ambiguous);

        [LibraryImport(DllName)]
        [return: MarshalAs(UnmanagedType.I4)]
        public static partial int bitnet_free_string(IntPtr ptr);

        [LibraryImport(DllName)]
        [return: MarshalAs(UnmanagedType.I4)]
        public static partial int bitnet_vault_fingerprint([MarshalAs(UnmanagedType.LPUTF8Str)] string path);
    }
}
