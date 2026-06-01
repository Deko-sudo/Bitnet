using System;
using System.Runtime.InteropServices;
using System.Text;
using BitNet.Desktop.Native;

string vaultPath = Path.GetFullPath("demo_ffivault.bitnet");
string password = "demopass";

Console.WriteLine("=== BitNet FFI Demo ===\n");

// 1. Init
Console.WriteLine("[1] bitnet_init() ...");
int rc = BitnetCore.bitnet_init();
Console.WriteLine($"    Result: {rc}\n");

// 2. Create vault (if not exists)
if (!File.Exists(vaultPath))
{
    Console.WriteLine($"[2] Creating vault: {vaultPath}");
    rc = BitnetCore.SecureVaultCreate(vaultPath, password);
    Console.WriteLine($"    Result: {rc}");
}
else
{
    Console.WriteLine($"[2] Vault already exists: {vaultPath}");
}

// 3. Unlock
Console.WriteLine("\n[3] Unlocking vault...");
rc = BitnetCore.SecureVaultUnlock(vaultPath, password);
Console.WriteLine($"    Result: {rc}");
int unlocked = BitnetCore.bitnet_vault_is_unlocked();
Console.WriteLine($"    IsUnlocked: {unlocked}");

// 4. Add an entry
Console.WriteLine("\n[4] Adding entry...");
string entryJson = "{\"title\":\"GitHub\",\"username\":\"dev\",\"password\":\"SuperSecret123!\",\"url\":\"https://github.com\",\"notes\":\"Demo entry\"}";
rc = BitnetCore.SecureAddEntry("00000000000000000000000000000000", entryJson);
Console.WriteLine($"    AddEntry result: {rc}");

// 5. Save vault
Console.WriteLine("\n[5] Saving vault...");
rc = BitnetCore.SecureVaultSave(vaultPath, password);
Console.WriteLine($"    Save result: {rc}");

// 6. Generate password
Console.WriteLine("\n[6] Generating password...");
IntPtr pwdPtr = BitnetCore.bitnet_generate_password(24, 1, 1, 1, 1, 0);
string? generated = Marshal.PtrToStringUTF8(pwdPtr);
Console.WriteLine($"    Generated: {generated}");
if (pwdPtr != IntPtr.Zero)
    BitnetCore.bitnet_free_string(pwdPtr);

// 7. List entries
Console.WriteLine("\n[7] Listing entries...");
IntPtr listPtr = BitnetCore.bitnet_list_entries();
string? entriesJson = Marshal.PtrToStringUTF8(listPtr);
Console.WriteLine($"    Entries: {entriesJson ?? "(null)"}");
if (listPtr != IntPtr.Zero)
    BitnetCore.bitnet_free_string(listPtr);

// 8. Fingerprint
Console.WriteLine("\n[8] Vault fingerprint...");
rc = BitnetCore.bitnet_vault_fingerprint(vaultPath);
Console.WriteLine($"    Result: {rc}");

// 9. Lock
Console.WriteLine("\n[9] Locking vault...");
rc = BitnetCore.bitnet_vault_lock();
Console.WriteLine($"    Result: {rc}");

Console.WriteLine("\n=== Demo finished ===");
