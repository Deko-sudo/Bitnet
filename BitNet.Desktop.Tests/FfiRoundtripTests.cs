using System;
using System.IO;
using System.Text.Json;
using System.Text.RegularExpressions;
using Xunit;
using Xunit.Abstractions;

using BitNet.Desktop.Native;

namespace BitNet.Desktop.Tests
{
    /// <summary>
    /// Integration tests for the BitNet FFI round-trip.
    /// Each test creates a temporary vault, validates an operation, and deletes the vault.
    /// </summary>
    public class FfiRoundtripTests : IDisposable
    {
        private readonly string _vaultPath;
        private readonly string _masterPassword;
        private bool _vaultCreated;

        public FfiRoundtripTests(ITestOutputHelper output)
        {
            _vaultPath = Path.Combine(Path.GetTempPath(), $"bitnet_test_{Guid.NewGuid()}.bitnet");
            _masterPassword = "master_password";
            _vaultCreated = false;

            // Ensure DLL can be found — add target\release to PATH for this process
            string dllDir = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, @"..\..\..\..\target\release"));
            if (!Directory.Exists(dllDir))
                dllDir = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, @"..\..\..\..\target\debug"));
            if (Directory.Exists(dllDir))
            {
                Environment.SetEnvironmentVariable("PATH", dllDir + ";" + Environment.GetEnvironmentVariable("PATH"));
            }

            try
            {
                int rc = BitnetCore.bitnet_init();
                output.WriteLine($"bitnet_init() = {rc}");
            }
            catch (Exception ex)
            {
                output.WriteLine($"bitnet_init() threw: {ex.Message}");
            }
        }

        public void Dispose()
        {
            try { File.Delete(_vaultPath); } catch { /* ignore */ }
            BitnetCore.bitnet_vault_lock();
        }

        // ===================================================================
        // Helper methods
        // ===================================================================
        private void CreateAndUnlockVault()
        {
            int rc = BitnetCore.SecureVaultCreate(_vaultPath, _masterPassword);
            Assert.Equal(0, rc);
            _vaultCreated = true;

            rc = BitnetCore.SecureVaultUnlock(_vaultPath, _masterPassword);
            Assert.Equal(0, rc);
        }

        private static string CreateTestEntryJson(string title, string username, string password,
            string url, string? totpSecret = null, string notes = "")
        {
            var dict = new System.Collections.Generic.Dictionary<string, object?>
            {
                ["title"] = title,
                ["username"] = username,
                ["password"] = password,
                ["url"] = url,
                ["notes"] = notes,
            };
            if (totpSecret != null)
                dict["totp_secret"] = totpSecret;
            return JsonSerializer.Serialize(dict);
        }

        // Helper: convert JSON byte-array uuid to hex string
        private static string UuidArrayToHex(JsonElement uuidElement)
        {
            var sb = new System.Text.StringBuilder(32);
            foreach (var b in uuidElement.EnumerateArray())
                sb.AppendFormat("{0:x2}", b.GetByte());
            return sb.ToString();
        }

        [Fact]
        public void Init_Succeeds()
        {
            int rc = BitnetCore.bitnet_init();
            Assert.Equal(0, rc);
        }

        [Fact]
        public void VaultCreate_Unlock_Success()
        {
            int rc = BitnetCore.SecureVaultCreate(_vaultPath, _masterPassword);
            Assert.Equal(0, rc);
            _vaultCreated = true;

            rc = BitnetCore.SecureVaultUnlock(_vaultPath, _masterPassword);
            Assert.Equal(0, rc);
        }

        [Fact]
        public void AddEntry_ListEntries()
        {
            CreateAndUnlockVault();

            // Create a top-level group  
            var groupUuidPtr = BitnetCore.bitnet_create_group(null!, "TestGroup");
            Assert.NotEqual(IntPtr.Zero, groupUuidPtr);
            string groupUuid = System.Runtime.InteropServices.Marshal.PtrToStringUTF8(groupUuidPtr) ?? "";
            BitnetCore.bitnet_free_string(groupUuidPtr);

            string entryJson = CreateTestEntryJson(
                "GitHub", "alice", "secret123", "https://github.com");

            int rc = BitnetCore.SecureAddEntry(groupUuid, entryJson);
            Assert.Equal(0, rc);

            // list entries
            var listPtr = BitnetCore.bitnet_list_entries();
            Assert.NotEqual(IntPtr.Zero, listPtr);
            string listJson = System.Runtime.InteropServices.Marshal.PtrToStringUTF8(listPtr) ?? "[]";
            BitnetCore.bitnet_free_string(listPtr);

            using var doc = JsonDocument.Parse(listJson);
            Assert.True(doc.RootElement.GetArrayLength() > 0,
                "Expected at least one entry after adding.");
        }

        [Fact]
        public void GetPassword_MatchesInput()
        {
            CreateAndUnlockVault();

            var groupUuidPtr = BitnetCore.bitnet_create_group(null!, "TestGroup");
            string groupUuid = System.Runtime.InteropServices.Marshal.PtrToStringUTF8(groupUuidPtr) ?? "";
            BitnetCore.bitnet_free_string(groupUuidPtr);

            const string originalPassword = "Secret123!";
            string entryJson = CreateTestEntryJson(
                "TestEntry", "bob", originalPassword, "https://example.com");

            int rc = BitnetCore.SecureAddEntry(groupUuid, entryJson);
            Assert.Equal(0, rc);

            // Get password via buffer API
            var listPtr = BitnetCore.bitnet_list_entries();
            string listJson = System.Runtime.InteropServices.Marshal.PtrToStringUTF8(listPtr) ?? "[]";
            BitnetCore.bitnet_free_string(listPtr);

            using var doc = JsonDocument.Parse(listJson);
            string entryUuid = UuidArrayToHex(doc.RootElement[0].GetProperty("uuid"));

            // Get password via buffer API
            var sb = new System.Text.StringBuilder(128);
            rc = BitnetCore.bitnet_entry_get_password(entryUuid, sb, (nuint)sb.Capacity);
            Assert.Equal(0, rc);
            Assert.Equal(originalPassword, sb.ToString());
        }

        [Fact]
        public void GetUsername_MatchesInput()
        {
            CreateAndUnlockVault();

            var groupUuidPtr = BitnetCore.bitnet_create_group(null!, "TestGroup");
            string groupUuid = System.Runtime.InteropServices.Marshal.PtrToStringUTF8(groupUuidPtr) ?? "";
            BitnetCore.bitnet_free_string(groupUuidPtr);

            const string originalUser = "charlie";
            string entryJson = CreateTestEntryJson(
                "Mail", originalUser, "pwd", "https://mail.com");

            int rc = BitnetCore.SecureAddEntry(groupUuid, entryJson);
            Assert.Equal(0, rc);

            // Get UUID from list_entries
            var listPtr = BitnetCore.bitnet_list_entries();
            string listJson = System.Runtime.InteropServices.Marshal.PtrToStringUTF8(listPtr) ?? "[]";
            BitnetCore.bitnet_free_string(listPtr);
            using var doc = JsonDocument.Parse(listJson);
            string entryUuid = UuidArrayToHex(doc.RootElement[0].GetProperty("uuid"));

            var detailPtr = BitnetCore.bitnet_entry_get_details(entryUuid);
            Assert.NotEqual(IntPtr.Zero, detailPtr);
            string detailJson = System.Runtime.InteropServices.Marshal.PtrToStringUTF8(detailPtr) ?? "";
            BitnetCore.bitnet_free_string(detailPtr);

            using var detailDoc = JsonDocument.Parse(detailJson);
            string username = detailDoc.RootElement.GetProperty("username").GetString()!;
            Assert.Equal(originalUser, username);
        }

        [Fact]
        public void GetTotp_ReturnsSixDigitCode()
        {
            CreateAndUnlockVault();

            var groupUuidPtr = BitnetCore.bitnet_create_group(null!, "TestGroup");
            string groupUuid = System.Runtime.InteropServices.Marshal.PtrToStringUTF8(groupUuidPtr) ?? "";
            BitnetCore.bitnet_free_string(groupUuidPtr);

            string entryJson = CreateTestEntryJson(
                "2FA-Site", "dave", "pwd2", "https://2fa.com",
                totpSecret: "JBSWY3DPEHPK3PXP");

            int rc = BitnetCore.SecureAddEntry(groupUuid, entryJson);
            Assert.Equal(0, rc);

            // Get UUID
            var listPtr = BitnetCore.bitnet_list_entries();
            string listJson = System.Runtime.InteropServices.Marshal.PtrToStringUTF8(listPtr) ?? "[]";
            BitnetCore.bitnet_free_string(listPtr);
            using var doc = JsonDocument.Parse(listJson);
            string entryUuid = UuidArrayToHex(doc.RootElement[0].GetProperty("uuid"));

            // Use buffered TOTP API
            var result = BitnetCore.GetTotpBuffered(entryUuid);
            Assert.NotNull(result);
            Assert.True(Regex.IsMatch(result.Value.code, @"^\d{6}$"),
                $"Expected 6-digit TOTP, got '{result.Value.code}'");
            Assert.True(result.Value.remaining is >= 0 and <= 30,
                $"Remaining seconds {result.Value.remaining} out of range.");
        }

        [Fact]
        public void DeleteEntry_RemovesFromList()
        {
            CreateAndUnlockVault();

            var groupUuidPtr = BitnetCore.bitnet_create_group(null!, "TestGroup");
            string groupUuid = System.Runtime.InteropServices.Marshal.PtrToStringUTF8(groupUuidPtr) ?? "";
            BitnetCore.bitnet_free_string(groupUuidPtr);

            string entryJson = CreateTestEntryJson(
                "Temp", "eve", "pwd3", "https://temp.com");

            int rc = BitnetCore.SecureAddEntry(groupUuid, entryJson);
            Assert.Equal(0, rc);

            // Get UUID
            var listPtr = BitnetCore.bitnet_list_entries();
            string listJson = System.Runtime.InteropServices.Marshal.PtrToStringUTF8(listPtr) ?? "[]";
            BitnetCore.bitnet_free_string(listPtr);
            using var doc = JsonDocument.Parse(listJson);
            string entryUuid = UuidArrayToHex(doc.RootElement[0].GetProperty("uuid"));

            // Delete
            rc = BitnetCore.bitnet_delete_entry(entryUuid);
            Assert.Equal(0, rc);

            // List again — should be empty
            listPtr = BitnetCore.bitnet_list_entries();
            listJson = System.Runtime.InteropServices.Marshal.PtrToStringUTF8(listPtr) ?? "[]";
            BitnetCore.bitnet_free_string(listPtr);
            using var doc2 = JsonDocument.Parse(listJson);
            Assert.Equal(0, doc2.RootElement.GetArrayLength());
        }
    }
}
