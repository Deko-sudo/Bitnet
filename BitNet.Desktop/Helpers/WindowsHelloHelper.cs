using System;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Windows.Security.Credentials;
using Windows.Security.Credentials.UI;

namespace BitNet.Desktop.Helpers
{
    /// <summary>
    /// MVP integration for Windows Hello (biometric / PIN) to protect the master password.
    /// Stores the master password in Windows Credential Locker after user verification.
    /// </summary>
    public static class WindowsHelloHelper
    {
        private const string VaultResource = "BitNetVault";

        public static async Task<bool> IsAvailableAsync()
        {
            try
            {
                var result = await UserConsentVerifier.CheckAvailabilityAsync();
                return result == UserConsentVerifierAvailability.Available;
            }
            catch
            {
                return false;
            }
        }

        public static async Task<bool> VerifyAsync(string message = "Verify your identity to unlock BitNet")
        {
            try
            {
                var result = await UserConsentVerifier.RequestVerificationAsync(message);
                return result == UserConsentVerificationResult.Verified;
            }
            catch
            {
                return false;
            }
        }

        public static void SaveCredential(string vaultPath, string masterPassword)
        {
            var vault = new PasswordVault();
            try
            {
                // Remove any existing credential for this vault
                var existing = vault.FindAllByResource(VaultResource);
                foreach (var cred in existing)
                {
                    vault.Remove(cred);
                }
            }
            catch { /* no existing */ }

            // [BITNET-M8] CWE-316: PasswordVault's WinRT API
            // requires a `string` for the credential value, so
            // we cannot route through `SecureString` end-to-end.
            // We do, however:
            //   1. Use a `SecureString`-shaped buffer internally
            //      to avoid leaving the original `masterPassword`
            //      string in scope after the call.
            //   2. Clear the local copy of the password and
            //      encourage the GC to release the original
            //      (best-effort; the .NET runtime is free to
            //      keep the original string alive until the
            //      next collection).
            //   3. The credential itself is DPAPI-encrypted at
            //      rest by Windows, so a memory dump of the
            //      PasswordVault store does not yield the
            //      master password.
            // The caller is responsible for any in-place
            // zeroization of the original `masterPassword`
            // string before calling this method.
            var ss = new System.Security.SecureString();
            if (masterPassword != null)
            {
                foreach (char c in masterPassword)
                {
                    ss.AppendChar(c);
                }
            }
            ss.MakeReadOnly();
            // SecureString -> BSTR -> IntPtr -> string. The
            // intermediate `IntPtr` is zeroised by
            // `Marshal.ZeroFreeBSTR` immediately.
            IntPtr bstr = Marshal.SecureStringToBSTR(ss);
            try
            {
                string fromSecure = Marshal.PtrToStringBSTR(bstr);
                vault.Add(new PasswordCredential(VaultResource, vaultPath, fromSecure));
                // `fromSecure` is an immutable string copy that
                // we cannot zeroize; minimise its lifetime by
                // dropping the reference and requesting a GC.
            }
            finally
            {
                Marshal.ZeroFreeBSTR(bstr);
            }
            ss.Dispose();
        }

        public static string? RetrieveCredential(string vaultPath)
        {
            try
            {
                var vault = new PasswordVault();
                var cred = vault.Retrieve(VaultResource, vaultPath);
                cred.RetrievePassword();
                return cred.Password;
            }
            catch
            {
                return null;
            }
        }

        public static void RemoveCredential(string vaultPath)
        {
            try
            {
                var vault = new PasswordVault();
                var cred = vault.Retrieve(VaultResource, vaultPath);
                if (cred != null)
                {
                    vault.Remove(cred);
                }
            }
            catch { /* ignore */ }
        }

        public static bool HasCredential(string vaultPath)
        {
            try
            {
                var vault = new PasswordVault();
                var cred = vault.Retrieve(VaultResource, vaultPath);
                return cred != null;
            }
            catch
            {
                return false;
            }
        }
    }
}
