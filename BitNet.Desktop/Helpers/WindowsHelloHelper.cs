using System;
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

            vault.Add(new PasswordCredential(VaultResource, vaultPath, masterPassword));
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
