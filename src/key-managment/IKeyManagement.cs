// Modified in 2026 by Sasiru382. These independently authored changes are documented in Git history.
using System;
using System.Threading.Tasks;

namespace Kamus.KeyManagement
{
    public interface IKeyManagement
    {
        Task<string> Encrypt(string data, string serviceAccountId, bool createKeyIfMissing = true);
        Task<string> Decrypt(string encryptedData, string serviceAccountId);

        /// <summary>
        /// Performs a lightweight connectivity check against the underlying key management
        /// provider (e.g. Azure Key Vault token acquisition). Returns normally on success.
        /// Throws on failure so the caller (liveness probe) can return 503.
        /// </summary>
        Task VerifyConnectivity();
    }

    public class DecryptionFailureException : Exception
    {
        public DecryptionFailureException(string reason, Exception innerException) : base(reason, innerException)
        {

        }
    }
}
