using System;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Serilog;

namespace Kamus.KeyManagement
{
    public class EnvelopeEncryptionDecorator : IKeyManagement, IDisposable
    {
        private readonly IKeyManagement mMasterKeyManagement;
        private readonly int mMaximumDataLength;
        private readonly ILogger mLogger = Log.ForContext<EnvelopeEncryptionDecorator>();

        public EnvelopeEncryptionDecorator(IKeyManagement masterKeyManagement, int maximumDataLength)
        {
            mMasterKeyManagement = masterKeyManagement;
            mMaximumDataLength = maximumDataLength;
        }

        public async Task<string> Encrypt(string data, string serviceAccountId, bool createKeyIfMissing = true)
        {
            if (data.Length <= mMaximumDataLength)
            {
                return await mMasterKeyManagement.Encrypt(data, serviceAccountId, createKeyIfMissing);
            }

            mLogger.Information("Encryption data too length, using envelope encryption");

            var dataKey = RijndaelUtils.GenerateKey(256);
            try
            {
                var (encryptedData, iv) = RijndaelUtils.Encrypt(dataKey, Encoding.UTF8.GetBytes(data));
                var encryptedDataKey = await mMasterKeyManagement.Encrypt(Convert.ToBase64String(dataKey), serviceAccountId, createKeyIfMissing);
                return EnvelopeEncryptionUtils.Wrap(encryptedDataKey, iv, encryptedData);
            }
            finally
            {
                // FIX: Clear sensitive key material from memory after use
                Array.Clear(dataKey, 0, dataKey.Length);
            }
        }

        public Task VerifyConnectivity() => mMasterKeyManagement.VerifyConnectivity();

        public void Dispose() => (mMasterKeyManagement as IDisposable)?.Dispose();

        public Task<string> Decrypt(string encryptedData, string serviceAccountId)
        {
            return EnvelopeEncryptionUtils.Unwrap(encryptedData).Match(
                some: async t =>
                {
                    (string encryptedDataKey, byte[] iv, byte[] actualEncryptedData) = t;

                    var key = await mMasterKeyManagement.Decrypt(encryptedDataKey, serviceAccountId);
                    var keyBytes = Convert.FromBase64String(key);

                    try
                    {
                        var decrypted = RijndaelUtils.Decrypt(keyBytes, iv, actualEncryptedData);
                        return Encoding.UTF8.GetString(decrypted);
                    }
                    finally
                    {
                        // FIX: Clear sensitive key material from memory after use
                        Array.Clear(keyBytes, 0, keyBytes.Length);
                    }
                },
                none: () => mMasterKeyManagement.Decrypt(encryptedData, serviceAccountId)
            );
        }
    }
}
