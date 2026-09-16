using System;
using System.IO;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;
using Optional.Unsafe;
using Polly;


namespace Kamus.KeyManagement
{
    public class AwsKeyManagement : IKeyManagement
    {
        private readonly IAmazonKeyManagementService mAmazonKeyManagementService;
        private readonly string mCmkPrefix;
        private readonly bool mEnableAutomaticKeyRotation;

        public AwsKeyManagement(
            IAmazonKeyManagementService amazonKeyManagementService,
            string cmkPrefix,
            bool enableAutomaticKeyRotation)
        {
            mAmazonKeyManagementService = amazonKeyManagementService;
            mCmkPrefix = string.IsNullOrEmpty(cmkPrefix) ? "" : $"{cmkPrefix}-";
            mEnableAutomaticKeyRotation = enableAutomaticKeyRotation;
        }

        public Task VerifyConnectivity() => Task.CompletedTask;

        public async Task<string> Encrypt(string data, string serviceAccountId, bool createKeyIfMissing = true)
        {
            var masterKeyAlias = $"alias/{mCmkPrefix}kamus/{KeyIdCreator.Create(serviceAccountId)}";
            var (dataKey, encryptedDataKey) = await GenerateEncryptionKey(masterKeyAlias);

            try
            {
                var (encryptedData, iv) = RijndaelUtils.Encrypt(dataKey, Encoding.UTF8.GetBytes(data));
                return EnvelopeEncryptionUtils.Wrap(encryptedDataKey, iv, encryptedData);
            }
            finally
            {
                // FIX: Clear sensitive data from memory
                Array.Clear(dataKey, 0, dataKey.Length);
            }
        }

        public async Task<string> Decrypt(string encryptedData, string serviceAccountId)
        {
            var tuple = EnvelopeEncryptionUtils.Unwrap(encryptedData).ValueOrFailure("Invalid encrypted data format");

            var (encryptedDataKey, iv, actualEncryptedData) = tuple;

            var masterKeyAlias = $"alias/{mCmkPrefix}kamus/{KeyIdCreator.Create(serviceAccountId)}";

            // FIX: Properly dispose MemoryStream using 'using' statement
            using var ciphertextStream = new MemoryStream(Convert.FromBase64String(encryptedDataKey));
            var decryptionResult = await mAmazonKeyManagementService.DecryptAsync(new DecryptRequest
            {
                CiphertextBlob = ciphertextStream,
                KeyId = masterKeyAlias
            });

            using var plaintextStream = decryptionResult.Plaintext;
            var plaintextBytes = plaintextStream.ToArray();
            try
            {
                var decrypted = RijndaelUtils.Decrypt(plaintextBytes, iv, actualEncryptedData);
                return Encoding.UTF8.GetString(decrypted);
            }
            finally
            {
                // FIX: Clear sensitive data from memory
                Array.Clear(plaintextBytes, 0, plaintextBytes.Length);
                ClearStream(plaintextStream);
            }
        }

        private async Task<(byte[] dataKey, string encryptedDataKey)> GenerateEncryptionKey(string keyAlias)
        {
            GenerateDataKeyResponse? generateKeyResponse = null;
            try
            {
                generateKeyResponse = await mAmazonKeyManagementService.GenerateDataKeyAsync(
                    new GenerateDataKeyRequest { KeyId = keyAlias, KeySpec = "AES_256" });
            }
            catch (NotFoundException)
            {
                await GenerateMasterKey(keyAlias);
                generateKeyResponse = await mAmazonKeyManagementService.GenerateDataKeyAsync(
                    new GenerateDataKeyRequest { KeyId = keyAlias, KeySpec = "AES_256" });
            }

            using var plaintextStream = generateKeyResponse.Plaintext;
            using var encryptedStream = generateKeyResponse.CiphertextBlob;
            try
            {
                if (generateKeyResponse.HttpStatusCode != HttpStatusCode.OK)
                {
                    throw new Exception($"Couldn't generate encryption key for {keyAlias}");
                }

                var encryptedDataKey = ConvertMemoryStreamToBase64String(encryptedStream);
                return (plaintextStream.ToArray(), encryptedDataKey);
            }
            finally
            {
                ClearStream(plaintextStream);
            }
        }

        private static void ClearStream(MemoryStream? stream)
        {
            if (stream == null) return;
            if (stream.TryGetBuffer(out var buffer))
            {
                Array.Clear(buffer.Array!, buffer.Offset, buffer.Count);
            }
            else if (stream.CanWrite)
            {
                stream.Position = 0;
                var zeros = new byte[256];
                while (stream.Position < stream.Length)
                    stream.Write(zeros, 0, (int)Math.Min(zeros.Length, stream.Length - stream.Position));
            }
        }

        private static string ConvertMemoryStreamToBase64String(MemoryStream ms)
        {
            return Convert.ToBase64String(ms.ToArray());
        }

        private async Task GenerateMasterKey(string keyAlias)
        {
            var createKeyResponse = await mAmazonKeyManagementService.CreateKeyAsync(new CreateKeyRequest { });
            if (mEnableAutomaticKeyRotation) {
                await mAmazonKeyManagementService.EnableKeyRotationAsync(
                    new EnableKeyRotationRequest
                    {
                        KeyId = createKeyResponse.KeyMetadata.KeyId
                    });
            }

            await Policy
                .Handle<NotFoundException>()
                .WaitAndRetryAsync(3, attempt => TimeSpan.FromSeconds(0.5 * attempt))
                .ExecuteAsync(async () =>
                    await mAmazonKeyManagementService.CreateAliasAsync(keyAlias, createKeyResponse.KeyMetadata.KeyId));

        }
    }
}
