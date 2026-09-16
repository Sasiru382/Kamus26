using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Azure;
using Azure.Core;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Serilog;

namespace Kamus.KeyManagement
{
    public class AzureKeyVaultKeyManagement : IKeyManagement, IDisposable
    {
        private readonly KeyClient _keyClient;
        private readonly TokenCredential _credential;
        private readonly string _keyVaultName;
        private readonly string _keyType;
        private readonly int _keySize;
        private readonly ILogger _logger = Log.ForContext<AzureKeyVaultKeyManagement>();

        // Bounded cache for CryptographyClient instances with size limit and expiration
        // This prevents memory leaks when many unique service accounts are used
        private readonly MemoryCache _cryptoClientCache;
        private const int MaxCacheSize = 1000;
        private static readonly TimeSpan CacheExpiration = TimeSpan.FromHours(1);

        // Timeout for Key Vault operations to prevent hanging requests
        private static readonly TimeSpan OperationTimeout = TimeSpan.FromSeconds(30);

        public AzureKeyVaultKeyManagement(KeyClient keyClient, TokenCredential credential, IConfiguration configuration)
        {
            _keyClient = keyClient;
            _credential = credential;

            _keyVaultName = configuration["KeyManagement:KeyVault:Name"] ??
                throw new ArgumentException("KeyVault name not configured");
            _keyType = configuration["KeyManagement:KeyVault:KeyType"] ?? "RSA";

            if (!int.TryParse(configuration["KeyManagement:KeyVault:KeyLength"], out _keySize))
            {
                throw new Exception($"Expected key length int, got {configuration["KeyManagement:KeyVault:KeyLength"]}");
            }

            // Initialize bounded memory cache
            _cryptoClientCache = new MemoryCache(new MemoryCacheOptions
            {
                SizeLimit = MaxCacheSize
            });
        }

        public async Task<string> Decrypt(string encryptedData, string serviceAccountId)
        {
            var hash = KeyIdCreator.Create(serviceAccountId);

            try
            {
                using var cts = new CancellationTokenSource(OperationTimeout);

                var key = await _keyClient.GetKeyAsync(hash, cancellationToken: cts.Token);

                var cryptoClient = GetOrCreateCryptoClient(key.Value.Id);

                var decryptResult = await cryptoClient.DecryptAsync(
                    EncryptionAlgorithm.RsaOaep,
                    Convert.FromBase64String(encryptedData),
                    cts.Token);

                return Encoding.UTF8.GetString(decryptResult.Plaintext);
            }
            catch (OperationCanceledException e)
            {
                _logger.Error(e, "Key Vault decrypt operation timed out after {Timeout}s for service account {ServiceAccount}",
                    OperationTimeout.TotalSeconds, serviceAccountId);
                throw new DecryptionFailureException($"KeyVault operation timed out after {OperationTimeout.TotalSeconds}s", e);
            }
            catch (RequestFailedException e)
            {
                throw new DecryptionFailureException("KeyVault decryption failed", e);
            }
            catch (FormatException e)
            {
                throw new DecryptionFailureException("Invalid encrypted data format - probably an issue with the encryption", e);
            }
        }

        public async Task VerifyConnectivity()
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            try
            {
                await foreach (var _ in _keyClient.GetPropertiesOfKeysAsync(cts.Token))
                {
                    break;
                }
            }
            catch (OperationCanceledException ex)
            {
                _logger.Error(ex, "VerifyConnectivity: Key Vault token acquisition timed out after 5 s");
                throw new Exception("Kamus connectivity check failed: token acquisition timed out", ex);
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "VerifyConnectivity: Key Vault connectivity check failed");
                throw new Exception("Kamus connectivity check failed", ex);
            }
        }

        public async Task<string> Encrypt(string data, string serviceAccountId, bool createKeyIfMissing = true)
        {
            var hash = KeyIdCreator.Create(serviceAccountId);

            using var cts = new CancellationTokenSource(OperationTimeout);

            KeyVaultKey key;
            try
            {
                key = await _keyClient.GetKeyAsync(hash, cancellationToken: cts.Token);
            }
            catch (OperationCanceledException e)
            {
                _logger.Error(e, "Key Vault get key operation timed out after {Timeout}s for service account {ServiceAccount}",
                    OperationTimeout.TotalSeconds, serviceAccountId);
                throw new Exception($"KeyVault operation timed out after {OperationTimeout.TotalSeconds}s", e);
            }
            catch (RequestFailedException e) when (e.Status == 404 && createKeyIfMissing)
            {
                _logger.Information(
                    "KeyVault key was not found for service account id {serviceAccount}, creating new one.",
                    serviceAccountId);

                CreateRsaKeyOptions keyOptions;
                if (_keyType.ToUpperInvariant() == "RSA-HSM")
                {
                    keyOptions = new CreateRsaKeyOptions(hash, hardwareProtected: true) { KeySize = _keySize };
                }
                else
                {
                    keyOptions = new CreateRsaKeyOptions(hash, hardwareProtected: false) { KeySize = _keySize };
                }

                try
                {
                    key = await _keyClient.CreateRsaKeyAsync(keyOptions, cts.Token);
                }
                catch (OperationCanceledException createError)
                {
                    throw new Exception($"KeyVault operation timed out after {OperationTimeout.TotalSeconds}s", createError);
                }
            }

            var cryptoClient = GetOrCreateCryptoClient(key.Id);

            try
            {
                var encryptResult = await cryptoClient.EncryptAsync(
                    EncryptionAlgorithm.RsaOaep,
                    Encoding.UTF8.GetBytes(data),
                    cts.Token);

                return Convert.ToBase64String(encryptResult.Ciphertext);
            }
            catch (OperationCanceledException e)
            {
                _logger.Error(e, "Key Vault encrypt operation timed out after {Timeout}s for service account {ServiceAccount}",
                    OperationTimeout.TotalSeconds, serviceAccountId);
                throw new Exception($"KeyVault operation timed out after {OperationTimeout.TotalSeconds}s", e);
            }
        }

        /// <summary>
        /// Gets an existing CryptographyClient from cache or creates a new one.
        /// Uses bounded MemoryCache to prevent memory leaks with many unique service accounts.
        /// Cache entries expire after 1 hour and the cache is limited to 1000 entries.
        /// </summary>
        private CryptographyClient GetOrCreateCryptoClient(Uri keyId)
        {
            var cacheKey = keyId.ToString();

            if (_cryptoClientCache.TryGetValue(cacheKey, out CryptographyClient? cachedClient) && cachedClient != null)
            {
                return cachedClient;
            }

            _logger.Debug("Creating new CryptographyClient for key {keyId}", keyId);
            var newClient = new CryptographyClient(keyId, _credential);

            var cacheOptions = new MemoryCacheEntryOptions()
                .SetSize(1)  // Each entry counts as 1 toward the size limit
                .SetSlidingExpiration(CacheExpiration)
                .RegisterPostEvictionCallback((key, value, reason, state) =>
                {
                    _logger.Debug("CryptographyClient evicted from cache. Key: {Key}, Reason: {Reason}", key, reason);
                });

            _cryptoClientCache.Set(cacheKey, newClient, cacheOptions);

            return newClient;
        }

        public void Dispose() => _cryptoClientCache.Dispose();
    }
}
