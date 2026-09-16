using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Azure;
using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using Microsoft.Extensions.Configuration;
using Serilog;

namespace Kamus.KeyManagement
{
    /// <summary>
    /// A resilient wrapper around Azure Key Vault that can self-heal **without**
    /// a pod restart by:
    ///
    /// 1. Recreating the <see cref="TokenCredential"/> + <see cref="KeyClient"/>
    ///    after consecutive failures (clears Azure SDK internal token cache).
    /// 2. Treating token-acquisition timeouts (<see cref="OperationCanceledException"/>)
    ///    as an **immediate** signal to recreate — not waiting for N failures,
    ///    because a stuck IMDS/OIDC path will block every subsequent request too.
    /// 3. Running a periodic background probe that detects a degraded credential
    ///    and recreates it **before** the next encrypt/decrypt call arrives.
    /// 4. Using <see cref="WorkloadIdentityCredential"/> directly when the workload
    ///    identity env vars are present, avoiding the slow <see cref="DefaultAzureCredential"/>
    ///    chain fallback during transient failures.
    /// </summary>
    public class ResilientAzureKeyVaultKeyManagement : IKeyManagement, IDisposable
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger _logger = Log.ForContext<ResilientAzureKeyVaultKeyManagement>();
        private readonly Uri _vaultUri;
        private readonly object _lock = new object();
        private readonly Func<TokenCredential>? _credentialFactory;
        private readonly Func<TokenCredential, KeyClient>? _keyClientFactory;
        private readonly Func<DateTime> _utcNow;
        private bool _disposed;

        private const int MaxConsecutiveFailures = 3;
        private int _consecutiveFailures = 0;
        private DateTime _lastCredentialCreation = DateTime.MinValue;

        // 5 minute cooldown prevents tight loops and Azure AD/Key Vault throttling
        // during prolonged outages, including the first five minutes after startup.
        private static readonly TimeSpan MinCredentialAge = TimeSpan.FromMinutes(5);

        private volatile KeyClient _keyClient = null!;
        private volatile TokenCredential _credential = null!;

        private static readonly TimeSpan OperationTimeout = TimeSpan.FromSeconds(30);

        // Background health probe
        private readonly Timer? _healthProbeTimer;
        private static readonly TimeSpan HealthProbeInterval = TimeSpan.FromSeconds(30);
        private int _healthProbeRunning = 0;

        public ResilientAzureKeyVaultKeyManagement(IConfiguration configuration)
            : this(configuration, null, null, () => DateTime.UtcNow, true)
        {
        }

        internal ResilientAzureKeyVaultKeyManagement(
            IConfiguration configuration,
            Func<TokenCredential>? credentialFactory,
            Func<TokenCredential, KeyClient>? keyClientFactory,
            Func<DateTime> utcNow,
            bool startHealthProbe)
        {
            _configuration = configuration;
            _credentialFactory = credentialFactory;
            _keyClientFactory = keyClientFactory;
            _utcNow = utcNow;
            var keyVaultName = configuration["KeyManagement:KeyVault:Name"] ??
                throw new ArgumentException("KeyVault name not configured");
            _vaultUri = new Uri($"https://{keyVaultName}.vault.azure.net");

            CreateCredentialAndClient();

            if (startHealthProbe)
            {
                _healthProbeTimer = new Timer(
                    _ => RunHealthProbe(), null, HealthProbeInterval, HealthProbeInterval);
            }
        }

        // ─── credential lifecycle ────────────────────────────────────────────

        private void CreateCredentialAndClient()
        {
            lock (_lock)
            {
                _logger.Information("Creating new Azure credential and KeyClient for {Vault}", _vaultUri);

                var managedIdentityClientId = _configuration["ActiveDirectory:ManagedIdentityClientId"];
                var clientId = _configuration["ActiveDirectory:ClientId"];
                var clientSecret = _configuration["ActiveDirectory:ClientSecret"];
                var tenantId = _configuration["ActiveDirectory:TenantId"];

                TokenCredential credential;

                // Prefer the most specific credential type available.
                // DefaultAzureCredential probes multiple sources and can introduce
                // multi-second delays when early sources time out (e.g. IMDS).
                var wiClientId = Environment.GetEnvironmentVariable("AZURE_CLIENT_ID");
                var wiTenantId = Environment.GetEnvironmentVariable("AZURE_TENANT_ID");
                var wiTokenFile = Environment.GetEnvironmentVariable("AZURE_FEDERATED_TOKEN_FILE");

                if (_credentialFactory != null)
                {
                    credential = _credentialFactory();
                }
                else if (!string.IsNullOrEmpty(wiClientId)
                    && !string.IsNullOrEmpty(wiTenantId)
                    && !string.IsNullOrEmpty(wiTokenFile))
                {
                    _logger.Information("Using WorkloadIdentityCredential (direct, no fallback chain)");
                    credential = new WorkloadIdentityCredential(new WorkloadIdentityCredentialOptions
                    {
                        ClientId = wiClientId,
                        TenantId = wiTenantId,
                        TokenFilePath = wiTokenFile,
                    });
                }
                else if (!string.IsNullOrEmpty(clientId)
                    && !string.IsNullOrEmpty(clientSecret)
                    && !string.IsNullOrEmpty(tenantId))
                {
                    _logger.Information("Using ClientSecretCredential");
                    credential = new ClientSecretCredential(tenantId, clientId, clientSecret);
                }
                else
                {
                    _logger.Information("Using DefaultAzureCredential (fallback)");
                    var opts = new DefaultAzureCredentialOptions
                    {
                        Retry =
                        {
                            MaxRetries = 3,
                            Delay = TimeSpan.FromSeconds(1),
                            MaxDelay = TimeSpan.FromSeconds(10),
                            NetworkTimeout = TimeSpan.FromSeconds(15),
                        },
                    };

                    if (!string.IsNullOrEmpty(managedIdentityClientId))
                    {
                        opts.ManagedIdentityClientId = managedIdentityClientId;
                    }

                    credential = new DefaultAzureCredential(opts);
                }

                var keyClientOptions = new KeyClientOptions
                {
                    Retry =
                    {
                        MaxRetries = 3,
                        Delay = TimeSpan.FromSeconds(1),
                        MaxDelay = TimeSpan.FromSeconds(10),
                        NetworkTimeout = TimeSpan.FromSeconds(20),
                    },
                };

                _keyClient = _keyClientFactory?.Invoke(credential) ?? new KeyClient(_vaultUri, credential, keyClientOptions);
                _credential = credential;
                _lastCredentialCreation = _utcNow();
                Interlocked.Exchange(ref _consecutiveFailures, 0);

                _logger.Information("Azure credential and KeyClient (re)created successfully");
            }
        }

        private void RecordSuccess()
        {
            Interlocked.Exchange(ref _consecutiveFailures, 0);
        }

        private void RecordFailureAndMaybeRecreate(Exception ex, bool isTokenTimeout = false)
        {
            var failures = Interlocked.Increment(ref _consecutiveFailures);
            _logger.Warning(ex,
                "Key Vault operation failed. Consecutive failures: {Failures}, isTokenTimeout: {IsTokenTimeout}",
                failures, isTokenTimeout);

            // Token-acquisition timeouts indicate the credential itself is stuck.
            // Recreate immediately (respecting MinCredentialAge) rather than waiting
            // for MaxConsecutiveFailures — every queued request will time out otherwise.
            bool shouldRecreate = isTokenTimeout || failures >= MaxConsecutiveFailures;

            if (shouldRecreate)
            {
                // Check the cooldown under the same lock as recreation so parallel
                // failures cannot all recreate the credential in succession.
                lock (_lock)
                {
                    if (_disposed) return;
                    var credentialAge = _utcNow() - _lastCredentialCreation;
                    if (credentialAge >= MinCredentialAge)
                    {
                        try
                        {
                            CreateCredentialAndClient();
                        }
                        catch (Exception recreationError)
                        {
                            // A timer callback must never crash the process if
                            // credential configuration becomes invalid at runtime.
                            _logger.Error(recreationError, "Azure credential recreation failed");
                            _lastCredentialCreation = _utcNow();
                        }
                    }
                }
            }
        }

        private (KeyClient Client, TokenCredential Credential) GetClientSnapshot()
        {
            lock (_lock)
            {
                if (_disposed) throw new ObjectDisposedException(nameof(ResilientAzureKeyVaultKeyManagement));
                return (_keyClient, _credential);
            }
        }

        // ─── background health probe ─────────────────────────────────────────

        private async void RunHealthProbe()
        {
            if (Interlocked.CompareExchange(ref _healthProbeRunning, 1, 0) != 0)
                return;

            try
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                var client = GetClientSnapshot().Client;
                await foreach (var _ in client.GetPropertiesOfKeysAsync(cts.Token))
                {
                    break;
                }
                RecordSuccess();
            }
            catch (Exception ex)
            {
                _logger.Warning(ex, "Background health probe failed — triggering credential recreation check");
                RecordFailureAndMaybeRecreate(ex, isTokenTimeout: ex is OperationCanceledException);
            }
            finally
            {
                Interlocked.Exchange(ref _healthProbeRunning, 0);
            }
        }

        // ─── IKeyManagement ──────────────────────────────────────────────────

        public async Task<string> Decrypt(string encryptedData, string serviceAccountId)
        {
            var hash = KeyIdCreator.Create(serviceAccountId);

            try
            {
                using var cts = new CancellationTokenSource(OperationTimeout);

                var snapshot = GetClientSnapshot();
                var key = await snapshot.Client.GetKeyAsync(hash, cancellationToken: cts.Token);
                var cryptoClient = new CryptographyClient(key.Value.Id, snapshot.Credential);

                var decryptResult = await cryptoClient.DecryptAsync(
                    EncryptionAlgorithm.RsaOaep,
                    Convert.FromBase64String(encryptedData),
                    cts.Token);

                RecordSuccess();
                return Encoding.UTF8.GetString(decryptResult.Plaintext);
            }
            catch (OperationCanceledException ex)
            {
                RecordFailureAndMaybeRecreate(ex, isTokenTimeout: true);
                _logger.Error(ex,
                    "Key Vault decrypt timed out after {Timeout}s for {SA}",
                    OperationTimeout.TotalSeconds, serviceAccountId);
                throw new DecryptionFailureException(
                    $"KeyVault operation timed out after {OperationTimeout.TotalSeconds}s", ex);
            }
            catch (RequestFailedException ex)
            {
                RecordFailureAndMaybeRecreate(ex);
                throw new DecryptionFailureException("KeyVault decryption failed", ex);
            }
            catch (FormatException ex)
            {
                throw new DecryptionFailureException("Invalid encrypted data format", ex);
            }
            catch (AuthenticationFailedException ex)
            {
                RecordFailureAndMaybeRecreate(ex);
                throw new DecryptionFailureException("KeyVault authentication failed", ex);
            }
        }

        public async Task VerifyConnectivity()
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            try
            {
                var client = GetClientSnapshot().Client;
                await foreach (var _ in client.GetPropertiesOfKeysAsync(cts.Token))
                {
                    break;
                }
                RecordSuccess();
            }
            catch (OperationCanceledException ex)
            {
                RecordFailureAndMaybeRecreate(ex, isTokenTimeout: true);
                _logger.Error(ex, "VerifyConnectivity: token acquisition timed out after 5 s");
                throw new Exception("Kamus connectivity check failed: token acquisition timed out", ex);
            }
            catch (Exception ex)
            {
                RecordFailureAndMaybeRecreate(ex);
                _logger.Error(ex, "VerifyConnectivity: Key Vault connectivity check failed");
                throw new Exception("Kamus connectivity check failed", ex);
            }
        }

        public async Task<string> Encrypt(string data, string serviceAccountId, bool createKeyIfMissing = true)
        {
            var hash = KeyIdCreator.Create(serviceAccountId);
            var keyType = _configuration["KeyManagement:KeyVault:KeyType"] ?? "RSA";

            if (!int.TryParse(_configuration["KeyManagement:KeyVault:KeyLength"], out var keySize))
            {
                throw new Exception(
                    $"Expected key length int, got {_configuration["KeyManagement:KeyVault:KeyLength"]}");
            }

            using var cts = new CancellationTokenSource(OperationTimeout);
            var snapshot = GetClientSnapshot();

            KeyVaultKey key;
            try
            {
                key = await snapshot.Client.GetKeyAsync(hash, cancellationToken: cts.Token);
            }
            catch (OperationCanceledException ex)
            {
                RecordFailureAndMaybeRecreate(ex, isTokenTimeout: true);
                _logger.Error(ex,
                    "Key Vault get key timed out after {Timeout}s for {SA}",
                    OperationTimeout.TotalSeconds, serviceAccountId);
                throw new Exception(
                    $"KeyVault operation timed out after {OperationTimeout.TotalSeconds}s", ex);
            }
            catch (RequestFailedException ex) when (ex.Status == 404 && createKeyIfMissing)
            {
                _logger.Information(
                    "Key not found for {SA}, creating new one.", serviceAccountId);

                var keyOptions = keyType.ToUpperInvariant() == "RSA-HSM"
                    ? new CreateRsaKeyOptions(hash, hardwareProtected: true) { KeySize = keySize }
                    : new CreateRsaKeyOptions(hash, hardwareProtected: false) { KeySize = keySize };

                try
                {
                    key = await snapshot.Client.CreateRsaKeyAsync(keyOptions, cts.Token);
                }
                catch (OperationCanceledException createEx)
                {
                    RecordFailureAndMaybeRecreate(createEx, isTokenTimeout: true);
                    throw new Exception("KeyVault create key operation timed out", createEx);
                }
                catch (Exception createEx)
                {
                    RecordFailureAndMaybeRecreate(createEx);
                    throw;
                }
            }
            catch (RequestFailedException ex)
            {
                RecordFailureAndMaybeRecreate(ex);
                throw;
            }
            catch (AuthenticationFailedException ex)
            {
                RecordFailureAndMaybeRecreate(ex);
                throw;
            }

            var cryptoClient = new CryptographyClient(key.Id, snapshot.Credential);

            try
            {
                var encryptResult = await cryptoClient.EncryptAsync(
                    EncryptionAlgorithm.RsaOaep,
                    Encoding.UTF8.GetBytes(data),
                    cts.Token);

                RecordSuccess();
                return Convert.ToBase64String(encryptResult.Ciphertext);
            }
            catch (OperationCanceledException ex)
            {
                RecordFailureAndMaybeRecreate(ex, isTokenTimeout: true);
                _logger.Error(ex,
                    "Key Vault encrypt timed out after {Timeout}s for {SA}",
                    OperationTimeout.TotalSeconds, serviceAccountId);
                throw new Exception(
                    $"KeyVault operation timed out after {OperationTimeout.TotalSeconds}s", ex);
            }
            catch (RequestFailedException ex)
            {
                RecordFailureAndMaybeRecreate(ex);
                throw;
            }
            catch (AuthenticationFailedException ex)
            {
                RecordFailureAndMaybeRecreate(ex);
                throw;
            }
        }

        public void Dispose()
        {
            lock (_lock)
            {
                if (_disposed) return;
                _disposed = true;
                _healthProbeTimer?.Dispose();
            }
        }
    }
}
