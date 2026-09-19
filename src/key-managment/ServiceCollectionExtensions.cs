// Modified in 2026 by Sasiru382. These independently authored changes are documented in Git history.
using System;
using Amazon;
using Amazon.KeyManagementService;
using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using Google.Cloud.Kms.V1;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Serilog;

namespace Kamus.KeyManagement
{
    public static class ServiceCollectionExtensions
    {
        public static void AddKeyManagement(
            this IServiceCollection services,
            IConfiguration configuration,
            ILogger logger)
        {

            services.AddSingleton<IKeyManagement>(s =>
            {
                var provider = configuration.GetValue<string>("KeyManagement:Provider");
                logger.Information("Selected KeyManagement: {provider}", provider);
                return provider switch
                {
                    "AwsKms" => GetAwsKeyManagement(logger, configuration),
                    "GoogleKms" => GetGoogleCloudKeyManagement(configuration),
                    "AzureKeyVault" => GetAzureKeyVaultKeyManagement(configuration, logger),
                    "AESKey" => GetAesKeyManagement(logger, configuration),
                    _ => throw new InvalidOperationException($"Unsupported provider type: {provider}")
                };
            });

        }

        private static IKeyManagement GetAesKeyManagement(ILogger logger, IConfiguration configuration)
        {
            var key = configuration.GetValue<string>("KeyManagement:AES:Key");
            var useKeyDerivation = configuration.GetValue<bool>("KeyManagement:AES:UseKeyDeriviation", false);

            if (string.IsNullOrEmpty(key))
            {
                logger.Warning("Random key was created for SymmetricKeyManagement, it might break distributed deployments");
                return new SymmetricKeyManagement(RijndaelUtils.GenerateKey(256), useKeyDerivation);
            }

            return new SymmetricKeyManagement(Convert.FromBase64String(key), useKeyDerivation);
        }

        private static IKeyManagement GetAzureKeyVaultKeyManagement(IConfiguration configuration, ILogger logger)
        {
            // Use resilient mode by default - recreates credentials on consecutive failures
            // Set KeyManagement:KeyVault:ResilientMode to false to use standard mode
            var useResilientMode = configuration.GetValue<bool>("KeyManagement:KeyVault:ResilientMode", true);

            if (useResilientMode)
            {
                logger.Information("Using ResilientAzureKeyVaultKeyManagement (auto-recreates credentials on failures)");
                return new EnvelopeEncryptionDecorator(
                    new ResilientAzureKeyVaultKeyManagement(configuration),
                    configuration.GetValue<int>("KeyManagement:KeyVault:MaximumDataLength"));
            }

            // Standard mode with retry options
            var keyVaultName = configuration["KeyManagement:KeyVault:Name"];
            var vaultUri = new Uri($"https://{keyVaultName}.vault.azure.net");

            // Authentication priority:
            // 1. Workload Identity / User Assigned Managed Identity (if ManagedIdentityClientId is provided)
            //    - Uses DefaultAzureCredential which automatically detects Workload Identity env vars
            //    - AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_FEDERATED_TOKEN_FILE
            // 2. App Registration / Service Principal (if ClientId, ClientSecret, TenantId are provided)
            // 3. DefaultAzureCredential (system-assigned MI, Azure CLI, etc.)

            var managedIdentityClientId = configuration["ActiveDirectory:ManagedIdentityClientId"];
            var clientId = configuration["ActiveDirectory:ClientId"];
            var clientSecret = configuration["ActiveDirectory:ClientSecret"];
            var tenantId = configuration["ActiveDirectory:TenantId"];

            TokenCredential credential;

            // Configure retry options for token acquisition to prevent hanging on token refresh
            var credentialOptions = new DefaultAzureCredentialOptions
            {
                Retry =
                {
                    MaxRetries = 3,
                    Delay = TimeSpan.FromSeconds(1),
                    MaxDelay = TimeSpan.FromSeconds(10),
                    NetworkTimeout = TimeSpan.FromSeconds(15)
                }
            };

            if (!string.IsNullOrEmpty(managedIdentityClientId))
            {
                // Use DefaultAzureCredential with ManagedIdentityClientId hint
                // This supports both Workload Identity (when AZURE_* env vars are set)
                // and VMSS-assigned User Assigned Managed Identity
                logger.Information("Using DefaultAzureCredential with Managed Identity hint for Azure Key Vault. ClientId: {clientId}", managedIdentityClientId);
                credentialOptions.ManagedIdentityClientId = managedIdentityClientId;
                credential = new DefaultAzureCredential(credentialOptions);
            }
            else if (!string.IsNullOrEmpty(clientId) && !string.IsNullOrEmpty(clientSecret) && !string.IsNullOrEmpty(tenantId))
            {
                // Use App Registration / Service Principal
                logger.Information("Using App Registration (Service Principal) for Azure Key Vault. ClientId: {clientId}", clientId);
                credential = new ClientSecretCredential(tenantId, clientId, clientSecret);
            }
            else
            {
                // Fall back to DefaultAzureCredential (system-assigned MI, Azure CLI, environment, etc.)
                logger.Information("Using DefaultAzureCredential for Azure Key Vault (system-assigned MI or local development)");
                credential = new DefaultAzureCredential(credentialOptions);
            }

            // Configure KeyClient with retry options for Key Vault operations
            var keyClientOptions = new KeyClientOptions
            {
                Retry =
                {
                    MaxRetries = 3,
                    Delay = TimeSpan.FromSeconds(1),
                    MaxDelay = TimeSpan.FromSeconds(10),
                    NetworkTimeout = TimeSpan.FromSeconds(20)
                }
            };

            var keyClient = new KeyClient(vaultUri, credential, keyClientOptions);

            return new EnvelopeEncryptionDecorator(
                new AzureKeyVaultKeyManagement(keyClient, credential, configuration),
                configuration.GetValue<int>("KeyManagement:KeyVault:MaximumDataLength"));
        }

        private static IKeyManagement GetGoogleCloudKeyManagement(IConfiguration configuration)
        {
            var location = configuration.GetValue<string>("KeyManagement:GoogleKms:Location");
            var keyRingName = configuration.GetValue<string>("KeyManagement:GoogleKms:KeyRingName");
            var protectionLevel = configuration.GetValue<string>("KeyManagement:GoogleKms:ProtectionLevel");
            var rotationPeriod = configuration.GetValue<string>("KeyManagement:GoogleKms:RotationPeriod");
            var projectName = configuration.GetValue<string>("KeyManagement:GoogleKms:ProjectId");

            return new GoogleCloudKeyManagement(
                KeyManagementServiceClient.Create(),
                projectName,
                keyRingName,
                location,
                protectionLevel,
                rotationPeriod);
        }

        private static IKeyManagement GetAwsKeyManagement(ILogger logger, IConfiguration configuration)
        {
            AmazonKeyManagementServiceClient kmsService;
            var region = configuration.GetValue<string>("KeyManagement:AwsKms:Region");
            var awsKey = configuration.GetValue<string>("KeyManagement:AwsKms:Key");
            var awsSecret = configuration.GetValue<string>("KeyManagement:AwsKms:Secret");
            var cmkPrefix = configuration.GetValue<string>("KeyManagement:AwsKms:CmkPrefix");
            var enableAutomaticKeyRotation = configuration.GetValue<bool>("KeyManagement:AwsKms:AutomaticKeyRotation", false);

            if (string.IsNullOrEmpty(region) || string.IsNullOrEmpty(awsKey) || string.IsNullOrEmpty(awsSecret))
            {
                logger.Information("AwsKms credentials were not provided, using default AWS SDK credentials discovery");
                kmsService = new AmazonKeyManagementServiceClient();
            }
            else
            {
                kmsService = new AmazonKeyManagementServiceClient(awsKey, awsSecret, RegionEndpoint.GetBySystemName(region));
            }

            return new AwsKeyManagement(kmsService, cmkPrefix, enableAutomaticKeyRotation);
        }
    }
}
