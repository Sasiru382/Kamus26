using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Azure;
using Azure.Core;
using Azure.Security.KeyVault.Keys;
using Kamus.KeyManagement;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace unit.KeyManagement
{
    public class ConnectivityTests
    {
        private static IConfiguration Configuration() => new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string>
            {
                ["KeyManagement:KeyVault:Name"] = "unit-test-vault",
                ["KeyManagement:KeyVault:KeyLength"] = "2048"
            }).Build();

        [Fact]
        public async Task StandardProbeEnumeratesEmptyVaultAndPassesCancellationToken()
        {
            var client = new ProbeClient();
            using var provider = new AzureKeyVaultKeyManagement(client, new TestCredential(), Configuration());
            await provider.VerifyConnectivity();
            Assert.Equal(1, client.Probes);
            Assert.True(client.Token.CanBeCanceled);
        }

        [Fact]
        public async Task StandardProbePropagatesFailure()
        {
            var client = new ProbeClient { Failure = new RequestFailedException(403, "denied") };
            using var provider = new AzureKeyVaultKeyManagement(client, new TestCredential(), Configuration());
            var error = await Assert.ThrowsAsync<Exception>(() => provider.VerifyConnectivity());
            Assert.Same(client.Failure, error.InnerException);
        }

        [Fact]
        public async Task ResilientProbeRecreatesAfterThreeFailuresAndHonorsCooldown()
        {
            var now = DateTime.UtcNow;
            var creations = 0;
            var client = new ProbeClient { Failure = new RequestFailedException(503, "unavailable") };
            using var provider = new ResilientAzureKeyVaultKeyManagement(Configuration(),
                () => { creations++; return new TestCredential(); }, _ => client, () => now, false);
            for (var i = 0; i < 3; i++)
                await Assert.ThrowsAsync<Exception>(() => provider.VerifyConnectivity());
            Assert.Equal(1, creations);

            now = now.AddMinutes(5);
            await Assert.ThrowsAsync<Exception>(() => provider.VerifyConnectivity());
            Assert.Equal(2, creations);
            for (var i = 0; i < 3; i++)
                await Assert.ThrowsAsync<Exception>(() => provider.VerifyConnectivity());
            Assert.Equal(2, creations);
        }

        [Fact]
        public async Task SuccessResetsConsecutiveFailures()
        {
            var now = DateTime.UtcNow;
            var creations = 0;
            var client = new ProbeClient();
            using var provider = new ResilientAzureKeyVaultKeyManagement(Configuration(),
                () => { creations++; return new TestCredential(); }, _ => client, () => now, false);
            now = now.AddMinutes(6);
            client.Failure = new RequestFailedException(503, "unavailable");
            await Assert.ThrowsAsync<Exception>(() => provider.VerifyConnectivity());
            await Assert.ThrowsAsync<Exception>(() => provider.VerifyConnectivity());
            client.Failure = null;
            await provider.VerifyConnectivity();
            client.Failure = new RequestFailedException(503, "unavailable");
            await Assert.ThrowsAsync<Exception>(() => provider.VerifyConnectivity());
            Assert.Equal(1, creations);
        }

        [Fact]
        public async Task TokenTimeoutRecreatesWithoutWaitingForThreeFailures()
        {
            var now = DateTime.UtcNow;
            var creations = 0;
            var client = new ProbeClient { Failure = new OperationCanceledException() };
            using var provider = new ResilientAzureKeyVaultKeyManagement(Configuration(),
                () => { creations++; return new TestCredential(); }, _ => client, () => now, false);
            now = now.AddMinutes(6);
            await Assert.ThrowsAsync<Exception>(() => provider.VerifyConnectivity());
            Assert.Equal(2, creations);
        }

        private sealed class TestCredential : TokenCredential
        {
            public override AccessToken GetToken(TokenRequestContext context, CancellationToken token)
                => throw new InvalidOperationException("Tests must not contact Azure");
            public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext context, CancellationToken token)
                => throw new InvalidOperationException("Tests must not contact Azure");
        }

        private sealed class ProbeClient : KeyClient
        {
            public Exception Failure { get; set; }
            public int Probes { get; private set; }
            public CancellationToken Token { get; private set; }

            public override AsyncPageable<KeyProperties> GetPropertiesOfKeysAsync(CancellationToken cancellationToken = default)
            {
                Probes++;
                Token = cancellationToken;
                if (Failure != null) throw Failure;
                return AsyncPageable<KeyProperties>.FromPages(new[]
                {
                    Page<KeyProperties>.FromValues(Array.Empty<KeyProperties>(), null, null)
                });
            }
        }
    }
}
