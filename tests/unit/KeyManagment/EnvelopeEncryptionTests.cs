// Modified in 2026 by Sasiru382. These independently authored changes are documented in Git history.
using System;
using System.Threading.Tasks;
using Kamus.KeyManagement;
using Xunit;

namespace unit.KeyManagement
{
    public class EnvelopeEncryptionTests
    {
        [Theory]
        [InlineData("short")]
        [InlineData("a payload long enough to require envelope encryption")]
        public async Task RoundTripPreservesPayloadAndMasterKey(string payload)
        {
            var key = RijndaelUtils.GenerateKey(256);
            var originalKey = (byte[])key.Clone();
            using var provider = new EnvelopeEncryptionDecorator(new SymmetricKeyManagement(key, true), 10);
            var encrypted = await provider.Encrypt(payload, "sa");
            Assert.Equal(payload, await provider.Decrypt(encrypted, "sa"));
            Assert.Equal(originalKey, key);
            await provider.VerifyConnectivity();
        }

        [Fact]
        public async Task ForwardsConnectivityFailureAndDisposesInnerProvider()
        {
            var inner = new TestProvider();
            var decorator = new EnvelopeEncryptionDecorator(inner, 10);
            var error = await Assert.ThrowsAsync<InvalidOperationException>(() => decorator.VerifyConnectivity());
            Assert.Same(inner.Error, error);
            decorator.Dispose();
            Assert.True(inner.Disposed);
        }

        private sealed class TestProvider : IKeyManagement, IDisposable
        {
            public readonly InvalidOperationException Error = new InvalidOperationException("offline");
            public bool Disposed;
            public Task VerifyConnectivity() => Task.FromException(Error);
            public Task<string> Encrypt(string data, string sa, bool createKeyIfMissing = true) => throw new NotImplementedException();
            public Task<string> Decrypt(string data, string sa) => throw new NotImplementedException();
            public void Dispose() => Disposed = true;
        }
    }
}
