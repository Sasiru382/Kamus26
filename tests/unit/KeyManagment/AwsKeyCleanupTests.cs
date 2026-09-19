// Modified in 2026 by Sasiru382. These independently authored changes are documented in Git history.
using System;
using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Amazon;
using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;
using Amazon.Runtime;
using Kamus.KeyManagement;
using Xunit;

namespace unit.KeyManagement
{
    public class AwsKeyCleanupTests
    {
        [Fact]
        public async Task RoundTripClearsAndDisposesResponseKeyStreams()
        {
            using var client = new StubKmsClient();
            var provider = new AwsKeyManagement(client, "", false);
            var ciphertext = await provider.Encrypt("payload", "sa");
            Assert.False(client.GeneratedPlaintext.CanRead);
            Assert.False(client.GeneratedCiphertext.CanRead);
            Assert.All(client.GeneratedBuffer, value => Assert.Equal((byte)0, value));
            Assert.Equal("payload", await provider.Decrypt(ciphertext, "sa"));
            Assert.False(client.DecryptedPlaintext.CanRead);
            Assert.False(client.RequestCiphertext.CanRead);
            Assert.All(client.DecryptedBuffer, value => Assert.Equal((byte)0, value));
        }

        [Fact]
        public async Task FailedGenerationStillClearsAndDisposesResponseStreams()
        {
            using var client = new StubKmsClient { Status = HttpStatusCode.InternalServerError };
            var provider = new AwsKeyManagement(client, "", false);
            await Assert.ThrowsAsync<Exception>(() => provider.Encrypt("payload", "sa"));
            Assert.False(client.GeneratedPlaintext.CanRead);
            Assert.False(client.GeneratedCiphertext.CanRead);
            Assert.All(client.GeneratedBuffer, value => Assert.Equal((byte)0, value));
        }

        private sealed class StubKmsClient : AmazonKeyManagementServiceClient
        {
            private readonly byte[] _key = RijndaelUtils.GenerateKey(256);
            public HttpStatusCode Status = HttpStatusCode.OK;
            public MemoryStream GeneratedPlaintext;
            public MemoryStream GeneratedCiphertext;
            public MemoryStream DecryptedPlaintext;
            public MemoryStream RequestCiphertext;
            public byte[] GeneratedBuffer;
            public byte[] DecryptedBuffer;

            public StubKmsClient() : base(new AnonymousAWSCredentials(), RegionEndpoint.USEast1) { }

            public override Task<GenerateDataKeyResponse> GenerateDataKeyAsync(GenerateDataKeyRequest request, CancellationToken cancellationToken = default)
            {
                GeneratedBuffer = (byte[])_key.Clone();
                GeneratedPlaintext = new MemoryStream(GeneratedBuffer);
                GeneratedCiphertext = new MemoryStream(new byte[] { 1, 2, 3 });
                return Task.FromResult(new GenerateDataKeyResponse
                {
                    HttpStatusCode = Status,
                    Plaintext = GeneratedPlaintext,
                    CiphertextBlob = GeneratedCiphertext
                });
            }

            public override Task<DecryptResponse> DecryptAsync(DecryptRequest request, CancellationToken cancellationToken = default)
            {
                RequestCiphertext = request.CiphertextBlob;
                DecryptedBuffer = (byte[])_key.Clone();
                DecryptedPlaintext = new MemoryStream(DecryptedBuffer);
                return Task.FromResult(new DecryptResponse { Plaintext = DecryptedPlaintext });
            }
        }
    }
}
