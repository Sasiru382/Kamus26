// Modified in 2026 by Sasiru382. These independently authored changes are documented in Git history.
using System.Net;
using System.Text.Json;
using Kamus.Decryption;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Kamus.Decryption.Tests;

public sealed class KamusDecryptorClientTests
{
    [Theory]
    [InlineData("https://kamus.test", "https://kamus.test/api/v1/decrypt")]
    [InlineData("https://kamus.test/prefix", "https://kamus.test/prefix/api/v1/decrypt")]
    [InlineData("https://kamus.test/prefix/", "https://kamus.test/prefix/api/v1/decrypt")]
    public async Task SendsExpectedContractAndPreservesPlaintext(string baseAddress, string expectedUrl)
    {
        const string encrypted = "ciphertext\"\\\nvalue";
        const string plaintext = "  {\"secret\":\"value\"}\n";
        using var http = new HttpClient(new Handler(async (request, ct) =>
        {
            Assert.Equal(HttpMethod.Post, request.Method);
            Assert.Equal(expectedUrl, request.RequestUri!.AbsoluteUri);
            Assert.Equal("Bearer", request.Headers.Authorization!.Scheme);
            Assert.Equal("pod-token", request.Headers.Authorization.Parameter);
            Assert.Equal("application/json", request.Content!.Headers.ContentType!.MediaType);
            using var body = JsonDocument.Parse(await request.Content.ReadAsStringAsync(ct));
            Assert.Equal(encrypted, body.RootElement.GetProperty("data").GetString());
            Assert.Single(body.RootElement.EnumerateObject());
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(plaintext) };
        }));
        var client = new KamusDecryptorClient(http, Options(baseAddress), new TokenProvider());
        Assert.Equal(plaintext, await client.DecryptAsync(encrypted));
        Assert.Null(http.DefaultRequestHeaders.Authorization);
    }

    [Fact]
    public async Task RereadsRotatedTokenFileOnEachRequest()
    {
        string path = Path.GetTempFileName();
        try
        {
            var tokens = new List<string>();
            using var http = new HttpClient(new Handler((request, _) =>
            {
                tokens.Add(request.Headers.Authorization!.Parameter!);
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("") });
            }));
            var options = Options();
            options.TokenFilePath = path;
            var client = new KamusDecryptorClient(http, options);
            await File.WriteAllTextAsync(path, " first-token\n");
            Assert.Equal("", await client.DecryptAsync("encrypted"));
            await File.WriteAllTextAsync(path, "second-token\n");
            await client.DecryptAsync("encrypted");
            Assert.Equal(new[] { "first-token", "second-token" }, tokens);
        }
        finally { File.Delete(path); }
    }

    [Theory]
    [InlineData(400)]
    [InlineData(401)]
    [InlineData(403)]
    [InlineData(429)]
    [InlineData(500)]
    [InlineData(503)]
    [InlineData(302)]
    public async Task HttpFailuresExposeStatusWithoutLeakingBodyOrReason(int code)
    {
        int attempts = 0;
        using var http = new HttpClient(new Handler((_, _) =>
        {
            attempts++;
            return Task.FromResult(new HttpResponseMessage((HttpStatusCode)code)
            {
                Content = new StringContent("secret-body"), ReasonPhrase = "secret-reason"
            });
        }));
        var client = new KamusDecryptorClient(http, Options(), new TokenProvider());
        var error = await Assert.ThrowsAsync<KamusDecryptionException>(() => client.DecryptAsync("secret-ciphertext"));
        Assert.Equal((HttpStatusCode)code, error.StatusCode);
        Assert.DoesNotContain("secret-", error.ToString());
        Assert.Equal(1, attempts);
    }

    [Theory]
    [InlineData("")]
    [InlineData("  ")]
    [InlineData("invalid\r\nheader")]
    [InlineData("invalid\0token")]
    [InlineData("invalid\"token")]
    public async Task RejectsInvalidTokensBeforeSending(string token)
    {
        using var http = new HttpClient(new Handler((_, _) => throw new Exception("Must not send")));
        var client = new KamusDecryptorClient(http, Options(), new TokenProvider(token));
        await Assert.ThrowsAsync<InvalidOperationException>(() => client.DecryptAsync("encrypted"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("  ")]
    public async Task RejectsEmptyCiphertext(string? encrypted)
    {
        using var http = new HttpClient(new Handler((_, _) => throw new Exception("Must not send")));
        var client = new KamusDecryptorClient(http, Options(), new TokenProvider());
        await Assert.ThrowsAnyAsync<ArgumentException>(() => client.DecryptAsync(encrypted!));
    }

    [Fact]
    public async Task CallerCancellationIsPreserved()
    {
        using var cancellation = new CancellationTokenSource();
        using var http = new HttpClient(new Handler(async (_, ct) =>
        {
            cancellation.Cancel();
            await Task.Delay(System.Threading.Timeout.Infinite, ct);
            throw new Exception("Unreachable");
        }));
        var client = new KamusDecryptorClient(http, Options(), new TokenProvider());
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.DecryptAsync("encrypted", cancellation.Token));
    }

    [Fact]
    public async Task TimeoutCoversResponseBody()
    {
        using var http = new HttpClient(new Handler((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        { Content = new StreamContent(new WaitingStream()) })));
        var options = Options();
        options.Timeout = TimeSpan.FromMilliseconds(100);
        var client = new KamusDecryptorClient(http, options, new TokenProvider());
        await Assert.ThrowsAsync<TimeoutException>(() => client.DecryptAsync("encrypted"));
    }

    [Fact]
    public async Task TimeoutCoversTokenProvider()
    {
        using var http = new HttpClient(new Handler((_, _) => throw new Exception("Must not send")));
        var options = Options();
        options.Timeout = TimeSpan.FromMilliseconds(100);
        var client = new KamusDecryptorClient(http, options, new WaitingTokenProvider());
        await Assert.ThrowsAsync<TimeoutException>(() => client.DecryptAsync("encrypted"));
    }

    [Fact]
    public async Task MissingTokenFileFailsBeforeSending()
    {
        using var http = new HttpClient(new Handler((_, _) => throw new Exception("Must not send")));
        var options = Options();
        options.TokenFilePath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        var client = new KamusDecryptorClient(http, options);
        await Assert.ThrowsAsync<FileNotFoundException>(() => client.DecryptAsync("encrypted"));
    }

    [Fact]
    public async Task TransportFailurePropagates()
    {
        using var http = new HttpClient(new Handler((_, _) => throw new HttpRequestException("Connection failed")));
        var client = new KamusDecryptorClient(http, Options(), new TokenProvider());
        await Assert.ThrowsAsync<HttpRequestException>(() => client.DecryptAsync("encrypted"));
    }

    [Theory]
    [InlineData("http://kamus.test")]
    [InlineData("ftp://kamus.test")]
    [InlineData("https://user:password@kamus.test")]
    [InlineData("https://kamus.test?token=secret")]
    [InlineData("https://kamus.test#fragment")]
    [InlineData("relative/path")]
    public void InvalidBaseAddressesAreRejected(string address)
    {
        using var http = new HttpClient();
        var options = Options();
        options.BaseAddress = new Uri(address, UriKind.RelativeOrAbsolute);
        Assert.Throws<ArgumentException>(() => new KamusDecryptorClient(http, options));
    }

    [Fact]
    public void HttpCanBeExplicitlyEnabled()
    {
        using var http = new HttpClient();
        var options = Options("http://kamus.test");
        options.AllowInsecureHttp = true;
        _ = new KamusDecryptorClient(http, options);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(5000000000)]
    public void InvalidTimeoutsAreRejected(double milliseconds)
    {
        using var http = new HttpClient();
        var options = Options();
        options.Timeout = TimeSpan.FromMilliseconds(milliseconds);
        Assert.Throws<ArgumentOutOfRangeException>(() => new KamusDecryptorClient(http, options));
    }

    [Fact]
    public async Task DependencyInjectionUsesCustomProviderAndSupportsConcurrentCalls()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IKamusTokenProvider>(new TokenProvider("custom-token"));
        services.AddKamusDecryptorClient(o => o.BaseAddress = new Uri("https://kamus.test"))
            .ConfigurePrimaryHttpMessageHandler(() => new Handler(async (request, ct) =>
            {
                Assert.Equal("custom-token", request.Headers.Authorization!.Parameter);
                using var data = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(ct));
                await Task.Yield();
                return new HttpResponseMessage(HttpStatusCode.OK)
                { Content = new StringContent(data.RootElement.GetProperty("data").GetString()!) };
            }));
        using var provider = services.BuildServiceProvider();
        var client = provider.GetRequiredService<IKamusDecryptorClient>();
        var inputs = Enumerable.Range(0, 20).Select(i => $"ciphertext-{i}").ToArray();
        var results = await Task.WhenAll(inputs.Select(input => client.DecryptAsync(input)));
        Assert.Equal(inputs, results);
    }

    private static KamusDecryptorOptions Options(string baseAddress = "https://kamus.test") =>
        new() { BaseAddress = new Uri(baseAddress) };

    private sealed class TokenProvider(string token = "pod-token") : IKamusTokenProvider
    {
        public Task<string> GetTokenAsync(CancellationToken cancellationToken = default) => Task.FromResult(token);
    }

    private sealed class WaitingTokenProvider : IKamusTokenProvider
    {
        public async Task<string> GetTokenAsync(CancellationToken cancellationToken = default)
        {
            await Task.Delay(System.Threading.Timeout.Infinite, cancellationToken);
            return "unreachable";
        }
    }

    private sealed class Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            send(request, cancellationToken);
    }

    private sealed class WaitingStream : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() => throw new NotSupportedException();
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            await Task.Delay(System.Threading.Timeout.Infinite, cancellationToken);
            return 0;
        }
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
    }
}
