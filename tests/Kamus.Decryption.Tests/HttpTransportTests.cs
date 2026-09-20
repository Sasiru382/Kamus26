// Modified in 2026 by Sasiru382. These independently authored changes are documented in Git history.
using System.Net;
using System.Text.Json;
using Kamus.Decryption;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Kamus.Decryption.Tests;

public sealed class HttpTransportTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DefaultRegistrationCallsRealHttpEndpointWithoutFollowingRedirects(bool redirect)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        builder.Logging.ClearProviders();
        await using var server = builder.Build();
        var tokenFile = Path.GetTempFileName();
        int requests = 0;
        server.MapPost("/prefix/api/v1/decrypt", async context =>
        {
            Interlocked.Increment(ref requests);
            if (context.Request.Headers.Authorization != "Bearer pod-token")
            {
                context.Response.StatusCode = 401;
                return;
            }
            using var body = await JsonDocument.ParseAsync(context.Request.Body);
            if (body.RootElement.GetProperty("data").GetString() != "encrypted-value")
            {
                context.Response.StatusCode = 400;
                return;
            }
            if (redirect)
                context.Response.Redirect("/redirected");
            else
                await context.Response.WriteAsync("  plaintext 日本語\n");
        });
        server.MapGet("/redirected", () =>
        {
            Interlocked.Increment(ref requests);
            return "Must not follow";
        });
        try
        {
            await server.StartAsync();
            await File.WriteAllTextAsync(tokenFile, "pod-token\n");
            var address = server.Services.GetRequiredService<IServer>()
                .Features.Get<IServerAddressesFeature>()!.Addresses.Single();
            var services = new ServiceCollection();
            services.AddKamusDecryptorClient(options =>
            {
                options.BaseAddress = new Uri(address + "/prefix");
                options.AllowInsecureHttp = true;
                options.TokenFilePath = tokenFile;
            });
            using var provider = services.BuildServiceProvider();
            var client = provider.GetRequiredService<IKamusDecryptorClient>();
            if (redirect)
            {
                var error = await Assert.ThrowsAsync<KamusDecryptionException>(() => client.DecryptAsync("encrypted-value"));
                Assert.Equal(HttpStatusCode.Found, error.StatusCode);
            }
            else
            {
                Assert.Equal("  plaintext 日本語\n", await client.DecryptAsync("encrypted-value"));
            }
            Assert.Equal(1, requests);
        }
        finally
        {
            await server.StopAsync();
            File.Delete(tokenFile);
        }
    }
}
