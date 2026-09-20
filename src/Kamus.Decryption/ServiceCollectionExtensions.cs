// Modified in 2026 by Sasiru382. These independently authored changes are documented in Git history.
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Kamus.Decryption;

public static class ServiceCollectionExtensions
{
    public static IHttpClientBuilder AddKamusDecryptorClient(this IServiceCollection services,
        Action<KamusDecryptorOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);
        services.Configure(configure);
        services.TryAddSingleton<IKamusTokenProvider>(provider => new ServiceAccountTokenProvider(
            provider.GetRequiredService<IOptions<KamusDecryptorOptions>>().Value.TokenFilePath));

        return services.AddHttpClient<IKamusDecryptorClient, KamusDecryptorClient>((http, provider) =>
            new KamusDecryptorClient(http,
                provider.GetRequiredService<IOptions<KamusDecryptorOptions>>().Value,
                provider.GetRequiredService<IKamusTokenProvider>()))
            .ConfigureHttpClient(http => http.Timeout = System.Threading.Timeout.InfiniteTimeSpan)
            .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false })
            .RedactLoggedHeaders(_ => true)
            .RemoveAllLoggers();
    }
}
