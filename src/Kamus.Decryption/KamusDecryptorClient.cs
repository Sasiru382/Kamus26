// Modified in 2026 by Sasiru382. These independently authored changes are documented in Git history.
using System.Net.Http.Headers;
using System.Net.Http.Json;

namespace Kamus.Decryption;

/// <summary>A reusable client. The caller owns the supplied HttpClient and its handlers.</summary>
public sealed class KamusDecryptorClient : IKamusDecryptorClient
{
    private readonly HttpClient _httpClient;
    private readonly IKamusTokenProvider _tokenProvider;
    private readonly Uri _endpoint;
    private readonly TimeSpan _timeout;

    public KamusDecryptorClient(HttpClient httpClient, KamusDecryptorOptions options,
        IKamusTokenProvider? tokenProvider = null)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();
        _httpClient = httpClient;
        _tokenProvider = tokenProvider ?? new ServiceAccountTokenProvider(options.TokenFilePath);
        // Preserve an optional path prefix, with or without its trailing slash.
        _endpoint = new Uri(new Uri(options.BaseAddress!.AbsoluteUri.TrimEnd('/') + "/"), "api/v1/decrypt");
        _timeout = options.Timeout;
    }

    public async Task<string> DecryptAsync(string encryptedData, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(encryptedData);
        cancellationToken.ThrowIfCancellationRequested();
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_timeout);
        try
        {
            var token = (await _tokenProvider.GetTokenAsync(timeout.Token).ConfigureAwait(false))?.Trim();
            if (string.IsNullOrWhiteSpace(token) ||
                token.Any(c => !char.IsAsciiLetterOrDigit(c) && !"-._~+/=".Contains(c)))
                throw new InvalidOperationException("The service-account token is empty or contains invalid characters.");

            using var request = new HttpRequestMessage(HttpMethod.Post, _endpoint);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            request.Content = JsonContent.Create(new { data = encryptedData });
            using var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead,
                timeout.Token).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
                throw new KamusDecryptionException(response.StatusCode);

            // The server returns raw content, not a JSON-encoded string.
            return await response.Content.ReadAsStringAsync(timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException("The Kamus decryption operation timed out.");
        }
    }
}
