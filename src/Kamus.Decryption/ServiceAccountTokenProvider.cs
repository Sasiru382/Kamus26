// Modified in 2026 by Sasiru382. These independently authored changes are documented in Git history.
namespace Kamus.Decryption;

public sealed class ServiceAccountTokenProvider : IKamusTokenProvider
{
    private readonly string _tokenFilePath;

    public ServiceAccountTokenProvider(string tokenFilePath = "/var/run/secrets/kubernetes.io/serviceaccount/token")
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tokenFilePath);
        _tokenFilePath = tokenFilePath;
    }

    public async Task<string> GetTokenAsync(CancellationToken cancellationToken = default)
    {
        // Do not cache: Kubernetes replaces projected tokens as they rotate.
        return (await File.ReadAllTextAsync(_tokenFilePath, cancellationToken).ConfigureAwait(false)).Trim();
    }
}
