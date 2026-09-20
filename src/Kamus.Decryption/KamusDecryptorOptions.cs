// Modified in 2026 by Sasiru382. These independently authored changes are documented in Git history.
namespace Kamus.Decryption;

public sealed class KamusDecryptorOptions
{
    /// <summary>The decryptor service URL, optionally including a reverse-proxy path prefix.</summary>
    public Uri? BaseAddress { get; set; }

    public string TokenFilePath { get; set; } = "/var/run/secrets/kubernetes.io/serviceaccount/token";

    /// <summary>Limits the whole operation, including reading the token and response body.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(10);

    /// <summary>Explicitly permits HTTP for trusted local or service-mesh connections.</summary>
    public bool AllowInsecureHttp { get; set; }

    internal void Validate()
    {
        if (BaseAddress is null || !BaseAddress.IsAbsoluteUri ||
            (BaseAddress.Scheme != Uri.UriSchemeHttps && BaseAddress.Scheme != Uri.UriSchemeHttp) ||
            !string.IsNullOrEmpty(BaseAddress.UserInfo) || !string.IsNullOrEmpty(BaseAddress.Query) ||
            !string.IsNullOrEmpty(BaseAddress.Fragment))
            throw new ArgumentException("BaseAddress must be an absolute HTTP(S) URL without credentials, query, or fragment.", nameof(BaseAddress));

        if (BaseAddress.Scheme == Uri.UriSchemeHttp && !AllowInsecureHttp)
            throw new ArgumentException("Use HTTPS or explicitly enable AllowInsecureHttp for a trusted connection.", nameof(BaseAddress));

        if (Timeout <= TimeSpan.Zero || Timeout.TotalMilliseconds > uint.MaxValue - 1)
            throw new ArgumentOutOfRangeException(nameof(Timeout), "Timeout must be positive and less than 49.7 days.");
    }
}
