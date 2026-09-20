// Modified in 2026 by Sasiru382. These independently authored changes are documented in Git history.
namespace Kamus.Decryption;

/// <summary>Supplies a Kubernetes service-account token for each outgoing request.</summary>
public interface IKamusTokenProvider
{
    Task<string> GetTokenAsync(CancellationToken cancellationToken = default);
}
