// Modified in 2026 by Sasiru382. These independently authored changes are documented in Git history.
namespace Kamus.Decryption;

/// <summary>Decrypts values using the identity supplied by a Kubernetes service-account token.</summary>
public interface IKamusDecryptorClient
{
    Task<string> DecryptAsync(string encryptedData, CancellationToken cancellationToken = default);
}
