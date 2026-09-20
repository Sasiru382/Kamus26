// Modified in 2026 by Sasiru382. These independently authored changes are documented in Git history.
using System.Net;

namespace Kamus.Decryption;

/// <summary>An HTTP failure from Kamus. Response bodies are deliberately excluded.</summary>
public sealed class KamusDecryptionException : HttpRequestException
{
    public KamusDecryptionException(HttpStatusCode statusCode)
        : base(GetMessage(statusCode), null, statusCode) { }

    private static string GetMessage(HttpStatusCode statusCode) => statusCode switch
    {
        HttpStatusCode.BadRequest => "Kamus rejected the encrypted value or it does not match the workload identity (HTTP 400).",
        HttpStatusCode.Unauthorized => "Kamus could not authenticate the service-account token (HTTP 401).",
        HttpStatusCode.Forbidden => "Kamus denied decryption for the authenticated identity (HTTP 403).",
        HttpStatusCode.ServiceUnavailable => "The Kamus decryptor is temporarily unavailable (HTTP 503).",
        _ => $"Kamus decryption failed (HTTP {(int)statusCode})."
    };
}
