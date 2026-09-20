---
title: ".NET decryption client"
menu:
  main:
    parent: "user"
    identifier: "dotnet-client"
    weight: 4
---

<!-- Modified in 2026 by Sasiru382. These independently authored changes are documented in Git history. -->

# Decrypt inside a .NET application

`Kamus.Decryption` is a standalone .NET 8+ library. It calls the deployed decrypt API
using the application's Kubernetes service-account token. It returns plaintext to the
application without creating a Kubernetes Secret or running an init container.

Build a NuGet package with `dotnet pack src/Kamus.Decryption/Kamus.Decryption.csproj -c Release -o nupkg`,
then install it from your local folder or private feed. The package is not automatically published.

```csharp
using Kamus.Decryption;

builder.Services.AddKamusDecryptorClient(options =>
{
    options.BaseAddress = new Uri("https://kamus-decryptor.example.internal");
    options.Timeout = TimeSpan.FromSeconds(15);
});
```

Inject `IKamusDecryptorClient` and call `await client.DecryptAsync(ciphertext, cancellationToken)`.
The ciphertext must be encrypted for the namespace and service-account name of the application pod.
By default, the token is reread from `/var/run/secrets/kubernetes.io/serviceaccount/token` on every call.
Use the Kubernetes API token, not an Azure Workload Identity exchange token. The decryptor
validates it via Kubernetes TokenReview and performs the KMS operation on the application's behalf.

The library requires HTTPS by default. Explicitly set `AllowInsecureHttp` only when an HTTP
connection is trusted or protected by your infrastructure. HTTP errors produce
`KamusDecryptionException` with a `StatusCode`; timeouts produce `TimeoutException` and
caller cancellation propagates normally. The client does not automatically retry or refresh secrets.

See the [package README](https://github.com/Sasiru382/Kamus26/blob/codex/key-vault-resilience/src/Kamus.Decryption/README.md)
for direct use without DI, custom token providers, packaging, and error handling.
