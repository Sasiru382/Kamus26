<!-- Modified in 2026 by Sasiru382. These independently authored changes are documented in Git history. -->
# Kamus.Decryption

A standalone .NET 8+ NuGet client for calling the Kamus decryptor from application code.
It has no references to the Kamus server, Kubernetes SDK, or cloud KMS packages.
The application supplies ciphertext; the client returns the decrypted string. It does not
create Kubernetes Secrets or require an init container.

## Build and install

From the repository root:

```sh
dotnet pack src/Kamus.Decryption/Kamus.Decryption.csproj -c Release -o nupkg
dotnet nuget add source /absolute/path/to/kamus/nupkg --name kamus-local
dotnet add /path/to/YourApp.csproj package Kamus.Decryption --version 0.1.0
```

These commands register and use the locally built package. Normal NuGet sources must remain configured
to restore its Microsoft.Extensions.Http dependency. Alternatively, upload the generated
`.nupkg` to your private NuGet feed and install from that feed. This repository does not
automatically publish the package to NuGet.org or any other feed.

## ASP.NET Core / dependency injection

```csharp
using Kamus.Decryption;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddKamusDecryptorClient(options =>
{
    options.BaseAddress = new Uri(builder.Configuration["Kamus:BaseAddress"]!);
    options.Timeout = TimeSpan.FromSeconds(15);
    // Set AllowInsecureHttp = true only for a trusted HTTP connection,
    // e.g. local development or transport protected by your service mesh.
});

var app = builder.Build();
var decryptor = app.Services.GetRequiredService<IKamusDecryptorClient>();
var encryptedConnectionString = builder.Configuration["EncryptedConnectionString"]!;
var connectionString = await decryptor.DecryptAsync(encryptedConnectionString);
// Pass connectionString to your database client; never log it or return it in an endpoint.
await app.RunAsync();
```

Inject `IKamusDecryptorClient` into your own services for on-demand decryption. The client is
safe for concurrent requests and does not mutate shared authorization headers or cache plaintext.
The registration returns `IHttpClientBuilder` for further configuration.

## Direct use without a DI container

```csharp
using Kamus.Decryption;

using var handler = new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false };
using var http = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
var decryptor = new KamusDecryptorClient(http, new KamusDecryptorOptions
{
    BaseAddress = new Uri("https://kamus-decryptor.example.internal"),
    Timeout = TimeSpan.FromSeconds(15)
});
string plaintext = await decryptor.DecryptAsync(encryptedValue, cancellationToken);
```

Reuse the client and HttpClient for multiple calls; dispose the HttpClient when its owner stops.
For direct use, the caller configures the handler: disable redirects and body/header logging.
The supplied HttpClient may impose a shorter timeout than the package's own timeout.

## Kubernetes authentication

The default token file is `/var/run/secrets/kubernetes.io/serviceaccount/token`.
Run the application pod with the **same namespace and service-account name** used when
encrypting the value. Ensure that its Kubernetes API token is mounted and that the application
can reach the decryptor. The decryptor itself needs Kubernetes TokenReview permission and
the configured KMS access. The application does not need KMS credentials.

The client rereads the file on every call to support projected-token rotation. Set
`TokenFilePath` for a different mount, or supply an `IKamusTokenProvider`:

```csharp
builder.Services.AddSingleton<IKamusTokenProvider, MyTokenProvider>();
builder.Services.AddKamusDecryptorClient(options =>
    options.BaseAddress = new Uri("https://kamus-decryptor.example.internal"));
```

Custom providers must be safe for concurrent use. They must return a Kubernetes service-account
token accepted by the decryptor's TokenReview, not an Azure Key Vault access token or the
Azure Workload Identity token with audience `api://AzureADTokenExchange`. The existing decryptor
does not request a custom audience in TokenReview; use a token accepted by the Kubernetes API.
Outside Kubernetes, arrange a valid token provider and network access explicitly.

## Protocol, errors, and lifecycle

The client sends `POST <BaseAddress>/api/v1/decrypt` with JSON `{"data":"<ciphertext>"}`
and a Bearer token. A path prefix in BaseAddress is preserved. Successful content is returned
verbatim, including JSON-looking strings, empty values, and whitespace.

- `KamusDecryptionException` includes `StatusCode` for non-success HTTP responses.
  `400` means invalid ciphertext or identity mismatch; `401` means authentication failed;
  `403` means identity rejected; `503` means unavailable.
- `HttpRequestException` covers transport failures.
- `TimeoutException` means the operation exceeded its time budget, including token and body reads.
- Caller cancellation propagates as `OperationCanceledException`.
- Token file access errors propagate as filesystem exceptions. Empty or malformed tokens are rejected.

No automatic retries are made; decide the retry budget at application startup or the call site.
Startup decryption requires a reachable decryptor. Store returned values only as long as needed;
the package cannot erase immutable .NET strings. It does not refresh secrets automatically.

HTTPS is required by default; `AllowInsecureHttp` explicitly permits HTTP. The DI registration
disables redirects and HttpClientFactory logging and redacts all headers. The client itself never
logs tokens or payloads, and HTTP error bodies/reason phrases are excluded from exceptions.
Review any logging, tracing, or custom handlers you add for secret exposure.
