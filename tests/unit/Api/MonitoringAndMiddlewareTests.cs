// Modified in 2026 by Sasiru382. These independently authored changes are documented in Git history.
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Kamus;
using Kamus.Controllers;
using Kamus.KeyManagement;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace unit.Api
{
    public class MonitoringAndMiddlewareTests
    {
        [Theory]
        [InlineData(false, 200)]
        [InlineData(true, 503)]
        public async Task LivenessReflectsProviderHealth(bool fails, int expected)
        {
            var controller = new MonitoringController(new ProbeProvider(fails));
            var result = Assert.IsAssignableFrom<ObjectResult>(await controller.IsAlive());
            Assert.Equal(expected, result.StatusCode);
        }

        [Theory]
        [InlineData("bad-request", 499)]
        [InlineData("cancelled", 499)]
        [InlineData("reset", 499)]
        [InlineData("server-cancelled", 500)]
        [InlineData("disk-error", 500)]
        [InlineData("server-error", 500)]
        public async Task MiddlewareDistinguishesDisconnectsFromServerErrors(string failure, int status)
        {
            var context = new DefaultHttpContext();
            using var body = new MemoryStream();
            context.Response.Body = body;
            if (failure == "cancelled") context.RequestAborted = new CancellationToken(true);
            Exception error = failure switch
            {
                "bad-request" => new BadHttpRequestException("Unexpected end of request content"),
                "cancelled" or "server-cancelled" => new OperationCanceledException(),
                "reset" => new IOException("connection reset"),
                "disk-error" => new IOException("disk read failure"),
                _ => new InvalidOperationException("failed")
            };
            await Middleware(error).Invoke(context);
            Assert.Equal(status, context.Response.StatusCode);
            Assert.Equal(status == 499, body.Length == 0);
        }

        [Fact]
        public async Task MiddlewareDoesNotRewriteStartedResponse()
        {
            var context = new DefaultHttpContext();
            var feature = new StartedResponseFeature();
            context.Features.Set<IHttpResponseFeature>(feature);
            await Middleware(new InvalidOperationException()).Invoke(context);
            Assert.Equal(202, feature.StatusCode);
        }

        [Fact]
        public async Task MiddlewareToleratesFailureWritingErrorResponse()
        {
            var context = new DefaultHttpContext();
            using var closed = new MemoryStream();
            closed.Dispose();
            context.Response.Body = closed;
            await Middleware(new InvalidOperationException()).Invoke(context);
            Assert.Equal(500, context.Response.StatusCode);
        }

        private static ErrorHandlingMiddleware Middleware(Exception error) => new ErrorHandlingMiddleware(
            _ => Task.FromException(error), NullLogger<ErrorHandlingMiddleware>.Instance);

        private sealed class StartedResponseFeature : IHttpResponseFeature
        {
            public int StatusCode { get; set; } = 202;
            public string ReasonPhrase { get; set; }
            public IHeaderDictionary Headers { get; set; } = new HeaderDictionary();
            public Stream Body { get; set; } = Stream.Null;
            public bool HasStarted => true;
            public void OnStarting(Func<object, Task> callback, object state) { }
            public void OnCompleted(Func<object, Task> callback, object state) { }
        }

        private sealed class ProbeProvider : IKeyManagement
        {
            private readonly bool _fails;
            public ProbeProvider(bool fails) => _fails = fails;
            public Task VerifyConnectivity() => _fails ? Task.FromException(new Exception("offline")) : Task.CompletedTask;
            public Task<string> Encrypt(string data, string sa, bool createKeyIfMissing = true) => throw new NotImplementedException();
            public Task<string> Decrypt(string data, string sa) => throw new NotImplementedException();
        }
    }
}
