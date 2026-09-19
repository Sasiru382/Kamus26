// Modified in 2026 by Sasiru382. These independently authored changes are documented in Git history.
using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Kamus
{
    /// <summary>
    /// Middleware for handling exceptions globally.
    /// Specifically handles client disconnections gracefully to avoid noisy error logs.
    /// </summary>
    public class ErrorHandlingMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<ErrorHandlingMiddleware> _logger;

        public ErrorHandlingMiddleware(RequestDelegate next, ILogger<ErrorHandlingMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task Invoke(HttpContext httpContext)
        {
            try
            {
                await _next.Invoke(httpContext);
            }
            catch (Microsoft.AspNetCore.Http.BadHttpRequestException ex)
            {
                // Client disconnected before sending complete request body.
                // This is typically caused by client-side timeouts - not a server error.
                // Log as warning instead of error to reduce noise.
                _logger.LogWarning(
                    "Client disconnected prematurely: {Message}. Path: {Path}",
                    ex.Message,
                    httpContext.Request.Path);

                // Don't try to write response - client is already gone
                if (!httpContext.Response.HasStarted)
                {
                    httpContext.Response.StatusCode = 499; // Client Closed Request (nginx convention)
                }
            }
            catch (OperationCanceledException) when (httpContext.RequestAborted.IsCancellationRequested)
            {
                // Request was cancelled by the client (client timeout/disconnect)
                _logger.LogWarning(
                    "Request cancelled by client. Path: {Path}",
                    httpContext.Request.Path);

                if (!httpContext.Response.HasStarted)
                {
                    httpContext.Response.StatusCode = 499;
                }
            }
            catch (IOException ex) when (IsClientDisconnectException(ex))
            {
                // Connection reset or broken pipe - client disconnected
                _logger.LogWarning(
                    "Client connection lost: {Message}. Path: {Path}",
                    ex.Message,
                    httpContext.Request.Path);

                if (!httpContext.Response.HasStarted)
                {
                    httpContext.Response.StatusCode = 499;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unhandled exception while processing request. Path: {Path}", httpContext.Request.Path);

                if (!httpContext.Response.HasStarted)
                {
                    httpContext.Response.StatusCode = 500;
                    try
                    {
                        await httpContext.Response.WriteAsync("server failed to handle response");
                    }
                    catch
                    {
                        // Client might have disconnected, ignore
                    }
                }
            }
        }

        /// <summary>
        /// Checks if the IOException is caused by client disconnection.
        /// </summary>
        private static bool IsClientDisconnectException(IOException ex)
        {
            // Common patterns for client disconnection
            var message = ex.Message?.ToLowerInvariant() ?? string.Empty;
            return message.Contains("connection reset") ||
                   message.Contains("broken pipe") ||
                   message.Contains("connection aborted") ||
                   message.Contains("an existing connection was forcibly closed");
        }
    }

    // Extension method used to add the middleware to the HTTP request pipeline.
    public static class ErrorHandlingMiddlewareExtensions
    {
        public static IApplicationBuilder UseExceptionMiddleware(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<ErrorHandlingMiddleware>();
        }
    }
}
