using System;
using Azure.Core;
using Azure.Identity;
using Microsoft.Extensions.Configuration;

namespace integration
{
    public static class Utils
    {
        public static TokenCredential CreateAzureCredential(IConfiguration configuration)
        {
            var tenantId = configuration["ActiveDirectory:TenantId"];
            var clientId = configuration["ActiveDirectory:ClientId"];
            var secret = configuration["ActiveDirectory:ClientSecret"];
            return !string.IsNullOrEmpty(tenantId) && !string.IsNullOrEmpty(clientId) && !string.IsNullOrEmpty(secret)
                ? new ClientSecretCredential(tenantId, clientId, secret)
                : new DefaultAzureCredential();
        }
    }
}
