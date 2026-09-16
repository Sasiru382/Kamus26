using System;
using System.Threading.Tasks;
using Kamus.KeyManagement;
using Microsoft.AspNetCore.Mvc;
using ILogger = Serilog.ILogger;
using Log = Serilog.Log;

namespace Kamus.Controllers
{
    public class MonitoringController : Controller
    {
        private readonly IKeyManagement _keyManagement;
        private readonly ILogger _logger = Log.ForContext<MonitoringController>();

        public MonitoringController(IKeyManagement keyManagement)
        {
            _keyManagement = keyManagement;
        }

        /// <summary>
        /// Liveness probe endpoint. Returns 200 only when Key Vault token acquisition
        /// and connectivity are healthy. Returns 503 when degraded so Kubernetes will
        /// restart the pod automatically instead of leaving it stuck returning 500 on
        /// encrypt requests.
        /// </summary>
        [HttpGet]
        [Route("api/v1/isAlive")]
        public async Task<IActionResult> IsAlive()
        {
            try
            {
                await _keyManagement.VerifyConnectivity();
                return Ok(true);
            }
            catch (Exception ex)
            {
                _logger.Warning(ex, "Liveness check failed — Key Vault connectivity is unhealthy");
                return StatusCode(503, "Kamus encryptor is unhealthy: Key Vault connectivity check failed");
            }
        }

        [HttpGet]
        [Route("")]
        public string Welcome()
        {
            return "welcome";
        }
    }
}
