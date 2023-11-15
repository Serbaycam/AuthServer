using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AppNoAuth.API.Controllers
{
    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    public class NoAuthController : ControllerBase
    {
        [HttpGet]
        public IActionResult GetStock()
        {
            return Ok("Ok");
        }
    }
}
