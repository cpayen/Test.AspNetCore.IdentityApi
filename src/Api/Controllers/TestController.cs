using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Api.Controllers
{
    [Authorize]
    [Produces("application/json")]
    [Route("api/test")]
    public class TestController : Controller
    {
        // GET api/test/admin
        [HttpGet]
        [Route("admin")]
        [Authorize(Roles = "Administrator")]
        public IActionResult Admin()
        {
            var userName = User.Identity.Name;
            return Ok($"Admin profile only. Welcome {userName}!");
        }

        // GET api/test/user
        [HttpGet]
        [Route("user")]
        [Authorize(Roles = "User")]
        public IActionResult UserData()
        {
            var userName = User.Identity.Name;
            return Ok($"User profile only. Welcome {userName}!");
        }

        // GET api/test/private
        [HttpGet]
        [Route("private")]
        public IActionResult PrivateData()
        {
            return Ok($"Authorized users can see this.");
        }

        // GET api/test/public
        [AllowAnonymous]
        [HttpGet]
        [Route("public")]
        public IActionResult Public()
        {
            return Ok($"Everyboby can see this.");
        }
    }
}