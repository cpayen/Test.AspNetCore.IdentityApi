using Api.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using System.Threading.Tasks;

namespace Api.Controllers
{
    [Authorize]
    [Produces("application/json")]
    [Route("api/account")]
    public class AccountController : Controller
    {
        private readonly IConfiguration _configuration;
        private readonly UserManager<AppUser> _userManager;

        public AccountController(IConfiguration configuration, UserManager<AppUser> userManager)
        {
            _configuration = configuration;
            _userManager = userManager;
        }

        [AllowAnonymous]
        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDTO request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var user = new AppUser { UserName = request.UserName, Email = request.Email };
            var result = await _userManager.CreateAsync(user, request.Password);
            if (result.Succeeded)
            {
                var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                return Ok($"EmailConfirmationToken: {code}");
            }

            return Ok("Oops, problem.");
        }
        
        [AllowAnonymous]
        [HttpPost]
        [Route("confirmemail")]
        public async Task<IActionResult> ConfirmEmail([FromBody] ConfirmEmailDTO request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            var user = await _userManager.FindByIdAsync(request.UserId);
            if (user == null)
            {
                return BadRequest($"Unable to load user with ID '{request.UserId}'.");
            }
            var result = await _userManager.ConfirmEmailAsync(user, request.Code);
            if (result.Succeeded)
            {
                return Ok("Email confirmed.");
            }

            return Ok("Oops, problem.");
        }
    }

    // TODO: Move it to another place?
    public class RegisterDTO
    {
        public string UserName { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
    }
    public class ConfirmEmailDTO
    {
        public string UserId { get; set; }
        public string Code { get; set; }
    }
}