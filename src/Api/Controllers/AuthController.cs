using Api.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Api.Controllers
{
    [Authorize]
    [Produces("application/json")]
    [Route("api/auth")]
    public class AuthController : Controller
    {
        private readonly IConfiguration _configuration;
        private readonly UserManager<AppUser> _userManager;

        public AuthController(IConfiguration configuration, UserManager<AppUser> userManager)
        {
            _configuration = configuration;
            _userManager = userManager;
        }

        [AllowAnonymous]
        [HttpPost]
        [Route("requesttoken")]
        public async Task<IActionResult> RequestToken([FromBody] RequestTokenDTO request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            
            var identity = await GetClaimsIdentity(request.Username, request.Password);
            if (identity == null)
            {
                return BadRequest(ModelState);
            }

            // TODO: Move token creation it to security (or service?) layer.
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration.GetSection("ApiConfiguration")["SecurityKey"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _configuration.GetSection("ApiConfiguration")["Issuer"],
                audience: _configuration.GetSection("ApiConfiguration")["Audiance"],
                claims: identity.Claims,
                expires: DateTime.Now.AddMinutes(30),
                signingCredentials: creds);

            // TODO: Add refresh token and expiration time.
            // http://piotrgankiewicz.com/2017/12/07/jwt-refresh-tokens-and-net-core/
            // https://www.c-sharpcorner.com/article/handle-refresh-token-using-asp-net-core-2-0-and-json-web-token/
            return Ok(new
            {
                request_token = new JwtSecurityTokenHandler().WriteToken(token)
            });
        }

        //TODO: Move it to service layer.
        private async Task<ClaimsIdentity> GetClaimsIdentity(string userName, string password)
        {
            if (string.IsNullOrEmpty(userName) || string.IsNullOrEmpty(password))
            {
                return await Task.FromResult<ClaimsIdentity>(null);
            }

            // get the user to verifty
            var user = await _userManager.FindByNameAsync(userName);

            if (user == null) return await Task.FromResult<ClaimsIdentity>(null);

            // check the credentials
            if (await _userManager.CheckPasswordAsync(user, password))
            {
                Claim[] claims = new[]
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(ClaimTypes.Email, user.Email)
                };
                ClaimsIdentity claimsIdentity = new ClaimsIdentity(claims, "Token");

                // add user's roles
                var rolesClaims = new List<Claim>();
                var roles = await _userManager.GetRolesAsync(user);
                foreach (var role in roles)
                {
                    rolesClaims.Add(new Claim(ClaimTypes.Role, role));
                }
                claimsIdentity.AddClaims(rolesClaims);

                return claimsIdentity;
            }

            // Credentials are invalid
            return await Task.FromResult<ClaimsIdentity>(null);
        }
    }

    // TODO: Move it to another place?
    public class RequestTokenDTO
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }
}