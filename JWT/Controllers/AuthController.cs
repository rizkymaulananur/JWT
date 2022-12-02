using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace JWT.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public static User users = new User();
        private readonly IConfiguration _configuration;

        public AuthController(IConfiguration configuratio)
        {
            _configuration = configuratio;
        }

        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserDTO request)
        {
            CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);

            users.Username = request.Username;
            users.PasswwordHash = passwordHash;
            users.PasswordSalt = passwordSalt;

            return Ok(users);
        }

        [HttpPost("login")]
        public async Task<ActionResult<string>> Login(UserDTO request)
        {
            if (users.Username != request.Username)
            {
                return BadRequest("User not found.");
            }

            if (!VerifiPasswordHash(request.Password, users.PasswwordHash, users.PasswordSalt))
            {
                return BadRequest("Wrong password.");
            }
            string token = CreateToken(users);
            return Ok(token);
        }

        private string CreateToken(User users)
        {
            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, users.Username)
            };

            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(
                _configuration.GetSection("AppSettings:Token").Value));

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: creds);

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        }

        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }

        private bool VerifiPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512(passwordSalt))
            {
                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return computedHash.SequenceEqual(passwordHash);
            }
        }
    }
}
