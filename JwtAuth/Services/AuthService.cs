using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using JwtAuth.Data;
using JwtAuth.Entities;
using JwtAuth.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace JwtAuth.Services
{
    public class AuthService(UserDbContext context, IConfiguration configuration) : IAuthService
    {
        public async Task<TokenResponseDto?> LoginAsync(UserDto request)
        {
            var user = await context.Users.FirstOrDefaultAsync(u => u.Username == request.Username);
            if (user == null)
            {
                return null;
            }
            if (new PasswordHasher<User>().VerifyHashedPassword(user, user.PasswordHash, request.Password)
                == PasswordVerificationResult.Failed)
            {
                return null;
            }

            return await CreateTokenResponse(user);
        }

        public async Task<User?> RegisterAsync(UserDto request)
        {
            if (await context.Users.AnyAsync<User>(u => u.Username == request.Username))
            {
                return null;
            }
            var user = new User() { Role = request.Role };
            var hashedPassword = new PasswordHasher<User>()
                                    .HashPassword(user, request.Password);
            user.Username = request.Username;
            user.PasswordHash = hashedPassword;

            context.Users.Add(user);
            await context.SaveChangesAsync();
            return user;
        }

        private async Task<User?> ValidateRefreshTokenAsync(Guid Id, string refershToken)
        {
            var user = await context.Users.FindAsync(Id);
            if (user is null || user.RefreshToken != refershToken || user.RefreshTokenExpiry <= DateTime.UtcNow)
            {
                return null;
            }
            return user;
        }

        public async Task<TokenResponseDto?> RefreshTokensAsync(RefreshTokenRequestDto refreshTokenRequestDto)
        {
            var user = await ValidateRefreshTokenAsync(refreshTokenRequestDto.UserId, refreshTokenRequestDto.RefreshToken);

            if (user is null)
            {
                return null;
            }
            return await CreateTokenResponse(user);
        }

        private string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        private async Task<string> GenerateAndSaveRefreshTokenAsync(User user)
        {
            var refershToken = GenerateRefreshToken();
            user.RefreshToken = refershToken;
            user.RefreshTokenExpiry = DateTime.UtcNow.AddDays(1);
            await context.SaveChangesAsync();
            return refershToken;
        }

        private async Task<TokenResponseDto> CreateTokenResponse(User? user)
        {
            return new TokenResponseDto()
            {
                AccessToken = CreateToken(user),
                RefreshToken = await GenerateAndSaveRefreshTokenAsync(user)
            };

        }
        private string CreateToken(User user)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Role,user.Role)
            };

            var key = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(configuration.GetValue<string>("AppSettings:Token")!));

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512);

            var tokenDescriptor = new JwtSecurityToken(
                issuer: configuration.GetValue<string>("AppSettings:Issuer"),
                audience: configuration.GetValue<string>("AppSettings:Audience"),
                claims: claims,
                notBefore: DateTime.UtcNow,
                expires: DateTime.UtcNow.AddDays(1),
                signingCredentials: creds
                );

            return new JwtSecurityTokenHandler().WriteToken(tokenDescriptor);
        }

    }
}
