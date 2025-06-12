namespace BlazorWasmClient.Services
{
    using System.IdentityModel.Tokens.Jwt;
    using System.Net.Http.Headers;
    using System.Net.Http.Json;
    using System.Security.Claims;
    using Blazored.LocalStorage;
    using BlazorWasmClient.Models;

    public class TokenService
    {
        private readonly ILocalStorageService _localStorage;
        private readonly HttpClient _httpClient;

        public TokenService(HttpClient httpClient, ILocalStorageService localStorage)
        {
            _httpClient = httpClient;
            _localStorage = localStorage;
        }

        public string? AccessToken { get; private set; }
        public string? RefreshToken { get; private set; }
        public string? UserRole { get; private set; }
        public bool IsLoggedIn => !string.IsNullOrEmpty(AccessToken);

        public async Task SetTokensAsync(TokenResponseDto tokens)
        {
            AccessToken = tokens.AccessToken;
            RefreshToken = tokens.RefreshToken;

            await _localStorage.SetItemAsync("access_token", AccessToken);
            await _localStorage.SetItemAsync("refresh_token", RefreshToken);

            var handler = new JwtSecurityTokenHandler();
            var token = handler.ReadJwtToken(AccessToken);
            UserRole = token.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Role)?.Value;

            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", AccessToken);
        }

        public async Task TryRefreshTokenAsync()
        {
            var userId = GetClaim(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(userId)) return;

            var refreshReq = new RefreshTokenRequestDto
            {
                UserId = Guid.Parse(userId),
                RefreshToken = await _localStorage.GetItemAsync<string>("refresh_token")
            };

            var result = await _httpClient.PostAsJsonAsync("api/Authe/refresh-token", refreshReq);
            if (result.IsSuccessStatusCode)
            {
                var tokens = await result.Content.ReadFromJsonAsync<TokenResponseDto>();
                if (tokens != null)
                {
                    await SetTokensAsync(tokens);
                }
            }
            else
            {
                Logout();
            }
        }

        public string? GetClaim(string claimType)
        {
            if (AccessToken == null) return null;
            var handler = new JwtSecurityTokenHandler();
            var token = handler.ReadJwtToken(AccessToken);
            return token.Claims.FirstOrDefault(c => c.Type == claimType)?.Value;
        }

        public void Logout()
        {
            AccessToken = null;
            RefreshToken = null;
            UserRole = null;
            _httpClient.DefaultRequestHeaders.Authorization = null;
            _localStorage.RemoveItemAsync("access_token");
            _localStorage.RemoveItemAsync("refresh_token");
        }
    }

}
