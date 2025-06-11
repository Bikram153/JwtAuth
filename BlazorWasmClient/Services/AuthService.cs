using System.Net.Http.Json;
using Blazored.LocalStorage;
using JwtAuth.Models;
using Microsoft.AspNetCore.Components.Authorization;

namespace BlazorWasmClient.Services
{
    public class AuthService
    {
        public readonly HttpClient _http;
        public readonly ILocalStorageService _localStorage;
        public readonly AuthenticationStateProvider _authProvider;

        public AuthService(HttpClient http, ILocalStorageService localStorage, AuthenticationStateProvider authProvider)
        {
            _http = http;
            _localStorage = localStorage;
            _authProvider = authProvider;
        }

        public async Task<bool> Register(UserDto user)
        {
            var result = await _http.PostAsJsonAsync("api/Authe/register", user);
            return result.IsSuccessStatusCode;
        }

        public async Task<bool> Login(UserDto user)
        {
            var response = await _http.PostAsJsonAsync("api/Authe/login", user);
            if (!response.IsSuccessStatusCode)
            {
                return false;
            }

            var tokenData = await response.Content.ReadFromJsonAsync<TokenResponseDto>();
            await _localStorage.SetItemAsync("accessToken", tokenData?.AccessToken);
            await _localStorage.SetItemAsync("refreshToken", tokenData?.RefreshToken);

            ((CustomAuthStateProvider)_authProvider).NotifyAuthenticationStateChanged();
            return true;
        }
    }
}
