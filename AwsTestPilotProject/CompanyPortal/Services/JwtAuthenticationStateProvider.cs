using Microsoft.AspNetCore.Components.Authorization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.JSInterop;
using System.Text.Json;

namespace CompanyPortal.Services
{
    public class JwtAuthenticationStateProvider : AuthenticationStateProvider
    {
        private readonly ITokenService _tokenService;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IConfiguration _configuration;

        public JwtAuthenticationStateProvider(ITokenService tokenService, IHttpContextAccessor httpContextAccessor, IConfiguration configuration)
        {
            _tokenService = tokenService;
            _httpContextAccessor = httpContextAccessor;
            _configuration = configuration;
        }

        public override async Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            try
            {
                var sessionId = GetSessionId();
                if (string.IsNullOrEmpty(sessionId))
                {
                    return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
                }

                var token = await _tokenService.GetAccessTokenAsync(sessionId);
                
                if (string.IsNullOrEmpty(token))
                {
                    return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
                }

                // Validate token is not expired before parsing
                if (IsTokenExpired(token))
                {
                    // Clear expired token
                    await _tokenService.ClearTokensAsync(sessionId);
                    return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
                }

                var claims = ParseClaimsFromJwt(token);
                var identity = new ClaimsIdentity(claims, "jwt");
                var user = new ClaimsPrincipal(identity);

                return new AuthenticationState(user);
            }
            catch
            {
                return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
            }
        }

        public async Task NotifyUserAuthentication(string accessToken, string? idToken = null)
        {
            var sessionId = GetSessionId();
            if (!string.IsNullOrEmpty(sessionId))
            {
                await _tokenService.StoreTokenAsync(sessionId, accessToken, idToken);
                
                var claims = ParseClaimsFromJwt(accessToken);
                var identity = new ClaimsIdentity(claims, "jwt");
                var user = new ClaimsPrincipal(identity);

                NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(user)));
            }
        }

        public async Task NotifyUserLogout()
        {
            var sessionId = GetSessionId();
            if (!string.IsNullOrEmpty(sessionId))
            {
                await _tokenService.ClearTokensAsync(sessionId);
            }

            var identity = new ClaimsIdentity();
            var user = new ClaimsPrincipal(identity);

            NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(user)));
        }

        public async Task<string?> GetTokenForSso()
        {
            var sessionId = GetSessionId();
            return string.IsNullOrEmpty(sessionId) ? null : await _tokenService.GetAccessTokenAsync(sessionId);
        }

        private string? GetSessionId()
        {
            return _httpContextAccessor.HttpContext?.Session?.Id;
        }

        private static IEnumerable<Claim> ParseClaimsFromJwt(string jwt)
        {
            var payload = jwt.Split('.')[1];
            var jsonBytes = ParseBase64WithoutPadding(payload);
            var keyValuePairs = JsonSerializer.Deserialize<Dictionary<string, object>>(jsonBytes);

            var claims = new List<Claim>();

            foreach (var kvp in keyValuePairs)
            {
                if (kvp.Value is JsonElement element)
                {
                    if (element.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var item in element.EnumerateArray())
                        {
                            claims.Add(new Claim(kvp.Key, item.GetString()));
                        }
                    }
                    else
                    {
                        claims.Add(new Claim(kvp.Key, element.GetString()));
                    }
                }
                else
                {
                    claims.Add(new Claim(kvp.Key, kvp.Value.ToString()));
                }
            }

            // Map Cognito claims to standard claims
            var usernameClaim = claims.FirstOrDefault(c => c.Type == "cognito:username");
            if (usernameClaim != null)
            {
                claims.Add(new Claim(ClaimTypes.Name, usernameClaim.Value));
            }

            var emailClaim = claims.FirstOrDefault(c => c.Type == "email");
            if (emailClaim != null)
            {
                claims.Add(new Claim(ClaimTypes.Email, emailClaim.Value));
            }

            return claims;
        }

        private static byte[] ParseBase64WithoutPadding(string base64)
        {
            switch (base64.Length % 4)
            {
                case 2: base64 += "=="; break;
                case 3: base64 += "="; break;
            }
            return Convert.FromBase64String(base64);
        }

        private static bool IsTokenExpired(string jwt)
        {
            try
            {
                var payload = jwt.Split('.')[1];
                var jsonBytes = ParseBase64WithoutPadding(payload);
                var keyValuePairs = JsonSerializer.Deserialize<Dictionary<string, object>>(jsonBytes);

                if (keyValuePairs?.TryGetValue("exp", out var expObj) == true)
                {
                    if (expObj is JsonElement expElement && expElement.ValueKind == JsonValueKind.Number)
                    {
                        var exp = expElement.GetInt64();
                        var expDateTime = DateTimeOffset.FromUnixTimeSeconds(exp);
                        return expDateTime <= DateTimeOffset.UtcNow;
                    }
                }
                return true; // If we can't determine expiration, consider it expired
            }
            catch
            {
                return true; // If parsing fails, consider it expired
            }
        }
    }

    public static class JwtAuthenticationExtensions
    {
        public static IServiceCollection AddJwtAuthentication(this IServiceCollection services)
        {
            services.AddScoped<AuthenticationStateProvider, JwtAuthenticationStateProvider>();
            return services;
        }
    }
}
