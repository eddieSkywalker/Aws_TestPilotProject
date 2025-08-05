using Microsoft.AspNetCore.Authentication;

namespace CompanyPortal.Services
{
    public interface ISsoService
    {
        Task<string?> GetTokenForSsoAsync();
    }

    public class SsoService : ISsoService
    {
        private readonly ITokenService _tokenService;
        private readonly IHttpContextAccessor _httpContextAccessor;

        public SsoService(ITokenService tokenService, IHttpContextAccessor httpContextAccessor)
        {
            _tokenService = tokenService;
            _httpContextAccessor = httpContextAccessor;
        }

        public async Task<string?> GetTokenForSsoAsync()
        {
            var sessionId = _httpContextAccessor.HttpContext?.Session?.Id;
            if (string.IsNullOrEmpty(sessionId))
                return null;

            // Try to get token from our storage first
            var token = await _tokenService.GetAccessTokenAsync(sessionId);
            
            // If not in storage, try to get it from the current authentication context
            if (string.IsNullOrEmpty(token))
            {
                var httpContext = _httpContextAccessor.HttpContext;
                if (httpContext?.User?.Identity?.IsAuthenticated == true)
                {
                    // Get token from authentication properties
                    token = await httpContext.GetTokenAsync("access_token");
                    if (!string.IsNullOrEmpty(token))
                    {
                        // Store it for future SSO use
                        await _tokenService.StoreTokenAsync(sessionId, token);
                    }
                }
            }

            return token;
        }
    }
}
