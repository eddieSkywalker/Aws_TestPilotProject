using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Net.Http;
using System.Text.Json;

namespace CompanyPortal.Controllers
{
    [Route("jwt-auth")]
    public class JwtAuthController : Controller
    {
        private readonly IConfiguration _configuration;
        private readonly HttpClient _httpClient;
        private readonly ILogger<JwtAuthController> _logger;
        private readonly CompanyPortal.Services.ITokenService _tokenService;
        private readonly CompanyPortal.Services.JwtAuthenticationStateProvider _authStateProvider;

        public JwtAuthController(
            IConfiguration configuration, 
            HttpClient httpClient, 
            ILogger<JwtAuthController> logger,
            CompanyPortal.Services.ITokenService tokenService,
            CompanyPortal.Services.JwtAuthenticationStateProvider authStateProvider)
        {
            _configuration = configuration;
            _httpClient = httpClient;
            _logger = logger;
            _tokenService = tokenService;
            _authStateProvider = authStateProvider;
        }

        [HttpGet("login")]
        public IActionResult Login(string returnUrl = "/")
        {
            try
            {
                // Debug: Log configuration values (mask sensitive data)
                var authority = _configuration["Cognito:Authority"];
                var clientId = _configuration["Cognito:ClientId"];
                var clientSecret = _configuration["Cognito:ClientSecret"];
                
                _logger.LogInformation("=== LOGIN DEBUG INFO ===");
                _logger.LogInformation("Environment: {Environment}", Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT"));
                _logger.LogInformation("Authority: {Authority}", authority);
                _logger.LogInformation("ClientId: {ClientId}", clientId);
                _logger.LogInformation("ClientSecret configured: {HasSecret}", !string.IsNullOrEmpty(clientSecret));
                _logger.LogInformation("Request Scheme: {Scheme}", Request.Scheme);
                _logger.LogInformation("Request Host: {Host}", Request.Host);
                
                // Check if still using placeholder values
                if (string.IsNullOrEmpty(authority) || authority.Contains("your-auth-provider"))
                {
                    var error = "Cognito Authority not configured. Current value: " + authority;
                    _logger.LogError(error);
                    return BadRequest(error);
                }
                
                if (string.IsNullOrEmpty(clientId) || clientId.Contains("your-client-id"))
                {
                    var error = "Cognito ClientId not configured. Current value: " + clientId;
                    _logger.LogError(error);
                    return BadRequest(error);
                }
                
                if (string.IsNullOrEmpty(clientSecret) || clientSecret.Contains("your-client-secret"))
                {
                    var error = "Cognito ClientSecret not configured";
                    _logger.LogError(error);
                    return BadRequest(error);
                }
                
                // Build redirect URI - must match Cognito app client setting
                var redirectUri = Request.Scheme + "://" + Request.Host + "/signin-oidc";
                
                // Redirect to Cognito for authentication
                var cognitoLoginUrl = $"{authority}/oauth2/authorize" +
                                     $"?client_id={clientId}" +
                                     $"&response_type=code" +
                                     $"&scope=openid+email+profile" +
                                     $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
                                     $"&state={Uri.EscapeDataString(returnUrl)}";
                
                _logger.LogInformation("Redirect URI: {RedirectUri}", redirectUri);
                _logger.LogInformation("Cognito URL: {Url}", cognitoLoginUrl);
                _logger.LogInformation("About to redirect to Cognito...");
                _logger.LogInformation("=== END DEBUG INFO ===\n\n");
                
                // Use MVC redirect instead of Response.Redirect for better Blazor compatibility
                return Redirect(cognitoLoginUrl);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in Login method");
                return BadRequest($"Login error: {ex.Message}");
            }
        }

        [HttpGet("/signin-oidc")]
        public async Task<IActionResult> Callback(string code, string state = "/")
        {
            if (string.IsNullOrEmpty(code))
            {
                return BadRequest("Authorization code is missing");
            }

            try
            {
                // Exchange code for tokens
                var tokenResponse = await ExchangeCodeForTokens(code);
                
                if (tokenResponse != null && !string.IsNullOrEmpty(tokenResponse.AccessToken))
                {
                    // Store tokens server-side and notify authentication state
                    await _authStateProvider.NotifyUserAuthentication(tokenResponse.AccessToken, tokenResponse.IdToken);
                    
                    // Redirect to the desired page
                    return Redirect(state);
                }
                
                return BadRequest("Failed to obtain access token");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Authentication callback failed");
                return BadRequest($"Authentication failed: {ex.Message}");
            }
        }

        [HttpPost("logout")]
        public async Task<IActionResult> Logout()
        {
            await _authStateProvider.NotifyUserLogout();
            return Redirect("/");
        }

        [HttpGet("sso-redirect")]
        public async Task<IActionResult> SsoRedirect(string targetUrl, string token)
        {
            // Store the SSO token and notify authentication state
            await _authStateProvider.NotifyUserAuthentication(token);
            return Redirect(targetUrl ?? "/");
        }

        private async Task<TokenResponse?> ExchangeCodeForTokens(string code)
        {
            try
            {
                var tokenEndpoint = $"{_configuration["Cognito:Authority"]}/oauth2/token";
                var redirectUri = Request.Scheme + "://" + Request.Host + "/signin-oidc";

                var parameters = new Dictionary<string, string>
                {
                    {"grant_type", "authorization_code"},
                    {"client_id", _configuration["Cognito:ClientId"] ?? throw new InvalidOperationException("ClientId not configured")},
                    {"client_secret", _configuration["Cognito:ClientSecret"] ?? throw new InvalidOperationException("ClientSecret not configured")},
                    {"code", code},
                    {"redirect_uri", redirectUri}
                };

                var content = new FormUrlEncodedContent(parameters);
                var response = await _httpClient.PostAsync(tokenEndpoint, content);
                
                if (response.IsSuccessStatusCode)
                {
                    var responseContent = await response.Content.ReadAsStringAsync();
                    return JsonSerializer.Deserialize<TokenResponse>(responseContent, new JsonSerializerOptions
                    {
                        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
                    });
                }
                else
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    _logger.LogError("Token exchange failed: {StatusCode} - {Content}", response.StatusCode, errorContent);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Exception during token exchange");
            }

            return null;
        }
    }

    public class TokenResponse
    {
        public string? AccessToken { get; set; }
        public string? IdToken { get; set; }
        public string? RefreshToken { get; set; }
        public string? TokenType { get; set; }
        public int ExpiresIn { get; set; }
    }
}
