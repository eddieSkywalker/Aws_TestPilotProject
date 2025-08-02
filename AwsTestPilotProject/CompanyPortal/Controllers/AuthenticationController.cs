using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using System.Threading.Tasks;

namespace CompanyPortal.Controllers
{
    [Route("authentication")]
    public class AuthenticationController : Controller
    {
        [HttpGet("challenge")]
        public IActionResult Challenge(string returnUrl = "/")
        {
            return Challenge(new AuthenticationProperties { RedirectUri = returnUrl }, OpenIdConnectDefaults.AuthenticationScheme);
        }

        [HttpGet("signout")]
        public async Task<IActionResult> SignOut()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            await HttpContext.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme);

            // Build Cognito logout URL from config
            var cognitoDomain = HttpContext.RequestServices.GetService<IConfiguration>()?["Cognito:Authority"];
            var clientId = HttpContext.RequestServices.GetService<IConfiguration>()?["Cognito:ClientId"];
            // Use the current app's base URL for post-logout redirect
            var request = HttpContext.Request;
            var baseUrl = $"{request.Scheme}://{request.Host}";
            var postLogoutRedirectUri = baseUrl + "/authentication/loggedout";

            // Cognito:Authority may include "/oauth2" or not; ensure only the domain part is used
            string domain = cognitoDomain?.TrimEnd('/');
            if (domain != null && domain.EndsWith("/oauth2"))
                domain = domain.Substring(0, domain.Length - "/oauth2".Length);

            var cognitoLogoutUrl = $"{domain}/logout?client_id={clientId}&logout_uri={System.Net.WebUtility.UrlEncode(postLogoutRedirectUri)}";
            return Redirect(cognitoLogoutUrl);
        }
    }
}