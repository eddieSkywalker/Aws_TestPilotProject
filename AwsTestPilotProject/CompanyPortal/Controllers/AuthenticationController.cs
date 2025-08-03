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
            // Sign out locally
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            await HttpContext.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme);

            // Build Cognito logout URL
            var config = HttpContext.RequestServices.GetService<IConfiguration>();
            var cognitoDomain = config?["Cognito:Authority"];
            var clientId = config?["Cognito:ClientId"];
            var request = HttpContext.Request;
            var baseUrl = $"{request.Scheme}://{request.Host}";
            var postLogoutRedirectUri = baseUrl + "/authentication/loggedout";

            // Remove /oauth2 if present
            string domain = cognitoDomain?.TrimEnd('/');
            if (domain != null && domain.EndsWith("/oauth2"))
                domain = domain.Substring(0, domain.Length - "/oauth2".Length);

            var cognitoLogoutUrl = $"{domain}/logout?client_id={clientId}&logout_uri={System.Net.WebUtility.UrlEncode(postLogoutRedirectUri)}";
            return Redirect(cognitoLogoutUrl);
        }
    }
}