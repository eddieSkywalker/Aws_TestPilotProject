using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Mvc;

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
            return Redirect("/");
        }
    }
}