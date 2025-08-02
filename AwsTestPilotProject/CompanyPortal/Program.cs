using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System.Security.Claims;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.AspNetCore.HttpOverrides;

var builder = WebApplication.CreateBuilder(args);

// Configure logging
builder.Logging.ClearProviders();
builder.Logging.AddConsole();
builder.Logging.SetMinimumLevel(LogLevel.Information);

var logger = builder.Services.BuildServiceProvider().GetRequiredService<ILogger<Program>>();

// Debug: Log configuration loading
logger.LogInformation("Environment: {Environment}", builder.Environment.EnvironmentName);
logger.LogInformation("Content Root: {ContentRoot}", builder.Environment.ContentRootPath);

// Add services to the container.
builder.Services.AddRazorPages();
builder.Services.AddServerSideBlazor();
builder.Services.AddHttpClient();
builder.Services.AddHttpContextAccessor();

// Add session support for token storage
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromHours(1);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});

// Add Token Service for SSO capability (but use built-in auth state provider)
builder.Services.AddSingleton<CompanyPortal.Services.ITokenService, CompanyPortal.Services.TokenService>();
builder.Services.AddScoped<CompanyPortal.Services.ISsoService, CompanyPortal.Services.SsoService>();

// ----- Add Authentication for Cognito (Hybrid Approach)
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
.AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
{
    // options.LoginPath = "/authentication/login";
    options.LogoutPath = "/authentication/logout";

    // LocalHost development needs custom domains set in local "Hosts" file 
    // in order to pass credentials across domains for auto authentication.
    // For example, add the following line to your Hosts file: 127.0.0.1 App1.localtest.me
    // If not, you will be requested to login each time you access an app.
    if (!builder.Environment.IsDevelopment())
    {
        options.Cookie.Domain = builder.Configuration["Cookie:Domain"];
    }
})
.AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
{
    options.Authority = builder.Configuration["Cognito:Authority"];
    options.ClientId = builder.Configuration["Cognito:ClientId"];
    options.ClientSecret = builder.Configuration["Cognito:ClientSecret"];
    options.ResponseType = OpenIdConnectResponseType.Code;
    options.CallbackPath = "/signin-oidc";
    options.SignedOutCallbackPath = "/signout-callback-oidc";
    options.RequireHttpsMetadata = true; // Ensure HTTPS is used
    options.SaveTokens = true;
    
    // Add required scopes
    options.Scope.Clear();
    options.Scope.Add("openid");
    options.Scope.Add("email");
    options.Scope.Add("profile");
    
    options.Events = new OpenIdConnectEvents
    {
        OnTokenValidated = async context =>
        {
            // Extract tokens for SSO capability
            var tokenService = context.HttpContext.RequestServices.GetRequiredService<CompanyPortal.Services.ITokenService>();
            var sessionId = context.HttpContext.Session.Id;
            
            var accessToken = context.TokenEndpointResponse?.AccessToken;
            var idToken = context.TokenEndpointResponse?.IdToken;
            
            if (!string.IsNullOrEmpty(accessToken))
            {
                await tokenService.StoreTokenAsync(sessionId, accessToken, idToken);
            }
        }
    };
});

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("WarehouseUser", policy =>
    {
        policy.RequireAssertion(context =>
            context.User.HasClaim("cognito:groups", "Warehouse")
        );
    });

    options.AddPolicy("CustomerUser", policy =>
    {
        policy.RequireAssertion(context =>
            context.User.HasClaim("cognito:groups", "Customer")
        );
    });
});

// builder.WebHost.ConfigureKestrel((context, options) =>
// {
//     options.Configure(context.Configuration.GetSection("Kestrel"));
// });


var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseForwardedHeaders(new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedFor
});

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseSession(); // Add session support
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers(); // This enables MVC controller routes
app.MapBlazorHub();
app.MapFallbackToPage("/_Host");

app.Run();