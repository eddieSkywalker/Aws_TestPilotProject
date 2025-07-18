using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System.Security.Claims;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Web;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages();
builder.Services.AddServerSideBlazor();

// ----- Add Authentication for Cognito (IDENTICAL to BoardGameTracker)
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
.AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
{
    options.Cookie.Name = "CompanyAuth";         // SAME as BoardGameTracker
    options.Cookie.SameSite = SameSiteMode.Lax;  // Add this
    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest; // Add this
    options.LoginPath = "/authentication/challenge";
    options.LogoutPath = "/authentication/signout";

    // Set domain only in production
    if (!builder.Environment.IsDevelopment())
    {
        options.Cookie.Domain = ".yourcompany.com";
    }
})
.AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
{
    options.Authority = builder.Configuration["Cognito:Authority"];
    options.ResponseType = OpenIdConnectResponseType.Code;
    options.Scope.Clear();
    options.Scope.Add("openid");
    options.Scope.Add("email");
    options.Scope.Add("profile");
    options.ClientId = builder.Configuration["Cognito:ClientId"];
    options.ClientSecret = builder.Configuration["Cognito:ClientSecret"];
    options.SaveTokens = true;
    options.GetClaimsFromUserInfoEndpoint = true;
    options.ClaimActions.MapJsonKey("groups", "cognito:groups");
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

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers(); // This enables MVC controller routes
app.MapBlazorHub();
app.MapFallbackToPage("/_Host");

app.Run();