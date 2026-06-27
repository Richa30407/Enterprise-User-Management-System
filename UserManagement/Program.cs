using Npgsql;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.DataProtection;
using System.IO;


var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();

builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo("/tmp/keys"))
    .SetApplicationName("UserManagement");


// Register application services
builder.Services.AddHttpContextAccessor();
builder.Services.AddSingleton<UserManagement.Services.IAppLogger, UserManagement.Services.AppLogger>();
builder.Services.AddScoped<UserManagement.Repositories.IUserRepository, UserManagement.Repositories.UserRepository>();
builder.Services.AddScoped<UserManagement.Repositories.IEmailService, UserManagement.Repositories.EmailService>();

// Register ASP.NET Core Identity custom stores and services
builder.Services.AddScoped<Microsoft.AspNetCore.Identity.IUserStore<UserManagement.Models.ApplicationUser>, UserManagement.Repositories.DapperUserStore>();
builder.Services.AddScoped<Microsoft.AspNetCore.Identity.IRoleStore<UserManagement.Models.ApplicationRole>, UserManagement.Repositories.DapperRoleStore>();

builder.Services.AddIdentity<UserManagement.Models.ApplicationUser, UserManagement.Models.ApplicationRole>(options =>
{
    // Password settings
    options.Password.RequireDigit = false;
    options.Password.RequiredLength = 6;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequireUppercase = false;
    options.Password.RequireLowercase = false;

    // Lockout settings
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers = true;
})
.AddDefaultTokenProviders();

builder.Services.AddScoped<Microsoft.AspNetCore.Identity.IPasswordHasher<UserManagement.Models.ApplicationUser>, UserManagement.Services.CustomPasswordHasher>();

builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.HttpOnly = true;
    options.ExpireTimeSpan = TimeSpan.FromMinutes(20);
    options.LoginPath = "/Account/Login";
    options.LogoutPath = "/Account/Logout";
    options.AccessDeniedPath = "/Account/Login";
    options.SlidingExpiration = true;
});

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("RequireAdminOrSuperAdmin", policy =>
        policy.RequireRole("Admin", "SuperAdmin"));
    options.AddPolicy("RequireSuperAdmin", policy =>
        policy.RequireRole("SuperAdmin"));
});

// Configure Session memory storage services
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(20);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

// Capture status codes (401, 403, 404, 500) and execute the custom handler
app.UseStatusCodePagesWithReExecute("/Home/StatusCodeHandler/{0}");

// Global exception handling middleware to catch unhandled exceptions
app.UseMiddleware<UserManagement.Middleware.ErrorHandlingMiddleware>();

app.UseRouting();

// Enable Session Middleware strictly before UseAuthorization
app.UseSession();

app.UseAuthentication();
app.UseAuthorization();

// Set Register Page as the default application landing page
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Account}/{action=Register}/{id?}");

// Force database schema migration on startup
using (var scope = app.Services.CreateScope())
{
    scope.ServiceProvider.GetRequiredService<UserManagement.Repositories.IUserRepository>();
}

// Register lifetime events logging
var logger = app.Services.GetRequiredService<UserManagement.Services.IAppLogger>();
app.Lifetime.ApplicationStarted.Register(() =>
{
    logger.Log("System", "Application Start", "Success", "Application started successfully.");
});
app.Lifetime.ApplicationStopping.Register(() =>
{
    logger.Log("System", "Application Stop", "Success", "Application is stopping.");
});

app.Run();