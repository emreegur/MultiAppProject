using Microsoft.EntityFrameworkCore;
using NLog;
using NLog.Web;
using Hangfire;
using Hangfire.MemoryStorage;
using MyWebApp.Middlewares;
using Microsoft.AspNetCore.HttpOverrides;  // <-- Burayı ekledim

var logger = LogManager.Setup().LoadConfigurationFromAppSettings().GetCurrentClassLogger();

try
{
    var builder = WebApplication.CreateBuilder(args);

    builder.Logging.ClearProviders();
    builder.Logging.SetMinimumLevel(Microsoft.Extensions.Logging.LogLevel.Trace);
    builder.Host.UseNLog();

    builder.Services.AddControllersWithViews();
    builder.Services.AddHttpClient();

    builder.Services.AddHangfire(config =>
    {
        config.SetDataCompatibilityLevel(CompatibilityLevel.Version_170)
              .UseSimpleAssemblyNameTypeSerializer()
              .UseRecommendedSerializerSettings()
              .UseMemoryStorage();
    });
    builder.Services.AddHangfireServer();

    builder.Services.AddDbContext<KullaniciDepoContext>(options =>
    {
        options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"));
    });

    builder.Services.AddAuthentication("CookieAuth")
        .AddCookie("CookieAuth", options =>
        {
            options.LoginPath = "/Home/Index";
            options.LogoutPath = "/Home/LogOut";
            options.Cookie.Name = "MyWebApp.Auth";
            options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
            options.SlidingExpiration = true;
        });

    builder.Services.AddSession(options =>
    {
        options.IdleTimeout = TimeSpan.FromMinutes(30);
        options.Cookie.HttpOnly = true;
        options.Cookie.IsEssential = true;
    });

    builder.Services.AddStackExchangeRedisCache(options =>
    {
        options.Configuration = "localhost:6379";
        options.InstanceName = "MyWebApp_";
    });

    var app = builder.Build();

    if (!app.Environment.IsDevelopment())
    {
        app.UseExceptionHandler("/Home/Error");
        app.UseHsts();
    }

    app.UseHttpsRedirection();
    app.UseStaticFiles();

    // ** Proxy arkasında gerçek client IP için ForwardedHeaders middleware eklendi **
    app.UseForwardedHeaders(new ForwardedHeadersOptions
    {
        ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
    });

    app.UseRouting();

    app.UseAuthentication();
    app.UseAuthorization();

    // AuthToken'ı context'e ata
    app.Use(async (context, next) =>
    {
        var token = context.Request.Cookies["AuthToken"];
        if (!string.IsNullOrEmpty(token))
        {
            context.Items["AuthToken"] = token;
        }
        await next();
    });

    app.UseHangfireDashboard("/hangfire");

    app.UseSession();

    // Redis tabanlı oturum doğrulama middleware
    app.UseMiddleware<SessionValidationMiddleware>();

    app.MapControllerRoute(
        name: "default",
        pattern: "{controller=Home}/{action=Index}/{id?}");

    app.Run();
}
catch (Exception ex)
{
    logger.Error(ex, "An error occurred during application startup");
    throw;
}
finally
{
    LogManager.Shutdown();
}
