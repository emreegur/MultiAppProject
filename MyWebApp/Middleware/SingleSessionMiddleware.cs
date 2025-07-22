using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using StackExchange.Redis;
using System.Threading.Tasks;

namespace MyWebApp.Middlewares
{
    public class SessionValidationMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ConnectionMultiplexer _redis;

        public SessionValidationMiddleware(RequestDelegate next)
        {
            _next = next;
            _redis = ConnectionMultiplexer.Connect("localhost:6379");
        }

        public async Task Invoke(HttpContext context)
        {
            var username = context.Session.GetString("Username");
            var currentSessionKey = context.Session.GetString("SessionKey");

            if (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(currentSessionKey))
            {
                var db = _redis.GetDatabase();
                var storedSessionKey = await db.StringGetAsync(username);

                if (storedSessionKey.HasValue && storedSessionKey != currentSessionKey)
                {
                    // Oturum geçersiz: session temizle, cookie auth çıkışı yap, yönlendir
                    context.Session.Clear();
                    await context.SignOutAsync(); // 👈 Cookie oturumu da bitir
                    context.Response.Redirect("/Home/Index?expired=true");
                    return;
                }
            }

            await _next(context);
        }
    }
}
