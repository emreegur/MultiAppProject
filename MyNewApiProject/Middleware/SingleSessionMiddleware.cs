using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Distributed;
using System.IdentityModel.Tokens.Jwt;
using System.Threading.Tasks;

public class SingleSessionMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IDistributedCache _cache;

    public SingleSessionMiddleware(RequestDelegate next, IDistributedCache cache)
    {
        _next = next;
        _cache = cache;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var token = context.Request.Headers["Authorization"].ToString().Replace("Bearer ", "");
        if (string.IsNullOrEmpty(token))
            token = context.Request.Cookies["auth_token"];

        if (!string.IsNullOrEmpty(token))
        {
            var (userId, jti) = GetUserIdAndJtiFromToken(token);
            if (userId.HasValue && !string.IsNullOrEmpty(jti))
            {
                var cacheKey = $"session:{userId.Value}";
                var storedJti = await _cache.GetStringAsync(cacheKey);

                if (storedJti != jti)
                {
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsync("Invalid or expired session.");
                    return;
                }
            }
            else
            {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsync("Invalid token.");
                return;
            }
        }

        await _next(context);
    }

    private (int? userId, string? jti) GetUserIdAndJtiFromToken(string token)
    {
        try
        {
            var handler = new JwtSecurityTokenHandler();
            var jwtToken = handler.ReadJwtToken(token);
            var userIdClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == "UserId");
            var jtiClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Jti);
            return (userIdClaim != null ? int.Parse(userIdClaim.Value) : null, jtiClaim?.Value);
        }
        catch
        {
            return (null, null);
        }
    }
}