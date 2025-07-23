using System.Diagnostics;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using MyWebApp.Models;
using Newtonsoft.Json;
using NLog;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;
using Microsoft.Extensions.Configuration;
using Hangfire;
using MyWebApp.Entities;
using StackExchange.Redis;
using Microsoft.AspNetCore.HttpOverrides; // UseForwardedHeaders için gerekebilir
using System.Linq;

namespace MyWebApp.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly HttpClient _httpClient;
        private static readonly NLog.Logger nlogLogger = LogManager.GetCurrentClassLogger();

        public HomeController(ILogger<HomeController> logger, IConfiguration configuration, IHttpClientFactory httpClientFactory)
        {
            _logger = logger;
            _httpClientFactory = httpClientFactory;
            _httpClient = _httpClientFactory.CreateClient();

            var apiBaseUrl = configuration["ApiSettings:BaseUrl"] ?? "http://localhost:5270/";
            _httpClient.BaseAddress = new Uri(apiBaseUrl);
        }

        // Gerçek client IP'si alma metodu
        private string GetClientIp()
        {
            var forwardedFor = HttpContext.Request.Headers["X-Forwarded-For"].FirstOrDefault();
            if (!string.IsNullOrEmpty(forwardedFor))
            {
                return forwardedFor.Split(',').First().Trim();
            }
            return HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        }

        public IActionResult Index()
        {
            RecurringJob.AddOrUpdate("KullaniciGuncelle", () => KullaniciListesiGuncelle(), Cron.Minutely);
            RecurringJob.AddOrUpdate("LogGuncelle", () => LoglariGuncelle(), Cron.Minutely);

            return View();
        }

        [HttpPost]
[ValidateAntiForgeryToken]
public async Task<IActionResult> Login(LoginModel model)
{
    if (!ModelState.IsValid)
    {
        ViewBag.LoginError = "Lütfen tüm alanları doldurun.";
        return View("Index");
    }

    var loginDto = new LoginDto { Email = model.Email, Sifre = model.Sifre };
    var json = JsonConvert.SerializeObject(loginDto);
    var content = new StringContent(json, Encoding.UTF8, "application/json");

    var response = await _httpClient.PostAsync("api/auth/login", content);
    var username = model.Email ?? "unknown";
    var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    if (ipAddress == "::1") ipAddress = "127.0.0.1";

    using (NLog.ScopeContext.PushProperty("Username", username))
    using (NLog.ScopeContext.PushProperty("IPAddress", ipAddress))
    {
        if (response.IsSuccessStatusCode)
        {
            var responseBody = await response.Content.ReadAsStringAsync();
            var loginResult = JsonConvert.DeserializeObject<LoginResponse>(responseBody);

            if (loginResult?.Token != null)
            {
                TempData["ShowWelcomePopup"] = "true";

                var logMessage = $"User {username} logged in from IP {ipAddress}";
                nlogLogger.Info(logMessage);
                BackgroundJob.Enqueue(() => LogToApiHangfire("Info", logMessage, username, ipAddress));

                var claims = new[] { new Claim(ClaimTypes.Name, username) };
                var identity = new ClaimsIdentity(claims, "CookieAuth");
                var principal = new ClaimsPrincipal(identity);
                await HttpContext.SignInAsync("CookieAuth", principal);

                Response.Cookies.Append("AuthToken", loginResult.Token, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.Strict
                });

                var sessionKey = Guid.NewGuid().ToString();
                HttpContext.Session.SetString("Username", username);
                HttpContext.Session.SetString("SessionKey", sessionKey);
                var redis = ConnectionMultiplexer.Connect("localhost:6379");
                var db = redis.GetDatabase();
                await db.StringSetAsync(username, sessionKey);

                return RedirectToAction("Dashboard");
            }

            ViewBag.LoginError = "Token alınamadı.";
            return View("Index");
        }

        string apiError = await response.Content.ReadAsStringAsync();
        nlogLogger.Warn("Login failed. API response: {0}", apiError);
        ViewBag.LoginError = apiError;
        await LogToApi("Warn", $"Login failed from IP {ipAddress}. API response: {apiError}", username, ipAddress);
        return View("Index");
    }
}

        [HttpPost]
[ValidateAntiForgeryToken]
public async Task<IActionResult> LogOut()
{
    var username = User.Identity?.Name ?? "unknown";
    var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    if (ipAddress == "::1") ipAddress = "127.0.0.1";

    using (NLog.ScopeContext.PushProperty("Username", username))
    using (NLog.ScopeContext.PushProperty("IPAddress", ipAddress))
    {
        nlogLogger.Info("User '{Username}' with IP {IPAddress} logged out.");
        await LogToApi("Info", $"User {username} with IP {ipAddress} logged out.", username, ipAddress);
    }

    AttachJwtFromCookie();
    var response = await _httpClient.PostAsync("api/auth/logout", null);

    HttpContext.Session.Clear();
    await HttpContext.SignOutAsync("CookieAuth");
    Response.Cookies.Delete("AuthToken");

    TempData["Message"] = "Çıkış yapıldı.";
    return RedirectToAction("Index");
}

        [HttpPost]
        [Authorize]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> AddUser(Kullanici user)
        {
            AttachJwtFromCookie();

            var username = User.Identity?.Name ?? "unknown";
            var ipAddress = GetClientIp();

            using (NLog.ScopeContext.PushProperty("Username", username))
            {
                if (!ModelState.IsValid)
                {
                    TempData["ErrorMessage"] = "Tüm alanları doğru doldurun.";
                    return RedirectToAction("Users");
                }

                var json = JsonConvert.SerializeObject(user);
                var content = new StringContent(json, Encoding.UTF8, "application/json");

                var response = await _httpClient.PostAsync("api/auth/kullanicilar", content);

                if (response.IsSuccessStatusCode)
                {
                    TempData["SuccessMessage"] = "Kullanıcı eklendi.";
                    await LogToApi("Info", $"User {username} added user {user.Eposta}", username, ipAddress);
                }
                else
                {
                    var apiError = await response.Content.ReadAsStringAsync();
                    TempData["ErrorMessage"] = apiError;
                    await LogToApi("Warn", $"Failed to add user. API: {apiError}", username, ipAddress);
                }

                return RedirectToAction("Users");
            }
        }

        private async Task LogToApi(string level, string message, string username, string? ipAddress)
        {
            var logDto = new LogDto
            {
                Level = level,
                Message = message,
                Username = username,
                IpAddress = ipAddress
            };

            var json = JsonConvert.SerializeObject(logDto);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            try
            {
                await _httpClient.PostAsync("api/auth/log", content);
            }
            catch (Exception ex)
            {
                nlogLogger.Error(ex, "Failed to send log to API.");
            }
        }

        [Authorize]
        public IActionResult Dashboard() => View();

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
[AllowAnonymous]
[ValidateAntiForgeryToken]
public async Task<IActionResult> Register(RegisterModel model)
{
    if (!ModelState.IsValid)
        return View(model);
    
    try
            {
                var json = JsonConvert.SerializeObject(model);
                var content = new StringContent(json, Encoding.UTF8, "application/json");

                var response = await _httpClient.PostAsync("api/auth/register", content);

                if (response.IsSuccessStatusCode)
                {
                    TempData["SuccessMessage"] = "Kayıt başarılı!";
                    return RedirectToAction("Index");
                }
                else
                {
                    var error = await response.Content.ReadAsStringAsync();
                    ModelState.AddModelError(string.Empty, $"Kayıt başarısız: {error}");
                }
            }
            catch (Exception ex)
            {
                ModelState.AddModelError(string.Empty, $"Hata oluştu: {ex.Message}");
            }

    return View(model);
}


        [Authorize]
        public async Task<IActionResult> Logs()
        {
            AttachJwtFromCookie();

            var viewModel = new UserAndLogViewModel
            {
                Users = new List<Kullanici>(),
                Logs = new List<LogEntry>(),
                Roles = new List<MyWebApp.Entities.Role>()
            };

            var response = await _httpClient.GetAsync("api/auth/logs");

            if (response.IsSuccessStatusCode)
            {
                var json = await response.Content.ReadAsStringAsync();
                viewModel.Logs = JsonConvert.DeserializeObject<List<LogEntry>>(json) ?? new List<LogEntry>();

            }
            else
            {
                TempData["ErrorMessage"] = "Loglar yüklenemedi.";
            }

            return View(viewModel);
        }

        [Authorize]
        public async Task<IActionResult> Users()
        {
            AttachJwtFromCookie();

            var viewModel = new UserAndLogViewModel
            {
                Users = new List<Kullanici>(),
                Logs = new List<LogEntry>(),
                Roles = new List<MyWebApp.Entities.Role>()
            };

            var responseRoles = await _httpClient.GetAsync("api/auth/roles");
            if (responseRoles.IsSuccessStatusCode)
            {
                var jsonRoles = await responseRoles.Content.ReadAsStringAsync();
                viewModel.Roles = JsonConvert.DeserializeObject<List<MyWebApp.Entities.Role>>(jsonRoles) ?? new List<MyWebApp.Entities.Role>();

            }

            var responseUsers = await _httpClient.GetAsync("api/auth/kullanicilar");
            if (responseUsers.IsSuccessStatusCode)
            {
                var jsonUsers = await responseUsers.Content.ReadAsStringAsync();
                var users = JsonConvert.DeserializeObject<List<Kullanici>>(jsonUsers);

                if (users != null)
                {
                    foreach (var user in users)
                    {
                        if (user.RoleId.HasValue)
                            user.Role = viewModel.Roles.FirstOrDefault(r => r.Id == user.RoleId);
                    }

                    viewModel.Users = users;
                }
            }

            return View(viewModel);
        }

        [HttpPost]
        [Authorize]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> UpdateUser(Kullanici user)
        {
            AttachJwtFromCookie();

            var json = JsonConvert.SerializeObject(user);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            var response = await _httpClient.PutAsync($"api/auth/kullanicilar/{user.Id}", content);

            if (response.IsSuccessStatusCode)
            {
                TempData["SuccessMessage"] = "Kullanıcı güncellendi.";
            }
            else
            {
                var apiError = await response.Content.ReadAsStringAsync();
                TempData["ErrorMessage"] = apiError;
            }

            return RedirectToAction("Users");
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        private void AttachJwtFromCookie()
        {
            var token = Request.Cookies["AuthToken"];
            if (!string.IsNullOrEmpty(token) && _httpClient.DefaultRequestHeaders.Authorization == null)
            {
                _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            }
        }

        [NonAction]
        public void KullaniciListesiGuncelle()
        {
            nlogLogger.Info("Kullanıcı listesi güncelleme işi tetiklendi.");
        }

        [NonAction]
        public void LoglariGuncelle()
        {
            nlogLogger.Info("Loglar güncelleme işi tetiklendi.");
        }

        public static async Task LogToApiHangfire(string level, string message, string username, string? ipAddress)
        {
            using var httpClient = new HttpClient();
            httpClient.BaseAddress = new Uri("http://localhost:5270/");
            var logDto = new LogDto { Level = level, Message = message, Username = username, IpAddress = ipAddress };
            var json = JsonConvert.SerializeObject(logDto);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            try
            {
                await httpClient.PostAsync("api/auth/log", content);
            }
            catch (Exception ex)
            {
                LogManager.GetCurrentClassLogger().Error(ex, "Hangfire log gönderim hatası");
            }
        }

        public class LoginDto
        {
            public string? Email { get; set; }
            public string? Sifre { get; set; }
        }

        public class LogDto
        {
            public string? Level { get; set; }
            public string? Message { get; set; }
            public string? Username { get; set; }
            public string? IpAddress { get; set; }
        }

        public class LoginResponse
        {
            public string? Token { get; set; }
            public int Id { get; set; }
            public string? Ad { get; set; }
            public string? Email { get; set; }
        }
    }
}
