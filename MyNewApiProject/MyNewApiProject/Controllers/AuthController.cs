using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using MyNewApiProject.Data;
using MyNewApiProject.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Caching.Distributed;
using System.Text.Json;

namespace MyNewApiProject.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly KullaniciDepoContext _context;
        private readonly IConfiguration _configuration;
        private readonly IDistributedCache _cache;

        public AuthController(KullaniciDepoContext context, IConfiguration configuration, IDistributedCache cache)
        {
            _context = context;
            _configuration = configuration;
            _cache = cache;
        }

        // POST: api/auth/login
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto login)
        {
            if (login == null || string.IsNullOrEmpty(login.Email) || string.IsNullOrEmpty(login.Sifre))
                return BadRequest(new { message = "E-posta veya şifre boş olamaz." });

            var kullanici = await _context.Kullanicilar
                .FirstOrDefaultAsync(x => x.Eposta == login.Email && x.Sifre == login.Sifre);

            if (kullanici == null)
                return Unauthorized(new { message = "Geçersiz e-posta veya şifre." });

            // JWT Token oluştur
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!);
            var jti = Guid.NewGuid().ToString();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.Name, kullanici.KullaniciAdi!),
                    new Claim(ClaimTypes.Email, kullanici.Eposta!),
                    new Claim("UserId", kullanici.Id.ToString()),
                    new Claim("RoleId", kullanici.RoleId?.ToString() ?? ""),
                    new Claim(JwtRegisteredClaimNames.Jti, jti)
                }),
                Expires = DateTime.UtcNow.AddMinutes(Convert.ToDouble(_configuration["Jwt:ExpireMinutes"] ?? "60")),
                Issuer = _configuration["Jwt:Issuer"],
                Audience = _configuration["Jwt:Audience"],
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            var tokenString = tokenHandler.WriteToken(token);

            // Redis'e aktif oturumu kaydet
            var cacheKey = $"session:{kullanici.Id}";
            var cacheOptions = new DistributedCacheEntryOptions
            {
                AbsoluteExpiration = tokenDescriptor.Expires
            };
            await _cache.SetStringAsync(cacheKey, jti, cacheOptions);

            // Cache temizle
            await _cache.RemoveAsync("kullanicilar_list");

            // Token'ı HTTP-only cookie olarak set et
            Response.Cookies.Append("auth_token", tokenString, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Expires = tokenDescriptor.Expires
            });

            return Ok(new
            {
                Token = tokenString,
                kullanici.Id,
                kullanici.Isim,
                kullanici.Eposta
            });
        }

        // POST: api/auth/logout
        [Authorize]
        [HttpPost("logout")]
        public async Task<IActionResult> Logout()
        {
            var userIdClaim = User.FindFirst("UserId")?.Value;
            if (string.IsNullOrEmpty(userIdClaim) || !int.TryParse(userIdClaim, out var userId))
                return Unauthorized(new { message = "Geçersiz token." });

            // Redis'ten oturumu sil
            var cacheKey = $"session:{userId}";
            await _cache.RemoveAsync(cacheKey);

            // Cookie'yi sil
            Response.Cookies.Delete("auth_token");

            // Cache temizle
            await _cache.RemoveAsync("kullanicilar_list");

            return Ok(new { message = "Çıkış başarılı." });
        }

        // POST: api/auth/register
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto register)
        {
            if (register == null || string.IsNullOrEmpty(register.Eposta) || string.IsNullOrEmpty(register.KullaniciAdi) || string.IsNullOrEmpty(register.Sifre))
                return BadRequest(new { message = "E-posta, kullanıcı adı veya şifre boş olamaz." });

            if (await _context.Kullanicilar.AnyAsync(x => x.Eposta == register.Eposta))
                return BadRequest(new { message = "Bu e-posta zaten kayıtlı." });

            if (await _context.Kullanicilar.AnyAsync(x => x.KullaniciAdi == register.KullaniciAdi))
                return BadRequest(new { message = "Bu kullanıcı adı zaten alınmış." });

            var kullanici = new Kullanici
            {
                Isim = register.Isim,
                Soyisim = register.Soyisim,
                Eposta = register.Eposta,
                KullaniciAdi = register.KullaniciAdi,
                Sifre = register.Sifre, 
                KayitTarihi = DateTime.UtcNow,
                RoleId = 2
            };

            _context.Kullanicilar.Add(kullanici);
            await _context.SaveChangesAsync();

            await _cache.RemoveAsync("kullanicilar_list");

            return Ok(new { message = "Kullanıcı başarıyla eklendi.", kullanici.Id });
        }

        // GET: api/auth/kullanicilar
        [Authorize]
        [HttpGet("kullanicilar")]
        public async Task<IActionResult> GetKullanicilar()
        {
            string cacheKey = "kullanicilar_list";
            var cachedKullanicilar = await _cache.GetStringAsync(cacheKey);
            if (!string.IsNullOrEmpty(cachedKullanicilar))
            {
                var kullanicilarFromCache = JsonSerializer.Deserialize<List<Kullanici>>(cachedKullanicilar);
                return Ok(kullanicilarFromCache);
            }

            var kullanicilar = await _context.Kullanicilar
                .Include(k => k.Role)
                .ToListAsync();

            var serializedData = JsonSerializer.Serialize(kullanicilar);
            var options = new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(10)
            };
            await _cache.SetStringAsync(cacheKey, serializedData, options);

            return Ok(kullanicilar);
        }

        // GET: api/auth/kullanicilar/{id}
        [Authorize]
        [HttpGet("kullanicilar/{id}")]
        public async Task<IActionResult> GetKullaniciById(int id)
        {
            var kullanici = await _context.Kullanicilar
                .Include(k => k.Role)
                .FirstOrDefaultAsync(k => k.Id == id);

            if (kullanici == null)
                return NotFound(new { message = "Kullanıcı bulunamadı." });

            return Ok(kullanici);
        }

        // PUT: api/auth/kullanicilar/{id}
        [Authorize]
        [HttpPut("kullanicilar/{id}")]
        public async Task<IActionResult> UpdateKullanici(int id, [FromBody] Kullanici guncelKullanici)
        {
            if (id != guncelKullanici.Id)
                return BadRequest(new { message = "ID uyuşmuyor." });

            if (string.IsNullOrEmpty(guncelKullanici.Isim) || string.IsNullOrEmpty(guncelKullanici.Soyisim) ||
                string.IsNullOrEmpty(guncelKullanici.Eposta) || string.IsNullOrEmpty(guncelKullanici.KullaniciAdi))
                return BadRequest(new { message = "Tüm alanlar (İsim, Soyisim, E-posta, Kullanıcı Adı) zorunludur." });

            var mevcut = await _context.Kullanicilar.FindAsync(id);
            if (mevcut == null)
                return NotFound(new { message = "Kullanıcı bulunamadı." });

            if (await _context.Kullanicilar.AnyAsync(x => x.Eposta == guncelKullanici.Eposta && x.Id != id))
                return BadRequest(new { message = "Bu e-posta zaten kayıtlı." });

            if (await _context.Kullanicilar.AnyAsync(x => x.KullaniciAdi == guncelKullanici.KullaniciAdi && x.Id != id))
                return BadRequest(new { message = "Bu kullanıcı adı zaten alınmış." });

            mevcut.Isim = guncelKullanici.Isim;
            mevcut.Soyisim = guncelKullanici.Soyisim;
            mevcut.Eposta = guncelKullanici.Eposta;
            mevcut.KullaniciAdi = guncelKullanici.KullaniciAdi;
            mevcut.Sifre = string.IsNullOrEmpty(guncelKullanici.Sifre) ? mevcut.Sifre : guncelKullanici.Sifre;
            mevcut.RoleId = guncelKullanici.RoleId;

            await _context.SaveChangesAsync();

            await _cache.RemoveAsync("kullanicilar_list");

            return Ok(new { message = "Kullanıcı başarıyla güncellendi." });
        }

        // GET: api/auth/roles
        [Authorize]
        [HttpGet("roles")]
        public async Task<IActionResult> GetRoles()
        {
            var roles = await _context.Role.ToListAsync();
            return Ok(roles);
        }

        // GET: api/auth/roles/{id}
        [Authorize]
        [HttpGet("roles/{id}")]
        public async Task<IActionResult> GetRoleById(int id)
        {
            var role = await _context.Role.FindAsync(id);
            if (role == null)
                return NotFound(new { message = "Rol bulunamadı." });

            return Ok(role);
        }

        // POST: api/auth/kullanicilar
        [HttpPost("kullanicilar")]
        public async Task<IActionResult> AddKullanici([FromBody] Kullanici kullanici)
        {
            if (kullanici == null || string.IsNullOrEmpty(kullanici.Eposta) || string.IsNullOrEmpty(kullanici.KullaniciAdi) || string.IsNullOrEmpty(kullanici.Sifre))
                return BadRequest(new { message = "E-posta, kullanıcı adı veya şifre boş olamaz." });

            if (await _context.Kullanicilar.AnyAsync(x => x.Eposta == kullanici.Eposta))
                return BadRequest(new { message = "Bu e-posta zaten kayıtlı." });

            if (await _context.Kullanicilar.AnyAsync(x => x.KullaniciAdi == kullanici.KullaniciAdi))
                return BadRequest(new { message = "Bu kullanıcı adı zaten alınmış." });

            kullanici.KayitTarihi = DateTime.UtcNow;

            _context.Kullanicilar.Add(kullanici);
            await _context.SaveChangesAsync();

            await _cache.RemoveAsync("kullanicilar_list");

            return Ok(new { message = "Kullanıcı başarıyla eklendi.", kullanici.Id });
        }

        // POST: api/auth/log
        [HttpPost("log")]
        public async Task<IActionResult> Log([FromBody] LogDto log)
        {
            if (log == null || string.IsNullOrEmpty(log.Level) || string.IsNullOrEmpty(log.Message))
                return BadRequest(new { message = "Log seviyesi veya mesajı boş olamaz." });

            var entry = new LogEntry
            {
                Level = log.Level,
                Message = log.Message,
                Username = log.Username,
                Timestamp = DateTime.UtcNow
            };

            _context.LogEntries.Add(entry);
            await _context.SaveChangesAsync();

            return Ok(new { message = "Log kaydedildi." });
        }

        // GET: api/auth/logs
        [HttpGet("logs")]
        public IActionResult GetLogs()
        {
            var logs = _context.LogEntries.OrderByDescending(l => l.Timestamp).ToList();
            return Ok(logs);
        }

        // POST: api/auth/cache-set
        [HttpPost("cache-set")]
        public async Task<IActionResult> SetCache([FromQuery] string key, [FromBody] object value)
        {
            if (string.IsNullOrEmpty(key) || value == null)
                return BadRequest(new { message = "Key veya value boş olamaz." });

            var json = JsonSerializer.Serialize(value);
            var options = new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(5)
            };

            await _cache.SetStringAsync(key, json, options);

            return Ok(new { message = $"'{key}' anahtarı ile cache'e veri kaydedildi." });
        }

        // GET: api/auth/cache-get
        [HttpGet("cache-get")]
        public async Task<IActionResult> GetCache([FromQuery] string key)
        {
            if (string.IsNullOrEmpty(key))
                return BadRequest(new { message = "Key boş olamaz." });

            var cachedData = await _cache.GetStringAsync(key);
            if (cachedData == null)
                return NotFound(new { message = $"'{key}' anahtarı ile cache'te veri bulunamadı." });

            return Ok(new { key, value = cachedData });
        }

        // DELETE: api/auth/cache-remove
        [HttpDelete("cache-remove")]
        public async Task<IActionResult> RemoveCache([FromQuery] string key)
        {
            if (string.IsNullOrEmpty(key))
                return BadRequest(new { message = "Key boş olamaz." });

            await _cache.RemoveAsync(key);
            return Ok(new { message = $"'{key}' anahtarı cache'den kaldırıldı." });
        }

        // POST: api/auth/kullanicilar/cache/clear
        [HttpPost("kullanicilar/cache/clear")]
        public async Task<IActionResult> ClearKullanicilarCache()
        {
            await _cache.RemoveAsync("kullanicilar_list");
            return Ok(new { message = "Kullanıcı listesi cache'den temizlendi." });
        }
    }

    public class LoginDto
    {
        public string? Email { get; set; }
        public string? Sifre { get; set; }
    }

    public class RegisterDto
    {
        public string? Isim { get; set; }
        public string? Soyisim { get; set; }
        public string? Eposta { get; set; }
        public string? KullaniciAdi { get; set; }
        public string? Sifre { get; set; }
        public int? RoleId { get; set; }
    }

    public class LogDto
    {
        public string? Level { get; set; }
        public string? Message { get; set; }
        public string? Username { get; set; }

        
    }
}