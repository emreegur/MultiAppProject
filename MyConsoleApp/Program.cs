using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Hangfire;
using Hangfire.MemoryStorage;

class Program
{
    public class Kullanici
    {
        public int id { get; set; }
        public string? isim { get; set; }
        public string? eposta { get; set; }
    }

    public class LogEntry
    {
        public string? level { get; set; }
        public string? message { get; set; }
        public string? username { get; set; }
        public DateTime createdAt { get; set; }
    }

    public class LogDto
    {
        public string? Level { get; set; }
        public string? Message { get; set; }
        public string? Username { get; set; }
    }

    static string? _token;
    static string? _email;
    static readonly HttpClient client = new HttpClient();

    static async Task Main(string[] args)
    {
        Console.Write("Email girin: ");
        string? emailInput = Console.ReadLine();
        Console.Write("Şifre girin: ");
        string? sifreInput = Console.ReadLine();

        if (string.IsNullOrWhiteSpace(emailInput) || string.IsNullOrWhiteSpace(sifreInput))
        {
            Console.WriteLine("❌ Email veya şifre boş olamaz.");
            return;
        }

        var loginData = new { email = emailInput, sifre = sifreInput };
        var json = JsonSerializer.Serialize(loginData);
        var content = new StringContent(json, Encoding.UTF8, "application/json");

        try
        {
            var loginResponse = await client.PostAsync("http://localhost:5270/api/auth/login", content);
            var loginJson = await loginResponse.Content.ReadAsStringAsync();

            if (!loginResponse.IsSuccessStatusCode)
            {
                Console.WriteLine("❌ Giriş başarısız.");
                Console.WriteLine(loginJson);
                return;
            }

            using JsonDocument doc = JsonDocument.Parse(loginJson);
            if (!doc.RootElement.TryGetProperty("token", out var tokenProp))
            {
                Console.WriteLine("❌ Token alınamadı.");
                return;
            }

            _token = tokenProp.GetString();
            _email = doc.RootElement.TryGetProperty("isim", out var emailProp) ? emailProp.GetString() : "bilinmiyor";

            Console.WriteLine($"\n✅ Hoş geldin, {_email}");
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _token);

            // Logla
            await LogEkle("Info", "Console App üzerinden giriş yapıldı.", _email!);

            
            // Hangfire başlat
            GlobalConfiguration.Configuration.UseMemoryStorage();
            using var server = new BackgroundJobServer();

            RecurringJob.AddOrUpdate("kullanicilar", () => KullaniciListesiCek(), "*/2 * * * *");     // çift dakikalar
            RecurringJob.AddOrUpdate("loglar", () => LoglariCek(), "1-59/2 * * * *");               // tek dakikalar

            Console.WriteLine("\n⏳ Arka plan işleri başladı. Çıkmak için ENTER'a bas.");
            Console.ReadLine();

        }
        catch (Exception ex)
        {
            Console.WriteLine("❌ Hata: " + ex.Message);
        }
    }

    public static async Task KullaniciListesiCek()
    {
        if (string.IsNullOrEmpty(_token)) return;

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _token);
        var response = await client.GetAsync("http://localhost:5270/api/auth/kullanicilar");
        var json = await response.Content.ReadAsStringAsync();

        if (response.IsSuccessStatusCode)
        {
            var kullanicilar = JsonSerializer.Deserialize<List<Kullanici>>(json);
            Console.WriteLine($"\n🕐 {DateTime.Now:HH:mm:ss} - Kullanıcılar:");
            foreach (var k in kullanicilar!)
                Console.WriteLine($"🆔 {k.id} | 👤 {k.isim} | 📧 {k.eposta}");
        }
        else
        {
            Console.WriteLine("❌ Kullanıcılar çekilemedi:");
            Console.WriteLine(json);
        }
    }

    public static async Task LoglariCek()
    {
        if (string.IsNullOrEmpty(_token)) return;

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _token);
        var response = await client.GetAsync("http://localhost:5270/api/auth/logs");
        var json = await response.Content.ReadAsStringAsync();

        if (response.IsSuccessStatusCode)
        {
            var logs = JsonSerializer.Deserialize<List<LogEntry>>(json);
            Console.WriteLine($"\n🕐 {DateTime.Now:HH:mm:ss} - Loglar:");
            foreach (var log in logs!)
                Console.WriteLine($"[{log.createdAt:HH:mm}] {log.level} - {log.username}: {log.message}");
        }
        else
        {
            Console.WriteLine("❌ Loglar çekilemedi:");
            Console.WriteLine(json);
        }
    }

    public static async Task LogEkle(string level, string message, string username)
    {
        var log = new LogDto
        {
            Level = level,
            Message = message,
            Username = username
        };

        var json = JsonSerializer.Serialize(log);
        var content = new StringContent(json, Encoding.UTF8, "application/json");

        try
        {
            var response = await client.PostAsync("http://localhost:5270/api/auth/log", content);
            if (response.IsSuccessStatusCode)
            {
                Console.WriteLine($"📤 Log eklendi: {message}");
            }
            else
            {
                Console.WriteLine("❌ Log eklenemedi:");
                Console.WriteLine(await response.Content.ReadAsStringAsync());
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Log gönderimi hatası: {ex.Message}");
        }
    }
}
