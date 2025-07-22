using MyWebApp.Entities;

namespace MyWebApp.Entities
{
    public class Kullanici
    {
       public int Id { get; set; }
        public string? Isim { get; set; }
        public string? Soyisim { get; set; }
        public string? Eposta { get; set; }
        public string? KullaniciAdi { get; set; }
        public string? Sifre { get; set; }
        public DateTime KayitTarihi { get; set; }


        
        public int? RoleId { get; set; }
        public Role? Role { get; set; }
    }

    public class LogEntry
    {
        public int Id { get; set; }
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
        public required string Level { get; set; }
        public required string Username { get; set; }
        public required string Message { get; set; }
    }
}
