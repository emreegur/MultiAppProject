using System.ComponentModel.DataAnnotations;

namespace MyNewApiProject.Models
{
    public class Kullanici
    {
        [Key]
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

    public class Role
    {
        public int Id { get; set; }
        public required string RoleName { get; set; }
    }
}
