using Microsoft.EntityFrameworkCore;
using MyNewApiProject.Models;

namespace MyNewApiProject.Data
{
    public class KullaniciDepoContext : DbContext
    {
        public KullaniciDepoContext(DbContextOptions<KullaniciDepoContext> options) : base(options)
        {
        }

        public DbSet<Kullanici> Kullanicilar { get; set; }
        public DbSet<LogEntry> LogEntries { get; set; }
        public DbSet<Role> Role { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<Kullanici>().ToTable("Kullanicilar");
            modelBuilder.Entity<LogEntry>().ToTable("LogEntries");
            modelBuilder.Entity<Role>().ToTable("Roles");

            modelBuilder.Entity<Kullanici>()
                .HasOne(k => k.Role)
                .WithMany()
                .HasForeignKey(k => k.RoleId)
                .OnDelete(DeleteBehavior.SetNull);
        }
    }
}