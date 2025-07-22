using Microsoft.EntityFrameworkCore;
using MyWebApp.Entities;

public class KullaniciDepoContext : DbContext
{
    public KullaniciDepoContext(DbContextOptions<KullaniciDepoContext> options) : base(options)
    {
    }

    public DbSet<Kullanici> Kullanicilar { get; set; }
    public DbSet<LogEntry> LogEntries { get; set; }
    public DbSet<Role> Role { get; set; }

    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        if (!optionsBuilder.IsConfigured)
        {
            optionsBuilder.UseSqlServer(
                "Server=localhost;Database=DenemeDb;User Id=sa;Password=YourStrong!Passw0rd;TrustServerCertificate=True;",
                options => options.EnableRetryOnFailure());
        }
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<Kullanici>().ToTable("Kullanicilar");
        modelBuilder.Entity<LogEntry>().ToTable("LogEntries");
        modelBuilder.Entity<Role>().ToTable("Role");

        modelBuilder.Entity<Kullanici>()
            .HasOne(k => k.Role)
            .WithMany()
            .HasForeignKey(k => k.RoleId)
            .OnDelete(DeleteBehavior.SetNull); // Optional ilişki
    }
}