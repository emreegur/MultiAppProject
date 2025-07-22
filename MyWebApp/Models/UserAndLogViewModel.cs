using MyWebApp.Entities;

namespace MyWebApp.Models
{
    public class UserAndLogViewModel
    {
        public required List<Kullanici> Users { get; set; }
        public required List<LogEntry> Logs { get; set; }
        public required List<Role> Roles { get; set; }
    }
}
