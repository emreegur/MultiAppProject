public class LogEntry
{
    public int Id { get; set; }
    public DateTime Timestamp { get; set; }
    public string? Level { get; set; }                // Log seviyesi: Info, Warn, Error vs.
    public string? Username { get; set; }
    public string? Message { get; set; }              // giriş mi yaptı çıkış mı falan
    
    public string? IPAddress { get; set; }
}
