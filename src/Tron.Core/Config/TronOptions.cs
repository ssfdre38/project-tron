namespace Tron.Core.Config;

public class TronOptions
{
    public const string Section = "Tron";

    public int CollectionIntervalSeconds { get; set; } = 30;

    public ThresholdOptions Thresholds { get; set; } = new();
    public WatchedServicesOptions WatchedServices { get; set; } = new();
    public AlertingOptions Alerting { get; set; } = new();
}

public class ThresholdOptions
{
    public float CpuWarningPercent { get; set; } = 80f;
    public float CpuCriticalPercent { get; set; } = 95f;
    public float MemoryWarningPercent { get; set; } = 80f;
    public float MemoryCriticalPercent { get; set; } = 95f;
    public float DiskWarningPercent { get; set; } = 85f;
    public float DiskCriticalPercent { get; set; } = 95f;
}

public class WatchedServicesOptions
{
    /// <summary>Windows service names to track specifically (e.g. "ash-server", "W3SVC").</summary>
    public List<string> Names { get; set; } = [];
}

public class AlertingOptions
{
    /// <summary>Discord webhook URL for alert delivery.</summary>
    public string? DiscordWebhookUrl { get; set; }
    /// <summary>Minimum severity to send alerts for.</summary>
    public string MinSeverity { get; set; } = "Warning";
}
