namespace Tron.Core.Config;

public class TronOptions
{
    public const string Section = "Tron";

    public int CollectionIntervalSeconds { get; set; } = 30;

    public ThresholdOptions Thresholds { get; set; } = new();
    public WatchedServicesOptions WatchedServices { get; set; } = new();
    public AlertingOptions Alerting { get; set; } = new();
    public BaselineOptions Baseline { get; set; } = new();
    public AiOptions Ai { get; set; } = new();
    public DashboardOptions Dashboard { get; set; } = new();
}

public class ThresholdOptions
{
    public float CpuWarningPercent { get; set; } = 80f;
    public float CpuCriticalPercent { get; set; } = 95f;
    public float MemoryWarningPercent { get; set; } = 80f;
    public float MemoryCriticalPercent { get; set; } = 95f;
    public float DiskWarningPercent { get; set; } = 85f;
    public float DiskCriticalPercent { get; set; } = 95f;
    /// <summary>Z-score threshold above which a metric is considered anomalous.</summary>
    public double AnomalyZScoreThreshold { get; set; } = 3.0;
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
    /// <summary>Alert cooldown in minutes to suppress duplicate alerts.</summary>
    public int CooldownMinutes { get; set; } = 15;
}

public class BaselineOptions
{
    /// <summary>Path to persist the baseline JSON file.</summary>
    public string StorePath { get; set; } = "tron-baseline.json";
    /// <summary>How often to save the baseline to disk (in minutes).</summary>
    public int SaveIntervalMinutes { get; set; } = 5;
    /// <summary>Whether to alert on anomalies detected via baseline deviation.</summary>
    public bool EnableAnomalyDetection { get; set; } = true;
}

public class AiOptions
{
    /// <summary>
    /// Base URL of the local AI endpoint (e.g. an ash-server or OpenAI-compatible server).
    /// Leave empty to disable AI analysis.
    /// </summary>
    public string? EndpointUrl { get; set; }
    /// <summary>Model name to request from the endpoint.</summary>
    public string Model { get; set; } = "gemma4-nano";
    /// <summary>Only invoke AI analysis for alerts at or above this severity.</summary>
    public string MinSeverityForAnalysis { get; set; } = "Warning";
}

public class DashboardOptions
{
    /// <summary>Whether to serve the local web dashboard.</summary>
    public bool Enabled { get; set; } = true;
    /// <summary>Port for the embedded HTTP dashboard (localhost only).</summary>
    public int Port { get; set; } = 18790;
}
