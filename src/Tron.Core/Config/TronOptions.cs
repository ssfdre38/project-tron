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
    public EmailOptions Email { get; set; } = new();
    public WebhookOptions Webhook { get; set; } = new();
    public ThreatIntelOptions ThreatIntel { get; set; } = new();
    public FileIntegrityOptions FileIntegrity { get; set; } = new();
    public CorrelationOptions Correlation { get; set; } = new();
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
    /// <summary>Port for the embedded HTTP dashboard.</summary>
    public int Port { get; set; } = 18790;
    /// <summary>
    /// Bind address for the dashboard HTTP listener.
    /// Default: 127.0.0.1 (localhost only — safe default).
    /// Use 0.0.0.0 to allow access from other machines on your network.
    /// </summary>
    public string BindAddress { get; set; } = "127.0.0.1";
    /// <summary>
    /// Optional public/LAN URL where this dashboard is reachable from outside the machine.
    /// Example: http://192.168.1.100:18790
    /// When set, Discord alerts that require approval will include a direct link to
    /// the dashboard so you can approve or deny from your phone/browser.
    /// </summary>
    public string? ExternalUrl { get; set; }
}

public class EmailOptions
{
    /// <summary>Set to true to enable email alerting via SMTP.</summary>
    public bool Enabled { get; set; } = false;
    public string SmtpHost { get; set; } = "smtp.gmail.com";
    public int SmtpPort { get; set; } = 587;
    public bool UseSsl { get; set; } = true;
    public string Username { get; set; } = "";
    public string Password { get; set; } = "";
    public string FromAddress { get; set; } = "tron@example.com";
    public string FromName { get; set; } = "Tron Guardian";
    public List<string> ToAddresses { get; set; } = [];
    /// <summary>Minimum severity level to send email for.</summary>
    public string MinSeverity { get; set; } = "Warning";
}

public class WebhookOptions
{
    /// <summary>Set to true to enable generic webhook alerting (Slack, Teams, PagerDuty, etc.).</summary>
    public bool Enabled { get; set; } = false;
    /// <summary>HTTP POST target URL.</summary>
    public string Url { get; set; } = "";
    /// <summary>Optional Authorization header value (e.g. "Bearer token123").</summary>
    public string? AuthHeader { get; set; }
    /// <summary>Minimum severity level to POST for.</summary>
    public string MinSeverity { get; set; } = "Warning";
    /// <summary>Include the full system snapshot in the webhook payload.</summary>
    public bool IncludeSnapshot { get; set; } = false;
}

public class ThreatIntelOptions
{
    /// <summary>Enable threat intelligence IP reputation checks.</summary>
    public bool Enabled { get; set; } = true;
    /// <summary>
    /// Path to a JSON blocklist file. Defaults to the built-in list shipped with Tron.
    /// Supply your own to extend or replace it.
    /// </summary>
    public string BlocklistPath { get; set; } = "";
    /// <summary>
    /// Optional AbuseIPDB API key for dynamic reputation lookups.
    /// Free tier: 1,000 checks/day. Leave blank to use local blocklist only.
    /// Get a free key at https://www.abuseipdb.com/
    /// </summary>
    public string AbuseIpDbApiKey { get; set; } = "";
    /// <summary>Only alert if AbuseIPDB confidence score meets this threshold (0-100).</summary>
    public int AbuseIpDbMinScore { get; set; } = 75;
    /// <summary>Cache AbuseIPDB results for this many minutes (reduces API usage).</summary>
    public int AbuseIpDbCacheDurationMinutes { get; set; } = 1440;
}

public class FileIntegrityOptions
{
    /// <summary>Enable File Integrity Monitoring. Hashes critical system files on first run, alerts on change.</summary>
    public bool Enabled { get; set; } = true;
    /// <summary>
    /// Additional directories to watch recursively (beyond built-in critical-file lists).
    /// Example: ["/etc/nginx/", "C:\\inetpub\\wwwroot"]
    /// </summary>
    public List<string> WatchDirectories { get; set; } = [];
    /// <summary>Additional individual files to monitor (full paths).</summary>
    public List<string> WatchFiles { get; set; } = [];
}

public class CorrelationOptions
{
    /// <summary>Enable the cross-monitor correlation engine.</summary>
    public bool Enabled { get; set; } = true;
    /// <summary>
    /// Sliding window in minutes. Alerts from different monitors that fall within this
    /// window are evaluated as a group against correlation rules.
    /// </summary>
    public int WindowMinutes { get; set; } = 5;
}

