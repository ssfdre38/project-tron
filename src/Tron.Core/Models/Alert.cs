namespace Tron.Core.Models;

public record Alert
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.UtcNow;
    public AlertSeverity Severity { get; init; }
    public AlertCategory Category { get; init; }
    public string Title { get; init; } = "";
    public string Message { get; init; } = "";
    public string? SuggestedAction { get; init; }
    public bool RequiresApproval { get; init; }
    public bool Acknowledged { get; init; }
    /// <summary>MITRE ATT&amp;CK technique this alert maps to, if known.</summary>
    public MitreAttackInfo? MitreAttack { get; init; }
}

/// <summary>MITRE ATT&amp;CK technique reference attached to an alert.</summary>
public record MitreAttackInfo(
    string TechniqueId,
    string TechniqueName,
    string TacticName)
{
    public string Url => $"https://attack.mitre.org/techniques/{TechniqueId.Replace('.', '/')}/";
}

public enum AlertSeverity { Info, Warning, Critical }

public enum AlertCategory
{
    Cpu,
    Memory,
    Disk,
    Network,
    Service,
    Process,
    Security,
    Agent,
    ThreatIntel
}
