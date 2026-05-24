using Tron.Core.Interfaces;
using Tron.Core.Models;

namespace Tron.Monitors.Monitors;

/// <summary>
/// Monitors system security events for suspicious authentication activity.
/// Works with Windows Security event log, Linux auth.log, and journald.
/// </summary>
public sealed class SecurityEventMonitor : IMonitor
{
    public string Name => "SecurityEvent";

    private const int FailedLoginThreshold = 5;

    // Windows event IDs and Linux equivalents that indicate failed logins
    private static readonly HashSet<string> FailedLoginEventIds = new(StringComparer.OrdinalIgnoreCase)
    {
        "4625",         // Windows: An account failed to log on
        "failed_login", // Linux: auth.log / journald
        "ssh_warning"   // Linux: SSH failed attempt via journald
    };

    // Windows event IDs for audit/policy changes
    private static readonly HashSet<string> AuditChangeEventIds = new(StringComparer.OrdinalIgnoreCase)
    {
        "4719"  // Windows: System audit policy was changed
    };

    public Task<IEnumerable<Alert>> CheckAsync(SystemSnapshot snapshot, CancellationToken ct = default)
    {
        var alerts = new List<Alert>();

        var failedLogins = snapshot.RecentSecurityEvents
            .Where(e => FailedLoginEventIds.Contains(e.EventId))
            .ToList();

        if (failedLogins.Count >= FailedLoginThreshold)
        {
            alerts.Add(new Alert
            {
                Severity         = AlertSeverity.Critical,
                Category         = AlertCategory.Security,
                Title            = "Possible Brute-Force Attack",
                Message          = $"{failedLogins.Count} failed login attempts detected in the last hour.",
                SuggestedAction  = BlockIpSuggestion(),
                RequiresApproval = true
            });
        }
        else if (failedLogins.Count > 0)
        {
            alerts.Add(new Alert
            {
                Severity  = AlertSeverity.Warning,
                Category  = AlertCategory.Security,
                Title     = "Failed Login Attempts",
                Message   = $"{failedLogins.Count} failed login attempt(s) detected in the last hour."
            });
        }

        // Audit / policy changes are always critical
        var auditChanges = snapshot.RecentSecurityEvents
            .Where(e => AuditChangeEventIds.Contains(e.EventId))
            .ToList();

        if (auditChanges.Count > 0)
            alerts.Add(new Alert
            {
                Severity        = AlertSeverity.Critical,
                Category        = AlertCategory.Security,
                Title           = "Audit Policy Changed",
                Message         = "System audit policy was modified — this could indicate an attacker covering their tracks.",
                SuggestedAction = "Review the security event log immediately.",
                RequiresApproval = false
            });

        return Task.FromResult<IEnumerable<Alert>>(alerts);
    }

    private static string BlockIpSuggestion()
    {
        if (OperatingSystem.IsWindows()) return "Review Security event log and consider blocking the source IP via Windows Firewall.";
        if (OperatingSystem.IsMacOS())   return "Review /var/log/system.log and consider blocking via pfctl or Little Snitch.";
        return "Review auth.log/journald and consider blocking the source IP via ufw/iptables or fail2ban.";
    }
}
