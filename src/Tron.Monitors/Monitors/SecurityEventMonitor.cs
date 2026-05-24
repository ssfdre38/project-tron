using Tron.Core.Interfaces;
using Tron.Core.Models;

namespace Tron.Monitors.Monitors;

/// <summary>Monitors Windows Security event log for suspicious authentication activity.</summary>
public sealed class SecurityEventMonitor : IMonitor
{
    public string Name => "SecurityEvent";

    // Group rapid repeated failures as a single alert
    private const int FailedLoginThreshold = 5;

    public Task<IEnumerable<Alert>> CheckAsync(SystemSnapshot snapshot, CancellationToken ct = default)
    {
        var alerts = new List<Alert>();

        var failedLogins = snapshot.RecentSecurityEvents
            .Where(e => e.EventId == "4625")
            .ToList();

        if (failedLogins.Count >= FailedLoginThreshold)
        {
            alerts.Add(new Alert
            {
                Severity = AlertSeverity.Critical,
                Category = AlertCategory.Security,
                Title = "Possible Brute-Force Attack",
                Message = $"{failedLogins.Count} failed login attempts detected in the last hour.",
                SuggestedAction = "Review Security event log and consider blocking the source IP via Windows Firewall.",
                RequiresApproval = true
            });
        }
        else if (failedLogins.Count > 0)
        {
            alerts.Add(new Alert
            {
                Severity = AlertSeverity.Warning,
                Category = AlertCategory.Security,
                Title = "Failed Login Attempts",
                Message = $"{failedLogins.Count} failed login attempt(s) detected in the last hour."
            });
        }

        // Audit policy change (4719) is always critical
        var auditChanges = snapshot.RecentSecurityEvents.Where(e => e.EventId == "4719").ToList();
        if (auditChanges.Count > 0)
            alerts.Add(new Alert
            {
                Severity = AlertSeverity.Critical,
                Category = AlertCategory.Security,
                Title = "Audit Policy Changed",
                Message = "Windows audit policy was modified — this could indicate an attacker covering their tracks.",
                SuggestedAction = "Review Security event log immediately.",
                RequiresApproval = false
            });

        return Task.FromResult<IEnumerable<Alert>>(alerts);
    }
}
