using Tron.Core.Interfaces;
using Tron.Core.Models;

namespace Tron.Monitors.Monitors;

/// <summary>Alerts when watched services go down or exhibit unexpected state changes.</summary>
public sealed class ServiceMonitor : IMonitor
{
    public string Name => "Service";

    public Task<IEnumerable<Alert>> CheckAsync(SystemSnapshot snapshot, CancellationToken ct = default)
    {
        var alerts = snapshot.Services
            .Where(s => s.IsWatched && s.Status != "Running")
            .Select(s => new Alert
            {
                Severity        = AlertSeverity.Critical,
                Category        = AlertCategory.Service,
                Title           = $"Service Down: {s.DisplayName}",
                Message         = $"Watched service '{s.Name}' ({s.DisplayName}) is in state: {s.Status}.",
                SuggestedAction = RestartCommand(s.Name),
                RequiresApproval = true
            });

        return Task.FromResult<IEnumerable<Alert>>(alerts);
    }

    private static string RestartCommand(string name)
    {
        if (OperatingSystem.IsWindows()) return $"Run: sc start {name}";
        if (OperatingSystem.IsMacOS())   return $"Run: launchctl start {name}";
        return $"Run: systemctl start {name}";
    }
}
