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
                Severity = AlertSeverity.Critical,
                Category = AlertCategory.Service,
                Title = $"Service Down: {s.DisplayName}",
                Message = $"Watched service '{s.Name}' ({s.DisplayName}) is in state: {s.Status}.",
                SuggestedAction = $"Restart the service: sc start {s.Name}",
                RequiresApproval = true
            });

        return Task.FromResult<IEnumerable<Alert>>(alerts);
    }
}
