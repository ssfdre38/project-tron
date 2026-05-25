using System.Collections.Concurrent;
using Tron.Core.Models;

namespace Tron.Service;

/// <summary>
/// Singleton that holds the latest system snapshot and a rolling window of recent alerts.
/// Written by TronWorker, read by DashboardService.
/// </summary>
public sealed class TronStateService
{
    private const int MaxAlerts = 100;

    private volatile SystemSnapshot _latest = new();
    private readonly ConcurrentQueue<Alert> _alerts = new();
    private readonly DateTimeOffset _startedAt = DateTimeOffset.UtcNow;

    public SystemSnapshot Latest => _latest;
    public TimeSpan Uptime => DateTimeOffset.UtcNow - _startedAt;

    public IReadOnlyList<Alert> RecentAlerts => _alerts.ToArray();

    public void UpdateSnapshot(SystemSnapshot snapshot) => _latest = snapshot;

    public void AddAlert(Alert alert)
    {
        _alerts.Enqueue(alert);
        // Trim to max window
        while (_alerts.Count > MaxAlerts)
            _alerts.TryDequeue(out _);
    }
}
