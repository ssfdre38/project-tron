using Tron.Core.Models;

namespace Tron.Core.Interfaces;

public interface IMonitor
{
    string Name { get; }
    Task<IEnumerable<Alert>> CheckAsync(SystemSnapshot snapshot, CancellationToken ct = default);
}

public interface IMetricsCollector
{
    Task<SystemSnapshot> CollectAsync(CancellationToken ct = default);
}

public interface IAlertSink
{
    Task SendAsync(Alert alert, CancellationToken ct = default);
}
