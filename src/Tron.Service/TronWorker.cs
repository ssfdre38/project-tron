using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Tron.Core.Config;
using Tron.Core.Interfaces;
using Tron.Core.Models;

namespace Tron.Service;

public sealed class TronWorker : BackgroundService
{
    private readonly IMetricsCollector _collector;
    private readonly IEnumerable<IMonitor> _monitors;
    private readonly IEnumerable<IAlertSink> _sinks;
    private readonly TronOptions _opts;
    private readonly ILogger<TronWorker> _log;

    // Deduplicate alerts — don't re-fire the same alert title within the cooldown window
    private readonly Dictionary<string, DateTimeOffset> _lastAlerted = [];
    private static readonly TimeSpan AlertCooldown = TimeSpan.FromMinutes(15);

    public TronWorker(
        IMetricsCollector collector,
        IEnumerable<IMonitor> monitors,
        IEnumerable<IAlertSink> sinks,
        IOptions<TronOptions> opts,
        ILogger<TronWorker> log)
    {
        _collector = collector;
        _monitors = monitors;
        _sinks = sinks;
        _opts = opts.Value;
        _log = log;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _log.LogInformation("Tron is online — watching the system.");

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var snapshot = await _collector.CollectAsync(stoppingToken);
                _log.LogDebug("Snapshot collected: CPU={Cpu:F1}% MEM={Mem:F1}%",
                    snapshot.Cpu.UsagePercent, snapshot.Memory.UsagePercent);

                foreach (var monitor in _monitors)
                {
                    IEnumerable<Alert> alerts;
                    try { alerts = await monitor.CheckAsync(snapshot, stoppingToken); }
                    catch (Exception ex)
                    {
                        _log.LogWarning(ex, "Monitor {Name} threw an exception", monitor.Name);
                        continue;
                    }

                    foreach (var alert in alerts)
                        await DispatchAlertAsync(alert, stoppingToken);
                }
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _log.LogError(ex, "Unexpected error in Tron collection loop");
            }

            await Task.Delay(TimeSpan.FromSeconds(_opts.CollectionIntervalSeconds), stoppingToken);
        }

        _log.LogInformation("Tron is shutting down.");
    }

    private async Task DispatchAlertAsync(Alert alert, CancellationToken ct)
    {
        var now = DateTimeOffset.UtcNow;
        if (_lastAlerted.TryGetValue(alert.Title, out var last) && now - last < AlertCooldown)
        {
            _log.LogDebug("Alert suppressed (cooldown): {Title}", alert.Title);
            return;
        }

        _lastAlerted[alert.Title] = now;
        _log.LogWarning("[{Severity}] {Title}: {Message}", alert.Severity, alert.Title, alert.Message);

        foreach (var sink in _sinks)
        {
            try { await sink.SendAsync(alert, ct); }
            catch (Exception ex) { _log.LogError(ex, "Alert sink {Sink} failed", sink.GetType().Name); }
        }
    }
}
