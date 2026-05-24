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
    private readonly IAiAnalyzer _analyzer;
    private readonly TronOptions _opts;
    private readonly ILogger<TronWorker> _log;

    private readonly Dictionary<string, DateTimeOffset> _lastAlerted = [];
    private TimeSpan AlertCooldown => TimeSpan.FromMinutes(_opts.Alerting.CooldownMinutes);

    public TronWorker(
        IMetricsCollector collector,
        IEnumerable<IMonitor> monitors,
        IEnumerable<IAlertSink> sinks,
        IAiAnalyzer analyzer,
        IOptions<TronOptions> opts,
        ILogger<TronWorker> log)
    {
        _collector = collector;
        _monitors = monitors;
        _sinks = sinks;
        _analyzer = analyzer;
        _opts = opts.Value;
        _log = log;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _log.LogInformation("Tron is online — watching the system. AI analysis: {AiStatus}",
            _analyzer.IsAvailable ? $"enabled ({_opts.Ai.Model})" : "disabled");

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var snapshot = await _collector.CollectAsync(stoppingToken);
                _log.LogDebug("Snapshot: CPU={Cpu:F1}% MEM={Mem:F1}% Connections={Conns}",
                    snapshot.Cpu.UsagePercent, snapshot.Memory.UsagePercent, snapshot.Connections.Count);

                var allAlerts = new List<Alert>();

                foreach (var monitor in _monitors)
                {
                    try
                    {
                        var alerts = await monitor.CheckAsync(snapshot, stoppingToken);
                        allAlerts.AddRange(alerts);
                    }
                    catch (Exception ex)
                    {
                        _log.LogWarning(ex, "Monitor {Name} threw an exception", monitor.Name);
                    }
                }

                // Run AI analysis on the batch if there are any significant alerts
                var significantAlerts = allAlerts
                    .Where(a => a.Severity >= AlertSeverity.Warning)
                    .ToList();

                string? aiAnalysis = null;
                if (significantAlerts.Count > 0 && _analyzer.IsAvailable)
                {
                    aiAnalysis = await _analyzer.AnalyzeAsync(significantAlerts, snapshot, stoppingToken);
                }

                foreach (var alert in allAlerts)
                    await DispatchAlertAsync(alert, stoppingToken);

                // Send AI analysis as a follow-up embed if present
                if (!string.IsNullOrWhiteSpace(aiAnalysis))
                {
                    var analysisAlert = new Alert
                    {
                        Severity = AlertSeverity.Info,
                        Category = AlertCategory.Agent,
                        Title = "🤖 Tron Analysis",
                        Message = aiAnalysis
                    };
                    foreach (var sink in _sinks)
                    {
                        try { await sink.SendAsync(analysisAlert, stoppingToken); }
                        catch (Exception ex) { _log.LogError(ex, "Sink {Sink} failed for AI analysis", sink.GetType().Name); }
                    }
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
