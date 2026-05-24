using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Tron.Core.Config;
using Tron.Core.Interfaces;
using Tron.Core.Models;

namespace Tron.Monitors.Monitors;

/// <summary>
/// Learns the normal behaviour of this system over time and raises anomaly alerts
/// when metrics deviate significantly from the established baseline.
/// Uses Welford's online algorithm for numerically stable running mean/variance.
/// </summary>
public sealed class BaselineMonitor : IMonitor
{
    private readonly IBaselineRepository _repo;
    private readonly TronOptions _opts;
    private readonly ILogger<BaselineMonitor> _log;

    private BaselineStore _store = new();
    private DateTimeOffset _lastSaved = DateTimeOffset.MinValue;
    private bool _loaded;

    public string Name => "Baseline";

    public BaselineMonitor(IBaselineRepository repo, IOptions<TronOptions> opts, ILogger<BaselineMonitor> log)
    {
        _repo = repo;
        _opts = opts.Value;
        _log = log;
    }

    public async Task<IEnumerable<Alert>> CheckAsync(SystemSnapshot snapshot, CancellationToken ct = default)
    {
        if (!_loaded)
        {
            _store = await _repo.LoadAsync(ct);
            _loaded = true;
            _log.LogInformation("[baseline] Loaded baseline: {Count} metrics, {Procs} known processes",
                _store.Metrics.Count, _store.KnownProcessNames.Count);
        }

        var alerts = new List<Alert>();

        if (_opts.Baseline.EnableAnomalyDetection)
        {
            CheckMetricAnomaly("cpu.usage", snapshot.Cpu.UsagePercent, alerts);
            CheckMetricAnomaly("mem.usage", snapshot.Memory.UsagePercent, alerts);
            foreach (var disk in snapshot.Disks)
                CheckMetricAnomaly($"disk.usage.{disk.Drive.TrimEnd('\\', '/')}", disk.UsagePercent, alerts);
        }

        // Update baseline with current values
        UpdateBaseline("cpu.usage", snapshot.Cpu.UsagePercent);
        UpdateBaseline("mem.usage", snapshot.Memory.UsagePercent);
        foreach (var disk in snapshot.Disks)
            UpdateBaseline($"disk.usage.{disk.Drive.TrimEnd('\\', '/')}", disk.UsagePercent);

        // Track known process names
        foreach (var proc in snapshot.TopProcesses)
            _store.KnownProcessNames.Add(proc.Name);

        // Track known remote hosts
        foreach (var conn in snapshot.Connections.Where(c => !string.IsNullOrEmpty(c.RemoteAddress)))
            _store.KnownRemoteHosts.Add(conn.RemoteAddress);

        // Persist on interval
        var saveInterval = TimeSpan.FromMinutes(_opts.Baseline.SaveIntervalMinutes);
        if (DateTimeOffset.UtcNow - _lastSaved >= saveInterval)
        {
            await _repo.SaveAsync(_store, ct);
            _lastSaved = DateTimeOffset.UtcNow;
            _log.LogDebug("[baseline] Saved. Metrics tracked: {Count}", _store.Metrics.Count);
        }

        return alerts;
    }

    private void CheckMetricAnomaly(string key, double value, List<Alert> alerts)
    {
        if (!_store.Metrics.TryGetValue(key, out var baseline) || !baseline.IsReady) return;

        var z = baseline.ZScore(value);
        var threshold = _opts.Thresholds.AnomalyZScoreThreshold;

        if (Math.Abs(z) >= threshold)
        {
            var direction = z > 0 ? "spike" : "drop";
            alerts.Add(new Alert
            {
                Severity = Math.Abs(z) >= threshold * 1.5 ? AlertSeverity.Critical : AlertSeverity.Warning,
                Category = GetCategory(key),
                Title = $"Anomaly: {FriendlyName(key)}",
                Message = $"{FriendlyName(key)} {direction} detected: current={value:F1}, baseline mean={baseline.Mean:F1} ±{baseline.StdDev:F1} (z={z:F1}, samples={baseline.SampleCount})",
                SuggestedAction = $"Investigate what is driving the unusual {FriendlyName(key).ToLowerInvariant()}."
            });
        }
    }

    private void UpdateBaseline(string key, double value)
    {
        if (!_store.Metrics.TryGetValue(key, out var baseline))
        {
            baseline = new MetricBaseline { MetricKey = key };
            _store.Metrics[key] = baseline;
        }
        baseline.Update(value);
    }

    private static AlertCategory GetCategory(string key) => key switch
    {
        var k when k.StartsWith("cpu") => AlertCategory.Cpu,
        var k when k.StartsWith("mem") => AlertCategory.Memory,
        var k when k.StartsWith("disk") => AlertCategory.Disk,
        _ => AlertCategory.Cpu
    };

    private static string FriendlyName(string key) => key switch
    {
        "cpu.usage" => "CPU Usage",
        "mem.usage" => "Memory Usage",
        var k when k.StartsWith("disk.usage.") => $"Disk {k["disk.usage.".Length..]} Usage",
        _ => key
    };
}
