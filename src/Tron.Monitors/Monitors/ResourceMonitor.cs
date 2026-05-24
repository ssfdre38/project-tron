using Microsoft.Extensions.Options;
using Tron.Core.Config;
using Tron.Core.Interfaces;
using Tron.Core.Models;

namespace Tron.Monitors.Monitors;

public sealed class ResourceMonitor : IMonitor
{
    private readonly TronOptions _opts;
    public string Name => "Resource";

    public ResourceMonitor(IOptions<TronOptions> opts) => _opts = opts.Value;

    public Task<IEnumerable<Alert>> CheckAsync(SystemSnapshot snapshot, CancellationToken ct = default)
    {
        var alerts = new List<Alert>();
        var t = _opts.Thresholds;

        // CPU
        if (snapshot.Cpu.UsagePercent >= t.CpuCriticalPercent)
            alerts.Add(Make(AlertSeverity.Critical, AlertCategory.Cpu,
                "CPU Critical",
                $"CPU usage is at {snapshot.Cpu.UsagePercent:F1}% — server is under extreme load.",
                "Identify top processes and consider restarting or throttling them."));
        else if (snapshot.Cpu.UsagePercent >= t.CpuWarningPercent)
            alerts.Add(Make(AlertSeverity.Warning, AlertCategory.Cpu,
                "CPU High",
                $"CPU usage is at {snapshot.Cpu.UsagePercent:F1}%."));

        // Memory
        if (snapshot.Memory.UsagePercent >= t.MemoryCriticalPercent)
            alerts.Add(Make(AlertSeverity.Critical, AlertCategory.Memory,
                "Memory Critical",
                $"Memory usage is at {snapshot.Memory.UsagePercent:F1}% ({FormatBytes(snapshot.Memory.TotalBytes - snapshot.Memory.AvailableBytes)} used of {FormatBytes(snapshot.Memory.TotalBytes)}).",
                "Consider restarting memory-heavy services or increasing RAM.", requiresApproval: true));
        else if (snapshot.Memory.UsagePercent >= t.MemoryWarningPercent)
            alerts.Add(Make(AlertSeverity.Warning, AlertCategory.Memory,
                "Memory High",
                $"Memory usage is at {snapshot.Memory.UsagePercent:F1}%."));

        // Disks
        foreach (var disk in snapshot.Disks)
        {
            if (disk.UsagePercent >= t.DiskCriticalPercent)
                alerts.Add(Make(AlertSeverity.Critical, AlertCategory.Disk,
                    $"Disk {disk.Drive} Critical",
                    $"Drive {disk.Drive} is {disk.UsagePercent:F1}% full ({FormatBytes(disk.FreeBytes)} free).",
                    "Free up disk space immediately.", requiresApproval: true));
            else if (disk.UsagePercent >= t.DiskWarningPercent)
                alerts.Add(Make(AlertSeverity.Warning, AlertCategory.Disk,
                    $"Disk {disk.Drive} Low Space",
                    $"Drive {disk.Drive} is {disk.UsagePercent:F1}% full ({FormatBytes(disk.FreeBytes)} free)."));
        }

        return Task.FromResult<IEnumerable<Alert>>(alerts);
    }

    private static Alert Make(AlertSeverity severity, AlertCategory category, string title,
        string message, string? action = null, bool requiresApproval = false) => new()
    {
        Severity = severity,
        Category = category,
        Title = title,
        Message = message,
        SuggestedAction = action,
        RequiresApproval = requiresApproval
    };

    private static string FormatBytes(long bytes) => bytes switch
    {
        >= 1_099_511_627_776 => $"{bytes / 1_099_511_627_776.0:F1} TB",
        >= 1_073_741_824 => $"{bytes / 1_073_741_824.0:F1} GB",
        >= 1_048_576 => $"{bytes / 1_048_576.0:F1} MB",
        _ => $"{bytes / 1024.0:F1} KB"
    };
}
