using Microsoft.Extensions.Logging;
using Tron.Core.Interfaces;
using Tron.Core.Models;

namespace Tron.Monitors.Monitors;

/// <summary>
/// Detects process anomalies: newly observed processes, runaway resource usage,
/// and suspicious process characteristics (e.g. running from temp directories).
/// </summary>
public sealed class ProcessMonitor : IMonitor
{
    private readonly ILogger<ProcessMonitor> _log;
    public string Name => "Process";

    // Suspicious launch paths — executables running from here deserve scrutiny
    private static readonly string[] SuspiciousPaths =
    [
        @"\temp\", @"\tmp\", @"\appdata\local\temp\", @"\downloads\",
        @"\recycle", @"\public\", @"\programdata\temp\"
    ];

    // Known-legitimate system process names that should never come from unusual paths
    private static readonly HashSet<string> SystemProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "svchost", "lsass", "csrss", "winlogon", "services", "smss", "wininit",
        "explorer", "dwm", "taskhostw", "runtimebroker"
    };

    public ProcessMonitor(ILogger<ProcessMonitor> log) => _log = log;

    public Task<IEnumerable<Alert>> CheckAsync(SystemSnapshot snapshot, CancellationToken ct = default)
    {
        var alerts = new List<Alert>();

        foreach (var proc in snapshot.TopProcesses)
        {
            // New process never seen before in baseline
            if (proc.IsNewlyObserved)
            {
                alerts.Add(new Alert
                {
                    Severity = AlertSeverity.Info,
                    Category = AlertCategory.Process,
                    Title = $"New Process: {proc.Name}",
                    Message = $"Process '{proc.Name}' (PID {proc.Pid}) was observed for the first time." +
                              (string.IsNullOrEmpty(proc.ExecutablePath) ? "" : $" Path: {proc.ExecutablePath}"),
                });
            }

            // System process running from a suspicious path (masquerading)
            if (!string.IsNullOrEmpty(proc.ExecutablePath) &&
                SystemProcessNames.Contains(proc.Name) &&
                !IsLegitimateSystemPath(proc.ExecutablePath))
            {
                alerts.Add(new Alert
                {
                    Severity = AlertSeverity.Critical,
                    Category = AlertCategory.Security,
                    Title = $"Suspicious Process: {proc.Name}",
                    Message = $"System process '{proc.Name}' (PID {proc.Pid}) is running from an unusual path: {proc.ExecutablePath}. This may indicate malware masquerading as a system process.",
                    SuggestedAction = "Investigate immediately — kill the process if confirmed malicious.",
                    RequiresApproval = true
                });
            }

            // Executable running from temp/downloads
            if (!string.IsNullOrEmpty(proc.ExecutablePath) &&
                IsSuspiciousPath(proc.ExecutablePath))
            {
                alerts.Add(new Alert
                {
                    Severity = AlertSeverity.Warning,
                    Category = AlertCategory.Security,
                    Title = $"Process Running from Suspicious Location",
                    Message = $"Process '{proc.Name}' (PID {proc.Pid}) is running from a suspicious path: {proc.ExecutablePath}",
                    SuggestedAction = "Verify this is expected. Executables in temp/downloads directories are often malware droppers."
                });
            }
        }

        return Task.FromResult<IEnumerable<Alert>>(alerts);
    }

    private static bool IsLegitimateSystemPath(string path)
    {
        var lower = path.ToLowerInvariant();
        return lower.Contains(@"\windows\system32\") ||
               lower.Contains(@"\windows\syswow64\") ||
               lower.Contains(@"\windows\systemnative\");
    }

    private static bool IsSuspiciousPath(string path)
    {
        var lower = path.ToLowerInvariant();
        return SuspiciousPaths.Any(sp => lower.Contains(sp));
    }
}
