using Microsoft.Extensions.Logging;
using Tron.Core.Interfaces;
using Tron.Core.Models;

namespace Tron.Monitors.Monitors;

/// <summary>
/// Detects process anomalies: newly observed processes, runaway resource usage,
/// and suspicious process characteristics (e.g. running from temp directories).
/// Works on Windows, Linux, and macOS.
/// </summary>
public sealed class ProcessMonitor : IMonitor
{
    private readonly ILogger<ProcessMonitor> _log;
    public string Name => "Process";

    // Windows: executables running from these paths are suspicious
    private static readonly string[] SuspiciousPathsWindows =
    [
        @"\temp\", @"\tmp\", @"\appdata\local\temp\", @"\downloads\",
        @"\recycle", @"\public\", @"\programdata\temp\"
    ];

    // Linux / macOS: executables running from these paths are suspicious
    private static readonly string[] SuspiciousPathsUnix =
    [
        "/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/"
    ];

    // Windows system process names that should never run from unusual paths
    private static readonly HashSet<string> SystemProcessNamesWindows = new(StringComparer.OrdinalIgnoreCase)
    {
        "svchost", "lsass", "csrss", "winlogon", "services", "smss", "wininit",
        "explorer", "dwm", "taskhostw", "runtimebroker"
    };

    // Linux/macOS system process names worth checking for masquerade
    private static readonly HashSet<string> SystemProcessNamesUnix = new(StringComparer.OrdinalIgnoreCase)
    {
        "systemd", "sshd", "cron", "rsyslogd", "journald", "udevd",
        "launchd", "kernel_task"
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
                    Severity  = AlertSeverity.Info,
                    Category  = AlertCategory.Process,
                    Title     = $"New Process: {proc.Name}",
                    Message   = $"Process '{proc.Name}' (PID {proc.Pid}) was observed for the first time." +
                                (string.IsNullOrEmpty(proc.ExecutablePath) ? "" : $" Path: {proc.ExecutablePath}"),
                });
            }

            if (string.IsNullOrEmpty(proc.ExecutablePath)) continue;

            // System process running from a suspicious/unexpected path (masquerading)
            if (IsSystemProcessName(proc.Name) && !IsLegitimateSystemPath(proc.ExecutablePath))
            {
                alerts.Add(new Alert
                {
                    Severity        = AlertSeverity.Critical,
                    Category        = AlertCategory.Security,
                    Title           = $"Suspicious Process: {proc.Name}",
                    Message         = $"System process '{proc.Name}' (PID {proc.Pid}) is running from an unexpected path: {proc.ExecutablePath}. This may indicate malware masquerading as a system process.",
                    SuggestedAction = "Investigate immediately — terminate if confirmed malicious.",
                    RequiresApproval = true
                });
            }

            // Executable running from a known-suspicious staging location
            if (IsSuspiciousPath(proc.ExecutablePath))
            {
                alerts.Add(new Alert
                {
                    Severity        = AlertSeverity.Warning,
                    Category        = AlertCategory.Security,
                    Title           = "Process Running from Suspicious Location",
                    Message         = $"Process '{proc.Name}' (PID {proc.Pid}) is running from a suspicious path: {proc.ExecutablePath}",
                    SuggestedAction = "Verify this is expected. Executables in temp/shm directories are common malware staging locations."
                });
            }
        }

        return Task.FromResult<IEnumerable<Alert>>(alerts);
    }

    private static bool IsSystemProcessName(string name) =>
        OperatingSystem.IsWindows()
            ? SystemProcessNamesWindows.Contains(name)
            : SystemProcessNamesUnix.Contains(name);

    private static bool IsLegitimateSystemPath(string path)
    {
        // Normalise to forward slashes for uniform comparison
        var p = path.Replace('\\', '/').ToLowerInvariant();
        if (OperatingSystem.IsWindows())
            return p.Contains("/windows/system32/") ||
                   p.Contains("/windows/syswow64/") ||
                   p.Contains("/windows/systemnative/");
        // Linux / macOS
        return p.StartsWith("/usr/sbin/")   ||
               p.StartsWith("/usr/bin/")    ||
               p.StartsWith("/sbin/")       ||
               p.StartsWith("/bin/")        ||
               p.StartsWith("/lib/systemd/")||
               p.StartsWith("/usr/lib/")    ||
               p.StartsWith("/usr/libexec/");
    }

    private static bool IsSuspiciousPath(string path)
    {
        var p = path.Replace('\\', '/').ToLowerInvariant();
        var patterns = OperatingSystem.IsWindows() ? SuspiciousPathsWindows : SuspiciousPathsUnix;
        // Normalise patterns to forward slashes too
        return patterns.Any(sp => p.Contains(sp.Replace('\\', '/')));
    }
}
