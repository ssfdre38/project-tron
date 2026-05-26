using Microsoft.Extensions.Logging;
using Tron.Core.Interfaces;
using Tron.Core.Models;

namespace Tron.Monitors.Monitors;

/// <summary>
/// Persistence Monitor. Detects new scheduled tasks, registry autorun entries (Windows),
/// cron jobs (Linux), and LaunchDaemons/LaunchAgents (macOS) that were not present
/// in the baseline established on the first run.
///
/// Cross-platform. Each platform uses the appropriate native persistence mechanisms.
/// MITRE ATT&amp;CK: T1053 (Scheduled Task/Job), T1547 (Boot or Logon Autostart Execution).
/// </summary>
public sealed class PersistenceMonitor : IMonitor
{
    private readonly ILogger<PersistenceMonitor> _log;

    public string Name => "Persistence";

    // Baseline fingerprints of known-good persistence entries
    private readonly HashSet<string> _knownEntries = new(StringComparer.OrdinalIgnoreCase);
    private bool _initialized;

    // Windows Task Scheduler XML task directory
    private static readonly string TasksDir =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                     "System32", "Tasks");

    // Windows registry Run key paths
    private static readonly string[] RegistryRunPaths =
    [
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    ];

    // Linux cron directories
    private static readonly string[] LinuxCronDirs =
    [
        "/etc/cron.d",
        "/etc/cron.hourly",
        "/etc/cron.daily",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
        "/var/spool/cron",
        "/var/spool/cron/crontabs",
    ];

    // macOS LaunchDaemon/LaunchAgent directories
    private static readonly string[] MacOsLaunchDirs =
    [
        "/Library/LaunchDaemons",
        "/Library/LaunchAgents",
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                     "Library", "LaunchAgents"),
    ];

    // Linux systemd unit directories for user-installed services
    private static readonly string[] LinuxSystemdDirs =
    [
        "/etc/systemd/system",
        "/usr/lib/systemd/system",
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                     ".config", "systemd", "user"),
    ];

    public PersistenceMonitor(ILogger<PersistenceMonitor> log)
    {
        _log = log;
    }

    public Task<IEnumerable<Alert>> CheckAsync(SystemSnapshot snapshot, CancellationToken ct = default)
    {
        var current = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var alerts = new List<Alert>();

        if (OperatingSystem.IsWindows())
        {
            CollectWindowsTasks(current);
            CollectWindowsRegistryRun(current);
        }
        else if (OperatingSystem.IsMacOS())
        {
            CollectFilesystemPersistence(MacOsLaunchDirs, current, "launchd plist");
            CollectLinuxCron(current); // macOS also has cron
        }
        else
        {
            CollectLinuxCron(current);
            CollectFilesystemPersistence(LinuxSystemdDirs, current, "systemd unit");
            CollectLinuxRcLocal(current);
        }

        if (!_initialized)
        {
            foreach (var entry in current)
                _knownEntries.Add(entry);
            _initialized = true;
            _log.LogDebug("Persistence baseline established with {Count} entries", _knownEntries.Count);
            return Task.FromResult<IEnumerable<Alert>>([]);
        }

        // Detect new entries not in the baseline
        foreach (var entry in current)
        {
            if (_knownEntries.Contains(entry)) continue;

            _knownEntries.Add(entry);
            var (type, name) = ParseEntry(entry);
            alerts.Add(new Alert
            {
                Severity         = AlertSeverity.Warning,
                Category         = AlertCategory.Persistence,
                Title            = $"New {type} Detected",
                Message          = $"A new persistence mechanism was registered: {name}. " +
                                   $"This {type.ToLowerInvariant()} was not present in the baseline. " +
                                   "Attackers commonly use scheduled tasks and registry run keys to survive reboots.",
                SuggestedAction  = $"Verify '{name}' was intentionally installed. If unknown, remove it and investigate the process that created it.",
                RequiresApproval = true,
            });
        }

        // Detect removed entries (optional telemetry — useful to catch anti-forensic cleanup)
        foreach (var known in _knownEntries.ToList())
        {
            if (current.Contains(known)) continue;
            _knownEntries.Remove(known);
            var (type, name) = ParseEntry(known);
            alerts.Add(new Alert
            {
                Severity  = AlertSeverity.Info,
                Category  = AlertCategory.Persistence,
                Title     = $"{type} Removed",
                Message   = $"A previously known persistence entry was removed: {name}. " +
                            "This may be normal (software uninstall) or may indicate anti-forensic cleanup.",
            });
        }

        return Task.FromResult<IEnumerable<Alert>>(alerts);
    }

    // ── Windows ──────────────────────────────────────────────────────────────

    private void CollectWindowsTasks(HashSet<string> current)
    {
        if (!Directory.Exists(TasksDir)) return;
        try
        {
            foreach (var file in Directory.EnumerateFiles(TasksDir, "*", SearchOption.AllDirectories))
            {
                // Use the relative path under Tasks as the unique key
                var rel = Path.GetRelativePath(TasksDir, file);
                current.Add($"task:{rel}");
            }
        }
        catch (Exception ex)
        {
            _log.LogDebug("PersistenceMonitor: cannot enumerate tasks dir: {Ex}", ex.Message);
        }
    }

    private void CollectWindowsRegistryRun(HashSet<string> current)
    {
#if TRON_WINDOWS
#pragma warning disable CA1416 // CollectWindowsRegistryRunCore is marked [SupportedOSPlatform("windows")]; TRON_WINDOWS is only defined on Windows builds
        CollectWindowsRegistryRunCore(current);
#pragma warning restore CA1416
#endif
    }

#if TRON_WINDOWS
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private void CollectWindowsRegistryRunCore(HashSet<string> current)
    {
        foreach (var keyPath in RegistryRunPaths)
        {
            try
            {
                // HKLM
                using var hklm = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(keyPath, writable: false);
                if (hklm != null)
                {
                    foreach (var name in hklm.GetValueNames())
                        current.Add($"reg:HKLM\\{keyPath}\\{name}={hklm.GetValue(name)}");
                }

                // HKCU
                using var hkcu = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(keyPath, writable: false);
                if (hkcu != null)
                {
                    foreach (var name in hkcu.GetValueNames())
                        current.Add($"reg:HKCU\\{keyPath}\\{name}={hkcu.GetValue(name)}");
                }
            }
            catch (Exception ex)
            {
                _log.LogDebug("PersistenceMonitor: registry read failed for {Key}: {Ex}", keyPath, ex.Message);
            }
        }
    }
#endif

    // ── Linux cron ───────────────────────────────────────────────────────────

    private void CollectLinuxCron(HashSet<string> current)
    {
        // /etc/crontab and /etc/cron.d/* — hash the file so we catch content changes too
        var cronFile = "/etc/crontab";
        if (File.Exists(cronFile))
            current.Add($"cron:file:{cronFile}:{GetFileFingerprint(cronFile)}");

        foreach (var dir in LinuxCronDirs)
        {
            if (!Directory.Exists(dir)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir))
                    current.Add($"cron:file:{file}:{GetFileFingerprint(file)}");
            }
            catch (Exception ex)
            {
                _log.LogDebug("PersistenceMonitor: cannot read {Dir}: {Ex}", dir, ex.Message);
            }
        }
    }

    // ── Filesystem-based persistence (macOS LaunchDaemons, systemd units) ───

    private void CollectFilesystemPersistence(string[] dirs, HashSet<string> current, string label)
    {
        foreach (var dir in dirs)
        {
            if (!Directory.Exists(dir)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir))
                    current.Add($"{label}:{file}:{GetFileFingerprint(file)}");
            }
            catch (Exception ex)
            {
                _log.LogDebug("PersistenceMonitor: cannot read {Dir}: {Ex}", dir, ex.Message);
            }
        }
    }

    // ── Linux /etc/rc.local ──────────────────────────────────────────────────

    private static void CollectLinuxRcLocal(HashSet<string> current)
    {
        const string rcLocal = "/etc/rc.local";
        if (File.Exists(rcLocal))
            current.Add($"rc.local:{GetFileFingerprint(rcLocal)}");
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static string GetFileFingerprint(string path)
    {
        try
        {
            var info = new FileInfo(path);
            // Use size + last-write as a lightweight "did this change" check
            return $"{info.Length}:{info.LastWriteTimeUtc.Ticks}";
        }
        catch { return "unreadable"; }
    }

    private static (string Type, string Name) ParseEntry(string entry)
    {
        if (entry.StartsWith("task:", StringComparison.OrdinalIgnoreCase))
            return ("Scheduled Task", entry[5..].Split(':')[0]);
        if (entry.StartsWith("reg:", StringComparison.OrdinalIgnoreCase))
            return ("Registry Run Entry", entry[4..].Split('=')[0]);
        if (entry.StartsWith("cron:", StringComparison.OrdinalIgnoreCase))
            return ("Cron Job", entry.Split(':').Skip(2).First());
        if (entry.StartsWith("launchd plist:", StringComparison.OrdinalIgnoreCase))
            return ("LaunchDaemon/LaunchAgent", entry.Split(':').Skip(1).First());
        if (entry.StartsWith("systemd unit:", StringComparison.OrdinalIgnoreCase))
            return ("Systemd Unit", entry.Split(':').Skip(1).First());
        return ("Persistence Entry", entry);
    }
}
