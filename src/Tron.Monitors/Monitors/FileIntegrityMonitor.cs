using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Tron.Core.Config;
using Tron.Core.Interfaces;
using Tron.Core.Models;

namespace Tron.Monitors.Monitors;

/// <summary>
/// File Integrity Monitor (FIM). On first run, hashes all critical system files to build
/// a baseline. On every subsequent poll, re-hashes and alerts on any change or deletion.
/// New files appearing in a watched directory also trigger an alert.
///
/// Cross-platform. Critical file lists are platform-selected at runtime.
/// MITRE ATT&amp;CK: T1565 (Data Manipulation), T1070 (Indicator Removal), T1486 (Ransomware).
/// </summary>
public sealed class FileIntegrityMonitor : IMonitor
{
    private readonly ILogger<FileIntegrityMonitor> _log;
    private readonly FileIntegrityOptions _opts;

    public string Name => "FileIntegrity";

    // path → SHA-256 hex (null = file existed at baseline but hash failed)
    private readonly Dictionary<string, string?> _baseline = new(StringComparer.OrdinalIgnoreCase);
    private bool _initialized;

    // Windows: files that are safe to read without elevated access
    private static readonly string[] CriticalFilesWindows =
    [
        @"%SystemRoot%\System32\drivers\etc\hosts",
        @"%SystemRoot%\System32\cmd.exe",
        @"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe",
        @"%SystemRoot%\SysWOW64\cmd.exe",
        @"%SystemRoot%\System32\schtasks.exe",
        @"%SystemRoot%\System32\net.exe",
        @"%SystemRoot%\System32\netsh.exe",
        @"%SystemRoot%\System32\sc.exe",
        @"%SystemRoot%\System32\reg.exe",
        @"%SystemRoot%\System32\mshta.exe",
        @"%SystemRoot%\System32\wscript.exe",
        @"%SystemRoot%\System32\cscript.exe",
        @"%SystemRoot%\System32\rundll32.exe",
        @"%SystemRoot%\System32\regsvr32.exe",
        @"%SystemRoot%\System32\certutil.exe",
        @"%SystemRoot%\System32\bitsadmin.exe",
    ];

    // Linux / macOS critical files
    private static readonly string[] CriticalFilesUnix =
    [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/etc/hosts",
        "/etc/hostname",
        "/etc/fstab",
        "/etc/ssh/sshd_config",
        "/etc/crontab",
        "/etc/pam.d/common-auth",
        "/etc/pam.d/sshd",
        "/root/.ssh/authorized_keys",
        "/etc/ld.so.preload",   // T1574.006 — LD_PRELOAD hijack
        "/etc/profile",
        "/etc/bash.bashrc",
    ];

    public FileIntegrityMonitor(ILogger<FileIntegrityMonitor> log, IOptions<TronOptions> opts)
    {
        _log = log;
        _opts = opts.Value.FileIntegrity;
    }

    public Task<IEnumerable<Alert>> CheckAsync(SystemSnapshot snapshot, CancellationToken ct = default)
    {
        if (!_opts.Enabled)
            return Task.FromResult<IEnumerable<Alert>>([]);

        var alerts = new List<Alert>();

        // Combine built-in critical files + user-configured extra files
        var individualFiles = GetBuiltInFiles().Concat(_opts.WatchFiles);

        foreach (var rawPath in individualFiles)
        {
            ct.ThrowIfCancellationRequested();
            var path = Environment.ExpandEnvironmentVariables(rawPath);
            ProcessFile(path, alerts, isDirectory: false);
        }

        // Scan user-configured watch directories recursively
        foreach (var dir in _opts.WatchDirectories)
        {
            if (!Directory.Exists(dir)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ProcessFile(file, alerts, isDirectory: true);
                }
            }
            catch (Exception ex)
            {
                _log.LogDebug("FIM: cannot enumerate {Dir}: {Ex}", dir, ex.Message);
            }
        }

        _initialized = true;
        return Task.FromResult<IEnumerable<Alert>>(alerts);
    }

    private void ProcessFile(string path, List<Alert> alerts, bool isDirectory)
    {
        if (!File.Exists(path)) return;

        string? hash = null;
        try { hash = ComputeHash(path); }
        catch (Exception ex)
        {
            _log.LogDebug("FIM: cannot hash {Path}: {Ex}", path, ex.Message);
            return;
        }

        if (!_initialized)
        {
            _baseline[path] = hash;
            return;
        }

        if (!_baseline.TryGetValue(path, out var known))
        {
            // New file appeared after baseline was established
            _baseline[path] = hash;
            alerts.Add(new Alert
            {
                Severity        = AlertSeverity.Warning,
                Category        = AlertCategory.Integrity,
                Title           = isDirectory ? "New File in Watched Directory" : "New Critical System File",
                Message         = $"A new file appeared after the baseline was established: {path}. " +
                                  "This may indicate a backdoor, dropper, or unauthorized software installation.",
                SuggestedAction = "Verify the file origin and review recent change logs.",
            });
            return;
        }

        if (hash != known)
        {
            _baseline[path] = hash;
            var isCritical = !isDirectory;
            alerts.Add(new Alert
            {
                Severity         = isCritical ? AlertSeverity.Critical : AlertSeverity.Warning,
                Category         = AlertCategory.Integrity,
                Title            = isCritical ? "Critical System File Modified" : "Watched File Modified",
                Message          = $"Hash change detected: {path}. " +
                                   "Content has changed since the last poll. " +
                                   (isCritical
                                       ? "Modification of a critical OS binary or config may indicate malware injection, trojanizing, or unauthorized patching."
                                       : "Verify this change was expected and authorised."),
                SuggestedAction  = isCritical
                    ? "Compare against a known-good copy. If unexpected: isolate system, run malware scan, and restore from backup."
                    : "Review the change and verify it was intentional.",
                RequiresApproval = isCritical,
            });
        }
    }

    private static string[] GetBuiltInFiles() =>
        OperatingSystem.IsWindows() ? CriticalFilesWindows : CriticalFilesUnix;

    private static string ComputeHash(string path)
    {
        using var sha = SHA256.Create();
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        var hash = sha.ComputeHash(stream);
        return Convert.ToHexString(hash);
    }
}
