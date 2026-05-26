using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Tron.Core.Config;
using Tron.Core.Models;

namespace Tron.Core.Services;

/// <summary>
/// Cross-monitor correlation engine. Accumulates alerts in a sliding time window and
/// fires composite alerts when multiple related indicators appear together — turning
/// individual noisy signals into high-confidence threat detections.
///
/// Rules:
///   1. Active Breach     — failed login + process-from-temp + C2/ThreatIntel connection
///   2. C2 Implant        — process-from-temp/suspicious + outbound C2 connection
///   3. Malware Install   — new persistence entry + suspicious/new process
///   4. Lateral Movement  — brute-force + admin-port connection (RDP/SMB/WinRM) to external IP
///   5. Ransomware Signal — multiple FIM changes + service stop within window
///
/// Each rule fires at most once per cooldown period (5 × window) to avoid alert fatigue.
/// </summary>
public sealed class CorrelationEngine
{
    private readonly CorrelationOptions _opts;
    private readonly ILogger<CorrelationEngine> _log;

    // Sliding window: all alerts seen within the window, keyed by their timestamp
    private readonly List<Alert> _window = [];

    // Per-rule cooldown tracking (rule name → last-fired timestamp)
    private readonly Dictionary<string, DateTimeOffset> _lastFired = [];

    public CorrelationEngine(IOptions<TronOptions> opts, ILogger<CorrelationEngine> log)
    {
        _opts = opts.Value.Correlation;
        _log = log;
    }

    /// <summary>
    /// Feed this cycle's alerts into the engine. Returns any composite correlation alerts.
    /// </summary>
    public IReadOnlyList<Alert> Correlate(IEnumerable<Alert> cycleAlerts)
    {
        if (!_opts.Enabled) return [];

        var now = DateTimeOffset.UtcNow;
        var cutoff = now - TimeSpan.FromMinutes(_opts.WindowMinutes);

        // Add new alerts to the window
        foreach (var a in cycleAlerts)
            _window.Add(a);

        // Evict expired alerts from the window
        _window.RemoveAll(a => a.Timestamp < cutoff);

        var correlations = new List<Alert>();

        EvaluateRule("ActiveBreach",      correlations, CheckActiveBreach);
        EvaluateRule("C2Implant",         correlations, CheckC2Implant);
        EvaluateRule("MalwareInstall",    correlations, CheckMalwareInstall);
        EvaluateRule("LateralMovement",   correlations, CheckLateralMovement);
        EvaluateRule("RansomwareSignal",  correlations, CheckRansomwareSignal);

        return correlations;
    }

    // ── Rule evaluator ───────────────────────────────────────────────────────

    private void EvaluateRule(string ruleName, List<Alert> output, Func<Alert?> rule)
    {
        var cooldown = TimeSpan.FromMinutes(_opts.WindowMinutes * 5);
        if (_lastFired.TryGetValue(ruleName, out var last) &&
            DateTimeOffset.UtcNow - last < cooldown)
            return;

        var result = rule();
        if (result == null) return;

        _lastFired[ruleName] = DateTimeOffset.UtcNow;
        _log.LogWarning("[Correlation] Rule '{Rule}' fired: {Title}", ruleName, result.Title);
        output.Add(result);
    }

    // ── Rule 1: Active Breach ────────────────────────────────────────────────
    // failed login + process from suspicious path + C2 or ThreatIntel connection

    private Alert? CheckActiveBreach()
    {
        bool hasFailedLogin = _window.Any(a =>
            a.Category == AlertCategory.Security &&
            ContainsAny(a, "failed", "brute", "4625", "login"));

        bool hasSuspiciousProcess = _window.Any(a =>
            a.Category is AlertCategory.Process &&
            ContainsAny(a, "temp", "suspicious", "masquerad", "unexpected"));

        bool hasC2 = _window.Any(a =>
            a.Category is AlertCategory.Network or AlertCategory.ThreatIntel &&
            a.Severity >= AlertSeverity.Warning);

        if (!hasFailedLogin || !hasSuspiciousProcess || !hasC2)
            return null;

        return new Alert
        {
            Severity         = AlertSeverity.Critical,
            Category         = AlertCategory.Correlation,
            Title            = "🚨 Active Breach Detected",
            Message          = $"Correlation engine fired: failed authentication, suspicious process activity, and a C2/threat-intel connection all appeared within a {_opts.WindowMinutes}-minute window. " +
                               "This combination strongly indicates an active intrusion — a compromised credential or exploit led to code execution, which is now beaconing home.",
            SuggestedAction  = "IMMEDIATE ACTION: isolate this host from the network, capture a memory dump if possible, and begin incident response. Review all recent logins and process creation events.",
            RequiresApproval = true,
            MitreAttack      = new MitreAttackInfo("T1078", "Valid Accounts", "Defense Evasion"),
        };
    }

    // ── Rule 2: C2 Implant ───────────────────────────────────────────────────
    // suspicious/new process + C2 outbound connection

    private Alert? CheckC2Implant()
    {
        bool hasSuspiciousProcess = _window.Any(a =>
            a.Category is AlertCategory.Process &&
            ContainsAny(a, "temp", "suspicious", "masquerad", "unexpected", "new process"));

        bool hasC2Connection = _window.Any(a =>
            a.Category == AlertCategory.Network &&
            ContainsAny(a, "c2", "4444", "31337", "1337", "suspicious outbound"));

        if (!hasSuspiciousProcess || !hasC2Connection)
            return null;

        return new Alert
        {
            Severity         = AlertSeverity.Critical,
            Category         = AlertCategory.Correlation,
            Title            = "🚨 C2 Implant Behaviour",
            Message          = $"A process running from a suspicious location is making outbound connections to a known command-and-control port within a {_opts.WindowMinutes}-minute window. " +
                               "This is the hallmark signature of a C2 implant (RAT, beacon, or reverse shell).",
            SuggestedAction  = "Kill the suspicious process, block the remote IP at the firewall, and inspect the full process tree for parent processes.",
            RequiresApproval = true,
            MitreAttack      = new MitreAttackInfo("T1095", "Non-Application Layer Protocol", "Command and Control"),
        };
    }

    // ── Rule 3: Malware Installation ─────────────────────────────────────────
    // new persistence entry + suspicious or newly-observed process

    private Alert? CheckMalwareInstall()
    {
        bool hasNewPersistence = _window.Any(a =>
            a.Category == AlertCategory.Persistence &&
            ContainsAny(a, "new", "detected") &&
            a.Severity >= AlertSeverity.Warning);

        bool hasSuspiciousProcess = _window.Any(a =>
            a.Category is AlertCategory.Process &&
            ContainsAny(a, "temp", "suspicious", "new process", "download"));

        if (!hasNewPersistence || !hasSuspiciousProcess)
            return null;

        return new Alert
        {
            Severity         = AlertSeverity.Critical,
            Category         = AlertCategory.Correlation,
            Title            = "🚨 Malware Installation Suspected",
            Message          = $"A new persistence mechanism (scheduled task, registry run key, or startup entry) appeared alongside a suspicious or newly-observed process within {_opts.WindowMinutes} minutes. " +
                               "This is consistent with a malware dropper establishing its foothold.",
            SuggestedAction  = "Remove the new persistence entry, terminate the suspicious process, and search for dropped files in %TEMP%, Downloads, and AppData.",
            RequiresApproval = true,
            MitreAttack      = new MitreAttackInfo("T1547", "Boot or Logon Autostart Execution", "Persistence"),
        };
    }

    // ── Rule 4: Lateral Movement ─────────────────────────────────────────────
    // brute-force / repeated logins + admin-port connection to external IP

    private Alert? CheckLateralMovement()
    {
        bool hasBruteForce = _window.Any(a =>
            a.Category == AlertCategory.Security &&
            (ContainsAny(a, "brute", "repeated", "multiple failed") ||
             (ContainsAny(a, "failed", "4625") && a.Severity >= AlertSeverity.Warning)));

        bool hasAdminPortConnection = _window.Any(a =>
            a.Category == AlertCategory.Network &&
            ContainsAny(a, "3389", "5985", "5986", "445", "rdp", "smb", "winrm", "admin port"));

        if (!hasBruteForce || !hasAdminPortConnection)
            return null;

        return new Alert
        {
            Severity         = AlertSeverity.Critical,
            Category         = AlertCategory.Correlation,
            Title            = "🚨 Lateral Movement Attempt",
            Message          = $"Credential brute-force activity and an external connection on an admin-access port (RDP, SMB, or WinRM) both occurred within {_opts.WindowMinutes} minutes. " +
                               "This pattern is consistent with an attacker attempting to move laterally through the network.",
            SuggestedAction  = "Block the source IPs, enable account lockout policy, audit AD / SSH login history, and verify no accounts were compromised.",
            RequiresApproval = true,
            MitreAttack      = new MitreAttackInfo("T1021", "Remote Services", "Lateral Movement"),
        };
    }

    // ── Rule 5: Ransomware Signal ────────────────────────────────────────────
    // multiple FIM change alerts + at least one service stop

    private Alert? CheckRansomwareSignal()
    {
        int fimChanges = _window.Count(a =>
            a.Category == AlertCategory.Integrity &&
            ContainsAny(a, "modified", "change"));

        bool hasServiceStop = _window.Any(a =>
            a.Category == AlertCategory.Service &&
            ContainsAny(a, "stop", "down", "not running"));

        if (fimChanges < 3 || !hasServiceStop)
            return null;

        return new Alert
        {
            Severity         = AlertSeverity.Critical,
            Category         = AlertCategory.Correlation,
            Title            = "🚨 Ransomware-Like Behaviour Detected",
            Message          = $"{fimChanges} file integrity alerts and a service stop occurred within {_opts.WindowMinutes} minutes. " +
                               "Rapid mass file modification combined with service disruption is the canonical ransomware pattern (stopping backup/AV services before encrypting files).",
            SuggestedAction  = "IMMEDIATE: disconnect from network, do NOT reboot (keys may be in RAM), take a snapshot, contact incident response. Check backup integrity before restoring.",
            RequiresApproval = true,
            MitreAttack      = new MitreAttackInfo("T1486", "Data Encrypted for Impact", "Impact"),
        };
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static bool ContainsAny(Alert alert, params string[] keywords)
    {
        var combined = $"{alert.Title} {alert.Message}".ToLowerInvariant();
        return keywords.Any(k => combined.Contains(k, StringComparison.OrdinalIgnoreCase));
    }
}
