using Tron.Core.Models;

namespace Tron.Core.Services;

/// <summary>
/// Maps Tron alert context to MITRE ATT&amp;CK technique IDs.
/// Uses the alert category and title/message keywords to assign the closest technique.
/// Reference: https://attack.mitre.org/
/// </summary>
public static class MitreAttackMapper
{
    // Well-known techniques used for quick lookup by category + keyword
    private static readonly MitreAttackInfo T1110     = new("T1110",     "Brute Force",                           "Credential Access");
    private static readonly MitreAttackInfo T1110_001 = new("T1110.001", "Password Guessing",                     "Credential Access");
    private static readonly MitreAttackInfo T1078     = new("T1078",     "Valid Accounts",                        "Defense Evasion");
    private static readonly MitreAttackInfo T1036     = new("T1036",     "Masquerading",                          "Defense Evasion");
    private static readonly MitreAttackInfo T1036_005 = new("T1036.005", "Match Legitimate Name or Location",     "Defense Evasion");
    private static readonly MitreAttackInfo T1059     = new("T1059",     "Command and Scripting Interpreter",     "Execution");
    private static readonly MitreAttackInfo T1204     = new("T1204",     "User Execution",                        "Execution");
    private static readonly MitreAttackInfo T1046     = new("T1046",     "Network Service Discovery",             "Discovery");
    private static readonly MitreAttackInfo T1021_001 = new("T1021.001", "Remote Desktop Protocol",               "Lateral Movement");
    private static readonly MitreAttackInfo T1021_002 = new("T1021.002", "SMB/Windows Admin Shares",              "Lateral Movement");
    private static readonly MitreAttackInfo T1021_006 = new("T1021.006", "Windows Remote Management",             "Lateral Movement");
    private static readonly MitreAttackInfo T1071     = new("T1071",     "Application Layer Protocol",            "Command and Control");
    private static readonly MitreAttackInfo T1071_001 = new("T1071.001", "Web Protocols",                         "Command and Control");
    private static readonly MitreAttackInfo T1095     = new("T1095",     "Non-Application Layer Protocol",        "Command and Control");
    private static readonly MitreAttackInfo T1571     = new("T1571",     "Non-Standard Port",                     "Command and Control");
    private static readonly MitreAttackInfo T1041     = new("T1041",     "Exfiltration Over C2 Channel",          "Exfiltration");
    private static readonly MitreAttackInfo T1496     = new("T1496",     "Resource Hijacking",                    "Impact");
    private static readonly MitreAttackInfo T1489     = new("T1489",     "Service Stop",                          "Impact");
    private static readonly MitreAttackInfo T1562_002 = new("T1562.002", "Disable Windows Event Logging",         "Defense Evasion");
    private static readonly MitreAttackInfo T1562     = new("T1562",     "Impair Defenses",                       "Defense Evasion");

    /// <summary>
    /// Returns the best-matching MITRE ATT&amp;CK technique for the given alert,
    /// or null if no confident match can be made.
    /// </summary>
    public static MitreAttackInfo? Map(Alert alert)
    {
        var combined = $"{alert.Title} {alert.Message}".ToLowerInvariant();

        return alert.Category switch
        {
            AlertCategory.Security    => MapSecurity(combined),
            AlertCategory.Process     => MapProcess(combined),
            AlertCategory.Network     => MapNetwork(combined),
            AlertCategory.Service     => MapService(combined),
            AlertCategory.ThreatIntel => MapThreatIntel(combined),
            AlertCategory.Cpu or AlertCategory.Memory => MapResourceAbuse(combined),
            _ => null
        };
    }

    private static MitreAttackInfo? MapSecurity(string text)
    {
        if (text.Contains("audit policy") || text.Contains("4719"))
            return T1562_002;
        if (text.Contains("brute") || text.Contains("repeated") || text.Contains("4625") || text.Contains("failed_login"))
            return T1110;
        if (text.Contains("password") || text.Contains("guess"))
            return T1110_001;
        if (text.Contains("logon") || text.Contains("login") || text.Contains("4624") || text.Contains("4648"))
            return T1078;
        if (text.Contains("impair") || text.Contains("disable"))
            return T1562;
        return null;
    }

    private static MitreAttackInfo? MapProcess(string text)
    {
        if (text.Contains("masquerad") || text.Contains("unexpected path") || text.Contains("system process"))
            return T1036;
        if (text.Contains("suspicious location") || text.Contains("temp") || text.Contains("appdata"))
            return T1036_005;
        if (text.Contains("script") || text.Contains("powershell") || text.Contains("cmd") || text.Contains("bash"))
            return T1059;
        if (text.Contains("new process") || text.Contains("newly observed") || text.Contains("unknown"))
            return T1204;
        return null;
    }

    private static MitreAttackInfo MapNetwork(string text)
    {
        if (text.Contains("port scan") || text.Contains("scanning"))
            return T1046;
        if (text.Contains("rdp") || text.Contains("3389"))
            return T1021_001;
        if (text.Contains("smb") || text.Contains("445"))
            return T1021_002;
        if (text.Contains("winrm") || text.Contains("5985") || text.Contains("5986"))
            return T1021_006;
        if (text.Contains("c2") || text.Contains("4444") || text.Contains("31337") || text.Contains("1337"))
            return T1095;
        if (text.Contains("non-standard") || text.Contains("unusual port"))
            return T1571;
        return T1071;
    }

    private static MitreAttackInfo? MapService(string text)
    {
        if (text.Contains("stop") || text.Contains("down") || text.Contains("not running"))
            return T1489;
        return null;
    }

    private static MitreAttackInfo MapThreatIntel(string text)
    {
        if (text.Contains("exfil") || text.Contains("upload"))
            return T1041;
        if (text.Contains("c2") || text.Contains("command") || text.Contains("control"))
            return T1095;
        return T1071_001;
    }

    private static MitreAttackInfo? MapResourceAbuse(string text)
    {
        if (text.Contains("high cpu") || text.Contains("high memory") || text.Contains("runaway") || text.Contains("spike"))
            return T1496;
        return null;
    }
}
