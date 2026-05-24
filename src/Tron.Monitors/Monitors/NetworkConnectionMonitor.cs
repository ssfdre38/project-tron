using Tron.Core.Interfaces;
using Tron.Core.Models;

namespace Tron.Monitors.Monitors;

/// <summary>
/// Monitors active network connections for suspicious activity:
/// unusual outbound connections, known-bad ports, unexpected listeners.
/// </summary>
public sealed class NetworkConnectionMonitor : IMonitor
{
    public string Name => "NetworkConnection";

    // Ports commonly abused by malware / C2 frameworks
    private static readonly HashSet<int> SuspiciousRemotePorts = [4444, 1337, 31337, 8888, 9999, 6666, 6667, 6668, 6669];

    // Ports that should only ever be listening locally, not connecting outbound
    private static readonly HashSet<int> LocalOnlyPorts = [445, 3389, 5985, 5986];

    public Task<IEnumerable<Alert>> CheckAsync(SystemSnapshot snapshot, CancellationToken ct = default)
    {
        var alerts = new List<Alert>();
        var established = snapshot.Connections
            .Where(c => c.State == "ESTABLISHED" || c.State == "Established")
            .ToList();

        // Suspicious remote ports
        var suspiciousConns = established
            .Where(c => SuspiciousRemotePorts.Contains(c.RemotePort))
            .ToList();

        foreach (var conn in suspiciousConns)
        {
            alerts.Add(new Alert
            {
                Severity = AlertSeverity.Critical,
                Category = AlertCategory.Security,
                Title = "Suspicious Outbound Connection",
                Message = $"Process '{conn.OwningProcess}' (PID {conn.OwningPid}) has an established connection to {conn.RemoteAddress}:{conn.RemotePort} — this port is commonly used by malware/C2 frameworks.",
                SuggestedAction = $"Block {conn.RemoteAddress} in Windows Firewall and investigate process {conn.OwningProcess}.",
                RequiresApproval = true
            });
        }

        // Services making unexpected outbound connections on admin-only ports
        var adminPortAbuse = established
            .Where(c => LocalOnlyPorts.Contains(c.LocalPort) && !IsPrivateAddress(c.RemoteAddress))
            .ToList();

        foreach (var conn in adminPortAbuse)
        {
            alerts.Add(new Alert
            {
                Severity = AlertSeverity.Warning,
                Category = AlertCategory.Security,
                Title = $"Unexpected Outbound on Port {conn.LocalPort}",
                Message = $"Port {conn.LocalPort} has an outbound connection to external address {conn.RemoteAddress}:{conn.RemotePort} via process '{conn.OwningProcess}'. This port should only be local.",
            });
        }

        // Detect potential port scanning: many CLOSE_WAIT / SYN_SENT to different hosts
        var synSent = snapshot.Connections
            .Where(c => c.State is "SYN_SENT" or "SYN_WAIT")
            .ToList();

        if (synSent.Count >= 10)
        {
            var distinctHosts = synSent.Select(c => c.RemoteAddress).Distinct().Count();
            if (distinctHosts >= 5)
            {
                alerts.Add(new Alert
                {
                    Severity = AlertSeverity.Warning,
                    Category = AlertCategory.Security,
                    Title = "Possible Port Scan / Network Sweep",
                    Message = $"{synSent.Count} outbound SYN connections to {distinctHosts} distinct hosts detected. This may indicate a network scan originating from this server.",
                    SuggestedAction = "Check which process is responsible and review firewall outbound rules."
                });
            }
        }

        return Task.FromResult<IEnumerable<Alert>>(alerts);
    }

    private static bool IsPrivateAddress(string address)
    {
        if (!System.Net.IPAddress.TryParse(address, out var ip)) return false;
        var bytes = ip.GetAddressBytes();
        if (bytes.Length != 4) return false;
        return bytes[0] == 10 ||
               (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
               (bytes[0] == 192 && bytes[1] == 168) ||
               bytes[0] == 127;
    }
}
