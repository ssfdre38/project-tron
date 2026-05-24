using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Tron.Core.Config;
using Tron.Core.Interfaces;
using Tron.Core.Models;

namespace Tron.Monitors.Collectors;

/// <summary>
/// Cross-platform metrics collector for Linux and macOS.
/// Uses /proc filesystem on Linux and command-line tools on macOS.
/// </summary>
public sealed class UnixMetricsCollector : IMetricsCollector
{
    private readonly TronOptions _opts;
    private readonly ILogger<UnixMetricsCollector> _log;

    // CPU delta state
    private (long idle, long total) _lastCpuStat;

    // Network delta state
    private Dictionary<string, (long rx, long tx)> _lastNetStats = [];
    private DateTime _lastNetTime = DateTime.MinValue;

    public UnixMetricsCollector(IOptions<TronOptions> opts, ILogger<UnixMetricsCollector> log)
    {
        _opts = opts.Value;
        _log = log;
        TryReadLinuxCpuStat(out _lastCpuStat);
        _lastNetTime = DateTime.UtcNow;
        _lastNetStats = ReadNetStats();
    }

    public async Task<SystemSnapshot> CollectAsync(CancellationToken ct = default)
    {
        var cpu = CollectCpu();
        var memory = CollectMemory();
        var disks = CollectDisks();
        var network = CollectNetwork();
        var services = await CollectServicesAsync(ct);
        var processes = CollectTopProcesses();
        var connections = await CollectConnectionsAsync(ct);
        var secEvents = await CollectSecurityEventsAsync(ct);

        return new SystemSnapshot
        {
            Cpu = cpu,
            Memory = memory,
            Disks = disks,
            Network = network,
            Services = services,
            TopProcesses = processes,
            Connections = connections,
            RecentSecurityEvents = secEvents
        };
    }

    // ─── CPU ─────────────────────────────────────────────────────────────────

    private CpuMetrics CollectCpu()
    {
        float usage = 0;
        try
        {
            if (OperatingSystem.IsLinux())
            {
                if (TryReadLinuxCpuStat(out var current))
                {
                    var idleDelta = current.idle - _lastCpuStat.idle;
                    var totalDelta = current.total - _lastCpuStat.total;
                    usage = totalDelta > 0 ? (1f - (float)idleDelta / totalDelta) * 100f : 0;
                    _lastCpuStat = current;
                }
            }
            else if (OperatingSystem.IsMacOS())
            {
                usage = GetMacOsCpuUsage();
            }
        }
        catch (Exception ex) { _log.LogWarning(ex, "Failed to collect CPU metrics"); }
        return new CpuMetrics { UsagePercent = Math.Clamp(usage, 0, 100), LogicalCoreCount = Environment.ProcessorCount };
    }

    private static bool TryReadLinuxCpuStat(out (long idle, long total) stat)
    {
        stat = (0, 0);
        try
        {
            var line = File.ReadLines("/proc/stat").FirstOrDefault(l => l.StartsWith("cpu "));
            if (line == null) return false;
            var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 5) return false;
            var user    = long.Parse(parts[1]);
            var nice    = long.Parse(parts[2]);
            var system  = long.Parse(parts[3]);
            var idle    = long.Parse(parts[4]);
            var iowait  = parts.Length > 5 ? long.Parse(parts[5]) : 0;
            var irq     = parts.Length > 6 ? long.Parse(parts[6]) : 0;
            var softirq = parts.Length > 7 ? long.Parse(parts[7]) : 0;
            var total   = user + nice + system + idle + iowait + irq + softirq;
            stat = (idle + iowait, total);
            return true;
        }
        catch { return false; }
    }

    private static float GetMacOsCpuUsage()
    {
        // iostat -c 2 gives two snapshots; parse the last line's idle column
        try
        {
            using var p = RunProcess("iostat", "-c 2");
            var output = p.StandardOutput.ReadToEnd();
            p.WaitForExit(4000);
            var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            if (lines.Length >= 2)
            {
                var cols = lines[^1].Trim().Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                // iostat output ends with idle% as the last column
                if (float.TryParse(cols[^1], System.Globalization.NumberStyles.Float,
                        System.Globalization.CultureInfo.InvariantCulture, out var idle))
                    return 100f - idle;
            }
        }
        catch { }
        return 0;
    }

    // ─── Memory ──────────────────────────────────────────────────────────────

    private MemoryMetrics CollectMemory()
    {
        try
        {
            if (OperatingSystem.IsLinux())  return ReadLinuxMeminfo();
            if (OperatingSystem.IsMacOS())  return GetMacOsMemory();
        }
        catch (Exception ex) { _log.LogWarning(ex, "Failed to collect memory metrics"); }
        return new MemoryMetrics();
    }

    private static MemoryMetrics ReadLinuxMeminfo()
    {
        var info = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in File.ReadLines("/proc/meminfo"))
        {
            var parts = line.Split(':', 2);
            if (parts.Length == 2 &&
                long.TryParse(parts[1].Trim().Split(' ')[0], out var val))
                info[parts[0].Trim()] = val;
        }
        var total     = info.TryGetValue("MemTotal",     out var t) ? t * 1024 : 0;
        var available = info.TryGetValue("MemAvailable", out var a) ? a * 1024 : 0;
        return new MemoryMetrics { TotalBytes = total, AvailableBytes = available };
    }

    private static MemoryMetrics GetMacOsMemory()
    {
        long total = 0, available = 0;
        try
        {
            using var p1 = RunProcess("sysctl", "-n hw.memsize");
            if (long.TryParse(p1.StandardOutput.ReadToEnd().Trim(), out total)) { }
            p1.WaitForExit(2000);

            using var p2 = RunProcess("vm_stat", "");
            var vmOutput = p2.StandardOutput.ReadToEnd();
            p2.WaitForExit(2000);

            long pageSize = 4096;
            long free = 0, inactive = 0;
            foreach (var line in vmOutput.Split('\n'))
            {
                var pageSizeMatch = Regex.Match(line, @"page size of (\d+) bytes");
                if (pageSizeMatch.Success) { pageSize = long.Parse(pageSizeMatch.Groups[1].Value); continue; }
                if (line.StartsWith("Pages free:"))     free     = ParseVmStatLine(line);
                if (line.StartsWith("Pages inactive:")) inactive = ParseVmStatLine(line);
            }
            available = (free + inactive) * pageSize;
        }
        catch { }
        return new MemoryMetrics { TotalBytes = total, AvailableBytes = available };
    }

    private static long ParseVmStatLine(string line)
    {
        var parts = line.Split(':', 2);
        return parts.Length == 2 && long.TryParse(parts[1].Trim().TrimEnd('.'), out var v) ? v : 0;
    }

    // ─── Disk ─────────────────────────────────────────────────────────────────

    private List<DiskMetrics> CollectDisks()
    {
        var results = new List<DiskMetrics>();
        try
        {
            foreach (var drive in DriveInfo.GetDrives().Where(d => d.IsReady))
            {
                results.Add(new DiskMetrics
                {
                    Drive = drive.Name,
                    TotalBytes = drive.TotalSize,
                    FreeBytes = drive.AvailableFreeSpace
                });
            }
        }
        catch (Exception ex) { _log.LogWarning(ex, "Failed to collect disk metrics"); }
        return results;
    }

    // ─── Network ──────────────────────────────────────────────────────────────

    private List<NetworkMetrics> CollectNetwork()
    {
        var results = new List<NetworkMetrics>();
        try
        {
            var now = DateTime.UtcNow;
            var current = ReadNetStats();
            var elapsed = (now - _lastNetTime).TotalSeconds;

            foreach (var (iface, cur) in current)
            {
                float rxPerSec = 0, txPerSec = 0;
                if (elapsed > 0 && _lastNetStats.TryGetValue(iface, out var prev))
                {
                    rxPerSec = (float)Math.Max(0, (cur.rx - prev.rx) / elapsed);
                    txPerSec = (float)Math.Max(0, (cur.tx - prev.tx) / elapsed);
                }
                results.Add(new NetworkMetrics
                {
                    Interface = iface,
                    BytesReceivedPerSec = rxPerSec,
                    BytesSentPerSec = txPerSec
                });
            }
            _lastNetStats = current;
            _lastNetTime = now;
        }
        catch (Exception ex) { _log.LogWarning(ex, "Failed to collect network metrics"); }
        return results;
    }

    private static Dictionary<string, (long rx, long tx)> ReadNetStats()
    {
        var stats = new Dictionary<string, (long rx, long tx)>();
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces()
                         .Where(n => n.OperationalStatus == OperationalStatus.Up &&
                                     n.NetworkInterfaceType != NetworkInterfaceType.Loopback))
            {
                var s = ni.GetIPv4Statistics();
                stats[ni.Name] = (s.BytesReceived, s.BytesSent);
            }
        }
        catch { }
        return stats;
    }

    // ─── Services ─────────────────────────────────────────────────────────────

    private Task<List<ServiceStatus>> CollectServicesAsync(CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            var watched = _opts.WatchedServices.Names;
            if (watched.Count == 0) return new List<ServiceStatus>();

            var results = new List<ServiceStatus>();
            foreach (var name in watched)
            {
                var status = await GetServiceStatusAsync(name, ct);
                results.Add(new ServiceStatus { Name = name, DisplayName = name, Status = status, IsWatched = true });
            }
            return results;
        }, ct);
    }

    private static async Task<string> GetServiceStatusAsync(string name, CancellationToken ct)
    {
        try
        {
            if (OperatingSystem.IsLinux())
            {
                using var p = RunProcess("systemctl", $"is-active {name}");
                var output = (await p.StandardOutput.ReadToEndAsync(ct)).Trim();
                await p.WaitForExitAsync(ct);
                return output == "active" ? "Running" : output;
            }
            if (OperatingSystem.IsMacOS())
            {
                using var p = RunProcess("launchctl", $"list {name}");
                await p.WaitForExitAsync(ct);
                return p.ExitCode == 0 ? "Running" : "Stopped";
            }
        }
        catch { }
        return "Unknown";
    }

    // ─── Processes ────────────────────────────────────────────────────────────

    private static List<ProcessInfo> CollectTopProcesses(int top = 20)
    {
        try
        {
            return Process.GetProcesses()
                .Select(p =>
                {
                    try
                    {
                        var path = "";
                        try { path = p.MainModule?.FileName ?? ""; } catch { }
                        DateTimeOffset? startTime = null;
                        try { startTime = p.StartTime.ToUniversalTime(); } catch { }
                        return new ProcessInfo
                        {
                            Pid = p.Id,
                            Name = p.ProcessName,
                            ExecutablePath = path,
                            MemoryBytes = p.WorkingSet64,
                            StartTime = startTime
                        };
                    }
                    catch { return null; }
                })
                .Where(p => p != null)
                .OrderByDescending(p => p!.MemoryBytes)
                .Take(top)
                .Select(p => p!)
                .ToList();
        }
        catch { return []; }
    }

    // ─── Network Connections ──────────────────────────────────────────────────

    private static Task<List<NetworkConnection>> CollectConnectionsAsync(CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            if (OperatingSystem.IsLinux())  return await ReadProcNetTcpAsync(ct);
            if (OperatingSystem.IsMacOS())  return await ReadMacNetstatAsync(ct);
            return new List<NetworkConnection>();
        }, ct);
    }

    private static async Task<List<NetworkConnection>> ReadProcNetTcpAsync(CancellationToken ct)
    {
        var results = new List<NetworkConnection>();
        try
        {
            var pidMap = BuildLinuxPidMap();
            foreach (var file in new[] { "/proc/net/tcp", "/proc/net/tcp6" })
            {
                if (!File.Exists(file)) continue;
                var lines = await File.ReadAllLinesAsync(file, ct);
                foreach (var line in lines.Skip(1))
                {
                    var parts = line.Trim().Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length < 10) continue;

                    var localHex  = parts[1];
                    var remoteHex = parts[2];
                    var stateHex  = parts[3];
                    var inode     = parts[9];

                    var state = int.TryParse(stateHex, System.Globalization.NumberStyles.HexNumber, null, out var s) ? s : 0;
                    var local  = ParseHexSocketAddr(localHex);
                    var remote = ParseHexSocketAddr(remoteHex);

                    results.Add(new NetworkConnection
                    {
                        Protocol       = "TCP",
                        LocalAddress   = local.addr,
                        LocalPort      = local.port,
                        RemoteAddress  = remote.addr,
                        RemotePort     = remote.port,
                        State          = LinuxTcpStateToString(state),
                        OwningProcess  = pidMap.TryGetValue(inode, out var name) ? name : "?"
                    });
                }
            }
        }
        catch { }
        return results;
    }

    /// <summary>Builds an inode → process-name map by scanning /proc/PID/fd symlinks.</summary>
    private static Dictionary<string, string> BuildLinuxPidMap()
    {
        var map = new Dictionary<string, string>();
        try
        {
            foreach (var pidDir in Directory.GetDirectories("/proc")
                         .Where(d => int.TryParse(Path.GetFileName(d), out _)))
            {
                var pid = Path.GetFileName(pidDir);
                string comm;
                try { comm = File.ReadAllText($"/proc/{pid}/comm").Trim(); }
                catch { continue; }

                var fdDir = $"/proc/{pid}/fd";
                if (!Directory.Exists(fdDir)) continue;
                try
                {
                    foreach (var fd in Directory.GetFiles(fdDir))
                    {
                        try
                        {
                            var target = new FileInfo(fd).LinkTarget ?? "";
                            if (target.StartsWith("socket:["))
                                map.TryAdd(target[8..^1], comm);
                        }
                        catch { }
                    }
                }
                catch { }
            }
        }
        catch { }
        return map;
    }

    private static (string addr, int port) ParseHexSocketAddr(string hex)
    {
        try
        {
            var colon = hex.LastIndexOf(':');
            if (colon < 0) return (hex, 0);
            var addrHex = hex[..colon];
            var port    = Convert.ToInt32(hex[(colon + 1)..], 16);
            string addr;
            if (addrHex.Length == 8) // IPv4 little-endian
            {
                var bytes = Convert.FromHexString(addrHex);
                Array.Reverse(bytes);
                addr = string.Join('.', bytes);
            }
            else if (addrHex.Length == 32) // IPv6: four little-endian 32-bit words
            {
                var ipBytes = Enumerable.Range(0, 4)
                    .SelectMany(i =>
                    {
                        var word = Convert.FromHexString(addrHex.Substring(i * 8, 8));
                        Array.Reverse(word);
                        return word;
                    })
                    .ToArray();
                addr = new System.Net.IPAddress(ipBytes).ToString();
            }
            else { addr = addrHex; }
            return (addr, port);
        }
        catch { return (hex, 0); }
    }

    private static string LinuxTcpStateToString(int state) => state switch
    {
        0x01 => "ESTABLISHED", 0x02 => "SYN_SENT",   0x03 => "SYN_RECV",
        0x04 => "FIN_WAIT1",   0x05 => "FIN_WAIT2",  0x06 => "TIME_WAIT",
        0x07 => "CLOSE",       0x08 => "CLOSE_WAIT", 0x09 => "LAST_ACK",
        0x0A => "LISTEN",      0x0B => "CLOSING",
        _ => "UNKNOWN"
    };

    private static async Task<List<NetworkConnection>> ReadMacNetstatAsync(CancellationToken ct)
    {
        var results = new List<NetworkConnection>();
        try
        {
            using var p = RunProcess("netstat", "-anp tcp");
            var output = await p.StandardOutput.ReadToEndAsync(ct);
            await p.WaitForExitAsync(ct);

            foreach (var line in output.Split('\n').Skip(2))
            {
                var parts = line.Trim().Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 5 || !parts[0].StartsWith("tcp")) continue;
                var local  = ParseDotNotationAddr(parts[3]);
                var remote = ParseDotNotationAddr(parts[4]);
                results.Add(new NetworkConnection
                {
                    Protocol      = "TCP",
                    LocalAddress  = local.addr,
                    LocalPort     = local.port,
                    RemoteAddress = remote.addr,
                    RemotePort    = remote.port,
                    State         = parts.Length >= 6 ? parts[5] : "UNKNOWN"
                });
            }
        }
        catch { }
        return results;
    }

    private static (string addr, int port) ParseDotNotationAddr(string s)
    {
        var last = s.LastIndexOf('.');
        if (last < 0) return (s, 0);
        var port = int.TryParse(s[(last + 1)..], out var p) ? p : 0;
        return (s[..last], port);
    }

    // ─── Security Events ──────────────────────────────────────────────────────

    private static Task<List<SecurityEvent>> CollectSecurityEventsAsync(CancellationToken ct)
    {
        if (OperatingSystem.IsLinux())  return ReadLinuxAuthEventsAsync(ct);
        // macOS: 'log show' is too slow for a polling loop — skip; users can forward to Discord manually
        return Task.FromResult(new List<SecurityEvent>());
    }

    private static async Task<List<SecurityEvent>> ReadLinuxAuthEventsAsync(CancellationToken ct)
    {
        // Try journald first (most modern distros)
        var journalResults = await ReadJournaldAsync(ct);
        if (journalResults.Count > 0) return journalResults;

        // Fallback: parse auth.log / secure
        return await ParseAuthLogAsync(ct);
    }

    private static async Task<List<SecurityEvent>> ReadJournaldAsync(CancellationToken ct)
    {
        var results = new List<SecurityEvent>();
        try
        {
            using var p = RunProcess("journalctl",
                "-u ssh -u sshd --since '1 hour ago' -o short --no-pager -p warning");
            var output = await p.StandardOutput.ReadToEndAsync(ct);
            await p.WaitForExitAsync(ct);
            if (p.ExitCode != 0) return results;

            foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                if (!line.Contains("Failed") && !line.Contains("Invalid") && !line.Contains("error")) continue;
                results.Add(new SecurityEvent
                {
                    Timestamp  = DateTimeOffset.UtcNow,
                    EventId    = "ssh_warning",
                    Source     = "journald/sshd",
                    Message    = line.Length > 300 ? line[..300] : line,
                    Severity   = SecuritySeverity.Warning
                });
            }
        }
        catch { }
        return results;
    }

    private static async Task<List<SecurityEvent>> ParseAuthLogAsync(CancellationToken ct)
    {
        var results = new List<SecurityEvent>();
        foreach (var logFile in new[] { "/var/log/auth.log", "/var/log/secure" })
        {
            if (!File.Exists(logFile)) continue;
            try
            {
                var lines = await File.ReadAllLinesAsync(logFile, ct);
                foreach (var line in lines.TakeLast(500))
                {
                    SecurityEvent? ev = null;
                    if (line.Contains("Failed password") || line.Contains("authentication failure"))
                        ev = new SecurityEvent
                        {
                            Timestamp = DateTimeOffset.UtcNow, EventId = "failed_login",
                            Source = "auth", Message = line.Length > 300 ? line[..300] : line,
                            Severity = SecuritySeverity.Warning
                        };
                    else if (line.Contains("sudo:") && line.Contains("COMMAND="))
                        ev = new SecurityEvent
                        {
                            Timestamp = DateTimeOffset.UtcNow, EventId = "sudo_command",
                            Source = "sudo", Message = line.Length > 300 ? line[..300] : line,
                            Severity = SecuritySeverity.Info
                        };
                    if (ev != null) results.Add(ev);
                }
                if (results.Count > 0) break;
            }
            catch { }
        }
        return results;
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────

    private static Process RunProcess(string exe, string args)
    {
        var p = new Process
        {
            StartInfo = new ProcessStartInfo(exe, args)
            {
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
                UseShellExecute        = false,
                CreateNoWindow         = true
            }
        };
        p.Start();
        return p;
    }
}
