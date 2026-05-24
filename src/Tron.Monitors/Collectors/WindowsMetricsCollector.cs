using System.Diagnostics;
using System.Management;
using System.Runtime.Versioning;
using System.ServiceProcess;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;using Tron.Core.Config;
using Tron.Core.Interfaces;
using Tron.Core.Models;

namespace Tron.Monitors.Collectors;

/// <summary>Collects a full system snapshot using Windows Performance Counters + WMI + SCM.</summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsMetricsCollector : IMetricsCollector, IDisposable
{
    private readonly TronOptions _opts;
    private readonly ILogger<WindowsMetricsCollector> _log;

    private readonly PerformanceCounter _cpuCounter;
    private readonly Dictionary<string, PerformanceCounter[]> _diskCounters = [];
    private readonly Dictionary<string, PerformanceCounter[]> _netCounters = [];

    // Security event IDs worth tracking (use int for InstanceId comparison)
    private static readonly HashSet<int> WatchedEventIds = new() { 4625, 4648, 4719, 4728, 4732, 4756, 4776, 7045 };

    public WindowsMetricsCollector(IOptions<TronOptions> opts, ILogger<WindowsMetricsCollector> log)
    {
        _opts = opts.Value;
        _log = log;
        _cpuCounter = new PerformanceCounter("Processor", "% Processor Time", "_Total", readOnly: true);
        InitDiskCounters();
        InitNetCounters();
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
        var secEvents = CollectSecurityEvents();

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

    private CpuMetrics CollectCpu()
    {
        try
        {
            var usage = _cpuCounter.NextValue();
            // Second read — first read is always 0 for this counter
            System.Threading.Thread.Sleep(100);
            usage = _cpuCounter.NextValue();
            return new CpuMetrics
            {
                UsagePercent = usage,
                LogicalCoreCount = Environment.ProcessorCount
            };
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Failed to read CPU counter");
            return new CpuMetrics { LogicalCoreCount = Environment.ProcessorCount };
        }
    }

    private static MemoryMetrics CollectMemory()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT TotalVisibleMemorySize, FreePhysicalMemory FROM Win32_OperatingSystem");
            foreach (ManagementObject obj in searcher.Get())
            {
                var total = Convert.ToInt64(obj["TotalVisibleMemorySize"]) * 1024;
                var free = Convert.ToInt64(obj["FreePhysicalMemory"]) * 1024;
                return new MemoryMetrics { TotalBytes = total, AvailableBytes = free };
            }
        }
        catch { /* fall through */ }
        return new MemoryMetrics();
    }

    private List<DiskMetrics> CollectDisks()
    {
        var results = new List<DiskMetrics>();
        try
        {
            foreach (var drive in DriveInfo.GetDrives().Where(d => d.IsReady))
            {
                var read = 0f;
                var write = 0f;
                var key = drive.Name.TrimEnd('\\', '/');
                if (_diskCounters.TryGetValue(key, out var counters))
                {
                    read = counters[0].NextValue();
                    write = counters[1].NextValue();
                }
                results.Add(new DiskMetrics
                {
                    Drive = drive.Name,
                    TotalBytes = drive.TotalSize,
                    FreeBytes = drive.AvailableFreeSpace,
                    ReadBytesPerSec = read,
                    WriteBytesPerSec = write
                });
            }
        }
        catch (Exception ex) { _log.LogWarning(ex, "Failed to collect disk metrics"); }
        return results;
    }

    private List<NetworkMetrics> CollectNetwork()
    {
        var results = new List<NetworkMetrics>();
        foreach (var (iface, counters) in _netCounters)
        {
            try
            {
                results.Add(new NetworkMetrics
                {
                    Interface = iface,
                    BytesReceivedPerSec = counters[0].NextValue(),
                    BytesSentPerSec = counters[1].NextValue()
                });
            }
            catch { /* skip broken interface */ }
        }
        return results;
    }

    private Task<List<ServiceStatus>> CollectServicesAsync(CancellationToken ct)
    {
        return Task.Run(() =>
        {
            var watched = _opts.WatchedServices.Names
                .Select(n => n.ToLowerInvariant())
                .ToHashSet();

            var results = new List<ServiceStatus>();
            try
            {
                var services = ServiceController.GetServices();
                foreach (var svc in services)
                {
                    var isWatched = watched.Contains(svc.ServiceName.ToLowerInvariant());
                    if (!isWatched && svc.Status == ServiceControllerStatus.Running) continue;
                    results.Add(new ServiceStatus
                    {
                        Name = svc.ServiceName,
                        DisplayName = svc.DisplayName,
                        Status = svc.Status.ToString(),
                        IsWatched = isWatched
                    });
                }
            }
            catch (Exception ex) { _log.LogWarning(ex, "Failed to collect service status"); }
            return results;
        }, ct);
    }

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
                        return new ProcessInfo
                        {
                            Pid = p.Id,
                            Name = p.ProcessName,
                            ExecutablePath = path,
                            MemoryBytes = p.WorkingSet64,
                            StartTime = TryGetStartTime(p)
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

    private static Task<List<NetworkConnection>> CollectConnectionsAsync(CancellationToken ct)
    {
        return Task.Run(() =>
        {
            var results = new List<NetworkConnection>();
            try
            {
                // Use netstat via WMI MSFT_NetTCPConnection for richer data
                using var searcher = new ManagementObjectSearcher(
                    @"root\StandardCimv2",
                    "SELECT LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess FROM MSFT_NetTCPConnection");

                // Build PID->ProcessName lookup
                var pidNames = Process.GetProcesses()
                    .ToDictionary(p => p.Id, p => { try { return p.ProcessName; } catch { return "?"; } });

                foreach (ManagementObject obj in searcher.Get())
                {
                    var pid = Convert.ToInt32(obj["OwningProcess"]);
                    var stateVal = Convert.ToInt32(obj["State"]);
                    results.Add(new NetworkConnection
                    {
                        Protocol = "TCP",
                        LocalAddress = obj["LocalAddress"]?.ToString() ?? "",
                        LocalPort = Convert.ToInt32(obj["LocalPort"]),
                        RemoteAddress = obj["RemoteAddress"]?.ToString() ?? "",
                        RemotePort = Convert.ToInt32(obj["RemotePort"]),
                        State = TcpStateToString(stateVal),
                        OwningPid = pid,
                        OwningProcess = pidNames.TryGetValue(pid, out var name) ? name : "?"
                    });
                }
            }
            catch
            {
                // MSFT_NetTCPConnection may not be available on all Windows versions — fall back to no connections
            }
            return results;
        }, ct);
    }

    private static string TcpStateToString(int state) => state switch
    {
        1 => "CLOSED", 2 => "LISTEN", 3 => "SYN_SENT", 4 => "SYN_RECEIVED",
        5 => "ESTABLISHED", 6 => "FIN_WAIT1", 7 => "FIN_WAIT2", 8 => "CLOSE_WAIT",
        9 => "CLOSING", 10 => "LAST_ACK", 11 => "TIME_WAIT", 12 => "DELETE_TCB",
        _ => "UNKNOWN"
    };

    private static DateTimeOffset? TryGetStartTime(Process p)
    {
        try { return p.StartTime.ToUniversalTime(); }
        catch { return null; }
    }

    private static List<SecurityEvent> CollectSecurityEvents(int maxEvents = 20)
    {
        var results = new List<SecurityEvent>();
        try
        {
            var log = new EventLog("Security");
            var recent = log.Entries.Cast<EventLogEntry>()
                .Where(e => e.TimeGenerated > DateTime.UtcNow.AddHours(-1)
                         && WatchedEventIds.Contains((int)e.InstanceId))
                .OrderByDescending(e => e.TimeGenerated)
                .Take(maxEvents);

            foreach (var e in recent)
            {
                var instanceId = (int)e.InstanceId;
                results.Add(new SecurityEvent
                {
                    Timestamp = new DateTimeOffset(e.TimeGenerated.ToUniversalTime()),
                    EventId   = instanceId.ToString(),
                    Source    = e.Source,
                    Message   = e.Message.Length > 300 ? e.Message[..300] + "…" : e.Message,
                    Severity  = instanceId == 4625 || instanceId == 4719 ? SecuritySeverity.Warning : SecuritySeverity.Info
                });
            }
        }
        catch { /* Security log may require elevated privileges */ }
        return results;
    }

    private void InitDiskCounters()
    {
        try
        {
            var cat = new PerformanceCounterCategory("LogicalDisk");
            foreach (var instance in cat.GetInstanceNames().Where(n => n != "_Total"))
            {
                _diskCounters[instance] =
                [
                    new PerformanceCounter("LogicalDisk", "Disk Read Bytes/sec", instance, readOnly: true),
                    new PerformanceCounter("LogicalDisk", "Disk Write Bytes/sec", instance, readOnly: true)
                ];
            }
        }
        catch (Exception ex) { _log.LogWarning(ex, "Could not init disk counters"); }
    }

    private void InitNetCounters()
    {
        try
        {
            var cat = new PerformanceCounterCategory("Network Interface");
            foreach (var instance in cat.GetInstanceNames())
            {
                _netCounters[instance] =
                [
                    new PerformanceCounter("Network Interface", "Bytes Received/sec", instance, readOnly: true),
                    new PerformanceCounter("Network Interface", "Bytes Sent/sec", instance, readOnly: true)
                ];
            }
        }
        catch (Exception ex) { _log.LogWarning(ex, "Could not init network counters"); }
    }

    public void Dispose()
    {
        _cpuCounter.Dispose();
        foreach (var c in _diskCounters.Values.SelectMany(x => x)) c.Dispose();
        foreach (var c in _netCounters.Values.SelectMany(x => x)) c.Dispose();
    }
}
