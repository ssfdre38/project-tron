namespace Tron.Core.Models;

public record SystemSnapshot
{
    public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.UtcNow;
    public CpuMetrics Cpu { get; init; } = new();
    public MemoryMetrics Memory { get; init; } = new();
    public List<DiskMetrics> Disks { get; init; } = [];
    public List<NetworkMetrics> Network { get; init; } = [];
    public List<ServiceStatus> Services { get; init; } = [];
    public List<ProcessInfo> TopProcesses { get; init; } = [];
    public List<SecurityEvent> RecentSecurityEvents { get; init; } = [];
}

public record CpuMetrics
{
    public float UsagePercent { get; init; }
    public int LogicalCoreCount { get; init; }
    public float? TemperatureCelsius { get; init; }
}

public record MemoryMetrics
{
    public long TotalBytes { get; init; }
    public long AvailableBytes { get; init; }
    public float UsagePercent => TotalBytes > 0 ? (float)(TotalBytes - AvailableBytes) / TotalBytes * 100 : 0;
}

public record DiskMetrics
{
    public string Drive { get; init; } = "";
    public long TotalBytes { get; init; }
    public long FreeBytes { get; init; }
    public float UsagePercent => TotalBytes > 0 ? (float)(TotalBytes - FreeBytes) / TotalBytes * 100 : 0;
    public float ReadBytesPerSec { get; init; }
    public float WriteBytesPerSec { get; init; }
}

public record NetworkMetrics
{
    public string Interface { get; init; } = "";
    public float BytesReceivedPerSec { get; init; }
    public float BytesSentPerSec { get; init; }
}

public record ServiceStatus
{
    public string Name { get; init; } = "";
    public string DisplayName { get; init; } = "";
    public string Status { get; init; } = "";
    public bool IsWatched { get; init; }
}

public record ProcessInfo
{
    public int Pid { get; init; }
    public string Name { get; init; } = "";
    public float CpuPercent { get; init; }
    public long MemoryBytes { get; init; }
    public bool IsWatched { get; init; }
}

public record SecurityEvent
{
    public DateTimeOffset Timestamp { get; init; }
    public string EventId { get; init; } = "";
    public string Source { get; init; } = "";
    public string Message { get; init; } = "";
    public SecuritySeverity Severity { get; init; }
}

public enum SecuritySeverity { Info, Warning, Critical }
