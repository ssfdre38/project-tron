using System.Text.Json.Serialization;

namespace Tron.Core.Models;

/// <summary>Rolling statistical baseline for a named metric (e.g. "cpu.usage", "mem.usage").</summary>
public class MetricBaseline
{
    public string MetricKey { get; set; } = "";
    public int SampleCount { get; set; }
    public double Mean { get; set; }
    public double M2 { get; set; }  // Welford's online algorithm accumulator
    public double Min { get; set; } = double.MaxValue;
    public double Max { get; set; } = double.MinValue;
    public DateTimeOffset FirstSeen { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset LastUpdated { get; set; } = DateTimeOffset.UtcNow;

    [JsonIgnore]
    public double Variance => SampleCount > 1 ? M2 / (SampleCount - 1) : 0;

    [JsonIgnore]
    public double StdDev => Math.Sqrt(Variance);

    /// <summary>Returns z-score for the given value (how many std-devs from the mean).</summary>
    public double ZScore(double value) => StdDev > 0 ? (value - Mean) / StdDev : 0;

    /// <summary>Update the running statistics with a new sample (Welford's algorithm).</summary>
    public void Update(double value)
    {
        SampleCount++;
        var delta = value - Mean;
        Mean += delta / SampleCount;
        var delta2 = value - Mean;
        M2 += delta * delta2;
        if (value < Min) Min = value;
        if (value > Max) Max = value;
        LastUpdated = DateTimeOffset.UtcNow;
    }

    /// <summary>True once we have enough samples to trust the baseline.</summary>
    [JsonIgnore]
    public bool IsReady => SampleCount >= 20;
}

public class BaselineStore
{
    public Dictionary<string, MetricBaseline> Metrics { get; set; } = [];
    public HashSet<string> KnownProcessNames { get; set; } = [];
    public HashSet<string> KnownRemoteHosts { get; set; } = [];
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset LastSavedAt { get; set; } = DateTimeOffset.UtcNow;
}
