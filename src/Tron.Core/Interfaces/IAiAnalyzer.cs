using Tron.Core.Models;

namespace Tron.Core.Interfaces;

/// <summary>
/// AI analysis layer — takes a collection of alerts and system context, returns a plain-English
/// analysis suitable for sending to Discord (or logging).
/// </summary>
public interface IAiAnalyzer
{
    /// <summary>True if this analyzer is available (model loaded, endpoint reachable, etc.).</summary>
    bool IsAvailable { get; }

    /// <summary>
    /// Analyze a set of alerts in the context of the current system snapshot.
    /// Returns a plain-English summary with context, severity assessment, and recommended action.
    /// </summary>
    Task<string?> AnalyzeAsync(IReadOnlyList<Alert> alerts, SystemSnapshot snapshot, CancellationToken ct = default);
}

/// <summary>Persists and loads the system baseline store.</summary>
public interface IBaselineRepository
{
    Task<BaselineStore> LoadAsync(CancellationToken ct = default);
    Task SaveAsync(BaselineStore store, CancellationToken ct = default);
}
