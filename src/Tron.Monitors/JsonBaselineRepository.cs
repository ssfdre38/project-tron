using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Tron.Core.Config;
using Tron.Core.Interfaces;
using Tron.Core.Models;

namespace Tron.Monitors;

/// <summary>
/// Persists the baseline store to a JSON file.
/// </summary>
public sealed class JsonBaselineRepository : IBaselineRepository
{
    private readonly string _path;
    private readonly ILogger<JsonBaselineRepository> _log;
    private static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = true };

    public JsonBaselineRepository(IOptions<TronOptions> opts, ILogger<JsonBaselineRepository> log)
    {
        _path = opts.Value.Baseline.StorePath;
        _log = log;
    }

    public async Task<BaselineStore> LoadAsync(CancellationToken ct = default)
    {
        if (!File.Exists(_path))
        {
            _log.LogInformation("[baseline] No baseline file found at {Path} — starting fresh.", _path);
            return new BaselineStore();
        }

        try
        {
            var json = await File.ReadAllTextAsync(_path, ct);
            return JsonSerializer.Deserialize<BaselineStore>(json) ?? new BaselineStore();
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "[baseline] Failed to load baseline file — starting fresh.");
            return new BaselineStore();
        }
    }

    public async Task SaveAsync(BaselineStore store, CancellationToken ct = default)
    {
        store.LastSavedAt = DateTimeOffset.UtcNow;
        try
        {
            var json = JsonSerializer.Serialize(store, JsonOpts);
            await File.WriteAllTextAsync(_path, json, ct);
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "[baseline] Failed to save baseline file.");
        }
    }
}
