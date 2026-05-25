using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Tron.Core.Config;
using Tron.Core.Interfaces;
using Tron.Core.Models;

namespace Tron.Alerting.Analyzers;

/// <summary>
/// Sends alert context to a local OpenAI-compatible endpoint (ash-server, llama.cpp server,
/// Ollama, etc.) and returns a plain-English analysis for Discord delivery.
/// </summary>
public sealed class LocalModelAnalyzer : IAiAnalyzer
{
    private readonly HttpClient _http;
    private readonly TronOptions _opts;
    private readonly ILogger<LocalModelAnalyzer> _log;

    public bool IsAvailable => !string.IsNullOrWhiteSpace(_opts.Ai.EndpointUrl);

    public LocalModelAnalyzer(HttpClient http, IOptions<TronOptions> opts, ILogger<LocalModelAnalyzer> log)
    {
        _http = http;
        _opts = opts.Value;
        _log = log;
    }

    public async Task<string?> AnalyzeAsync(IReadOnlyList<Alert> alerts, SystemSnapshot snapshot, CancellationToken ct = default)
    {
        if (!IsAvailable) return null;

        var systemPrompt = """
            You are Tron, an AI security and system monitoring agent running on a Windows Server.
            You receive structured alert data and system telemetry.
            Your job is to provide a concise, plain-English analysis (3-5 sentences max) that:
            1. Summarises what is happening
            2. Assesses the actual risk level (not just the alert severity)
            3. Gives one concrete next step
            Keep it direct — you're talking to a sysadmin on Discord. No bullet points, no headers.
            """;

        var userMessage = BuildUserMessage(alerts, snapshot);

        var requestBody = new
        {
            model = _opts.Ai.Model,
            messages = new[]
            {
                new { role = "system", content = systemPrompt },
                new { role = "user", content = userMessage }
            },
            // 1024 tokens required: Gemma 4 IT uses chain-of-thought reasoning internally (~700 thinking
            // tokens) before producing the actual response. 300 is insufficient — all budget goes to
            // thinking and content comes back empty. 1024 gives ~300 tokens of actual response.
            max_tokens = 1024,
            temperature = 0.3
        };

        var json = JsonSerializer.Serialize(requestBody);
        var requestContent = new StringContent(json, Encoding.UTF8, "application/json");

        try
        {
            var url = _opts.Ai.EndpointUrl!.TrimEnd('/') + "/v1/chat/completions";
            var response = await _http.PostAsync(url, requestContent, ct);
            response.EnsureSuccessStatusCode();

            var responseJson = await response.Content.ReadAsStringAsync(ct);
            using var doc = JsonDocument.Parse(responseJson);
            var message = doc.RootElement
                .GetProperty("choices")[0]
                .GetProperty("message");

            // Primary: content field (populated when model has enough tokens for thinking + response)
            var content = message.TryGetProperty("content", out var c) ? c.GetString() : null;
            if (!string.IsNullOrWhiteSpace(content)) return content;

            // Fallback: reasoning_content (Gemma 4 IT thinking model — rare case where content is empty)
            if (message.TryGetProperty("reasoning_content", out var rc))
            {
                var reasoning = rc.GetString();
                if (!string.IsNullOrWhiteSpace(reasoning))
                {
                    // Extract the last paragraph of reasoning as the final answer
                    var parts = reasoning.Split("\n\n", StringSplitOptions.RemoveEmptyEntries);
                    return parts.LastOrDefault()?.Trim();
                }
            }
            return null;
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "[ai-analyzer] Failed to get analysis from local model");
            return null;
        }
    }

    private static string BuildUserMessage(IReadOnlyList<Alert> alerts, SystemSnapshot snapshot)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"System state at {snapshot.Timestamp:yyyy-MM-dd HH:mm:ss} UTC:");
        sb.AppendLine($"CPU: {snapshot.Cpu.UsagePercent:F1}% | RAM: {snapshot.Memory.UsagePercent:F1}% | Cores: {snapshot.Cpu.LogicalCoreCount}");

        if (snapshot.Disks.Count > 0)
            sb.AppendLine("Disks: " + string.Join(", ", snapshot.Disks.Select(d => $"{d.Drive}{d.UsagePercent:F0}% full")));

        sb.AppendLine();
        sb.AppendLine($"Active alerts ({alerts.Count}):");
        foreach (var a in alerts)
        {
            sb.AppendLine($"[{a.Severity}] {a.Category}: {a.Title}");
            sb.AppendLine($"  {a.Message}");
            if (!string.IsNullOrEmpty(a.SuggestedAction))
                sb.AppendLine($"  Suggested: {a.SuggestedAction}");
        }

        if (snapshot.Connections.Count > 0)
        {
            var established = snapshot.Connections.Count(c => c.State == "ESTABLISHED");
            sb.AppendLine($"\nNetwork: {established} established connections, {snapshot.Connections.Count} total");
        }

        if (snapshot.RecentSecurityEvents.Count > 0)
            sb.AppendLine($"Security events in last hour: {snapshot.RecentSecurityEvents.Count}");

        return sb.ToString();
    }
}
