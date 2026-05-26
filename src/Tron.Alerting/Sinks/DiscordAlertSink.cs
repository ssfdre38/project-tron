using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Tron.Core.Config;
using Tron.Core.Interfaces;
using Tron.Core.Models;

namespace Tron.Alerting.Sinks;

/// <summary>Sends alerts to a Discord channel via webhook with colour-coded embeds.</summary>
public sealed class DiscordAlertSink : IAlertSink
{
    private readonly HttpClient _http;
    private readonly TronOptions _opts;
    private readonly ILogger<DiscordAlertSink> _log;

    private static readonly Dictionary<AlertSeverity, int> EmbedColours = new()
    {
        [AlertSeverity.Info]     = 0x5865F2, // Discord blurple
        [AlertSeverity.Warning]  = 0xFEE75C, // Yellow
        [AlertSeverity.Critical] = 0xED4245  // Red
    };

    private static readonly Dictionary<AlertSeverity, string> Emoji = new()
    {
        [AlertSeverity.Info]     = "ℹ️",
        [AlertSeverity.Warning]  = "⚠️",
        [AlertSeverity.Critical] = "🚨"
    };

    public DiscordAlertSink(HttpClient http, IOptions<TronOptions> opts, ILogger<DiscordAlertSink> log)
    {
        _http = http;
        _opts = opts.Value;
        _log = log;
    }

    public async Task SendAsync(Alert alert, CancellationToken ct = default)
    {
        var webhookUrl = _opts.Alerting.DiscordWebhookUrl;
        if (string.IsNullOrWhiteSpace(webhookUrl))
        {
            _log.LogDebug("No Discord webhook configured — skipping alert: {Title}", alert.Title);
            return;
        }

        if (!Enum.TryParse<AlertSeverity>(_opts.Alerting.MinSeverity, true, out var minSev))
            minSev = AlertSeverity.Warning;
        if (alert.Severity < minSev)
            return;

        var fields = new List<object>
        {
            new { name = "Category", value = alert.Category.ToString(), inline = true },
            new { name = "Severity", value = alert.Severity.ToString(), inline = true }
        };

        if (!string.IsNullOrEmpty(alert.SuggestedAction))
            fields.Add(new { name = "Suggested Action", value = alert.SuggestedAction, inline = false });

        if (alert.RequiresApproval)
        {
            var approvalMsg = "⚠️ This alert requires your review.";
            var externalUrl = _opts.Dashboard.ExternalUrl?.TrimEnd('/');
            if (!string.IsNullOrWhiteSpace(externalUrl))
                approvalMsg += $"\n[Open Dashboard]({externalUrl}) — Alert ID: `{alert.Id}`";
            else
                approvalMsg += $"\nAlert ID: `{alert.Id}` — Visit the dashboard to approve or deny.";
            fields.Add(new { name = "Action Required", value = approvalMsg, inline = false });
        }

        if (alert.MitreAttack != null)
            fields.Add(new
            {
                name  = "MITRE ATT&CK",
                value = $"[{alert.MitreAttack.TechniqueId} — {alert.MitreAttack.TechniqueName}]({alert.MitreAttack.Url})" +
                        $"\nTactic: {alert.MitreAttack.TacticName}",
                inline = false
            });

        var payload = new
        {
            embeds = new[]
            {
                new
                {
                    title = $"{Emoji[alert.Severity]} {alert.Title}",
                    description = alert.Message,
                    color = EmbedColours[alert.Severity],
                    fields,
                    footer = new { text = $"Tron • {alert.Timestamp:yyyy-MM-dd HH:mm:ss} UTC" },
                    timestamp = alert.Timestamp.ToString("o")
                }
            }
        };

        var json = JsonSerializer.Serialize(payload);
        var content = new StringContent(json, Encoding.UTF8, "application/json");

        try
        {
            var response = await _http.PostAsync(webhookUrl, content, ct);
            if (!response.IsSuccessStatusCode)
                _log.LogWarning("Discord webhook returned {Status} for alert: {Title}", response.StatusCode, alert.Title);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Failed to send alert to Discord: {Title}", alert.Title);
        }
    }
}
