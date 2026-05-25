using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Tron.Core.Config;
using Tron.Core.Interfaces;
using Tron.Core.Models;

namespace Tron.Alerting.Sinks;

/// <summary>
/// Generic HTTP webhook sink — POSTs a JSON alert payload to any URL.
/// Works with Slack incoming webhooks, Microsoft Teams, PagerDuty, custom SIEMs, etc.
/// </summary>
public sealed class WebhookAlertSink : IAlertSink
{
    private readonly HttpClient _http;
    private readonly WebhookOptions _opts;
    private readonly ILogger<WebhookAlertSink> _log;

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy   = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented          = false,
        Converters             = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) }
    };

    public WebhookAlertSink(HttpClient http, IOptions<TronOptions> opts, ILogger<WebhookAlertSink> log)
    {
        _http = http;
        _opts = opts.Value.Webhook;
        _log  = log;
    }

    public async Task SendAsync(Alert alert, CancellationToken ct = default)
    {
        if (!_opts.Enabled || string.IsNullOrWhiteSpace(_opts.Url))
            return;

        if (!Enum.TryParse<AlertSeverity>(_opts.MinSeverity, true, out var minSev))
            minSev = AlertSeverity.Warning;
        if (alert.Severity < minSev)
            return;

        var payload = new AlertWebhookPayload
        {
            Source    = "tron",
            Severity  = alert.Severity.ToString().ToLowerInvariant(),
            Category  = alert.Category.ToString().ToLowerInvariant(),
            Title     = alert.Title,
            Message   = alert.Message,
            Timestamp = alert.Timestamp,
            MitreAttack = alert.MitreAttack == null ? null : new MitrePayload(
                alert.MitreAttack.TechniqueId,
                alert.MitreAttack.TechniqueName,
                alert.MitreAttack.TacticName,
                alert.MitreAttack.Url),
            SuggestedAction  = alert.SuggestedAction,
            RequiresApproval = alert.RequiresApproval ? true : null
        };

        var json    = JsonSerializer.Serialize(payload, JsonOpts);
        var content = new StringContent(json, Encoding.UTF8, "application/json");

        if (!string.IsNullOrWhiteSpace(_opts.AuthHeader))
            _http.DefaultRequestHeaders.TryAddWithoutValidation("Authorization", _opts.AuthHeader);

        try
        {
            var response = await _http.PostAsync(_opts.Url, content, ct);
            if (!response.IsSuccessStatusCode)
                _log.LogWarning("[webhook] {Status} from {Url} for alert: {Title}",
                    (int)response.StatusCode, _opts.Url, alert.Title);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "[webhook] Failed to send alert: {Title}", alert.Title);
        }
    }

    private sealed record AlertWebhookPayload
    {
        public string Source { get; init; } = "tron";
        public string Severity { get; init; } = "";
        public string Category { get; init; } = "";
        public string Title { get; init; } = "";
        public string Message { get; init; } = "";
        public DateTimeOffset Timestamp { get; init; }
        public MitrePayload? MitreAttack { get; init; }
        public string? SuggestedAction { get; init; }
        public bool? RequiresApproval { get; init; }
    }

    private sealed record MitrePayload(string TechniqueId, string TechniqueName, string TacticName, string Url);
}
