using System.Net;
using System.Net.Mail;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Tron.Core.Config;
using Tron.Core.Interfaces;
using Tron.Core.Models;

namespace Tron.Alerting.Sinks;

/// <summary>
/// Sends alerts via SMTP email (plain-text + HTML).
/// Works with any SMTP server: Gmail, Outlook, self-hosted Postfix, etc.
/// </summary>
public sealed class EmailAlertSink : IAlertSink
{
    private readonly EmailOptions _opts;
    private readonly ILogger<EmailAlertSink> _log;

    private static readonly Dictionary<AlertSeverity, string> SeverityColour = new()
    {
        [AlertSeverity.Info]     = "#5865F2",
        [AlertSeverity.Warning]  = "#F59E0B",
        [AlertSeverity.Critical] = "#EF4444"
    };

    private static readonly Dictionary<AlertSeverity, string> SeverityEmoji = new()
    {
        [AlertSeverity.Info]     = "ℹ️",
        [AlertSeverity.Warning]  = "⚠️",
        [AlertSeverity.Critical] = "🚨"
    };

    public EmailAlertSink(IOptions<TronOptions> opts, ILogger<EmailAlertSink> log)
    {
        _opts = opts.Value.Email;
        _log  = log;
    }

    public async Task SendAsync(Alert alert, CancellationToken ct = default)
    {
        if (!_opts.Enabled)
            return;

        if (_opts.ToAddresses.Count == 0 || string.IsNullOrWhiteSpace(_opts.SmtpHost))
        {
            _log.LogDebug("[email] Not configured — skipping alert: {Title}", alert.Title);
            return;
        }

        // Check minimum severity
        if (!Enum.TryParse<AlertSeverity>(_opts.MinSeverity, true, out var minSev))
            minSev = AlertSeverity.Warning;
        if (alert.Severity < minSev)
            return;

        try
        {
            using var client = BuildSmtpClient();
            using var message = BuildMessage(alert);
            await client.SendMailAsync(message, ct);
            _log.LogDebug("[email] Alert sent: {Title}", alert.Title);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "[email] Failed to send alert: {Title}", alert.Title);
        }
    }

    private SmtpClient BuildSmtpClient()
    {
        var client = new SmtpClient(_opts.SmtpHost, _opts.SmtpPort)
        {
            EnableSsl   = _opts.UseSsl,
            DeliveryMethod = SmtpDeliveryMethod.Network
        };

        if (!string.IsNullOrWhiteSpace(_opts.Username))
            client.Credentials = new NetworkCredential(_opts.Username, _opts.Password);

        return client;
    }

    private MailMessage BuildMessage(Alert alert)
    {
        var subject = $"[Tron] [{alert.Severity}] {alert.Title}";
        var colour  = SeverityColour[alert.Severity];
        var emoji   = SeverityEmoji[alert.Severity];

        var html = new StringBuilder();
        html.AppendLine("<!DOCTYPE html><html><body style='font-family:system-ui,sans-serif;background:#0a0e1a;color:#e0f0ff;padding:20px'>");
        html.AppendLine($"<div style='max-width:600px;margin:auto;background:#111827;border:2px solid {colour};border-radius:8px;overflow:hidden'>");
        html.AppendLine($"<div style='background:{colour};padding:12px 20px'>");
        html.AppendLine($"  <h2 style='margin:0;color:#fff'>{emoji} {System.Net.WebUtility.HtmlEncode(alert.Title)}</h2>");
        html.AppendLine("</div>");
        html.AppendLine("<div style='padding:20px'>");
        html.AppendLine($"<p style='font-size:15px;line-height:1.6'>{System.Net.WebUtility.HtmlEncode(alert.Message)}</p>");
        html.AppendLine("<table style='width:100%;border-collapse:collapse;margin-top:16px'>");
        html.AppendLine(Row("Severity", alert.Severity.ToString()));
        html.AppendLine(Row("Category", alert.Category.ToString()));
        html.AppendLine(Row("Time",     alert.Timestamp.ToString("yyyy-MM-dd HH:mm:ss") + " UTC"));
        if (alert.MitreAttack is { } att)
            html.AppendLine(Row("MITRE ATT&amp;CK",
                $"<a href='{att.Url}' style='color:#00d4ff'>{att.TechniqueId} — {System.Net.WebUtility.HtmlEncode(att.TechniqueName)}</a>" +
                $" <span style='color:#6b8caa'>({System.Net.WebUtility.HtmlEncode(att.TacticName)})</span>"));
        if (!string.IsNullOrEmpty(alert.SuggestedAction))
            html.AppendLine(Row("Suggested Action", System.Net.WebUtility.HtmlEncode(alert.SuggestedAction)));
        html.AppendLine("</table>");
        html.AppendLine("</div>");
        html.AppendLine("<div style='background:#0a0e1a;padding:10px 20px;text-align:center;color:#6b8caa;font-size:12px'>");
        html.AppendLine("Tron System Guardian &nbsp;·&nbsp; TRON™ © The Walt Disney Company (project unaffiliated)");
        html.AppendLine("</div></div></body></html>");

        // Plain text fallback
        var plain = new StringBuilder();
        plain.AppendLine($"[{alert.Severity}] {alert.Title}");
        plain.AppendLine($"Time: {alert.Timestamp:yyyy-MM-dd HH:mm:ss} UTC");
        plain.AppendLine($"Category: {alert.Category}");
        plain.AppendLine();
        plain.AppendLine(alert.Message);
        if (alert.MitreAttack is { } a)
            plain.AppendLine($"\nMITRE ATT&CK: {a.TechniqueId} — {a.TechniqueName} ({a.TacticName})\n{a.Url}");
        if (!string.IsNullOrEmpty(alert.SuggestedAction))
            plain.AppendLine($"\nSuggested Action: {alert.SuggestedAction}");

        var msg = new MailMessage
        {
            From       = new MailAddress(_opts.FromAddress, _opts.FromName),
            Subject    = subject,
            Body       = plain.ToString(),
            IsBodyHtml = false
        };

        foreach (var to in _opts.ToAddresses)
            msg.To.Add(to);

        var htmlView = AlternateView.CreateAlternateViewFromString(
            html.ToString(), Encoding.UTF8, "text/html");
        msg.AlternateViews.Add(htmlView);

        return msg;
    }

    private static string Row(string label, string value) =>
        $"<tr><td style='padding:6px 8px;color:#6b8caa;font-size:12px;border-bottom:1px solid #1e3a5f;width:140px'>{label}</td>" +
        $"<td style='padding:6px 8px;border-bottom:1px solid #1e3a5f'>{value}</td></tr>";
}
