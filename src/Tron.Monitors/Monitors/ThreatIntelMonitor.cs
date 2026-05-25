using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Tron.Core.Config;
using Tron.Core.Interfaces;
using Tron.Core.Models;
using Tron.Core.Services;

namespace Tron.Monitors.Monitors;

/// <summary>
/// Checks outbound/inbound TCP connections against:
///   1. A local IP blocklist (ships with Tron, user-extensible)
///   2. AbuseIPDB reputation API (optional — requires a free API key)
///
/// Flags connections to known C2 ranges, Tor exit nodes, bulletproof hosting,
/// and reconnaissance scanners.
/// </summary>
public sealed class ThreatIntelMonitor : IMonitor
{
    public string Name => "ThreatIntel";

    private readonly ThreatIntelOptions _opts;
    private readonly HttpClient _http;
    private readonly ILogger<ThreatIntelMonitor> _log;

    // Parsed blocklist — loaded once on first check
    private List<CidrEntry> _blockedCidrs = [];
    private HashSet<int> _blockedPorts = [];
    private bool _loaded;

    // AbuseIPDB result cache: ip → (score, expiry)
    private readonly Dictionary<string, (int Score, DateTimeOffset Expiry)> _abuseCache = [];

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public ThreatIntelMonitor(
        HttpClient http,
        IOptions<TronOptions> opts,
        ILogger<ThreatIntelMonitor> log)
    {
        _http = http;
        _opts = opts.Value.ThreatIntel;
        _log  = log;
    }

    public async Task<IEnumerable<Alert>> CheckAsync(SystemSnapshot snapshot, CancellationToken ct = default)
    {
        if (!_opts.Enabled) return [];

        if (!_loaded) await LoadBlocklistAsync(ct);

        var alerts = new List<Alert>();

        foreach (var conn in snapshot.Connections)
        {
            if (string.IsNullOrEmpty(conn.RemoteAddress)) continue;
            if (!IPAddress.TryParse(conn.RemoteAddress, out var remoteIp)) continue;

            // Skip loopback / link-local / private — we only care about external traffic
            if (IsPrivateOrLoopback(remoteIp)) continue;

            // 1. Check blocked destination ports
            if (_blockedPorts.Contains(conn.RemotePort))
            {
                alerts.Add(CreateAlert(
                    AlertSeverity.Critical,
                    $"Connection to C2 Port {conn.RemotePort}",
                    $"Process '{conn.OwningProcess ?? "unknown"}' has an outbound connection to " +
                    $"{conn.RemoteAddress}:{conn.RemotePort} — a port commonly used by malware C2 frameworks (Metasploit, RATs, botnets).",
                    "Block this port at the firewall and investigate the process immediately.",
                    requiresApproval: true));
            }

            // 2. Check local blocklist (CIDR + known IPs)
            var blockMatch = _blockedCidrs.FirstOrDefault(e => e.Contains(remoteIp));
            if (blockMatch != null)
            {
                var severity = blockMatch.Tags.Contains("c2") || blockMatch.Tags.Contains("bulletproof")
                    ? AlertSeverity.Critical : AlertSeverity.Warning;

                alerts.Add(CreateAlert(
                    severity,
                    $"Connection to Blocked Range: {conn.RemoteAddress}",
                    $"Process '{conn.OwningProcess ?? "unknown"}' connected to {conn.RemoteAddress}:{conn.RemotePort}, " +
                    $"which is in a known-malicious range: {blockMatch.Note}",
                    $"Investigate '{conn.OwningProcess}' and block {conn.RemoteAddress} at the firewall if not expected.",
                    requiresApproval: severity == AlertSeverity.Critical));
            }

            // 3. AbuseIPDB check (if API key configured and not already locally flagged)
            if (!string.IsNullOrWhiteSpace(_opts.AbuseIpDbApiKey) && blockMatch == null)
            {
                var score = await GetAbuseScoreAsync(conn.RemoteAddress, ct);
                if (score >= _opts.AbuseIpDbMinScore)
                {
                    alerts.Add(CreateAlert(
                        score >= 90 ? AlertSeverity.Critical : AlertSeverity.Warning,
                        $"High-Risk IP: {conn.RemoteAddress}",
                        $"AbuseIPDB reports {conn.RemoteAddress} with a confidence score of {score}/100. " +
                        $"Process '{conn.OwningProcess ?? "unknown"}' has an active connection to this address on port {conn.RemotePort}.",
                        $"Review '{conn.OwningProcess}' and consider blocking {conn.RemoteAddress}. " +
                        $"See https://www.abuseipdb.com/check/{conn.RemoteAddress}",
                        requiresApproval: score >= 90));
                }
            }
        }

        return alerts;
    }

    private async Task LoadBlocklistAsync(CancellationToken ct)
    {
        _loaded = true;

        // Determine blocklist path: user override > default shipped with assembly
        var path = string.IsNullOrWhiteSpace(_opts.BlocklistPath)
            ? Path.Combine(AppContext.BaseDirectory, "ThreatIntel", "default-blocklist.json")
            : _opts.BlocklistPath;

        if (!File.Exists(path))
        {
            _log.LogWarning("[threat-intel] Blocklist not found at {Path} — running with port checks only.", path);
            return;
        }

        try
        {
            await using var stream = File.OpenRead(path);
            var doc = await JsonDocument.ParseAsync(stream, cancellationToken: ct);
            var root = doc.RootElement;

            // Parse blocked ports
            if (root.TryGetProperty("blockedPorts", out var portsEl))
            {
                foreach (var p in portsEl.EnumerateArray())
                    if (p.TryGetProperty("port", out var portEl) && portEl.TryGetInt32(out var port))
                        _blockedPorts.Add(port);
            }

            // Parse CIDR entries
            static List<string> GetTags(JsonElement el)
            {
                var tags = new List<string>();
                if (el.TryGetProperty("tags", out var tagsEl))
                    foreach (var t in tagsEl.EnumerateArray())
                        tags.Add(t.GetString() ?? "");
                return tags;
            }

            foreach (var section in new[] { "blockedCidrs", "knownMaliciousIps", "custom" })
            {
                if (!root.TryGetProperty(section, out var sectionEl)) continue;
                foreach (var entry in sectionEl.EnumerateArray())
                {
                    var cidrStr = entry.TryGetProperty("cidr", out var cidrEl) ? cidrEl.GetString()
                               : entry.TryGetProperty("ip", out var ipEl) ? ipEl.GetString()
                               : null;
                    if (string.IsNullOrWhiteSpace(cidrStr)) continue;

                    var note = entry.TryGetProperty("note", out var noteEl) ? noteEl.GetString() ?? "" : "";
                    var tags = GetTags(entry);

                    try { _blockedCidrs.Add(CidrEntry.Parse(cidrStr, note, tags)); }
                    catch { /* skip malformed entries */ }
                }
            }

            _log.LogInformation("[threat-intel] Loaded {Cidrs} CIDR ranges and {Ports} blocked ports from {Path}",
                _blockedCidrs.Count, _blockedPorts.Count, path);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "[threat-intel] Failed to load blocklist from {Path}", path);
        }
    }

    private async Task<int> GetAbuseScoreAsync(string ip, CancellationToken ct)
    {
        var now = DateTimeOffset.UtcNow;

        if (_abuseCache.TryGetValue(ip, out var cached) && cached.Expiry > now)
            return cached.Score;

        try
        {
            var request = new HttpRequestMessage(HttpMethod.Get,
                $"https://api.abuseipdb.com/api/v2/check?ipAddress={Uri.EscapeDataString(ip)}&maxAgeInDays=90");
            request.Headers.Add("Key", _opts.AbuseIpDbApiKey);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            var response = await _http.SendAsync(request, ct);
            if (!response.IsSuccessStatusCode)
            {
                _log.LogDebug("[threat-intel] AbuseIPDB returned {Status} for {Ip}", response.StatusCode, ip);
                return 0;
            }

            var json = await response.Content.ReadAsStringAsync(ct);
            using var doc = JsonDocument.Parse(json);
            var score = doc.RootElement.GetProperty("data").GetProperty("abuseConfidenceScore").GetInt32();

            var expiry = now.AddMinutes(_opts.AbuseIpDbCacheDurationMinutes);
            _abuseCache[ip] = (score, expiry);
            return score;
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "[threat-intel] AbuseIPDB check failed for {Ip}", ip);
            return 0;
        }
    }

    private static Alert CreateAlert(AlertSeverity severity, string title, string message,
        string? action = null, bool requiresApproval = false)
    {
        var alert = new Alert
        {
            Severity         = severity,
            Category         = AlertCategory.ThreatIntel,
            Title            = title,
            Message          = message,
            SuggestedAction  = action,
            RequiresApproval = requiresApproval
        };
        return alert with { MitreAttack = MitreAttackMapper.Map(alert) };
    }

    private static bool IsPrivateOrLoopback(IPAddress ip)
    {
        if (IPAddress.IsLoopback(ip)) return true;
        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 && ip.IsIPv6LinkLocal) return true;

        // IPv4 private ranges
        var bytes = ip.GetAddressBytes();
        if (ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) return false;
        return (bytes[0] == 10)
            || (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
            || (bytes[0] == 192 && bytes[1] == 168)
            || (bytes[0] == 169 && bytes[1] == 254); // link-local
    }
}

/// <summary>Parsed CIDR range entry from the blocklist.</summary>
internal sealed class CidrEntry
{
    private readonly IPAddress _network;
    private readonly IPAddress _mask;
    public string Note { get; }
    public List<string> Tags { get; }

    private CidrEntry(IPAddress network, IPAddress mask, string note, List<string> tags)
    {
        _network = network;
        _mask    = mask;
        Note     = note;
        Tags     = tags;
    }

    public static CidrEntry Parse(string cidr, string note, List<string> tags)
    {
        // Handle bare IP (no prefix length)
        if (!cidr.Contains('/')) cidr += "/32";

        var parts  = cidr.Split('/');
        var ip     = IPAddress.Parse(parts[0]);
        var prefix = int.Parse(parts[1]);

        var bytes  = ip.GetAddressBytes();
        var mask   = new byte[bytes.Length];
        for (int i = 0; i < bytes.Length; i++)
        {
            int bits = Math.Max(0, Math.Min(8, prefix - i * 8));
            mask[i]  = (byte)(bits == 0 ? 0 : (0xFF << (8 - bits)) & 0xFF);
        }

        var network = new IPAddress(bytes.Zip(mask, (b, m) => (byte)(b & m)).ToArray());
        return new CidrEntry(network, new IPAddress(mask), note, tags);
    }

    public bool Contains(IPAddress ip)
    {
        if (ip.AddressFamily != _network.AddressFamily) return false;
        var ipBytes      = ip.GetAddressBytes();
        var networkBytes = _network.GetAddressBytes();
        var maskBytes    = _mask.GetAddressBytes();
        return ipBytes.Zip(networkBytes, (i, n) => i).Zip(maskBytes, (i, m) => (byte)(i & m))
                      .SequenceEqual(networkBytes);
    }
}
