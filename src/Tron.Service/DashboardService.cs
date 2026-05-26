using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Tron.Core.Config;
using Tron.Core.Models;

namespace Tron.Service;

/// <summary>
/// Embedded HTTP dashboard — serves a live system status page on localhost.
/// No dependencies on ASP.NET Core; uses HttpListener for minimal footprint.
/// Access at http://localhost:{port}/
/// </summary>
public sealed class DashboardService : BackgroundService
{
    private readonly TronStateService _state;
    private readonly TronOptions _opts;
    private readonly ILogger<DashboardService> _log;

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy        = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition      = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented               = false,
        Converters                  = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) }
    };

    public DashboardService(TronStateService state, IOptions<TronOptions> opts, ILogger<DashboardService> log)
    {
        _state = state;
        _opts  = opts.Value;
        _log   = log;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_opts.Dashboard.Enabled)
        {
            _log.LogInformation("[dashboard] Disabled via config.");
            return;
        }

        var bind    = _opts.Dashboard.BindAddress;
        if (string.IsNullOrWhiteSpace(bind)) bind = "127.0.0.1";
        var prefix = $"http://{bind}:{_opts.Dashboard.Port}/";
        using var listener = new HttpListener();
        listener.Prefixes.Add(prefix);

        try { listener.Start(); }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "[dashboard] Could not start on {Prefix} — dashboard disabled.", prefix);
            return;
        }

        _log.LogInformation("[dashboard] Listening on {Prefix}", prefix);

        while (!stoppingToken.IsCancellationRequested)
        {
            HttpListenerContext? ctx = null;
            try
            {
                var getCtx = listener.GetContextAsync();
                var cancelled = Task.Delay(Timeout.Infinite, stoppingToken);
                var winner = await Task.WhenAny(getCtx, cancelled);
                if (winner == cancelled) break;
                ctx = await getCtx;
            }
            catch (OperationCanceledException) { break; }
            catch (HttpListenerException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception ex)
            {
                _log.LogWarning(ex, "[dashboard] Listener error");
                continue;
            }

            _ = HandleRequestAsync(ctx, stoppingToken);
        }

        listener.Stop();
    }

    private async Task HandleRequestAsync(HttpListenerContext ctx, CancellationToken ct)
    {
        try
        {
            var path   = ctx.Request.Url?.AbsolutePath ?? "/";
            var method = ctx.Request.HttpMethod.ToUpperInvariant();

            if (method == "GET" && path == "/api/status")
            {
                await WriteJsonAsync(ctx.Response, BuildStatusDto(), ct);
            }
            else if (method == "GET" && path == "/api/alerts")
            {
                await WriteJsonAsync(ctx.Response, BuildAlertsDto(), ct);
            }
            else if (method == "POST" && path.StartsWith("/api/alerts/") && path.EndsWith("/approve"))
            {
                await HandleApprovalActionAsync(ctx, path, AlertApprovalState.Approved, ct);
            }
            else if (method == "POST" && path.StartsWith("/api/alerts/") && path.EndsWith("/deny"))
            {
                await HandleApprovalActionAsync(ctx, path, AlertApprovalState.Denied, ct);
            }
            else if (method == "POST" && path.StartsWith("/api/alerts/") && path.EndsWith("/acknowledge"))
            {
                await HandleApprovalActionAsync(ctx, path, AlertApprovalState.Acknowledged, ct);
            }
            else
            {
                // Serve the dashboard HTML for everything else
                var html = GetDashboardHtml();
                var bytes = Encoding.UTF8.GetBytes(html);
                ctx.Response.ContentType = "text/html; charset=utf-8";
                ctx.Response.ContentLength64 = bytes.Length;
                await ctx.Response.OutputStream.WriteAsync(bytes, ct);
            }
        }
        catch { /* don't crash the listener on bad requests */ }
        finally
        {
            try { ctx.Response.Close(); } catch { }
        }
    }

    private async Task HandleApprovalActionAsync(
        HttpListenerContext ctx, string path, AlertApprovalState newState, CancellationToken ct)
    {
        // Extract alert ID from path: /api/alerts/{id}/approve
        var segments = path.Trim('/').Split('/');
        // segments: ["api", "alerts", "{id}", "approve"]
        if (segments.Length < 4 || !Guid.TryParse(segments[2], out var alertId))
        {
            ctx.Response.StatusCode = 400;
            await WriteJsonAsync(ctx.Response, new { error = "Invalid alert ID." }, ct);
            return;
        }

        var ok = _state.SetApprovalState(alertId, newState);
        if (!ok)
        {
            ctx.Response.StatusCode = 404;
            await WriteJsonAsync(ctx.Response, new { error = "Alert not found or does not require approval." }, ct);
            return;
        }

        _log.LogInformation("[dashboard] Alert {Id} → {State}", alertId, newState);
        ctx.Response.Headers["Access-Control-Allow-Origin"] = "*";
        await WriteJsonAsync(ctx.Response, new { success = true, state = newState.ToString().ToLowerInvariant() }, ct);
    }

    private async Task WriteJsonAsync(HttpListenerResponse response, object data, CancellationToken ct)
    {
        var json = JsonSerializer.Serialize(data, JsonOpts);
        var bytes = Encoding.UTF8.GetBytes(json);
        response.ContentType = "application/json; charset=utf-8";
        response.ContentLength64 = bytes.Length;
        response.Headers["Access-Control-Allow-Origin"] = "*";
        await response.OutputStream.WriteAsync(bytes, ct);
    }

    private IReadOnlyList<AlertDto> BuildAlertsDto() =>
        _state.RecentAlerts
            .Select(a => new AlertDto
            {
                Id             = a.Id,
                Timestamp      = a.Timestamp,
                Severity       = a.Severity,
                Category       = a.Category,
                Title          = a.Title,
                Message        = a.Message,
                SuggestedAction = a.SuggestedAction,
                RequiresApproval = a.RequiresApproval,
                ApprovalState  = _state.GetApprovalState(a.Id)
            })
            .ToList();

    private StatusDto BuildStatusDto()
    {
        var snap = _state.Latest;
        return new StatusDto
        {
            Timestamp    = snap.Timestamp,
            UptimeSeconds = (long)_state.Uptime.TotalSeconds,
            Cpu          = snap.Cpu,
            Memory       = snap.Memory,
            Disks        = snap.Disks,
            Network      = snap.Network,
            Services     = snap.Services,
            TopProcesses = snap.TopProcesses.Take(15).ToList(),
            Connections  = snap.Connections
                               .Where(c => c.State == "ESTABLISHED")
                               .Take(20).ToList(),
            RecentAlerts = BuildAlertsDto()
        };
    }

    // ─── Dashboard HTML (single-file, no external dependencies) ──────────────

    private string GetDashboardHtml() => """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Tron — System Guardian</title>
<style>
  :root {
    --bg: #0a0e1a; --surface: #111827; --surface2: #1a2235;
    --border: #1e3a5f; --text: #e0f0ff; --muted: #6b8caa;
    --tron: #00d4ff; --tron2: #0090cc; --green: #22c55e;
    --yellow: #facc15; --red: #ef4444; --orange: #f97316;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, monospace; font-size: 14px; }
  a { color: var(--tron); text-decoration: none; }

  header { background: var(--surface); border-bottom: 1px solid var(--border);
    padding: 12px 20px; display: flex; align-items: center; gap: 16px; }
  .logo { color: var(--tron); font-size: 22px; font-weight: 700; letter-spacing: 3px;
    text-shadow: 0 0 12px var(--tron); }
  .tagline { color: var(--muted); font-size: 12px; }
  .status-dot { width: 10px; height: 10px; border-radius: 50%; background: var(--green);
    box-shadow: 0 0 6px var(--green); margin-left: auto; }
  #uptime { color: var(--muted); font-size: 12px; }

  main { padding: 16px 20px; display: grid; gap: 16px; }

  .grid-3 { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; }
  .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
  @media (max-width: 900px) { .grid-3, .grid-2 { grid-template-columns: 1fr; } }

  .card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 14px; }
  .card-title { color: var(--tron); font-size: 11px; font-weight: 600; letter-spacing: 1.5px;
    text-transform: uppercase; margin-bottom: 10px; }

  .metric { display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; }
  .metric-val { font-size: 28px; font-weight: 700; }
  .metric-label { color: var(--muted); font-size: 11px; }
  .bar-bg { background: var(--surface2); border-radius: 4px; height: 6px; margin-top: 6px; overflow: hidden; }
  .bar { height: 100%; border-radius: 4px; transition: width 0.6s ease; }
  .bar-ok { background: var(--tron); }
  .bar-warn { background: var(--yellow); }
  .bar-crit { background: var(--red); }

  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { text-align: left; color: var(--muted); font-size: 11px; font-weight: 600;
    padding: 6px 8px; border-bottom: 1px solid var(--border); letter-spacing: 0.5px; }
  td { padding: 5px 8px; border-bottom: 1px solid #1a2235; }
  tr:hover td { background: var(--surface2); }
  .truncate { max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

  .badge { display: inline-block; padding: 2px 7px; border-radius: 4px; font-size: 11px; font-weight: 600; }
  .badge-info { background: #1e3a5f; color: var(--tron); }
  .badge-warning { background: #3a2e00; color: var(--yellow); }
  .badge-critical { background: #3a0808; color: var(--red); }
  .badge-ok { background: #0d2e1a; color: var(--green); }

  .btn { display: inline-flex; align-items: center; gap: 4px; padding: 3px 10px; border-radius: 4px;
    font-size: 11px; font-weight: 600; cursor: pointer; border: none; transition: opacity 0.15s; }
  .btn:hover { opacity: 0.85; }
  .btn-approve { background: #0d2e1a; color: var(--green); border: 1px solid #22c55e44; }
  .btn-deny { background: #3a0808; color: var(--red); border: 1px solid #ef444444; }
  .btn-ack { background: #1e3a5f; color: var(--tron); border: 1px solid #00d4ff44; }
  .approval-approved { color: var(--green); font-size: 11px; font-weight: 600; }
  .approval-denied { color: var(--red); font-size: 11px; font-weight: 600; }
  .approval-acknowledged { color: var(--muted); font-size: 11px; }
  .approval-pending { color: var(--yellow); font-size: 11px; font-weight: 600; }

  .svc-row { display: flex; justify-content: space-between; align-items: center; padding: 5px 0;
    border-bottom: 1px solid var(--border); }
  .svc-name { color: var(--text); }
  .svc-status { font-size: 12px; font-weight: 600; }
  .svc-running { color: var(--green); }
  .svc-down { color: var(--red); }

  #alert-count { background: var(--red); color: #fff; border-radius: 10px;
    padding: 1px 7px; font-size: 11px; margin-left: 6px; }
  .empty { color: var(--muted); font-style: italic; padding: 10px 0; text-align: center; }
  footer { text-align: center; color: var(--muted); font-size: 11px; padding: 16px;
    border-top: 1px solid var(--border); }
</style>
</head>
<body>
<header>
  <div>
    <div class="logo">TRON</div>
    <div class="tagline">System Guardian — I fight for the Users.</div>
  </div>
  <span id="uptime" style="margin-left:auto;margin-right:12px"></span>
  <div class="status-dot" id="dot" title="Live"></div>
</header>

<main>
  <!-- CPU / Memory / Disk -->
  <div id="metrics-grid" class="grid-3"></div>

  <!-- Disk list + Services -->
  <div class="grid-2">
    <div class="card">
      <div class="card-title">Disks</div>
      <table><thead><tr><th>Drive</th><th>Used</th><th>Free</th><th>Total</th></tr></thead>
      <tbody id="disks"></tbody></table>
    </div>
    <div class="card">
      <div class="card-title">Services</div>
      <div id="services"><div class="empty">No watched services configured</div></div>
    </div>
  </div>

  <!-- Alerts -->
  <div class="card">
    <div class="card-title">Recent Alerts <span id="alert-count" style="display:none"></span></div>
    <table>
      <thead><tr><th>Time</th><th>Severity</th><th>Category</th><th>Title</th><th>Message</th><th>Actions</th></tr></thead>
      <tbody id="alerts"></tbody>
    </table>
  </div>

  <!-- Processes + Connections -->
  <div class="grid-2">
    <div class="card">
      <div class="card-title">Top Processes (by RAM)</div>
      <table><thead><tr><th>PID</th><th>Name</th><th>RAM</th><th>Path</th></tr></thead>
      <tbody id="procs"></tbody></table>
    </div>
    <div class="card">
      <div class="card-title">Active Connections (ESTABLISHED)</div>
      <table><thead><tr><th>Process</th><th>Local Port</th><th>Remote</th></tr></thead>
      <tbody id="conns"></tbody></table>
    </div>
  </div>
</main>

<footer>
  Project Tron &nbsp;·&nbsp; TRON™ is a trademark of The Walt Disney Company &nbsp;·&nbsp;
  <span id="ts"></span>
</footer>

<script>
const fmtBytes = b => {
  if (b < 1e6) return (b/1024).toFixed(0)+'KB';
  if (b < 1e9) return (b/1048576).toFixed(0)+'MB';
  return (b/1073741824).toFixed(1)+'GB';
};
const fmtUptime = s => {
  const d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);
  return d>0?`${d}d ${h}h ${m}m`:`${h}h ${m}m`;
};
const pct = (used,total) => total>0?(used/total*100):0;
const barClass = v => v>=95?'bar-crit':v>=80?'bar-warn':'bar-ok';
const badgeClass = s => s==='critical'?'badge-critical':s==='warning'?'badge-warning':'badge-info';

function metricCard(label, value, bar, sub) {
  return `<div class="card">
    <div class="card-title">${label}</div>
    <div class="metric">
      <span class="metric-val" style="color:${bar>=95?'var(--red)':bar>=80?'var(--yellow)':'var(--tron)'}">${value}</span>
      <span class="metric-label">${sub}</span>
    </div>
    <div class="bar-bg"><div class="bar ${barClass(bar)}" style="width:${Math.min(bar,100).toFixed(1)}%"></div></div>
  </div>`;
}

function update(d) {
  document.getElementById('uptime').textContent = 'Up: ' + fmtUptime(d.uptimeSeconds);
  document.getElementById('ts').textContent = new Date(d.timestamp).toLocaleString();

  // CPU / Memory
  const cpuPct = d.cpu.usagePercent.toFixed(1);
  const memPct = d.memory.usagePercent.toFixed(1);
  const memUsed = d.memory.totalBytes - d.memory.availableBytes;
  let cards = metricCard('CPU', cpuPct+'%', parseFloat(cpuPct), d.cpu.logicalCoreCount+' cores');
  cards += metricCard('Memory', memPct+'%', parseFloat(memPct),
    fmtBytes(memUsed)+' / '+fmtBytes(d.memory.totalBytes));

  // Network (sum all interfaces)
  const rx = d.network.reduce((s,n)=>s+n.bytesReceivedPerSec,0);
  const tx = d.network.reduce((s,n)=>s+n.bytesSentPerSec,0);
  cards += metricCard('Network', fmtBytes(rx)+'/s ↓', 0, fmtBytes(tx)+'/s ↑');

  document.getElementById('metrics-grid').innerHTML = cards;

  // Disks
  document.getElementById('disks').innerHTML = d.disks.map(disk => {
    const used = disk.totalBytes - disk.freeBytes;
    const p = (disk.usagePercent||0).toFixed(1);
    return `<tr>
      <td>${disk.drive}</td>
      <td><span style="color:${parseFloat(p)>=95?'var(--red)':parseFloat(p)>=80?'var(--yellow)':'var(--green)'">${p}%</span></td>
      <td>${fmtBytes(disk.freeBytes)}</td>
      <td>${fmtBytes(disk.totalBytes)}</td>
    </tr>`;
  }).join('') || '<tr><td colspan="4" class="empty">No drives</td></tr>';

  // Services
  const svcs = d.services.filter(s=>s.isWatched);
  document.getElementById('services').innerHTML = svcs.length
    ? svcs.map(s=>`<div class="svc-row">
        <span class="svc-name">${s.displayName||s.name}</span>
        <span class="svc-status ${s.status==='Running'?'svc-running':'svc-down'}">${s.status}</span>
      </div>`).join('')
    : '<div class="empty">No watched services configured</div>';

  // Alerts
  const warnAlerts = d.recentAlerts.filter(a=>a.severity!=='info');
  const ac = document.getElementById('alert-count');
  if (warnAlerts.length) { ac.style.display=''; ac.textContent=warnAlerts.length; }
  else ac.style.display='none';

  document.getElementById('alerts').innerHTML = d.recentAlerts.length
    ? d.recentAlerts.slice(0,30).map(a=>{
        let actions = '';
        if (a.requiresApproval) {
          const s = a.approvalState;
          if (s === 'pending') {
            actions = `<button class="btn btn-approve" onclick="alertAction('${a.id}','approve')">✅ Approve</button>
                       <button class="btn btn-deny" onclick="alertAction('${a.id}','deny')" style="margin-left:4px">❌ Deny</button>`;
          } else if (s === 'approved') {
            actions = `<span class="approval-approved">✅ Approved</span>`;
          } else if (s === 'denied') {
            actions = `<span class="approval-denied">❌ Denied</span>`;
          } else if (s === 'acknowledged') {
            actions = `<span class="approval-acknowledged">👁 Acknowledged</span>`;
          }
        } else if (!a.requiresApproval && a.approvalState === 'none') {
          actions = `<button class="btn btn-ack" onclick="alertAction('${a.id}','acknowledge')">👁 Ack</button>`;
        }
        return `<tr>
          <td style="white-space:nowrap;color:var(--muted)">${new Date(a.timestamp).toLocaleTimeString()}</td>
          <td><span class="badge ${badgeClass(a.severity)}">${a.severity}</span></td>
          <td style="color:var(--muted)">${a.category}</td>
          <td style="font-weight:600">${a.title}${a.suggestedAction?`<div style="color:var(--muted);font-size:11px;margin-top:2px">→ ${a.suggestedAction}</div>`:''}</td>
          <td class="truncate">${a.message}</td>
          <td style="white-space:nowrap">${actions}</td>
        </tr>`;
      }).join('')
    : '<tr><td colspan="6" class="empty">No alerts yet — system looks clean.</td></tr>';

  // Processes
  document.getElementById('procs').innerHTML = d.topProcesses.map(p=>`<tr>
    <td style="color:var(--muted)">${p.pid}</td>
    <td style="font-weight:600">${p.name}</td>
    <td>${fmtBytes(p.memoryBytes)}</td>
    <td class="truncate" title="${p.executablePath||''}" style="color:var(--muted);font-size:11px">
      ${p.executablePath ? p.executablePath.split(/[\\/]/).pop() : '—'}
    </td>
  </tr>`).join('') || '<tr><td colspan="4" class="empty">—</td></tr>';

  // Connections
  document.getElementById('conns').innerHTML = d.connections.length
    ? d.connections.map(c=>`<tr>
        <td style="font-weight:600">${c.owningProcess||'?'}</td>
        <td style="color:var(--muted)">${c.localPort}</td>
        <td class="truncate">${c.remoteAddress}:${c.remotePort}</td>
      </tr>`).join('')
    : '<tr><td colspan="3" class="empty">No established connections</td></tr>';
}

async function alertAction(id, action) {
  try {
    const r = await fetch(`/api/alerts/${id}/${action}`, { method: 'POST' });
    if (r.ok) await poll();
  } catch { /* ignore */ }
}

async function poll() {
  try {
    const r = await fetch('/api/status');
    if (!r.ok) throw new Error(r.status);
    update(await r.json());
    document.getElementById('dot').style.background = 'var(--green)';
  } catch {
    document.getElementById('dot').style.background = 'var(--red)';
  }
}

poll();
setInterval(poll, 5000);
</script>
</body>
</html>
""";

    // ─── DTOs for the status and alerts APIs ─────────────────────────────────

    private sealed class StatusDto
    {
        public DateTimeOffset Timestamp { get; init; }
        public long UptimeSeconds { get; init; }
        public CpuMetrics Cpu { get; init; } = new();
        public MemoryMetrics Memory { get; init; } = new();
        public List<DiskMetrics> Disks { get; init; } = [];
        public List<NetworkMetrics> Network { get; init; } = [];
        public List<ServiceStatus> Services { get; init; } = [];
        public List<ProcessInfo> TopProcesses { get; init; } = [];
        public List<NetworkConnection> Connections { get; init; } = [];
        public IReadOnlyList<AlertDto> RecentAlerts { get; init; } = [];
    }

    private sealed class AlertDto
    {
        public Guid Id { get; init; }
        public DateTimeOffset Timestamp { get; init; }
        public AlertSeverity Severity { get; init; }
        public AlertCategory Category { get; init; }
        public string Title { get; init; } = "";
        public string Message { get; init; } = "";
        public string? SuggestedAction { get; init; }
        public bool RequiresApproval { get; init; }
        public AlertApprovalState ApprovalState { get; init; }
    }
}
