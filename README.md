# Project Tron — AI-native system guardian

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![.NET 10](https://img.shields.io/badge/.NET-10-purple.svg)](https://dotnet.microsoft.com/download/dotnet/10.0)
[![Platforms](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](README.md)

> *"I fight for the Users."*
> — Tron, [TRON (1982)](https://www.imdb.com/title/tt0084827/quotes/?item=qt0432721)

> **Codename**: Project Tron | **Production name**: TBD

> **Disclaimer**: TRON is a trademark and copyright of The Walt Disney Company.
> Project Tron is an independent open-source project inspired by the character Tron
> from the 1982 Disney film *TRON* — a security program whose sole purpose was to
> monitor communications, fight threats, and protect the system on behalf of its Users.
> This project is not affiliated with, endorsed by, or sponsored by Disney in any way.

An AI-native, cross-platform system monitoring and security daemon.
Runs on **Windows**, **Linux**, and **macOS** — as a Windows Service, systemd unit, or console app.
Watches everything — OS resources, services, processes, network connections,
security events — learns what *normal* looks like for your system, then alerts through
Discord in plain English. Asks before acting on anything critical. No cloud required.

## Requirements

- [.NET 10 Runtime](https://dotnet.microsoft.com/download/dotnet/10.0) (or use a self-contained release — no .NET install needed)
- Windows 10/11/Server 2019+, Ubuntu 20.04+, Debian 11+, or macOS 12+
- Discord webhook URL *(optional — Tron works without it)*
- [Ollama](https://ollama.com) with any model *(optional — AI analysis is disabled if not configured)*

## What it does

| Layer | What Tron watches |
|---|---|
| **Resources** | CPU, RAM, disk usage — alert when thresholds exceeded |
| **Services** | Watched services (Windows SCM / systemd / launchctl) — alert if any go down |
| **Security** | Security event log (Windows) / auth.log + journald (Linux/macOS) — failed logins, brute-force |
| **Processes** | Suspicious paths, masquerading system processes, newly appeared executables |
| **Network** | TCP connections — known C2 ports, port scanning, admin-port abuse |
| **Threat Intel** | Cross-references active connections against local IP blocklist + AbuseIPDB (optional) |
| **Baseline** | Welford online algorithm — learns normal, alerts on Z-score anomalies |
| **MITRE ATT&CK** | Every alert is automatically tagged with the matching ATT&CK technique (T-ID, tactic, link) |
| **AI Analysis** | Warning-level alerts get a plain-English explanation via any local OpenAI-compatible model |

## Architecture

```
Tron.Core        — Models (SystemSnapshot, Alert, Baseline) + interfaces + config
Tron.Monitors    — Platform-native metrics collector + 7 monitor layers (incl. ThreatIntel)
Tron.Alerting    — Alert sinks (Discord webhook, Email, generic Webhook) + AI analyzer
Tron.Service     — Worker service host (Windows Service / systemd / console)
```

## Quick start

**Prerequisites**: [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0)

```bash
git clone https://github.com/ssfdre38/project-tron.git
cd project-tron/src/Tron.Service
dotnet run
```

Open **http://localhost:18790/** to see the live dashboard.

Minimal `appsettings.json` (all sections are optional — Tron works without Discord or AI):

```json
{
  "Tron": {
    "CollectionIntervalSeconds": 30,
    "WatchedServices": { "Names": ["nginx", "postgresql"] },
    "Alerting": {
      "DiscordWebhookUrl": "https://discord.com/api/webhooks/YOUR_WEBHOOK_HERE",
      "CooldownMinutes": 15
    },
    "Baseline": {
      "StorePath": "tron-baseline.json",
      "EnableAnomalyDetection": true
    },
    "Ai": {
      "EndpointUrl": "http://localhost:11434",
      "Model": "llama3.2"
    }
  }
}
```

## Configuration reference

| Section | Key | Default | Description |
|---|---|---|---|
| `Tron` | `CollectionIntervalSeconds` | `30` | Poll interval |
| `Thresholds` | `CpuWarningPercent` | `80` | CPU % to trigger Warning |
| `Thresholds` | `CpuCriticalPercent` | `95` | CPU % to trigger Critical |
| `Thresholds` | `AnomalyZScoreThreshold` | `3.0` | Std-deviations before anomaly alert |
| `Alerting` | `DiscordWebhookUrl` | — | Discord webhook; leave blank to disable |
| `Alerting` | `MinSeverity` | `Warning` | Minimum alert level to send |
| `Alerting` | `CooldownMinutes` | `15` | Per-alert-title cooldown to reduce noise |
| `Email` | `Enabled` | `false` | Enable SMTP email alerts |
| `Email` | `SmtpHost` | — | SMTP server hostname |
| `Email` | `SmtpPort` | `587` | SMTP port (587 = STARTTLS, 465 = SSL) |
| `Email` | `FromAddress` | — | Sender address |
| `Email` | `ToAddresses` | `[]` | Recipient list |
| `Email` | `MinSeverity` | `Warning` | Don't email below this level |
| `Webhook` | `Enabled` | `false` | Enable generic HTTP webhook |
| `Webhook` | `Url` | — | Target URL (Slack, Teams, SIEM, custom) |
| `Webhook` | `AuthHeader` | — | Value for `Authorization` header (e.g. `Bearer token123`) |
| `Webhook` | `MinSeverity` | `Warning` | Don't POST below this level |
| `ThreatIntel` | `Enabled` | `true` | Enable IP blocklist monitor |
| `ThreatIntel` | `BlocklistPath` | — | Path to custom JSON blocklist; blank = use built-in list |
| `ThreatIntel` | `AbuseIpDbApiKey` | — | [AbuseIPDB](https://www.abuseipdb.com) API key; blank = local-only |
| `ThreatIntel` | `AbuseIpDbMinScore` | `75` | Confidence score threshold (0–100) |
| `Baseline` | `StorePath` | `tron-baseline.json` | Where to persist learned baseline |
| `Baseline` | `EnableAnomalyDetection` | `true` | Toggle z-score anomaly monitor |
| `FileIntegrity` | `Enabled` | `true` | Enable File Integrity Monitor |
| `FileIntegrity` | `WatchDirectories` | `[]` | Extra directories to hash every cycle |
| `FileIntegrity` | `WatchFiles` | `[]` | Extra individual files to hash every cycle |
| `Correlation` | `Enabled` | `true` | Enable the cross-monitor Correlation Engine |
| `Correlation` | `WindowMinutes` | `5` | Sliding window width for correlation rules |
| `Ai` | `EndpointUrl` | — | OpenAI-compatible endpoint (Ollama, any local model) |
| `Ai` | `Model` | `llama3.2` | Model name to call for alert analysis |
| `Ai` | `MinSeverityForAnalysis` | `Warning` | Don't call AI for Info-level alerts |
| `Dashboard` | `Enabled` | `true` | Serve the local web dashboard |
| `Dashboard` | `Port` | `18790` | Port for the dashboard HTTP server |
| `Dashboard` | `BindAddress` | `127.0.0.1` | Bind address. Use `0.0.0.0` to allow LAN access |
| `Dashboard` | `ExternalUrl` | — | Public/LAN URL of this dashboard (e.g. `http://192.168.1.100:18790`). When set, Discord approval alerts include a deep link |

## Monitors

### ResourceMonitor
Checks CPU / RAM / disk against configurable thresholds each collection cycle.

### ServiceMonitor
Watches services listed in `WatchedServices.Names`. Alerts immediately if any are not Running.

### SecurityEventMonitor
Reads the Windows Security event log:
- **4625** — Failed login (brute-force detection)
- **4719** — Audit policy changed
- **4624/4648** — Successful logins (anomalous-hours detection)

### ProcessMonitor
- Flags executables in suspicious paths (`Temp`, `AppData\Local\Temp`, `Downloads`, `$Recycle.Bin`)
- Detects masquerading: processes named `svchost`, `lsass`, `csrss` etc. running from non-System32 paths
- Tracks newly-observed process names against the learned baseline

### NetworkConnectionMonitor
- Known C2 / exfil destination ports (4444, 6666, 9999, 31337, 1337 and others)
- Port scanning: > 20 unique remote ports from one host in a single tick
- Admin ports from external IPs: RDP (3389), WinRM (5985/5986), SMB (445)

### ThreatIntelMonitor
Cross-references every active outbound connection against:
1. **Built-in blocklist** — ships with Tron; covers known C2 ranges, Tor exit nodes, bulletproof hosting,
   reconnaissance scanner infrastructure (Shodan, Censys), and dangerous destination ports
   (Metasploit 4444, Back Orifice 31337, IRC botnets 6666–6669, etc.)
2. **Custom blocklist** — point `ThreatIntel.BlocklistPath` at your own JSON file with the same schema
3. **AbuseIPDB** (optional) — if you provide a free API key, Tron checks every external IP and alerts
   on anything with a confidence score above `AbuseIpDbMinScore`. Results are cached for 24 hours
   to avoid burning the free tier

Private IPs (RFC 1918 / loopback / link-local) are always ignored.

### FileIntegrityMonitor
Tracks SHA-256 hashes of critical OS files and alerts if any change unexpectedly.

**Windows watch list**: `System32\cmd.exe`, `notepad.exe`, `calc.exe`, `certutil.exe`, `wscript.exe`, `mshta.exe`,
`powershell.exe` (SysWOW64 too), the `hosts` file, and all DLLs in `System32\drivers\etc`.

**Linux watch list**: `/bin/bash`, `/bin/sh`, `/bin/su`, `/usr/bin/sudo`, `/etc/passwd`, `/etc/shadow`,
`/etc/ssh/sshd_config`, `/etc/crontab`, `/etc/ld.so.preload`.

**macOS watch list**: `/bin/bash`, `/bin/zsh`, `/usr/bin/sudo`, `/etc/hosts`, `/etc/ssh/sshd_config`,
`/etc/pam.d/sudo`.

Additional directories can be added via `FileIntegrity.WatchDirectories` and specific files via
`FileIntegrity.WatchFiles`. The first run builds a baseline; subsequent runs compare hashes and alert on
any changed or newly-appeared file. MITRE: T1565 (Stored Data Manipulation), T1070 (Indicator Removal).

### PersistenceMonitor
Detects new startup entries across all three major platforms.

**Windows**: scans `System32\Tasks` for new scheduled tasks + HKLM and HKCU `Run`/`RunOnce` registry keys.

**Linux**: scans `/etc/cron*`, `/var/spool/cron`, `/etc/rc.local`, and systemd unit directories
(`/etc/systemd/system`, `/usr/lib/systemd/system`).

**macOS**: scans `/Library/LaunchDaemons`, `/Library/LaunchAgents`, and `~/Library/LaunchAgents`.

Baseline on first run; alerts on new entries. Also fires an Info alert when entries are removed —
a sign of an attacker covering their tracks. MITRE: T1053 (Scheduled Task/Job), T1547 (Boot/Logon Autostart).

### CorrelationEngine
After all monitors run each cycle, the engine applies five sliding-window rules that detect multi-stage attacks:

| Rule | Triggers when… |
|---|---|
| **Active Breach** | Auth failures + suspicious process + external C2 connection all within the window |
| **C2 Implant** | Suspicious process + external network connection from unexpected process |
| **Malware Install** | Persistence alert + suspicious process alert within the window |
| **Lateral Movement** | Auth failures + SMB/RDP/WinRM connection from an internal IP |
| **Ransomware Signal** | Multiple FIM changes + service-stopped alert + Shadow Copy deletion (vssadmin) |

Window defaults to 5 minutes, configurable via `Correlation.WindowMinutes`. Per-rule cooldown = 5× the
window to avoid repeated firing on the same event cluster.

### MITRE ATT&CK tagging
Every alert is automatically mapped to the closest [MITRE ATT&CK](https://attack.mitre.org) technique.
The technique ID, name, tactic, and direct URL appear in Discord embeds, email alerts, and webhook payloads.
Coverage includes: T1110 (Brute Force), T1046 (Network Scanning), T1059 (Scripting), T1496 (Resource Hijacking),
T1489 (Service Stop), T1562 (Defence Evasion), T1565 (Data Manipulation), T1053 (Scheduled Task),
T1547 (Autostart), T1486 (Ransomware), and ~20 others.

### Alert sinks — all optional, all independent
| Sink | Description |
|---|---|
| **Discord webhook** | Colour-coded embeds with severity, category, ATT&CK tag |
| **Email (SMTP)** | HTML + plain-text multipart; works with Gmail, Outlook, self-hosted Postfix |
| **Generic webhook** | HTTP POST JSON to any URL — Slack incoming hooks, Microsoft Teams, PagerDuty, custom SIEMs |

### BaselineMonitor
Learns CPU, memory, disk, network, process count, connection count using Welford's online algorithm.
After 20+ samples, flags anything beyond `AnomalyZScoreThreshold` standard deviations.
Baseline is automatically saved to disk every `SaveIntervalMinutes`.

### AI Analysis
After monitors run, any Warning+ alerts are bundled and sent to the configured
OpenAI-compatible endpoint. Any local model via [Ollama](https://ollama.com) works:

```bash
# Install Ollama, then pull any model:
ollama pull llama3.2        # recommended — fast and accurate
ollama pull gemma3:4b       # lighter option
```

Set `Ai.EndpointUrl` to `http://localhost:11434` and `Ai.Model` to the model name.
Leave `EndpointUrl` blank to run Tron without AI (all other monitors still work).

A purpose-trained `tron-model` is in design — see [`docs/custom-model.md`](docs/custom-model.md).

## Web dashboard

Once Tron is running, open your browser to:

```
http://localhost:18790/
```

The dashboard polls every 5 seconds and shows:
- **CPU / RAM / Network** gauges with colour-coded thresholds
- **Disk** usage table (all drives)
- **Watched services** status (Running / stopped)
- **Recent alerts** table with severity badges, suggested actions, and **approve/deny/acknowledge buttons**
- **Top 15 processes** by memory
- **Active TCP connections** (ESTABLISHED only)

### Alert approval

Certain high-severity alerts (suspicious processes, new persistence, threat-intel hits, correlation composites)
require human review. These appear with **⚠️ Action Required** in the Discord embed and show
**✅ Approve / ❌ Deny** buttons on the dashboard.

Clicking **Approve** or **Deny** records your decision and updates the alert state in the dashboard.

**To receive approval links in Discord**: set `Dashboard.ExternalUrl` to your machine's LAN address:

```json
"Dashboard": {
  "Enabled": true,
  "Port": 18790,
  "BindAddress": "0.0.0.0",
  "ExternalUrl": "http://192.168.1.100:18790"
}
```

Discord embeds will then include a direct link and the alert UUID so you can open the dashboard from your phone.

> **Security note**: `BindAddress: 0.0.0.0` makes the dashboard reachable on your LAN.
> Do not expose it to the public internet without a reverse proxy and authentication.



## Install as Windows Service

```powershell
dotnet publish -c Release -r win-x64 --self-contained -o out
sc create Tron binpath="C:\path\to\out\Tron.Service.exe"
sc start Tron
```

## Install on Linux (systemd)

```bash
# After extracting the Linux release zip:
sudo bash build/linux/install.sh ./Tron.Service
sudo systemctl status tron
```

## Install on macOS

```bash
# Run as a background process (console):
dotnet publish -c Release -r osx-arm64 --self-contained -o out
./out/Tron.Service
```

Or add a launchd plist to `/Library/LaunchDaemons/` to run at system startup.

## Custom model

See [`docs/custom-model.md`](docs/custom-model.md) for the full design —
a small model fine-tuned on real system telemetry and public security datasets
to provide accurate, context-aware alert analysis fully offline.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Issues and pull requests are welcome.

## License

[MIT](LICENSE) — see LICENSE for details.

> TRON™ is a trademark of The Walt Disney Company. This project is not affiliated with Disney.
