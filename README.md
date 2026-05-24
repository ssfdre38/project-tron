# Project Tron — AI-native system guardian

> *"I fight for the Users."*
> — Tron, [TRON (1982)](https://www.imdb.com/title/tt0084827/quotes/?item=qt0432721)

> **Codename**: Project Tron | **Production name**: TBD

> **Disclaimer**: TRON is a trademark and copyright of The Walt Disney Company.
> Project Tron is an independent open-source project inspired by the character Tron
> from the 1982 Disney film *TRON* — a security program whose sole purpose was to
> monitor communications, fight threats, and protect the system on behalf of its Users.
> This project is not affiliated with, endorsed by, or sponsored by Disney in any way.

An AI-native, next-generation security and monitoring daemon for Windows Server.
Watches everything — OS resources, services, processes, network connections,
security events — learns what *normal* looks like for your system, then alerts through
Discord in plain English. Asks before acting on anything critical.

## What it does

| Layer | What Tron watches |
|---|---|
| **Resources** | CPU, RAM, disk usage — alert when thresholds exceeded |
| **Services** | Watched Windows services — alert if any go down |
| **Security** | Windows Security event log — failed logins, brute-force, audit changes |
| **Processes** | Suspicious paths, masquerading system processes, newly appeared executables |
| **Network** | TCP connections — known C2 ports, port scanning, admin-port abuse |
| **Baseline** | Welford online algorithm — learns normal, alerts on Z-score anomalies |
| **AI Analysis** | Every warning-level alert gets a plain-English explanation via local model |

## Architecture

```
Tron.Core        — Models (SystemSnapshot, Alert, Baseline) + interfaces + config
Tron.Monitors    — Metrics collector (WMI/PerformanceCounters/SCM) + 6 monitor layers
Tron.Alerting    — Alert sinks (Discord webhook, colour-coded embeds) + AI analyzer
Tron.Service     — Worker service host (Windows Service or console)
```

## Quick start (dev)

```powershell
cd src/Tron.Service
dotnet run
```

Minimal `appsettings.json`:

```json
{
  "Tron": {
    "CollectionIntervalSeconds": 30,
    "WatchedServices": { "Names": ["ash-server"] },
    "Alerting": {
      "DiscordWebhookUrl": "https://discord.com/api/webhooks/...",
      "CooldownMinutes": 15
    },
    "Baseline": {
      "StorePath": "tron-baseline.json",
      "EnableAnomalyDetection": true
    },
    "Ai": {
      "EndpointUrl": "http://localhost:11434",
      "Model": "gemma4-nano"
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
| `Baseline` | `StorePath` | `tron-baseline.json` | Where to persist learned baseline |
| `Baseline` | `EnableAnomalyDetection` | `true` | Toggle z-score anomaly monitor |
| `Ai` | `EndpointUrl` | — | OpenAI-compatible endpoint (Ollama, ash-server) |
| `Ai` | `Model` | `gemma4-nano` | Model to call for alert analysis |
| `Ai` | `MinSeverityForAnalysis` | `Warning` | Don't call AI for Info-level alerts |

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

### BaselineMonitor
Learns CPU, memory, disk, network, process count, connection count using Welford's online algorithm.
After 20+ samples, flags anything beyond `AnomalyZScoreThreshold` standard deviations.
Baseline is automatically saved to disk every `SaveIntervalMinutes`.

### AI Analysis
After monitors run, any Warning+ alerts are bundled and sent to the configured
OpenAI-compatible endpoint (Ollama with `gemma4-nano` recommended). The model returns
a plain-English paragraph that is posted to Discord as a follow-up embed.

**Recommended local model**: `ssfdre38/gemma4-nano` on Ollama
A purpose-trained `tron-model` is in design — see [`docs/custom-model.md`](docs/custom-model.md).

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

## Custom model

See [`docs/custom-model.md`](docs/custom-model.md) for the full design —
a Gemma 4 Nano-based model fine-tuned on Windows security telemetry, trained
from Tron's own baseline data and public EVTX/threat datasets.

