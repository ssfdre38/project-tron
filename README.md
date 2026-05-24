# Project Tron — AI-native system guardian

> **Codename**: Project Tron | **Production name**: TBD

An AI-native, next-generation security and monitoring daemon for Windows Server.
Watches everything — OS resources, services, processes, security events — and reports
through Ash (Discord) in plain English. Asks before acting on anything critical.

## What it does

| Layer | What Tron watches |
|---|---|
| **Resources** | CPU, RAM, disk usage and I/O |
| **Services** | Watched Windows services — alerts if any go down |
| **Security** | Windows Security event log — failed logins, audit policy changes, suspicious auth |
| **Processes** | Top memory/CPU consumers, watched process tracking |
| **Network** | Interface throughput (more coming) |

## Architecture

```
Tron.Core        — Models (SystemSnapshot, Alert) + interfaces + config
Tron.Monitors    — Windows metrics collector (WMI/PerformanceCounters/SCM) + monitor checks
Tron.Alerting    — Alert sinks (Discord webhook with colour-coded embeds)
Tron.Service     — Worker service host (runs as Windows Service or console)
```

## Quick start (dev)

```powershell
cd src/Tron.Service
dotnet run
```

Configure `appsettings.json` or `appsettings.Development.json`:

```json
{
  "Tron": {
    "CollectionIntervalSeconds": 30,
    "WatchedServices": {
      "Names": ["ash-server", "W3SVC"]
    },
    "Alerting": {
      "DiscordWebhookUrl": "https://discord.com/api/webhooks/..."
    }
  }
}
```

## Install as Windows Service

```powershell
dotnet publish -c Release -r win-x64 --self-contained -o out
sc create Tron binpath="C:\path\to\out\Tron.Service.exe"
sc start Tron
```
