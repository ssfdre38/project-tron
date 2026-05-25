# Tron Model — Dataset Format

All training datasets use the **Gemma 4 chat format** (JSONL, one example per line).

## Schema

```json
{
  "messages": [
    {"role": "user",      "content": "<prompt — security event or system snapshot>"},
    {"role": "assistant", "content": "<analysis — verdict + explanation + actions>"}
  ],
  "metadata": {
    "source":    "security_events | telemetry | process_profiles | evtx",
    "severity":  "Critical | Warning | Info",
    "category":  "Security | Network | Process | ...",
    "labeled":   true,
    "label_model": "gemini-2.5-pro"
  }
}
```

## Datasets

| File | Built by | Size target | Content |
|---|---|---|---|
| `security_events.jsonl` | `normalize_evtx.py` | 50K events | Windows Security + Sysmon event parsing |
| `telemetry_snapshots.jsonl` | `snapshot_to_prompt.py` | 10K | Tron SystemSnapshot → analysis |
| `process_profiles.jsonl` | `normalize_evtx.py` | 5K | Process behavior profiles from Sysmon |

## Example — Security event (4625 failed logon)

```json
{
  "messages": [
    {
      "role": "user",
      "content": "SECURITY EVENT 4625\nCategory: Security | Severity: Warning\nEvent: Failed logon attempt: john.doe from 185.220.101.45 (Logon Type 3)\n\nAnalyze this security event. Is this suspicious? What MITRE ATT&CK technique does this correspond to? What should the operator do?"
    },
    {
      "role": "assistant",
      "content": "**Verdict: WARNING — Investigate IP, confirm no successful follow-up logon**\n\nA Type 3 (network) logon failure from 185.220.101.45 targeting account john.doe. This IP falls in a known Tor exit node range, which is a strong indicator this is an automated brute-force attempt rather than a legitimate user mistyping their password.\n\n**MITRE ATT&CK**: T1110.003 (Password Spraying) — Single account targeted across a network logon; combined with a known-malicious IP this fits the password spraying pattern.\n\n**Immediate actions**:\n1. Check for successful logon 4624 events from the same IP: `Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624} | Where-Object {$_.Message -match '185.220.101.45'}`\n2. Block 185.220.101.45 at the firewall\n3. Enable MFA on john.doe if not already active\n4. Check for concurrent 4625 events against other accounts — if yes, this is a spray campaign\n\n**False positive check**: Unlikely benign — legitimate users don't authenticate from Tor exit nodes."
    }
  ],
  "metadata": {
    "source": "evtx",
    "severity": "Warning",
    "category": "Security",
    "labeled": true,
    "label_model": "gemini-2.5-pro"
  }
}
```

## Example — Telemetry snapshot with anomaly

```json
{
  "messages": [
    {
      "role": "user",
      "content": "## System Snapshot — 2026-05-24T18:00:00Z\n\n**Resources**\n- CPU: 94.3%\n- Memory: 71.2% (14.9 GB / 21 GB)\n\n**Network**: 12 established connections\n- powershell.exe → 185.220.101.45:4444\n\n**Top processes by memory** (127 total)\n- powershell.exe (PID 4892) — 312 MB | CPU: 87.4%\n\n**Active alerts** (1)\n- [CRITICAL] Network: Connection to C2 Port 4444 [T1071 Application Layer Protocol]\n  powershell.exe has an outbound connection to 185.220.101.45:4444\n\nAnalyze the alerts in the context of this system snapshot. For each alert: give your verdict, explain what it likely is, state relevant MITRE ATT&CK context, and list immediate actions."
    },
    {
      "role": "assistant",
      "content": "**Verdict: CRITICAL — Contain Immediately**\n\npowershell.exe is consuming 87% CPU and maintaining a persistent outbound connection to port 4444 on a Tor exit node. This is a high-confidence active compromise. Port 4444 is the default Metasploit Meterpreter listener; the CPU spike suggests active payload execution (data staging, lateral movement, or crypto operations).\n\n**MITRE ATT&CK**: T1059.001 (PowerShell) as initial execution vector → T1071.001 (Application Layer Protocol C2) — The classic PowerShell-based Meterpreter reverse shell chain. The Tor exit node destination aligns with T1090.003 (Multi-hop Proxy).\n\n**Immediate actions**:\n1. Kill the process: `taskkill /PID 4892 /F`\n2. Block outbound to 185.220.101.45: `netsh advfirewall firewall add rule name=\"Block C2\" dir=out remoteip=185.220.101.45 action=block`\n3. Review PowerShell execution history: `Get-Content (Get-PSReadLineOption).HistorySavePath`\n4. Check for persistence (run in elevated PS): `Get-ScheduledTask | Where-Object {$_.TaskPath -notlike \"\\Microsoft\\*\"}`\n5. Check registry run keys: `Get-ItemProperty HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run`\n6. Consider isolating this machine from the network until forensic review is complete\n\n**False positive check**: No legitimate scenario produces a PowerShell process at 87% CPU with a persistent outbound connection to a Tor node on port 4444."
    }
  ],
  "metadata": {
    "source": "telemetry",
    "severity": "Critical",
    "category": "Network",
    "labeled": true,
    "label_model": "human"
  }
}
```

## Dataset sources (public, free)

| Source | URL | Format |
|---|---|---|
| EVTX attack samples | https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES | .evtx |
| EVTX baselines | https://github.com/NextronSystems/evtx-baseline | .evtx |
| MITRE ATT&CK STIX | https://github.com/mitre/cti | JSON |
| DARPA TCDE | https://www.darpa.mil/program/transparent-computing | PCAP + logs |
| LOLBins | https://lolbas-project.github.io/ | JSON |
| MalwareBazaar | https://bazaar.abuse.ch | CSV |
