#!/usr/bin/env python3
"""
normalize_evtx.py — Parse Windows EVTX event log files into tron-model training examples.

Supports:
  - Security event log (4625, 4624, 4648, 4719, 4720, 4732, 4698, 4702, 4697)
  - Sysmon event log (1=ProcessCreate, 3=NetworkConnect, 7=ImageLoad, 10=ProcessAccess, 11=FileCreate)
  - System event log (7045=ServiceInstall, 7036=ServiceStateChange)

Input:  Directory of .evtx files OR single .evtx file
Output: JSONL training pairs in Gemma 4 chat format

Usage:
    python normalize_evtx.py --input /path/to/evtx/ --output datasets/security_events.jsonl
    python normalize_evtx.py --input Security.evtx --output datasets/security_events.jsonl --label-with ollama/tron-model

Public EVTX datasets:
  - https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
  - https://github.com/NextronSystems/evtx-baseline
"""

import argparse
import json
import sys
from pathlib import Path


# Event ID → (category, severity, description template)
SECURITY_EVENTS = {
    4625: ("Security", "Warning",  "Failed logon attempt: {account} from {ip} (Logon Type {logon_type})"),
    4624: ("Security", "Info",     "Successful logon: {account} (Logon Type {logon_type})"),
    4648: ("Security", "Warning",  "Explicit credential logon: {account} → {target}"),
    4719: ("Security", "Critical", "Audit policy changed by {account}"),
    4720: ("Security", "Warning",  "New user account created: {new_account} by {account}"),
    4732: ("Security", "Warning",  "User added to privileged group: {account} → {group}"),
    4698: ("Security", "Warning",  "Scheduled task created: {task_name} by {account}"),
    4702: ("Security", "Warning",  "Scheduled task updated: {task_name} by {account}"),
    4697: ("Security", "Critical", "Service installed: {service_name} ({service_file})"),
}

SYSMON_EVENTS = {
    1:  ("Process",  "Info",     "Process created: {image} (PID {pid}) by {parent_image}"),
    3:  ("Network",  "Info",     "Network connection: {image} → {dest_ip}:{dest_port}"),
    7:  ("Process",  "Warning",  "Image loaded: {image_loaded} by {image}"),
    10: ("Process",  "Warning",  "Process access: {source_image} → {target_image} (access {granted_access})"),
    11: ("Security", "Info",     "File created: {target_filename} by {image}"),
    12: ("Security", "Warning",  "Registry key created/deleted: {target_object} by {image}"),
    13: ("Security", "Warning",  "Registry value set: {target_object} by {image}"),
}

# Known suspicious indicators
SUSPICIOUS_PATHS = ["\\temp\\", "\\appdata\\local\\temp\\", "\\downloads\\", "\\recycle.bin\\",
                    "\\public\\", "\\programdata\\", "%temp%", "%appdata%"]
SUSPICIOUS_NAMES = ["powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
                    "certutil.exe", "bitsadmin.exe", "regsvr32.exe", "rundll32.exe", "msiexec.exe"]
C2_PORTS = {4444, 4445, 31337, 1337, 6666, 6667, 6668, 6669, 9999, 12345, 27374, 65535}


def try_import_evtx():
    """Import python-evtx — give helpful error if not installed."""
    try:
        import Evtx.Evtx as evtx
        import Evtx.Views as e_views
        return evtx, e_views
    except ImportError:
        print("Error: python-evtx not installed. Run: pip install python-evtx lxml", file=sys.stderr)
        sys.exit(1)


def extract_field(record_xml: str, field: str) -> str:
    """Simple XML field extraction without full parse overhead."""
    import re
    # Try Data Name="field" first (EventData format)
    m = re.search(rf'Name="{re.escape(field)}"[^>]*>([^<]*)<', record_xml)
    if m:
        return m.group(1).strip()
    return ""


def classify_security_event(event_id: int, xml: str) -> dict | None:
    """Map a Windows security event to a training example."""
    if event_id not in SECURITY_EVENTS:
        return None

    category, severity, template = SECURITY_EVENTS[event_id]

    fields = {
        "account":      extract_field(xml, "SubjectUserName") or extract_field(xml, "TargetUserName") or "unknown",
        "ip":           extract_field(xml, "IpAddress") or "unknown",
        "logon_type":   extract_field(xml, "LogonType") or "?",
        "target":       extract_field(xml, "TargetServerName") or "unknown",
        "new_account":  extract_field(xml, "TargetUserName") or "unknown",
        "group":        extract_field(xml, "GroupName") or "unknown",
        "task_name":    extract_field(xml, "TaskName") or "unknown",
        "service_name": extract_field(xml, "ServiceName") or "unknown",
        "service_file": extract_field(xml, "ImagePath") or "unknown",
    }

    title = template.format(**{k: v for k, v in fields.items() if "{" + k + "}" in template})
    prompt = (f"SECURITY EVENT {event_id}\n"
              f"Category: {category} | Severity: {severity}\n"
              f"Event: {title}\n\n"
              f"Analyze this security event. Is this suspicious? What MITRE ATT&CK technique "
              f"does this correspond to? What should the operator do?")

    return {
        "event_id": event_id,
        "category": category,
        "severity": severity,
        "title": title,
        "prompt": prompt,
        "fields": fields
    }


def classify_sysmon_event(event_id: int, xml: str) -> dict | None:
    """Map a Sysmon event to a training example."""
    if event_id not in SYSMON_EVENTS:
        return None

    category, severity, template = SYSMON_EVENTS[event_id]

    fields = {
        "image":          extract_field(xml, "Image") or "unknown",
        "pid":            extract_field(xml, "ProcessId") or "?",
        "parent_image":   extract_field(xml, "ParentImage") or "unknown",
        "dest_ip":        extract_field(xml, "DestinationIp") or "unknown",
        "dest_port":      extract_field(xml, "DestinationPort") or "?",
        "image_loaded":   extract_field(xml, "ImageLoaded") or "unknown",
        "source_image":   extract_field(xml, "SourceImage") or "unknown",
        "target_image":   extract_field(xml, "TargetImage") or "unknown",
        "granted_access": extract_field(xml, "GrantedAccess") or "?",
        "target_filename":extract_field(xml, "TargetFilename") or "unknown",
        "target_object":  extract_field(xml, "TargetObject") or "unknown",
    }

    # Escalate severity for known suspicious indicators
    image_lower = fields["image"].lower()
    if any(s in image_lower for s in SUSPICIOUS_NAMES):
        severity = "Warning" if severity == "Info" else severity
    if event_id == 3:
        try:
            port = int(fields["dest_port"])
            if port in C2_PORTS:
                severity = "Critical"
        except ValueError:
            pass

    title = template.format(**{k: v for k, v in fields.items() if "{" + k + "}" in template})
    prompt = (f"SYSMON EVENT {event_id}\n"
              f"Category: {category} | Severity: {severity}\n"
              f"Event: {title}\n\n"
              f"Analyze this Sysmon event. Is this suspicious? What MITRE ATT&CK technique "
              f"might this represent? What should the operator do?")

    return {
        "event_id": event_id,
        "category": category,
        "severity": severity,
        "title": title,
        "prompt": prompt,
        "fields": fields
    }


def process_evtx_file(evtx_path: Path, evtx_lib, views_lib) -> list[dict]:
    examples = []
    try:
        with evtx_lib.Evtx(str(evtx_path)) as log:
            for record in log.records():
                try:
                    xml = record.xml()
                    # Extract event ID
                    import re
                    m = re.search(r"<EventID[^>]*>(\d+)</EventID>", xml)
                    if not m:
                        continue
                    event_id = int(m.group(1))

                    parsed = classify_security_event(event_id, xml) or classify_sysmon_event(event_id, xml)
                    if parsed:
                        examples.append({
                            "messages": [
                                {"role": "user",      "content": parsed["prompt"]},
                                {"role": "assistant", "content": "[NEEDS_LABEL]"}
                            ],
                            "metadata": {
                                "source": evtx_path.name,
                                "event_id": event_id,
                                "severity": parsed["severity"],
                                "category": parsed["category"],
                                "labeled": False
                            }
                        })
                except Exception:
                    continue
    except Exception as e:
        print(f"  ⚠ Failed to read {evtx_path.name}: {e}", file=sys.stderr)
    return examples


def main():
    parser = argparse.ArgumentParser(description="Parse EVTX files into tron-model training data")
    parser.add_argument("--input",      required=True, type=Path, help="EVTX file or directory of EVTX files")
    parser.add_argument("--output",     required=True, type=Path, help="Output JSONL training file")
    parser.add_argument("--max-events", type=int, default=100_000, help="Max events to process (default: 100000)")
    args = parser.parse_args()

    evtx_lib, views_lib = try_import_evtx()

    paths = []
    if args.input.is_dir():
        paths = list(args.input.rglob("*.evtx"))
        print(f"Found {len(paths)} EVTX files in {args.input}")
    elif args.input.is_file():
        paths = [args.input]
    else:
        print(f"Error: {args.input} not found", file=sys.stderr)
        sys.exit(1)

    args.output.parent.mkdir(parents=True, exist_ok=True)

    total = 0
    with open(args.output, "w") as f:
        for path in paths:
            if total >= args.max_events:
                break
            examples = process_evtx_file(path, evtx_lib, views_lib)
            for ex in examples:
                if total >= args.max_events:
                    break
                f.write(json.dumps(ex) + "\n")
                total += 1
            print(f"  {path.name}: {len(examples)} events")

    print(f"\n✓ {total} training examples written to {args.output}")
    print(f"  Next: run generate_analyses.py to label [NEEDS_LABEL] examples")


if __name__ == "__main__":
    main()
