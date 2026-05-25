#!/usr/bin/env python3
"""
snapshot_to_prompt.py — Convert Tron SystemSnapshot JSON records into
chat-format training examples for tron-model fine-tuning.

Input:  JSONL file where each line is a Tron SystemSnapshot (serialized by TronWorker)
Output: JSONL file in Gemma 4 chat format:
        {"messages": [{"role": "user", "content": "..."}, {"role": "assistant", "content": "..."}]}

The "assistant" responses are either:
  a) Operator-confirmed labels (from tron-feedback.jsonl if available)
  b) Placeholder [NEEDS_LABEL] for generate_analyses.py to fill in

Usage:
    python snapshot_to_prompt.py --input tron-snapshots.jsonl --output datasets/telemetry_snapshots.jsonl
    python snapshot_to_prompt.py --input tron-snapshots.jsonl --feedback tron-feedback.jsonl --output datasets/labeled.jsonl
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path


def format_snapshot_prompt(snapshot: dict, alerts: list[dict] | None = None) -> str:
    """Build the user-turn prompt from a SystemSnapshot dict."""
    cpu = snapshot.get("cpu", {})
    mem = snapshot.get("memory", {})
    disk_entries = snapshot.get("disks", [])
    conns = snapshot.get("connections", [])
    procs = snapshot.get("processes", [])
    ts = snapshot.get("timestamp", datetime.utcnow().isoformat())

    lines = [f"## System Snapshot — {ts}"]

    # Resources
    lines.append(f"\n**Resources**")
    lines.append(f"- CPU: {cpu.get('usagePercent', 0):.1f}%")
    lines.append(f"- Memory: {mem.get('usagePercent', 0):.1f}% "
                 f"({mem.get('usedBytes', 0) / 1e9:.1f} GB / {mem.get('totalBytes', 0) / 1e9:.1f} GB)")

    if disk_entries:
        lines.append(f"\n**Disks**")
        for d in disk_entries[:4]:
            lines.append(f"- {d.get('name', '?')}: {d.get('usagePercent', 0):.1f}% used "
                         f"({d.get('freeBytes', 0) / 1e9:.1f} GB free)")

    # Network
    established = [c for c in conns if c.get("state", "").upper() == "ESTABLISHED"]
    lines.append(f"\n**Network**: {len(established)} established connections")
    for c in established[:10]:
        lines.append(f"- {c.get('owningProcess', '?')} → {c.get('remoteAddress', '?')}:{c.get('remotePort', 0)}")
    if len(established) > 10:
        lines.append(f"  ... and {len(established) - 10} more")

    # Top processes
    top_procs = sorted(procs, key=lambda p: p.get("memoryMb", 0), reverse=True)[:10]
    if top_procs:
        lines.append(f"\n**Top processes by memory** ({len(procs)} total)")
        for p in top_procs:
            lines.append(f"- {p.get('name', '?')} (PID {p.get('pid', '?')}) — "
                         f"{p.get('memoryMb', 0):.0f} MB | CPU: {p.get('cpuPercent', 0):.1f}%")

    # Alerts context
    if alerts:
        lines.append(f"\n**Active alerts** ({len(alerts)})")
        for a in alerts:
            mitre = ""
            if a.get("mitreAttack"):
                m = a["mitreAttack"]
                mitre = f" [{m.get('techniqueId', '')} {m.get('techniqueName', '')}]"
            lines.append(f"- [{a.get('severity', '?').upper()}] {a.get('category', '?')}: "
                         f"{a.get('title', '')}{mitre}")
            if a.get("message"):
                lines.append(f"  {a['message'][:200]}")

        lines.append("\nAnalyze the alerts in the context of this system snapshot. "
                     "For each alert: give your verdict, explain what it likely is, "
                     "state relevant MITRE ATT&CK context, and list immediate actions.")
    else:
        lines.append("\nNo active alerts. Assess whether this system state is normal or warrants monitoring.")

    return "\n".join(lines)


def process_snapshot_file(input_path: Path, feedback_path: Path | None, output_path: Path) -> int:
    feedback: dict[str, str] = {}
    if feedback_path and feedback_path.exists():
        with open(feedback_path) as f:
            for line in f:
                rec = json.loads(line.strip())
                # feedback format: {"snapshot_id": "...", "analysis": "..."}
                feedback[rec["snapshot_id"]] = rec["analysis"]

    count = 0
    with open(input_path) as fin, open(output_path, "w") as fout:
        for line in fin:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as e:
                print(f"  ⚠ Skipping malformed line: {e}", file=sys.stderr)
                continue

            snapshot = record.get("snapshot", record)  # support both wrapped and bare
            alerts = record.get("alerts", [])
            snap_id = record.get("id", f"snap_{count}")

            prompt = format_snapshot_prompt(snapshot, alerts)

            # Use labelled response if available, else placeholder
            response = feedback.get(snap_id, "[NEEDS_LABEL]")

            example = {
                "id": snap_id,
                "messages": [
                    {"role": "user", "content": prompt},
                    {"role": "assistant", "content": response}
                ],
                "labeled": response != "[NEEDS_LABEL]"
            }
            fout.write(json.dumps(example) + "\n")
            count += 1

    return count


def main():
    parser = argparse.ArgumentParser(description="Convert Tron snapshots to training prompts")
    parser.add_argument("--input",    required=True,  type=Path, help="Input JSONL of SystemSnapshot records")
    parser.add_argument("--feedback", required=False, type=Path, help="Optional JSONL of operator-confirmed analyses")
    parser.add_argument("--output",   required=True,  type=Path, help="Output JSONL training file")
    args = parser.parse_args()

    if not args.input.exists():
        print(f"Error: input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    n = process_snapshot_file(args.input, args.feedback, args.output)
    labeled = sum(1 for _ in open(args.output) if '"labeled": true' in _)
    print(f"✓ {n} examples written to {args.output} ({labeled} labeled, {n - labeled} need labeling)")


if __name__ == "__main__":
    main()
