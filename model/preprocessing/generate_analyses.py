#!/usr/bin/env python3
"""
generate_analyses.py — Fill [NEEDS_LABEL] placeholders in training data using an LLM.

Works with any OpenAI-compatible endpoint:
  - Ollama (local): http://localhost:11434/v1
  - Gemini via openai-compat: https://generativelanguage.googleapis.com/v1beta/openai/
  - OpenAI: https://api.openai.com/v1

The labeling model sees the security event/snapshot and writes the assistant response
that tron-model will be trained to produce. Use a strong model (Gemini 2.5 Pro, GPT-4o,
gemma4-e4b) for high quality labels.

Usage:
    # Label with local Ollama (gemma4-e4b):
    python generate_analyses.py \\
        --input datasets/security_events.jsonl \\
        --output datasets/security_events_labeled.jsonl \\
        --endpoint http://localhost:11434/v1 \\
        --model gemma4-e4b

    # Label with Gemini 2.5 Pro (better quality):
    python generate_analyses.py \\
        --input datasets/telemetry_snapshots.jsonl \\
        --output datasets/telemetry_snapshots_labeled.jsonl \\
        --endpoint https://generativelanguage.googleapis.com/v1beta/openai/ \\
        --model gemini-2.5-pro \\
        --api-key $GEMINI_API_KEY
"""

import argparse
import json
import sys
import time
from pathlib import Path


LABELER_SYSTEM_PROMPT = """You are an expert security analyst writing training data for an AI security system called Tron.

For each security event or system snapshot you receive, write a concise, expert analysis that Tron should learn to produce.

Your response must follow this exact format:

**Verdict: [CRITICAL|WARNING|INFO] — [one-line summary]**

[2-3 sentences: what this event likely represents in plain English]

**MITRE ATT&CK**: [TechniqueID] ([TechniqueName]) — [brief tactic context]

**Immediate actions**:
1. [specific, copy-pasteable action]
2. [specific action]
3. [investigation step if needed]

**False positive check**: [when this could be benign — be specific]

Rules:
- Be direct and technical. The reader is a sysadmin.
- Under 250 words total.
- If the event is clearly benign (normal logon, routine service), say so briefly and skip the actions section.
- Never hallucinate specific process names, IPs, or commands that aren't in the input.
"""


def label_examples(examples: list[dict], client, model: str, batch_delay: float) -> list[dict]:
    from tqdm import tqdm

    labeled = []
    needs_label = [e for e in examples if e["messages"][-1]["content"] == "[NEEDS_LABEL]"]
    already_labeled = [e for e in examples if e["messages"][-1]["content"] != "[NEEDS_LABEL]"]

    print(f"  {len(needs_label)} examples need labeling, {len(already_labeled)} already labeled")

    for example in tqdm(needs_label, desc="Labeling"):
        user_content = example["messages"][0]["content"]
        try:
            response = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": LABELER_SYSTEM_PROMPT},
                    {"role": "user",   "content": user_content}
                ],
                max_tokens=512,
                temperature=0.2,
            )
            analysis = response.choices[0].message.content.strip()
            example["messages"][-1]["content"] = analysis
            if "metadata" in example:
                example["metadata"]["labeled"] = True
                example["metadata"]["label_model"] = model
            else:
                example["labeled"] = True
            labeled.append(example)
        except Exception as e:
            print(f"\n  ⚠ Labeling failed: {e}", file=sys.stderr)
            labeled.append(example)  # keep [NEEDS_LABEL] for retry

        if batch_delay > 0:
            time.sleep(batch_delay)

    return already_labeled + labeled


def main():
    parser = argparse.ArgumentParser(description="LLM-assisted labeling for tron-model training data")
    parser.add_argument("--input",       required=True,  type=Path,  help="Input JSONL with [NEEDS_LABEL] examples")
    parser.add_argument("--output",      required=True,  type=Path,  help="Output JSONL with analyses filled in")
    parser.add_argument("--endpoint",    default="http://localhost:11434/v1", help="OpenAI-compatible API endpoint")
    parser.add_argument("--model",       default="gemma4-e4b", help="Labeling model name")
    parser.add_argument("--api-key",     default="ollama",     help="API key (use 'ollama' for local Ollama)")
    parser.add_argument("--batch-delay", type=float, default=0.1, help="Seconds between requests (rate limiting)")
    parser.add_argument("--limit",       type=int,   default=None,  help="Max examples to label (for testing)")
    args = parser.parse_args()

    try:
        from openai import OpenAI
    except ImportError:
        print("Error: openai package not installed. Run: pip install openai", file=sys.stderr)
        sys.exit(1)

    if not args.input.exists():
        print(f"Error: {args.input} not found", file=sys.stderr)
        sys.exit(1)

    client = OpenAI(base_url=args.endpoint, api_key=args.api_key)

    # Test connectivity
    try:
        models = client.models.list()
        print(f"✓ Connected to {args.endpoint}")
    except Exception as e:
        print(f"⚠ Could not list models from {args.endpoint}: {e}", file=sys.stderr)
        print("  Continuing anyway — will fail on first label attempt if truly unreachable")

    examples = []
    with open(args.input) as f:
        for line in f:
            line = line.strip()
            if line:
                examples.append(json.loads(line))

    if args.limit:
        examples = examples[:args.limit]

    print(f"Loaded {len(examples)} examples from {args.input}")
    labeled = label_examples(examples, client, args.model, args.batch_delay)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w") as f:
        for ex in labeled:
            f.write(json.dumps(ex) + "\n")

    n_labeled = sum(1 for e in labeled if e.get("labeled") or
                    (e.get("metadata", {}).get("labeled", False)))
    print(f"\n✓ {len(labeled)} examples written to {args.output}")
    print(f"  {n_labeled} labeled, {len(labeled) - n_labeled} still need labeling")


if __name__ == "__main__":
    main()
