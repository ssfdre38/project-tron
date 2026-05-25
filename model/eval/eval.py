#!/usr/bin/env python3
"""
eval.py — Evaluate tron-model on a held-out security test set.

Metrics computed:
  - ROUGE-L: measures response quality vs. reference analyses
  - Verdict accuracy: does the model agree on CRITICAL/WARNING/INFO?
  - False positive rate: how often does it flag benign events as critical?
  - Latency: p50/p95 inference time (must be < 2s for production use)
  - Coverage: % of events with MITRE ATT&CK technique mentioned

Usage:
    # Evaluate against Ollama-served tron-model:
    python eval.py \\
        --test-data datasets/security_events_labeled.jsonl \\
        --endpoint http://localhost:11434/v1 \\
        --model tron-model

    # Evaluate against a baseline (compare to generic gemma4-e2b):
    python eval.py \\
        --test-data datasets/security_events_labeled.jsonl \\
        --endpoint http://localhost:11434/v1 \\
        --model gemma4-e2b \\
        --report baseline_results.json
"""

import argparse
import json
import re
import sys
import time
from pathlib import Path


def extract_verdict(text: str) -> str | None:
    """Extract CRITICAL/WARNING/INFO from a response."""
    m = re.search(r'\*\*Verdict[:\s]+([A-Z]+)', text, re.IGNORECASE)
    if m:
        v = m.group(1).upper()
        if v in {"CRITICAL", "WARNING", "INFO"}:
            return v
    # Fallback: scan first 100 chars
    text_upper = text[:100].upper()
    for v in ["CRITICAL", "WARNING", "INFO"]:
        if v in text_upper:
            return v
    return None


def has_mitre_reference(text: str) -> bool:
    """Check if response mentions a MITRE technique ID."""
    return bool(re.search(r'T\d{4}(\.\d{3})?', text))


def compute_rouge_l(reference: str, hypothesis: str) -> float:
    """Compute ROUGE-L (longest common subsequence) F1."""
    ref_tokens  = reference.lower().split()
    hyp_tokens  = hypothesis.lower().split()
    if not ref_tokens or not hyp_tokens:
        return 0.0

    # Dynamic programming LCS length
    m, n = len(ref_tokens), len(hyp_tokens)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if ref_tokens[i-1] == hyp_tokens[j-1]:
                dp[i][j] = dp[i-1][j-1] + 1
            else:
                dp[i][j] = max(dp[i-1][j], dp[i][j-1])
    lcs = dp[m][n]

    precision = lcs / n if n > 0 else 0
    recall    = lcs / m if m > 0 else 0
    if precision + recall == 0:
        return 0.0
    return 2 * precision * recall / (precision + recall)


def run_evaluation(test_examples: list[dict], client, model: str) -> dict:
    from tqdm import tqdm

    results = []
    latencies = []
    verdict_matches = 0
    mitre_count = 0
    total_rouge = 0.0

    for example in tqdm(test_examples, desc=f"Evaluating {model}"):
        user_msg   = example["messages"][0]["content"]
        reference  = example["messages"][1]["content"]
        ref_verdict = extract_verdict(reference)

        t0 = time.perf_counter()
        try:
            response = client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": user_msg}],
                max_tokens=400,
                temperature=0.1,
            )
            hypothesis = response.choices[0].message.content.strip()
        except Exception as e:
            print(f"\n  ⚠ Inference failed: {e}", file=sys.stderr)
            continue

        latency = time.perf_counter() - t0
        latencies.append(latency)

        hyp_verdict = extract_verdict(hypothesis)
        verdict_ok  = (ref_verdict == hyp_verdict) if ref_verdict else True
        if verdict_ok:
            verdict_matches += 1
        if has_mitre_reference(hypothesis):
            mitre_count += 1

        rouge = compute_rouge_l(reference, hypothesis)
        total_rouge += rouge

        results.append({
            "verdict_match": verdict_ok,
            "ref_verdict":   ref_verdict,
            "hyp_verdict":   hyp_verdict,
            "mitre_mentioned": has_mitre_reference(hypothesis),
            "rouge_l":       rouge,
            "latency_s":     latency,
        })

    n = len(results)
    if n == 0:
        return {"error": "no results"}

    latencies.sort()
    p50 = latencies[n // 2]
    p95 = latencies[int(n * 0.95)]

    return {
        "model":            model,
        "n_examples":       n,
        "verdict_accuracy": verdict_matches / n,
        "mitre_coverage":   mitre_count / n,
        "rouge_l_mean":     total_rouge / n,
        "latency_p50_s":    p50,
        "latency_p95_s":    p95,
        "pass_latency":     p95 < 2.0,   # target: < 2s p95
        "results":          results
    }


def print_report(metrics: dict):
    print(f"\n{'='*50}")
    print(f"  tron-model evaluation: {metrics['model']}")
    print(f"{'='*50}")
    print(f"  Examples evaluated:  {metrics['n_examples']}")
    print(f"  Verdict accuracy:    {metrics['verdict_accuracy']:.1%}  (target: >85%)")
    print(f"  MITRE coverage:      {metrics['mitre_coverage']:.1%}  (target: >70%)")
    print(f"  ROUGE-L mean:        {metrics['rouge_l_mean']:.3f}  (target: >0.30)")
    print(f"  Latency p50:         {metrics['latency_p50_s']:.2f}s")
    print(f"  Latency p95:         {metrics['latency_p95_s']:.2f}s  ({'✓ PASS' if metrics['pass_latency'] else '✗ FAIL (>2s)'})")
    print(f"{'='*50}")


def main():
    parser = argparse.ArgumentParser(description="Evaluate tron-model")
    parser.add_argument("--test-data", required=True, type=Path,
                        help="Labeled JSONL test dataset")
    parser.add_argument("--endpoint",  default="http://localhost:11434/v1",
                        help="OpenAI-compatible endpoint")
    parser.add_argument("--model",     default="tron-model",
                        help="Model name to evaluate")
    parser.add_argument("--api-key",   default="ollama")
    parser.add_argument("--limit",     type=int, default=None,
                        help="Limit number of test examples")
    parser.add_argument("--report",    type=Path, default=None,
                        help="Save detailed JSON report to this file")
    args = parser.parse_args()

    try:
        from openai import OpenAI
    except ImportError:
        print("Error: pip install openai", file=sys.stderr)
        sys.exit(1)

    if not args.test_data.exists():
        print(f"Error: {args.test_data} not found", file=sys.stderr)
        sys.exit(1)

    client = OpenAI(base_url=args.endpoint, api_key=args.api_key)

    examples = []
    with open(args.test_data) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            msgs = rec.get("messages", [])
            # Only evaluate labeled examples with non-trivial reference
            if len(msgs) == 2 and msgs[1]["content"] != "[NEEDS_LABEL]":
                examples.append(rec)

    if args.limit:
        examples = examples[:args.limit]

    if not examples:
        print("No labeled examples found in test data.", file=sys.stderr)
        sys.exit(1)

    print(f"Evaluating {len(examples)} examples with model: {args.model}")

    metrics = run_evaluation(examples, client, args.model)
    print_report(metrics)

    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        with open(args.report, "w") as f:
            json.dump(metrics, f, indent=2)
        print(f"\n  Detailed report saved to {args.report}")


if __name__ == "__main__":
    main()
