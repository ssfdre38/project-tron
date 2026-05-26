# Tron Custom Model — Design & Training Strategy

> **Status**: Design phase | **Codename**: tron-model

## Why a custom model?

Existing security AI tools are:
- Trained on generic, public CVE/threat data — not your specific environment
- Siloed — they see one log source, not the whole system simultaneously
- Reactive and rule-based at their core, with AI bolted on top
- Cloud-dependent, meaning your telemetry leaves your network

Tron's model will be:
- **Trained on real system telemetry** — learns what *your* system looks like at rest
- **Context-aware** — sees CPU, memory, processes, network, and event logs simultaneously
- **Conversational** — speaks to the operator in plain English
- **Air-gappable** — runs fully locally, no data leaves the machine

---

## Target Architecture

### Base model
Start from **Gemma 4 E4B** (4B parameters, IQ4_XS quantized) — better reasoning on novel attack
patterns than E2B while still hitting the <2s alert latency target on most hardware.

**Why E4B and not larger?**
- Inference must be fast (< 2 seconds per alert analysis)
- At IQ4_XS quantization it fits alongside normal workloads (~3 GB RAM)
- Security analysis is structured reasoning, not creative generation — smaller models excel here
- Users should be able to run this on any modern desktop or server
- Post fine-tune, the specialized weights close the gap to much larger generic models

### Fine-tuning approach
**Supervised fine-tuning (SFT)** on:
1. `(system_context, alert_data) -> plain_english_analysis` pairs
2. `(telemetry_snapshot) -> normal/anomalous` classification
3. `(security_event) -> severity_assessment + recommended_action`

**Format**: Standard chat template (same format any Ollama-served model expects)

---

## Training Data Strategy

### Dataset 1: Security Event Logs
- **Source**: Public EVTX datasets (EVTX-ATTACK-SAMPLES, DARPA TCDE, MITRE ATT&CK evaluations), Linux auth.log samples
- **Format**: Event log → (is_attack: bool, technique: str, severity: str, explanation: str)
- **Size target**: 50K+ labeled events
- **Augmentation**: Generate synthetic variants of known attack patterns

### Dataset 2: System Telemetry → Analysis Pairs
- **Source**: Generated from Tron's own baseline collector running on any system
- **Format**: `SystemSnapshot JSON → analysis paragraph`
- **Generation**: Use any capable LLM to write analysis paragraphs for captured snapshots
- **Size target**: 10K snapshots × varied scenarios = 10K pairs
- **Key scenarios to cover**:
  - Normal load (majority class)
  - CPU/memory spikes (legitimate vs. suspicious)
  - Service failures
  - Brute-force login attempts
  - New unknown processes
  - Unusual outbound connections

### Dataset 3: Process Behaviour Profiles
- **Source**: Windows process telemetry from Sysmon, Procmon; Linux process data from auditd
- **Format**: `(process_name, path, parent, connections) → (legitimate: bool, risk_score: 0-10, notes)`
- **Size target**: 5K process profiles
- **Covers**: Masquerading (fake svchost), DLL injection indicators, living-off-the-land binaries (LOLBins)

### Dataset 4: Security Incident Reports (NLP)
- **Source**: Public incident reports (NVD, US-CERT advisories, vendor postmortems)
- **Format**: Incident report text → structured summary (what happened, how detected, remediation)
- **Purpose**: Teach the model to reason about novel threats by analogy

### Dataset 5: Tron's Own Alerts (Self-supervised)
Once Tron is running, you can collect:
- Every alert fired + system snapshot at time of alert
- Operator response (acknowledged, dismissed, acted on)
- Outcome (false positive, true positive, action taken)

This becomes a **reinforcement signal** for future fine-tuning rounds — the model improves
from real operator feedback on your specific environment.

---

## Training Pipeline

```
Raw data sources
     │
     ▼
preprocessing/
  normalize_evtx.py        -- EVTX/auth.log → structured JSON
  snapshot_to_prompt.py    -- SystemSnapshot → training prompt
  generate_analyses.py     -- LLM-assisted label generation
     │
     ▼
datasets/
  security_events.jsonl    -- Event log training pairs
  telemetry_snapshots.jsonl -- Snapshot analysis pairs
  process_profiles.jsonl   -- Process behaviour data
     │
     ▼
training/
  finetune.py              -- Unsloth/TRL SFT trainer
  eval.py                  -- Evaluation on held-out set
     │
     ▼
tron-model-v1.gguf          -- Quantized for local inference
```

---

## Evaluation Metrics

| Metric | Target |
|---|---|
| False positive rate (alert accuracy) | < 5% |
| True positive rate (detect known attacks) | > 95% |
| Analysis latency (p95) | < 2 seconds |
| Analysis quality (human eval 1-5) | ≥ 4.0 |
| Novel threat detection (zero-shot) | Measured per release |

---

## Integration with Tron

The trained model replaces/augments `LocalModelAnalyzer`. Serve it with Ollama:

```bash
ollama create tron-model -f Modelfile
```

Then configure Tron to use it:

```json
"Ai": {
  "EndpointUrl": "http://localhost:11434",
  "Model": "tron-model"
}
```

The model runs entirely on your hardware — no telemetry leaves your network.

---

## Roadmap

| Phase | What |
|---|---|
| **Phase 1** | Tron collecting baseline data on a live system |
| **Phase 2** | Build datasets 1 + 3 from public sources |
| **Phase 3** | Generate dataset 2 from live Tron telemetry |
| **Phase 4** | First SFT fine-tune on a small base model |
| **Phase 5** | Evaluate, iterate, publish tron-model-v1 |
| **Phase 6** | Self-supervised improvement loop from operator feedback |

---

## Notes

- All training data stays local — no telemetry leaves your system
- The model will be open-source (published to Ollama + HuggingFace)
- Fine-tuning uses standard tooling: [Unsloth](https://github.com/unslothai/unsloth) + GGUF export via llama.cpp
- Contributions to the training datasets are welcome — see [CONTRIBUTING.md](../CONTRIBUTING.md)
