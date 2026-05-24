# Tron Custom Model — Design & Training Strategy

> **Status**: Design phase | **Codename**: tron-model

## Why a custom model?

Existing security AI tools are:
- Trained on generic, public CVE/threat data — not your specific environment
- Siloed — they see one log source, not the whole system simultaneously
- Reactive and rule-based at their core, with AI bolted on top
- Cloud-dependent, meaning your telemetry leaves your network

Tron's model will be:
- **Trained on real system telemetry** from this server's baseline
- **Context-aware** — it sees CPU, memory, processes, network, and event logs simultaneously
- **Conversational** — it speaks to the sysadmin in plain English through Ash
- **Air-gappable** — runs fully locally on your hardware

---

## Target Architecture

### Base model
Start from **Gemma 4 Nano** (2B params) — already fine-tuned by us, runs fast on this hardware,
small enough to inference in real-time as alerts come in.

**Why Nano and not Turbo?**
- Inference must be fast (< 2 seconds for alert analysis)
- Nano at 4-bit quantization fits comfortably in RAM alongside the server workload
- Security analysis is structured reasoning, not creative generation — smaller models excel here

### Fine-tuning approach
**Supervised fine-tuning (SFT)** on:
1. `(system_context, alert_data) -> plain_english_analysis` pairs
2. `(telemetry_snapshot) -> normal/anomalous` classification
3. `(security_event) -> severity_assessment + recommended_action`

**Format**: Gemma chat template (same as existing fine-tunes)

---

## Training Data Strategy

### Dataset 1: Windows Security Event Logs
- **Source**: Public EVTX datasets (EVTX-ATTACK-SAMPLES, DARPA TCDE, MITRE ATT&CK evaluations)
- **Format**: Event log → (is_attack: bool, technique: str, severity: str, explanation: str)
- **Size target**: 50K+ labeled events
- **Augmentation**: Generate synthetic variants of known attack patterns

### Dataset 2: System Telemetry → Analysis Pairs
- **Source**: Generate from Tron's own baseline collector running on this server
- **Format**: `SystemSnapshot JSON → analysis paragraph`
- **Generation**: Use Gemini/GPT-4 to write the analysis paragraphs for captured snapshots
- **Size target**: 10K snapshots × varied scenarios = 10K pairs
- **Key scenarios to cover**:
  - Normal load (majority)
  - CPU/memory spikes (legitimate vs. suspicious)
  - Service failures
  - Brute-force login attempts
  - New unknown processes
  - Unusual outbound connections

### Dataset 3: Process Behaviour Profiles
- **Source**: Windows process telemetry from Sysmon, Procmon captures
- **Format**: `(process_name, path, parent, connections) → (legitimate: bool, risk_score: 0-10, notes)`
- **Size target**: 5K process profiles
- **Covers**: Masquerading (fake svchost), DLL injection indicators, living-off-the-land binaries (LOLBins)

### Dataset 4: Security Incident Reports (NLP)
- **Source**: Public incident reports (NVD, US-CERT advisories, vendor postmortems)
- **Format**: Incident report text → structured summary (what happened, how detected, remediation)
- **Purpose**: Teach the model to reason about novel threats by analogy

### Dataset 5: Tron's Own Alerts (Self-supervised)
Once Tron is running, collect:
- Every alert fired + system snapshot at time of alert
- Operator response (acknowledged, dismissed, acted on)
- Outcome (false positive, true positive, action taken)

This becomes a **reinforcement signal** for future fine-tuning rounds — the model improves from real operator feedback on this specific system.

---

## Training Pipeline

```
Raw data sources
     │
     ▼
preprocessing/
  normalize_evtx.py        -- EVTX → structured JSON
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

The trained model replaces/augments `LocalModelAnalyzer`:

```csharp
// appsettings.json
"Ai": {
  "EndpointUrl": "http://localhost:11434",  // Ollama serving tron-model
  "Model": "tron-model-v1"
}
```

The model is served via Ollama (already on this system) — no new infrastructure needed.

---

## Timeline (rough)

| Phase | What | When |
|---|---|---|
| **Phase 1** | Tron running, collecting baseline data | Now → 2 weeks |
| **Phase 2** | Build datasets 1 + 3 (public sources) | Week 2-3 |
| **Phase 3** | Generate dataset 2 from live Tron telemetry | Week 3-4 |
| **Phase 4** | First SFT fine-tune on Gemma 4 Nano | Week 4-5 |
| **Phase 5** | Evaluate, iterate, publish tron-model-v1 | Week 5-6 |
| **Phase 6** | Self-supervised improvement loop | Ongoing |

---

## Notes

- All training data stays local — no telemetry leaves the server
- The model will be open-source (matching the gemma4-turbo/nano precedent)
- Will be published to Ollama + HuggingFace under `ssfdre38/tron-model`
- Fine-tuning uses the same pipeline as the g4turbo work (Unsloth + GGUF export)
